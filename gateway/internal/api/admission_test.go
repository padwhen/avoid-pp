// C22: admission control over HTTP, driven by a blocking fake detector.
//
// The acceptance criteria ask for a load fixture that never exceeds the
// configured concurrency or queue length. A fake that returns instantly cannot
// produce contention, so the fake here blocks until released — which is what
// makes the concurrency observable at all.
package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/admission"
	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/detector"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

// blockingAssessor holds every call until released, and records the high-water
// mark of concurrent calls independently of the controller's own counters — so
// the assertion does not trust the thing it is testing.
type blockingAssessor struct {
	gate     chan struct{}
	inFlight atomic.Int64
	peak     atomic.Int64
	started  atomic.Int64
	finished atomic.Int64
	// observed is closed-over state for tests that need to know a call arrived.
	arrived chan struct{}
}

func newBlockingAssessor() *blockingAssessor {
	return &blockingAssessor{
		gate:    make(chan struct{}),
		arrived: make(chan struct{}, 1024),
	}
}

func (b *blockingAssessor) Assess(
	ctx context.Context, req detector.AssessmentRequest,
) (*detector.AssessmentResponse, error) {
	b.started.Add(1)
	current := b.inFlight.Add(1)
	for {
		high := b.peak.Load()
		if current <= high || b.peak.CompareAndSwap(high, current) {
			break
		}
	}
	select {
	case b.arrived <- struct{}{}:
	default:
	}

	defer func() {
		b.inFlight.Add(-1)
		b.finished.Add(1)
	}()

	select {
	case <-b.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	response := &detector.AssessmentResponse{
		Assessment: contract.Assessment{
			Label:      contract.LabelNoInjectionDetected,
			Categories: []contract.Category{},
			Evidence:   []contract.EvidenceItem{},
		},
		Coverage: contract.Coverage{
			OriginalUTF8Bytes: len(req.Content.Text),
			ScannedUTF8Bytes:  len(req.Content.Text),
		},
	}
	response.Versions.Detector = "blocking-fake"
	response.Versions.Prompt = "none"
	return response, nil
}

func (b *blockingAssessor) releaseAll() { close(b.gate) }

// admissionRouter wires a router whose only interesting bound is admission.
func admissionRouter(
	t *testing.T, cfg admission.Config, timeout time.Duration,
) (http.Handler, *blockingAssessor, *admission.Controller) {
	t.Helper()

	registry, err := auth.NewRegistry([]auth.KeySpec{{
		Name:  "authorised",
		Key:   authorisedKey,
		Tasks: []contract.TaskID{contract.TaskTranslateFiEnV1},
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	big := limits.Bucket{PerSecond: 1e6, Burst: 1e6}
	limiter, err := limits.New(
		limits.Config{PerCaller: big, Global: big, Unauthenticated: big},
		[]string{"authorised"})
	if err != nil {
		t.Fatalf("limits.New: %v", err)
	}
	controller, err := admission.New(cfg)
	if err != nil {
		t.Fatalf("admission.New: %v", err)
	}

	assessor := newBlockingAssessor()
	readiness := NewReadiness()
	readiness.SetReady()
	return NewRouter(readiness, ScanDeps{
		Detector:  assessor,
		Timeout:   timeout,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mode:      policy.ModeMonitoring,
		Callers:   registry,
		Limiter:   limiter,
		Admission: controller,
	}), assessor, controller
}

// C22-AC1: the load fixture never exceeds either configured bound.
func TestLoadNeverExceedsConcurrencyOrQueue(t *testing.T) {
	const (
		maxActive = 3
		maxQueued = 5
		callers   = 60
	)
	router, assessor, controller := admissionRouter(
		t, admission.Config{MaxActive: maxActive, MaxQueued: maxQueued}, 5*time.Second)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses = map[int]int{}
	)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
			mu.Lock()
			statuses[rec.Code]++
			mu.Unlock()
		}()
	}

	// Wait until the slots and the queue are both full, then assert the
	// bounds while the system is actually saturated.
	waitUntil(t, func() bool {
		stats := controller.Stats()
		return stats.Active == maxActive && stats.Queued == maxQueued
	})

	saturated := controller.Stats()
	if saturated.Active > maxActive {
		t.Errorf("Active = %d, over the configured %d", saturated.Active, maxActive)
	}
	if saturated.Queued > maxQueued {
		t.Errorf("Queued = %d, over the configured %d", saturated.Queued, maxQueued)
	}

	assessor.releaseAll()
	wg.Wait()

	// The independent count, which never trusted the controller.
	if peak := assessor.peak.Load(); peak > maxActive {
		t.Errorf("the detector saw %d concurrent calls, over the configured %d",
			peak, maxActive)
	}
	stats := controller.Stats()
	if stats.PeakActive > maxActive {
		t.Errorf("PeakActive = %d, over %d", stats.PeakActive, maxActive)
	}
	if stats.PeakQueued > maxQueued {
		t.Errorf("PeakQueued = %d, over %d", stats.PeakQueued, maxQueued)
	}

	// Everything is accounted for, and the excess was shed rather than queued.
	if total := statuses[200] + statuses[503]; total != callers {
		t.Errorf("statuses %v do not account for %d requests", statuses, callers)
	}
	if statuses[503] == 0 {
		t.Error("no request was shed; the bound did not bind")
	}
	// Only admitted requests reached the detector.
	if started := assessor.started.Load(); int(started) != statuses[200] {
		t.Errorf("detector saw %d calls but %d requests succeeded", started, statuses[200])
	}
	if stats.Active != 0 || stats.Queued != 0 {
		t.Errorf("not drained: active=%d queued=%d", stats.Active, stats.Queued)
	}
	t.Logf("statuses %v; detector peak %d; controller peak active %d queued %d",
		statuses, assessor.peak.Load(), stats.PeakActive, stats.PeakQueued)
}

// C22-AC2: excess work receives 503 with retry guidance, not an indefinite wait.
func TestExcessWorkIsShedWith503(t *testing.T) {
	router, assessor, controller := admissionRouter(
		t, admission.Config{MaxActive: 1, MaxQueued: 0}, 5*time.Second)

	// Occupy the only slot.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	}()
	waitUntil(t, func() bool { return controller.Stats().Active == 1 })

	// With no queue, the next request is shed immediately.
	started := time.Now()
	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	elapsed := time.Since(started)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (%s)", rec.Code, rec.Body.String())
	}
	if code := errorCode(t, rec); code != contract.ErrCodeOverloaded {
		t.Errorf("code = %q, want overloaded", code)
	}
	// It must not have waited for the blocked call.
	if elapsed > time.Second {
		t.Errorf("the shed request took %v; it should not have waited", elapsed)
	}

	// Retry guidance, in the header and the body, as with a 429.
	header := rec.Header().Get("Retry-After")
	seconds, err := strconv.Atoi(header)
	if err != nil || seconds < 1 {
		t.Errorf("Retry-After = %q, want whole seconds of at least 1", header)
	}
	var body contract.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.RetryAfterSeconds != seconds {
		t.Errorf("retry_after_seconds = %d but Retry-After = %d",
			body.Error.RetryAfterSeconds, seconds)
	}
	if body.RequestID == "" {
		t.Error("a shed response carries no request_id")
	}

	// A shed request never reached the detector.
	if started := assessor.started.Load(); started != 1 {
		t.Errorf("detector saw %d calls, want only the admitted one", started)
	}

	assessor.releaseAll()
	wg.Wait()
}

// C22-AC2: a deadline that passes while queued releases the slot, and the
// request gets a timeout rather than being served late.
func TestDeadlineWhileQueuedReleasesTheSlot(t *testing.T) {
	// A short scan timeout, so the queued request runs out of budget while
	// the slot is still held.
	router, assessor, controller := admissionRouter(
		t, admission.Config{MaxActive: 1, MaxQueued: 4}, 150*time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	}()
	waitUntil(t, func() bool { return controller.Stats().Active == 1 })

	// This one queues, then times out.
	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504 (%s)", rec.Code, rec.Body.String())
	}
	if code := errorCode(t, rec); code != contract.ErrCodeDeadlineExceeded {
		t.Errorf("code = %q, want deadline_exceeded", code)
	}

	// The queue place was given back rather than held by a request that is
	// no longer waiting.
	waitUntil(t, func() bool { return controller.Stats().Queued == 0 })

	assessor.releaseAll()
	wg.Wait()

	// Capacity is fully restored.
	if stats := controller.Stats(); stats.Active != 0 {
		t.Errorf("Active = %d after everything finished, want 0", stats.Active)
	}
}

// C22-AC3: a long request uses the same bounded pathway. There is no separate
// route for large passages that could skip admission or the detector's own
// size limits.
func TestLongRequestsUseTheSameBoundedPathway(t *testing.T) {
	router, assessor, controller := admissionRouter(
		t, admission.Config{MaxActive: 1, MaxQueued: 0}, 5*time.Second)

	// The largest passage that can actually arrive.
	//
	// Not 32,768 multi-byte characters: "ä" is two UTF-8 bytes, so a
	// full-length Finnish passage is 64 KiB of text and exceeds the 64 KiB
	// body limit before admission is reached. The two limits are in different
	// units and the smaller binds, exactly as C20 documented — this test hit
	// that on the first run.
	long := strings.Repeat("a", contract.MaxTextChars)
	body, err := json.Marshal(map[string]any{
		"task_id": "translate_fi_en_v1",
		"content": map[string]any{
			"id":          "p-long",
			"source_type": "translation_input",
			"text":        long,
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		post(t, router, "Bearer "+authorisedKey, string(body))
	}()
	waitUntil(t, func() bool { return controller.Stats().Active == 1 })

	// It occupies exactly one slot — not zero, and not a separate pool.
	if stats := controller.Stats(); stats.Active != 1 {
		t.Errorf("Active = %d for a maximal passage, want exactly 1", stats.Active)
	}
	// And while it holds that slot, a small request is shed like any other.
	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503; a long request did not hold the bound",
			rec.Code)
	}

	assessor.releaseAll()
	wg.Wait()

	// The passage reached the detector whole: admission does not trim, and
	// the size limits that apply to it are the detector's own.
	if stats := controller.Stats(); stats.Active != 0 {
		t.Errorf("Active = %d, want 0 after release", stats.Active)
	}

	// A passage one character over the contract limit never reaches admission
	// at all, so size enforcement is not something admission can bypass.
	tooLong, _ := json.Marshal(map[string]any{
		"task_id": "translate_fi_en_v1",
		"content": map[string]any{
			"id":          "p-too-long",
			"source_type": "translation_input",
			"text":        strings.Repeat("a", contract.MaxTextChars+1),
		},
	})
	before := controller.Stats().Admitted
	rec = post(t, router, "Bearer "+authorisedKey, string(tooLong))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422 for an over-length passage", rec.Code)
	}
	if after := controller.Stats().Admitted; after != before {
		t.Error("an over-length passage consumed an admission slot")
	}
}

// Rejected requests never reach the detector, which is the AC3 property that
// matters for cost: a shed request must cost nothing downstream.
func TestShedRequestsNeverReachTheDetector(t *testing.T) {
	router, assessor, controller := admissionRouter(
		t, admission.Config{MaxActive: 1, MaxQueued: 0}, 5*time.Second)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	}()
	waitUntil(t, func() bool { return controller.Stats().Active == 1 })

	for range 50 {
		rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	}

	if started := assessor.started.Load(); started != 1 {
		t.Errorf("detector saw %d calls after 50 shed requests, want 1", started)
	}
	if stats := controller.Stats(); stats.Rejected != 50 {
		t.Errorf("Rejected = %d, want 50", stats.Rejected)
	}

	assessor.releaseAll()
	wg.Wait()
}

// Health endpoints are not gated by admission: readiness must answer while
// the service is saturated, which is exactly when someone is looking at it.
func TestHealthAnswersWhileSaturated(t *testing.T) {
	router, assessor, controller := admissionRouter(
		t, admission.Config{MaxActive: 1, MaxQueued: 0}, 5*time.Second)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	}()
	waitUntil(t, func() bool { return controller.Stats().Active == 1 })

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s while saturated = %d, want 200", path, rec.Code)
		}
	}

	assessor.releaseAll()
	wg.Wait()
}

// waitUntil polls rather than sleeping a guessed interval.
func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within the deadline")
}
