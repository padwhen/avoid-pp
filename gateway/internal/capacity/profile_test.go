// Package capacity measures what the gateway costs and where it saturates.
//
// C32 asks for capacity and cost budgets "selected from measured behavior
// rather than copied defaults". The defaults in config.go were reasoned
// about - rates.go argues from what a scan costs, admission.go from measured
// provider latency - but reasoned is not measured, and both files say so and
// name this commit.
//
// # Why a Go harness and not a load generator
//
// The acceptance criterion asks for "a reproducible synthetic load profile"
// and separately for provider work and gateway overhead to be reported
// apart. Both point the same way. An external load generator against a live
// stack measures the provider, the network and the machine's mood together,
// and reproduces none of them; what it cannot do at all is tell you which
// part of a latency number is yours.
//
// Driving the real router in-process against a detector whose latency is a
// parameter separates them by construction: injected latency is provider
// work, and everything above it is the gateway. It also costs nothing, so it
// can be run as often as anyone likes - which is most of what "reproducible"
// means in practice.
//
// What this cannot measure is the provider itself. That is the paid half of
// C32 and lives in evals/provider_profile.py.
//
// # Running it
//
//	make capacity
//
// Skipped by default. It takes about a minute, which is too long for `make
// check` to pay on every commit for a number that only changes when the
// service does.
package capacity

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/admission"
	"github.com/padwhen/avoid-pp/gateway/internal/api"
	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/config"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/detector"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
	"github.com/padwhen/avoid-pp/gateway/internal/obs"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

const capacityKey = "capacity-profile-key-aaaaaaaaaaaaaaaa"

// measuredProviderP50 is the C26 development run's median detector latency.
//
// Used as the injected latency for the realistic profile, so queue behaviour
// is observed at the speed this service actually runs at rather than at a
// speed chosen to make the test quick.
const measuredProviderP50 = 2833 * time.Millisecond

// Input size classes. "Maximum" is the contract's own ceiling, which is the
// only size at which the request-byte limit and the character limit can
// disagree - see TestTheTwoSizeLimitsDisagreeAtTheCeiling.
const (
	shortChars   = 50
	typicalChars = 150
	maxChars     = contract.MaxTextChars
)

func TestCapacityProfile(t *testing.T) {
	requireOptIn(t)

	report := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"hardware": map[string]any{
			"goos":       runtime.GOOS,
			"goarch":     runtime.GOARCH,
			"num_cpu":    runtime.NumCPU(),
			"gomaxprocs": runtime.GOMAXPROCS(0),
			"go_version": runtime.Version(),
			"note":       os.Getenv("AVOIDPP_CAPACITY_HARDWARE"),
		},
		"method": map[string]any{
			"detector": "in-process stub with injected latency; no provider is called",
			"separation": "injected latency is provider work by construction; " +
				"everything above it is gateway overhead",
			"provider_p50_source": "evals/reports/milestones/c26-live-development.json",
		},
	}

	report["overhead"] = overheadProfile(t)
	report["saturation"] = saturationProfile(t)
	report["shipped_defaults"] = map[string]any{
		"max_active":       config.DefaultMaxActive,
		"max_queued":       config.DefaultMaxQueued,
		"caller_rate":      config.DefaultCallerRate,
		"global_rate":      config.DefaultGlobalRate,
		"scan_timeout":     config.DefaultScanTimeout.String(),
		"max_request_byte": api.MaxRequestBytes,
	}

	write(t, report)
}

// overheadProfile answers "what does the gateway itself cost per request".
//
// The detector returns immediately, so the measured latency is almost
// entirely the gateway: parse, validate, authenticate, rate-limit, admit,
// make an internal HTTP call, decode, apply policy, serialise. Concurrency is
// held at 1 so nothing queues and the number is not a queue measurement
// wearing a latency label.
func overheadProfile(t *testing.T) map[string]any {
	t.Helper()
	out := map[string]any{}

	for _, size := range []struct {
		name  string
		chars int
	}{
		{"short", shortChars}, {"typical", typicalChars}, {"maximum", maxChars}} {
		stub := newStubDetector(t, 0)
		router, controller := newRouter(t, stub, 30*time.Second,
			shippedAdmission(),
			limits.Bucket{PerSecond: 1e6, Burst: 1e6})

		result := drive(t, router, driveOptions{
			text:        finnishOf(size.chars),
			requests:    200,
			concurrency: 1,
		})
		result["admission"] = statsOf(controller)
		out[size.name] = result
	}
	return out
}

// saturationProfile answers "where does it break, and how".
//
// Injected latency is the measured provider median, so the throughput ceiling
// is a real one: MaxActive slots divided by how long each occupies one. The
// offered load deliberately exceeds it, because the question C32-AC2 asks is
// not how fast the service is but what it does when asked for more than it
// has.
func saturationProfile(t *testing.T) map[string]any {
	t.Helper()
	out := map[string]any{}

	for _, profile := range []struct {
		name        string
		concurrency int
		requests    int
		cfg         admission.Config
	}{
		{"at_capacity", 4, 8, shippedAdmission()},
		{"over_capacity", 16, 24, shippedAdmission()},
		{"far_over_capacity", 64, 64, shippedAdmission()},
	} {
		stub := newStubDetector(t, measuredProviderP50)
		router, controller := newRouter(t, stub, 30*time.Second, profile.cfg,
			limits.Bucket{PerSecond: 1e6, Burst: 1e6})

		result := drive(t, router, driveOptions{
			text:        finnishOf(typicalChars),
			requests:    profile.requests,
			concurrency: profile.concurrency,
		})
		result["offered_concurrency"] = profile.concurrency
		result["admission"] = statsOf(controller)
		result["theoretical_throughput_per_second"] = round(
			float64(profile.cfg.MaxActive) / measuredProviderP50.Seconds())
		out[profile.name] = result
	}
	return out
}

type driveOptions struct {
	text        string
	requests    int
	concurrency int
}

// drive issues the requests and records what came back.
func drive(t *testing.T, router http.Handler, opts driveOptions) map[string]any {
	t.Helper()

	body := scanBody(t, opts.text)
	latencies := make([]time.Duration, opts.requests)
	statuses := make([]int, opts.requests)
	codes := make([]string, opts.requests)

	stopSampling, peakHeap := sampleHeap()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	work := make(chan int)
	var wg sync.WaitGroup
	started := time.Now()

	for range opts.concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range work {
				at := time.Now()
				status, code := issue(router, body)
				latencies[index] = time.Since(at)
				statuses[index] = status
				codes[index] = code
			}
		}()
	}
	for index := range opts.requests {
		work <- index
	}
	close(work)
	wg.Wait()

	elapsed := time.Since(started)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	stopSampling()

	errors := 0
	byCode := map[string]int{}
	ok := make([]time.Duration, 0, len(latencies))
	for index, status := range statuses {
		if status != http.StatusOK {
			errors++
			byCode[codes[index]]++
			continue
		}
		ok = append(ok, latencies[index])
	}

	return map[string]any{
		"requests":            opts.requests,
		"concurrency":         opts.concurrency,
		"text_chars":          len([]rune(opts.text)),
		"text_bytes":          len(opts.text),
		"wall_clock_seconds":  round(elapsed.Seconds()),
		"throughput_per_sec":  round(float64(opts.requests) / elapsed.Seconds()),
		"error_rate":          round(float64(errors) / float64(opts.requests)),
		"errors_by_code":      byCode,
		"latency_ms":          percentiles(ok),
		"bytes_per_request":   int64(after.TotalAlloc-before.TotalAlloc) / int64(opts.requests),
		"peak_heap_in_use_mb": round(float64(peakHeap()) / (1 << 20)),
		"peak_heap_note": "whole test process: gateway, in-process stub detector and the " +
			"harness itself. An upper bound on the gateway alone, not an attribution.",
	}
}

func issue(router http.Handler, body string) (int, string) {
	request := httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+capacityKey)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code == http.StatusOK {
		return recorder.Code, ""
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &envelope)
	code := envelope.Error.Code
	if code == "" {
		code = "unknown"
	}
	return recorder.Code, code
}

// sampleHeap watches heap occupancy for the duration of a profile.
//
// Go exposes no peak-heap counter, so it is sampled. 10ms is frequent enough
// to catch a profile that accumulates and cheap enough not to distort one.
func sampleHeap() (stop func(), peak func() uint64) {
	done := make(chan struct{})
	var mu sync.Mutex
	var highest uint64

	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				var stats runtime.MemStats
				runtime.ReadMemStats(&stats)
				mu.Lock()
				if stats.HeapInuse > highest {
					highest = stats.HeapInuse
				}
				mu.Unlock()
			}
		}
	}()

	var once sync.Once
	return func() { once.Do(func() { close(done) }) }, func() uint64 {
		mu.Lock()
		defer mu.Unlock()
		return highest
	}
}

func percentiles(samples []time.Duration) map[string]any {
	if len(samples) == 0 {
		return map[string]any{"samples": 0}
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	at := func(fraction float64) float64 {
		index := int(float64(len(sorted)-1) * fraction)
		return round(float64(sorted[index].Microseconds()) / 1000)
	}
	total := time.Duration(0)
	for _, sample := range sorted {
		total += sample
	}
	return map[string]any{
		"samples": len(sorted),
		"min":     at(0),
		"p50":     at(0.50),
		"p90":     at(0.90),
		"p95":     at(0.95),
		"p99":     at(0.99),
		"max":     at(1),
		"mean":    round(float64((total / time.Duration(len(sorted))).Microseconds()) / 1000),
	}
}

func statsOf(controller *admission.Controller) map[string]any {
	stats := controller.Stats()
	return map[string]any{
		"max_active":      stats.MaxActive,
		"max_queued":      stats.MaxQueued,
		"peak_active":     stats.PeakActive,
		"peak_queued":     stats.PeakQueued,
		"admitted":        stats.Admitted,
		"rejected":        stats.Rejected,
		"cancelled":       stats.Cancelled,
		"queued_requests": stats.WaitCount,
		"mean_wait_ms":    round(float64(stats.MeanWait().Microseconds()) / 1000),
		"max_wait_ms":     round(float64(stats.MaxWait.Microseconds()) / 1000),
	}
}

// newStubDetector answers every assessment after a fixed delay.
//
// The delay is the whole point: it stands in for provider work, so whatever
// latency the gateway adds on top is measurable by subtraction.
func newStubDetector(t *testing.T, latency time.Duration) *url.URL {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				RequestID string `json:"request_id"`
				Content   struct {
					Text string `json:"text"`
				} `json:"content"`
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &request)

			if latency > 0 {
				time.Sleep(latency)
			}

			encoded := len(request.Content.Text)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
			  "request_id": %q,
			  "assessment": {"label": "no_injection_detected", "categories": [], "evidence": []},
			  "coverage": {"original_utf8_bytes": %d, "scanned_utf8_bytes": %d, "truncated": false},
			  "versions": {"detector": "capacity-stub", "prompt": "none"}
			}`, request.RequestID, encoded, encoded)
		}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse stub URL: %v", err)
	}
	return parsed
}

func newRouter(
	t *testing.T,
	detectorURL *url.URL,
	timeout time.Duration,
	admissionCfg admission.Config,
	rate limits.Bucket,
) (http.Handler, *admission.Controller) {
	t.Helper()

	registry, err := auth.NewRegistry([]auth.KeySpec{{
		Name:  "capacity",
		Key:   capacityKey,
		Tasks: []contract.TaskID{contract.TaskTranslateFiEnV1},
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	limiter, err := limits.New(
		limits.Config{PerCaller: rate, Global: rate, Unauthenticated: rate},
		[]string{"capacity"})
	if err != nil {
		t.Fatalf("limits.New: %v", err)
	}
	controller, err := admission.New(admissionCfg)
	if err != nil {
		t.Fatalf("admission.New: %v", err)
	}

	readiness := api.NewReadiness()
	readiness.SetReady()
	// Logging to io.Discard, because a profile that measures the cost of
	// writing to a strings.Builder is measuring the harness.
	router := api.NewRouter(readiness, api.ScanDeps{
		Detector:  detector.New(detectorURL, timeout),
		Timeout:   timeout,
		Log:       slog.New(obs.NewHandler(io.Discard, slog.LevelError)),
		Mode:      policy.ModeEnforcement,
		Callers:   registry,
		Limiter:   limiter,
		Admission: controller,
	})
	return router, controller
}

func scanBody(t *testing.T, text string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"task_id": "translate_fi_en_v1",
		"content": map[string]any{
			"id":            "capacity-1",
			"source_type":   "translation_input",
			"language_hint": "fi",
			"text":          text,
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// finnishOf builds a passage of exactly n characters.
//
// Real Finnish rather than filler, because the byte-to-character ratio is
// what makes the two size limits disagree, and 'a' repeated would hide it.
// Built from a fixed sentence rather than from the corpus: a benchmark must
// not depend on dataset contents, and reading the holdout to time a request
// would spend a one-time resource on a stopwatch.
func finnishOf(n int) string {
	const source = "Ilmatieteen laitos ennustaa viikonlopuksi räntäsateita maan " +
		"etelä- ja keskiosiin, ja lämpötila pysyttelee nollan tuntumassa. "
	var builder strings.Builder
	runes := []rune(source)
	for index := 0; index < n; index++ {
		builder.WriteRune(runes[index%len(runes)])
	}
	return builder.String()
}

func round(value float64) float64 {
	return float64(int64(value*10000+0.5)) / 10000
}

// shippedAdmission is what a deployment actually gets.
//
// Profiling hand-written numbers would measure a configuration nobody runs,
// and would keep passing after the defaults changed.
func shippedAdmission() admission.Config {
	return admission.Config{
		MaxActive: config.DefaultMaxActive,
		MaxQueued: config.DefaultMaxQueued,
	}
}

func requireOptIn(t *testing.T) {
	t.Helper()
	if os.Getenv("AVOIDPP_CAPACITY") != "1" {
		t.Skip("set AVOIDPP_CAPACITY=1 (or run `make capacity`) to profile capacity")
	}
}

func write(t *testing.T, report map[string]any) {
	t.Helper()
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	path := filepath.Join("..", "..", "..", "evals", "reports", "c32-capacity.json")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Logf("wrote %s", path)
}
