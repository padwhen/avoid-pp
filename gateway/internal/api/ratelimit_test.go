// C21: rate limiting over HTTP.
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

// limitedRouter builds a router with tight limits, so a handful of requests
// is enough to exercise the 429 path.
func limitedRouter(t *testing.T, cfg limits.Config) (http.Handler, *countingAssessor) {
	t.Helper()

	registry, err := auth.NewRegistry([]auth.KeySpec{
		{
			Name:  "authorised",
			Key:   authorisedKey,
			Tasks: []contract.TaskID{contract.TaskTranslateFiEnV1},
		},
		{
			Name:  "second-caller",
			Key:   unauthorisedKey,
			Tasks: []contract.TaskID{contract.TaskTranslateFiEnV1},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	limiter, err := limits.New(cfg, []string{"authorised", "second-caller"})
	if err != nil {
		t.Fatalf("limits.New: %v", err)
	}

	counter := &countingAssessor{}
	readiness := NewReadiness()
	readiness.SetReady()
	return NewRouter(readiness, ScanDeps{
		Detector:  counter,
		Timeout:   2 * time.Second,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mode:      policy.ModeMonitoring,
		Callers:   registry,
		Limiter:   limiter,
		Admission: permissiveAdmission(),
	}), counter
}

func tight(perSecond float64, burst int) limits.Bucket {
	return limits.Bucket{PerSecond: perSecond, Burst: burst}
}

func generous() limits.Bucket { return limits.Bucket{PerSecond: 1e6, Burst: 1e6} }

// C21-AC1 and AC3: over the burst, requests become 429 and stop reaching the
// detector entirely.
func TestOverTheBurstIs429AndNeverReachesTheDetector(t *testing.T) {
	const burst = 3
	router, counter := limitedRouter(t, limits.Config{
		PerCaller:       tight(1, burst),
		Global:          generous(),
		Unauthenticated: generous(),
	})

	// The burst is admitted.
	for i := range burst {
		rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (%s)", i+1, rec.Code, rec.Body.String())
		}
	}
	if calls := counter.calls.Load(); calls != burst {
		t.Fatalf("detector calls = %d, want %d", calls, burst)
	}

	// Everything beyond it is refused, and the detector sees none of it.
	for i := range 20 {
		rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d past the burst: status = %d, want 429", i+1, rec.Code)
		}
	}
	if calls := counter.calls.Load(); calls != burst {
		t.Errorf("detector calls = %d after 20 rate-limited requests, want %d still",
			calls, burst)
	}
}

// C21-AC1: the 429 carries retry guidance a client can act on, in both the
// header and the body.
func TestRateLimitedResponseCarriesRetryGuidance(t *testing.T) {
	router, _ := limitedRouter(t, limits.Config{
		PerCaller:       tight(1, 1),
		Global:          generous(),
		Unauthenticated: generous(),
	})

	if rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1")); rec.Code != http.StatusOK {
		t.Fatalf("the first request was refused: %d", rec.Code)
	}

	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if code := errorCode(t, rec); code != contract.ErrCodeRateLimited {
		t.Errorf("code = %q, want rate_limited", code)
	}

	// The header, for clients and proxies that honour it automatically.
	header := rec.Header().Get("Retry-After")
	if header == "" {
		t.Fatal("no Retry-After header")
	}
	headerSeconds, err := strconv.Atoi(header)
	if err != nil {
		t.Fatalf("Retry-After = %q, want whole seconds", header)
	}
	if headerSeconds < 1 {
		t.Errorf("Retry-After = %d; a value of 0 invites an immediate retry", headerSeconds)
	}

	// The body field, for an application whose client library does not
	// surface response headers on an error path.
	var body contract.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.RetryAfterSeconds != headerSeconds {
		t.Errorf("retry_after_seconds = %d but Retry-After = %d; they must agree",
			body.Error.RetryAfterSeconds, headerSeconds)
	}
	if body.RequestID == "" {
		t.Error("a rate-limited response carries no request_id")
	}
}

// The response must not say which bucket was hit. Telling a caller it was the
// global limit rather than its own discloses that other callers are busy.
func TestRateLimitedResponseDoesNotDiscloseTheScope(t *testing.T) {
	// Caller-scoped refusal.
	callerLimited, _ := limitedRouter(t, limits.Config{
		PerCaller:       tight(1, 1),
		Global:          generous(),
		Unauthenticated: generous(),
	})
	post(t, callerLimited, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	byCaller := post(t, callerLimited, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))

	// Global-scoped refusal. With both bursts at 1, the first caller's single
	// request drains the shared bucket while the second caller's own bucket
	// is still full — so the refusal it gets can only be the global one.
	globalLimited, _ := limitedRouter(t, limits.Config{
		PerCaller:       tight(1, 1),
		Global:          tight(1, 1),
		Unauthenticated: generous(),
	})
	post(t, globalLimited, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	byGlobal := post(t, globalLimited, "Bearer "+unauthorisedKey, taskBody("translate_fi_en_v1"))

	if byCaller.Code != http.StatusTooManyRequests || byGlobal.Code != http.StatusTooManyRequests {
		t.Fatalf("expected two 429s, got %d and %d", byCaller.Code, byGlobal.Code)
	}

	var a, b contract.ErrorResponse
	_ = json.Unmarshal(byCaller.Body.Bytes(), &a)
	_ = json.Unmarshal(byGlobal.Body.Bytes(), &b)

	if a.Error.Code != b.Error.Code || a.Error.Message != b.Error.Message {
		t.Errorf("the two refusals are distinguishable:\n caller %+v\n global %+v",
			a.Error, b.Error)
	}
	for _, word := range []string{"global", "caller", "other", "tenant"} {
		if strings.Contains(strings.ToLower(b.Error.Message), word) {
			t.Errorf("the message discloses the scope: %q", b.Error.Message)
		}
	}
}

// C21-AC2: unauthenticated traffic is bounded, and cannot create state.
func TestUnauthenticatedTrafficIsBounded(t *testing.T) {
	const burst = 3
	router, counter := limitedRouter(t, limits.Config{
		PerCaller:       generous(),
		Global:          generous(),
		Unauthenticated: tight(1, burst),
	})

	// The first few bad credentials get a 401.
	for i := range burst {
		rec := post(t, router, "Bearer "+strings.Repeat("z", 40), taskBody("translate_fi_en_v1"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, rec.Code)
		}
	}

	// Past the burst the answer becomes 429, which discloses less than 401.
	for i := range 20 {
		rec := post(t, router, "Bearer "+strings.Repeat("z", 40), taskBody("translate_fi_en_v1"))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d past the burst: status = %d, want 429", i+1, rec.Code)
		}
	}

	// A legitimate caller is unaffected by the flood. This is the property
	// that makes one shared unauthenticated bucket acceptable instead of a
	// per-source map an attacker could grow.
	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	if rec.Code != http.StatusOK {
		t.Errorf("an authenticated caller got %d during an unauthenticated flood", rec.Code)
	}
	if calls := counter.calls.Load(); calls != 1 {
		t.Errorf("detector calls = %d, want exactly 1", calls)
	}
}

// A credential-guessing flood from many distinct sources must not create
// per-source state. Each request here carries a different remote address.
func TestAFloodFromManySourcesCreatesNoState(t *testing.T) {
	router, counter := limitedRouter(t, limits.Config{
		PerCaller:       generous(),
		Global:          generous(),
		Unauthenticated: tight(1, 1),
	})

	for i := range 500 {
		req := httptest.NewRequest(http.MethodPost, "/v1/scans",
			strings.NewReader(taskBody("translate_fi_en_v1")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 40))
		// A distinct source per request, which is what would fill a per-IP map.
		req.RemoteAddr = "10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256) + ":1234"
		// And distinct forwarding headers, in case anything reads those.
		req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		req.Header.Set("X-Real-IP", req.RemoteAddr)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d: status = %d, want 401 or 429", i, rec.Code)
		}
	}

	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector calls = %d, want 0", calls)
	}
}

// Rate limiting runs before the body is parsed, so a refused request costs no
// parsing either.
func TestRateLimitPrecedesParsing(t *testing.T) {
	router, counter := limitedRouter(t, limits.Config{
		PerCaller:       tight(1, 1),
		Global:          generous(),
		Unauthenticated: generous(),
	})

	// Spend the single token on a valid request.
	if rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1")); rec.Code != http.StatusOK {
		t.Fatalf("the first request was refused: %d", rec.Code)
	}

	// Now send bodies that would each be a 400 or 422. The 429 must win,
	// because the limiter runs first.
	for name, body := range map[string]string{
		"malformed":      `}{`,
		"duplicate keys": `{"a":1,"a":2}`,
		"unknown field":  `{"task_id":"translate_fi_en_v1","policy":"x"}`,
		"wrong type":     `{"task_id":123}`,
		"oversized":      strings.Repeat("x", MaxRequestBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			rec := post(t, router, "Bearer "+authorisedKey, body)
			if rec.Code != http.StatusTooManyRequests {
				t.Errorf("status = %d, want 429 before parsing", rec.Code)
			}
		})
	}

	if calls := counter.calls.Load(); calls != 1 {
		t.Errorf("detector calls = %d, want 1", calls)
	}
}

// An unauthorised task is still rate limited: authorisation happens in the
// handler, which is behind the limiter, so a caller cannot probe task grants
// without spending its own budget.
func TestRateLimitAppliesBeforeAuthorisation(t *testing.T) {
	router, _ := limitedRouter(t, limits.Config{
		PerCaller:       tight(1, 1),
		Global:          generous(),
		Unauthenticated: generous(),
	})

	if rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1")); rec.Code != http.StatusOK {
		t.Fatalf("the first request was refused: %d", rec.Code)
	}
	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_sv_en_v1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 rather than an unknown-task answer", rec.Code)
	}
}

// Health endpoints are not rate limited: a readiness probe that starts
// failing because it polled too often would take the instance out of service
// for no reason.
func TestHealthEndpointsAreNotRateLimited(t *testing.T) {
	router, _ := limitedRouter(t, limits.Config{
		PerCaller:       tight(1, 1),
		Global:          tight(1, 1),
		Unauthenticated: tight(1, 1),
	})

	for range 50 {
		for _, path := range []string{"/healthz", "/readyz"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200", path, rec.Code)
			}
		}
	}
}

// Fail closed: without a limiter the route is absent rather than unlimited.
func TestScanRouteIsAbsentWithoutALimiter(t *testing.T) {
	registry, err := auth.NewRegistry([]auth.KeySpec{{
		Name:  "authorised",
		Key:   authorisedKey,
		Tasks: []contract.TaskID{contract.TaskTranslateFiEnV1},
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	counter := &countingAssessor{}
	readiness := NewReadiness()
	readiness.SetReady()
	router := NewRouter(readiness, ScanDeps{
		Detector:  counter,
		Timeout:   time.Second,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mode:      policy.ModeMonitoring,
		Callers:   registry,
		Admission: permissiveAdmission(),
		// Limiter deliberately nil.
	})

	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 with no limiter configured", rec.Code)
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector calls = %d, want 0", calls)
	}
}

// C21-AC3: concurrent admission over HTTP is race-free, and the number
// admitted never exceeds the burst.
func TestConcurrentRequestsRespectTheBurst(t *testing.T) {
	const burst = 10
	router, counter := limitedRouter(t, limits.Config{
		// A sustained rate low enough that refills cannot meaningfully add to
		// the burst inside the test's runtime.
		PerCaller:       tight(0.01, burst),
		Global:          generous(),
		Unauthenticated: generous(),
	})

	var (
		wg                 sync.WaitGroup
		mu                 sync.Mutex
		ok, limited, other int
	)

	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
			mu.Lock()
			switch rec.Code {
			case http.StatusOK:
				ok++
			case http.StatusTooManyRequests:
				limited++
			default:
				other++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if other != 0 {
		t.Errorf("%d requests got an unexpected status", other)
	}
	if ok != burst {
		t.Errorf("admitted %d, want exactly %d; tokens were double-counted under contention",
			ok, burst)
	}
	if limited != 100-burst {
		t.Errorf("rate limited %d, want %d", limited, 100-burst)
	}
	if calls := counter.calls.Load(); int(calls) != burst {
		t.Errorf("detector calls = %d, want %d", calls, burst)
	}
}
