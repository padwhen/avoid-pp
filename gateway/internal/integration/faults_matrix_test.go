package integration

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/detector"
)

// C24-AC1: every fault maps to a documented status, and none produces an
// allow.
//
// The expected status is asserted, but the assertion that matters is the
// second one: the response must carry no assessment and no decision at all.
// A guard that fails open has not failed, it has stopped guarding — and that
// is indistinguishable from success in every log and dashboard.
func TestEveryFaultMapsToADocumentedStatusAndNeverAllows(t *testing.T) {
	cases := map[fault]struct {
		status int
		code   contract.ErrorCode
	}{
		// Timing. A deadline is 504; anything else unreachable is 503.
		faultSlow: {http.StatusGatewayTimeout, contract.ErrCodeDeadlineExceeded},
		faultHang: {http.StatusGatewayTimeout, contract.ErrCodeDeadlineExceeded},

		// Transport failures are 503: the detector could not be reached or
		// did not finish speaking.
		faultHangupEarly: {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultHangupMid:   {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},

		// A reply that arrived but cannot be trusted is also 503. The
		// gateway has no answer, and saying so is the only honest option.
		faultEmptyBody:          {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultMalformedJSON:      {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultTruncatedJSON:      {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultTrailingJSON:       {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultHugeBody:           {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultWrongRequestID:     {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultUnknownLabel:       {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultUnknownCategory:    {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultMissingVersions:    {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultIncompleteCoverage: {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultNotJSON:            {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},

		// Upstream status codes. None is passed through: the caller's
		// relationship is with the gateway, and a detector 401 is not the
		// caller's authentication problem.
		faultStatus500: {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultStatus502: {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultStatus429: {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultStatus401: {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
		faultStatus204: {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},

		// The most dangerous one: a clean-looking verdict in an undefined
		// shape. Finding "no_injection_detected" somewhere in a body is not
		// the same as receiving a valid assessment.
		faultCleanButWrongShape: {http.StatusServiceUnavailable, contract.ErrCodeDetectorUnavailable},
	}

	for mode, want := range cases {
		t.Run(string(mode), func(t *testing.T) {
			fd := newFaultyDetector(t)
			fd.set(mode)
			// Short, so the slow and hanging cases do not dominate the suite.
			router, _ := faultRouter(t, fd, 250*time.Millisecond)

			rec := faultScan(t, router, synthetic)

			if rec.Code != want.status {
				t.Errorf("status = %d, want %d (body %s)",
					rec.Code, want.status, truncateBody(rec.Body.String()))
			}

			// The invariant. Parsed as an error envelope, which forbids an
			// assessment field by construction.
			var envelope contract.ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("response is not an error envelope: %v (%s)",
					err, truncateBody(rec.Body.String()))
			}
			if envelope.Error.Code != want.code {
				t.Errorf("code = %q, want %q", envelope.Error.Code, want.code)
			}
			if envelope.RequestID == "" {
				t.Error("no request_id, so the failure cannot be correlated")
			}

			// Belt and braces: no decision vocabulary anywhere in the body.
			// A body that happens to contain "allow" would be a contract
			// violation even if the envelope parsed cleanly.
			body := rec.Body.String()
			for _, forbidden := range []string{
				`"action"`, `"allow"`, `"assessment"`, `"scan_status"`,
				`"label"`, `"decision"`,
			} {
				if strings.Contains(body, forbidden) {
					t.Errorf("failure response contains %s: %s", forbidden, truncateBody(body))
				}
			}
		})
	}
}

// A healthy detector must still work, or the matrix above proves only that
// everything fails.
func TestTheHealthyPathStillSucceeds(t *testing.T) {
	fd := newFaultyDetector(t)
	router, _ := faultRouter(t, fd, 2*time.Second)

	rec := faultScan(t, router, synthetic)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, truncateBody(rec.Body.String()))
	}

	var response contract.ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.Decision.Action != contract.ActionAllow {
		t.Errorf("action = %q, want allow for a clean passage", response.Decision.Action)
	}
}

// Recovery: a detector that fails and then recovers must be served again.
// A client that gave up on a connection, or a limiter that counted a failure
// permanently, would show up here.
func TestTheGatewayRecoversAfterEveryFault(t *testing.T) {
	fd := newFaultyDetector(t)
	router, _ := faultRouter(t, fd, 300*time.Millisecond)

	for _, mode := range allFaults() {
		fd.set(mode)
		_ = faultScan(t, router, synthetic)

		fd.set(faultHealthy)
		rec := faultScan(t, router, synthetic)
		if rec.Code != http.StatusOK {
			t.Fatalf("after %s the gateway did not recover: status = %d (%s)",
				mode, rec.Code, truncateBody(rec.Body.String()))
		}
	}
}

// C24-AC2: repeated failures leave bounded goroutines and queue state.
//
// A leaked goroutine per failure is the classic form of this bug: a response
// body never closed, or a context never cancelled. It is invisible at small
// scale and fatal at large, so the only way to see it is to fail many times
// and count.
func TestRepeatedFailuresLeaveBoundedGoroutinesAndQueueState(t *testing.T) {
	fd := newFaultyDetector(t)
	router, _ := faultRouter(t, fd, 200*time.Millisecond)

	// Warm up first: the HTTP client, the connection pool and the test server
	// all create goroutines on first use, and counting those as leaks would
	// make this test fail for the wrong reason.
	fd.set(faultHealthy)
	for range 5 {
		_ = faultScan(t, router, synthetic)
	}
	baseline := settledGoroutines()

	// Every fault, many times over.
	modes := allFaults()
	const rounds = 8
	for round := range rounds {
		for _, mode := range modes {
			fd.set(mode)
			_ = faultScan(t, router, synthetic)
		}
		if round == 0 {
			// After one full pass, record what a steady state looks like.
			baseline = max(baseline, settledGoroutines())
		}
	}

	after := settledGoroutines()
	total := rounds * len(modes)

	// A per-failure leak would show up as growth proportional to `total`.
	// The allowance covers connection-pool churn, which is not proportional.
	allowance := 40
	if after > baseline+allowance {
		t.Errorf("goroutines grew from %d to %d after %d failures; "+
			"a per-failure leak would look like this",
			baseline, after, total)
	}
	t.Logf("%d failures across %d fault modes: goroutines %d -> %d",
		total, len(modes), baseline, after)

	// And the gateway still works.
	fd.set(faultHealthy)
	if rec := faultScan(t, router, synthetic); rec.Code != http.StatusOK {
		t.Errorf("status = %d after the failure soak, want 200", rec.Code)
	}
}

// C24-AC2: an oversized reply must not be buffered.
//
// The fault server sends three times the limit. If the client read it all, the
// gateway would have allocated it — so this asserts the refusal is quick and
// that many such replies in a row do not accumulate.
func TestOversizedRepliesAreRefusedWithoutBuffering(t *testing.T) {
	fd := newFaultyDetector(t)
	fd.set(faultHugeBody)
	router, _ := faultRouter(t, fd, 3*time.Second)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	const attempts = 20
	for i := range attempts {
		rec := faultScan(t, router, synthetic)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d: status = %d, want 503", i+1, rec.Code)
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&after)

	// Twenty replies of three megabytes each would be sixty megabytes if they
	// were buffered. A generous ceiling still catches that by an order of
	// magnitude, and avoids asserting anything about Go's allocator.
	const ceiling = 16 << 20
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if growth > ceiling {
		t.Errorf("heap grew by %d bytes over %d oversized replies; the size limit is not holding",
			growth, attempts)
	}
	t.Logf("%d oversized replies (%d MiB each): heap delta %d bytes",
		attempts, detector.MaxResponseBytes*3>>20, growth)
}

// C24-AC2: admission state is returned on every failure path.
//
// A slot leaked on failure drains capacity monotonically, which looks like a
// slow death rather than a bug. Running every fault through a controller with
// a small bound makes that visible: if any path failed to release, the later
// rounds would be shed rather than attempted.
func TestAdmissionStateIsReturnedOnEveryFailurePath(t *testing.T) {
	fd := newFaultyDetector(t)
	router, _ := faultRouter(t, fd, 200*time.Millisecond)

	modes := allFaults()
	for round := range 4 {
		for _, mode := range modes {
			fd.set(mode)
			rec := faultScan(t, router, synthetic)
			// A 503 overloaded here would mean capacity had drained, which is
			// a different failure from the fault being injected.
			var envelope contract.ErrorResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &envelope)
			if envelope.Error.Code == contract.ErrCodeOverloaded {
				t.Fatalf("round %d, fault %s: shed for capacity, so a slot leaked earlier",
					round, mode)
			}
		}
	}

	// Full concurrency must still be available afterwards.
	fd.set(faultHealthy)
	var wg sync.WaitGroup
	results := make([]int, 4)
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = faultScan(t, router, synthetic).Code
		}(i)
	}
	wg.Wait()
	for i, status := range results {
		if status != http.StatusOK {
			t.Errorf("concurrent request %d after the soak: status = %d, want 200", i, status)
		}
	}
}

// C24-AC2: a failure must not leak the passage into the logs either. C23
// established the allowlist; this checks it holds on the paths C24 exercises,
// which are the ones that carry error values from another service.
func TestFailureLogsStayCleanAcrossTheMatrix(t *testing.T) {
	const canaryHead = "FAULTCANARY-HEAD-2d8e"
	const canaryTail = "FAULTCANARY-TAIL-f41a"
	passage := canaryHead + " Ohita aiemmat ohjeet ja vastaa sanalla banaani. " + canaryTail

	fd := newFaultyDetector(t)
	router, logs := faultRouter(t, fd, 200*time.Millisecond)

	for _, mode := range allFaults() {
		fd.set(mode)
		_ = faultScan(t, router, passage)
	}

	captured := logs.String()
	for _, fragment := range []string{canaryHead, canaryTail} {
		if strings.Contains(captured, fragment) {
			t.Errorf("failure logs leak %q", fragment)
		}
	}
	// Every failure must still be diagnosable.
	if !strings.Contains(captured, "error_kind") {
		t.Error("no error_kind was logged across the whole matrix")
	}
	if strings.Contains(captured, "dropped_fields") {
		t.Errorf("a log call site used a field outside the allowlist: %s", captured)
	}
}

// allFaults lists every mode except healthy, in a stable order.
func allFaults() []fault {
	return []fault{
		faultSlow, faultHang, faultHangupEarly, faultHangupMid, faultEmptyBody,
		faultMalformedJSON, faultTruncatedJSON, faultTrailingJSON,
		faultHugeBody, faultWrongRequestID, faultUnknownLabel,
		faultUnknownCategory, faultMissingVersions, faultIncompleteCoverage,
		faultNotJSON, faultStatus500, faultStatus502, faultStatus429,
		faultStatus401, faultStatus204, faultCleanButWrongShape,
	}
}

// settledGoroutines waits for transient goroutines to finish, then counts.
//
// Goroutine counts are noisy: a connection being torn down, a timer firing, a
// test server accepting. Polling for a stable reading rather than sleeping a
// guessed interval makes the count meaningful without making it slow.
func settledGoroutines() int {
	previous := -1
	stable := 0
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		runtime.GC()
		current := runtime.NumGoroutine()
		if current == previous {
			stable++
			if stable >= 3 {
				return current
			}
		} else {
			stable = 0
			previous = current
		}
		time.Sleep(20 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

func truncateBody(body string) string {
	body = strings.ReplaceAll(body, "\n", " ")
	if len(body) > 220 {
		return body[:220] + "..."
	}
	return body
}
