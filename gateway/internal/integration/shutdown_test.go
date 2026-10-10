// C24-AC3: shutdown under in-flight work.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/api"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/obs"
	"github.com/padwhen/avoid-pp/gateway/internal/server"
)

// liveGateway runs the real listener, so shutdown is exercised through the
// same path a signal would take rather than through httptest.
type liveGateway struct {
	addr   string
	cancel context.CancelFunc
	logs   *bytes.Buffer

	// Run's error, delivered once. It is cached on first read because a
	// one-shot channel read twice blocks forever — which is exactly the hang
	// the first draft of these tests produced, since both the test body and
	// its cleanup wanted the result.
	done     chan error
	waitOnce sync.Once
	runErr   error
	returned bool
}

// wait returns Run's error, blocking at most for the timeout. Safe to call
// more than once.
func (g *liveGateway) wait(timeout time.Duration) (error, bool) {
	g.waitOnce.Do(func() {
		select {
		case g.runErr = <-g.done:
			g.returned = true
		case <-time.After(timeout):
		}
	})
	return g.runErr, g.returned
}

func startLiveGateway(
	t *testing.T, fd *faultyDetector, scanTimeout, drain time.Duration,
) *liveGateway {
	t.Helper()

	router, _ := faultRouter(t, fd, scanTimeout)
	logs := &bytes.Buffer{}

	srv, err := server.New(server.Options{
		Addr:    "127.0.0.1:0",
		Handler: router,
		Drain:   drain,
		Log:     slog.New(obs.NewHandler(logs, slog.LevelDebug)),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	gateway := &liveGateway{addr: srv.Addr(), done: done, cancel: cancel, logs: logs}
	t.Cleanup(func() {
		cancel()
		gateway.wait(5 * time.Second)
	})

	// Wait for the listener to answer rather than sleeping.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + gateway.addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			return gateway
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the gateway never became reachable")
	return nil
}

// scanOver sends a real HTTP request to the running gateway.
func scanOver(addr, text string) (int, string, error) {
	raw, err := json.Marshal(map[string]any{
		"task_id": "translate_fi_en_v1",
		"content": map[string]any{
			"id":          "p-shutdown",
			"source_type": "translation_input",
			"text":        text,
		},
	})
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequest(http.MethodPost,
		"http://"+addr+"/v1/scans", bytes.NewReader(raw))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+faultKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

// C24-AC3: in-flight work finishes, and the drain completes within budget.
//
// The detector here is slow but not slower than the drain budget, so the
// correct behaviour is that accepted requests complete rather than being cut
// off. C07 established that for health endpoints; this establishes it for a
// scan that is mid-call to another service.
func TestShutdownCompletesInFlightWorkWithinBudget(t *testing.T) {
	fd := newFaultyDetector(t)
	// Slower than instant, so requests are genuinely in flight, but well
	// inside the drain budget.
	fd.set(faultHealthy)
	gateway := startLiveGateway(t, fd, 5*time.Second, 3*time.Second)

	const inFlight = 4
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []int
		errs    []error
	)

	// Hold the detector so the requests are provably mid-call when shutdown
	// begins, rather than relying on timing.
	release := make(chan struct{})
	fd.hold(release)

	for range inFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, _, err := scanOver(gateway.addr, synthetic)
			mu.Lock()
			if err != nil {
				errs = append(errs, err)
			} else {
				results = append(results, status)
			}
			mu.Unlock()
		}()
	}

	// Wait until all four are actually inside the detector call.
	waitForCalls(t, fd, inFlight)

	started := time.Now()
	gateway.cancel()

	// Let the detector answer, as a healthy dependency would during a drain.
	close(release)

	runErr, returned := gateway.wait(10 * time.Second)
	if !returned {
		t.Fatal("Run did not return; the drain budget was not honoured")
	}
	elapsed := time.Since(started)
	wg.Wait()

	if runErr != nil {
		t.Errorf("Run returned %v; a drain that completes should return nil", runErr)
	}
	// Within budget, with headroom for scheduling rather than a tight bound.
	if elapsed > 5*time.Second {
		t.Errorf("drain took %v, over the 3s budget", elapsed)
	}

	// C24-AC3: defined outcomes. Every in-flight request either completed or
	// failed cleanly; none was cut off mid-response.
	if len(errs) > 0 {
		t.Errorf("%d in-flight requests were cut off during drain: %v", len(errs), errs)
	}
	if len(results) != inFlight {
		t.Fatalf("got %d results for %d in-flight requests", len(results), inFlight)
	}
	for _, status := range results {
		if status != http.StatusOK {
			t.Errorf("in-flight request got %d, want 200; accepted work should finish", status)
		}
	}
	t.Logf("drained %d in-flight scans in %v (budget 3s)", inFlight, elapsed)
}

// C24-AC3: a drain that cannot finish reports it rather than exiting zero.
//
// The detector holds longer than the budget allows, so the drain expires with
// work still in flight. Exiting silently would make a routinely-too-short
// budget invisible.
func TestADrainThatExpiresReportsIt(t *testing.T) {
	fd := newFaultyDetector(t)
	gateway := startLiveGateway(t, fd, 10*time.Second, 300*time.Millisecond)

	release := make(chan struct{})
	fd.hold(release)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _ = scanOver(gateway.addr, synthetic)
	}()
	waitForCalls(t, fd, 1)

	// Released explicitly below rather than in a defer. A deferred close
	// would run *after* wg.Wait(), so the wait would be on a request that is
	// waiting on the close — a deadlock broken only by the scan timeout,
	// which is what made the first version of this test take ten seconds.
	released := false
	releaseNow := func() {
		if !released {
			released = true
			close(release)
		}
	}
	defer releaseNow()

	started := time.Now()
	gateway.cancel()

	runErr, returned := gateway.wait(10 * time.Second)
	if !returned {
		t.Fatal("Run did not return")
	}
	elapsed := time.Since(started)

	// Let the held request finish before waiting for it.
	releaseNow()
	wg.Wait()

	if runErr == nil {
		t.Error("Run returned nil after an incomplete drain; a too-short budget would be invisible")
	}
	if runErr != nil && !strings.Contains(runErr.Error(), "drain") {
		t.Errorf("error = %v, want it to mention the drain", runErr)
	}
	// It must give up at the budget rather than waiting for the work.
	if elapsed > 3*time.Second {
		t.Errorf("drain waited %v past a 300ms budget", elapsed)
	}
	t.Logf("incomplete drain reported after %v: %v", elapsed, runErr)
}

// C24-AC3: readiness fails the instant draining starts, so a load balancer
// routes new traffic away while accepted work finishes.
func TestReadinessFailsWhenDrainingBegins(t *testing.T) {
	fd := newFaultyDetector(t)
	router, _ := faultRouter(t, fd, time.Second)

	readiness := api.NewReadiness()
	readiness.SetReady()
	logs := &bytes.Buffer{}
	srv, err := server.New(server.Options{
		Addr:    "127.0.0.1:0",
		Handler: router,
		Drain:   time.Second,
		Log:     slog.New(obs.NewHandler(logs, slog.LevelDebug)),
		OnDrain: readiness.SetNotReady,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	defer cancel()

	addr := srv.Addr()
	waitReachable(t, addr)

	if status := probe(t, addr, "/readyz"); status != http.StatusOK {
		t.Fatalf("readiness before drain = %d, want 200", status)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}

	// The listener is closed after a drain, so readiness is checked on the
	// Readiness value itself: the point is that OnDrain flipped it, not that
	// a closed socket refuses connections.
	if readiness.Ready() {
		t.Error("readiness still reports ready after draining began")
	}
}

// A bounded soak: synthetic text through the whole fault matrix, repeatedly,
// asserting the gateway is in the same state at the end as at the beginning.
//
// Bounded on purpose. A soak that runs for an hour finds more, and does not
// belong in a suite that has to pass on every commit; this one is sized to
// catch per-iteration leaks, which are the kind that matter.
func TestBoundedSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("soak skipped under -short")
	}

	fd := newFaultyDetector(t)
	router, logs := faultRouter(t, fd, 150*time.Millisecond)

	// Synthetic text, varied so no code path can be accidentally caching.
	passages := make([]string, 16)
	for i := range passages {
		passages[i] = fmt.Sprintf(
			"%s Toisto %d. %s", synthetic, i, strings.Repeat("ä", i*32))
	}

	fd.set(faultHealthy)
	for range 5 {
		_ = faultScan(t, router, passages[0])
	}
	baseline := settledGoroutines()

	modes := append(allFaults(), faultHealthy)
	const rounds = 12
	statuses := map[int]int{}

	for round := range rounds {
		for index, mode := range modes {
			fd.set(mode)
			rec := faultScan(t, router, passages[(round+index)%len(passages)])
			statuses[rec.Code]++

			// The invariant, on every single iteration rather than at the end.
			if rec.Code == http.StatusOK && mode != faultHealthy {
				t.Fatalf("round %d: fault %s produced a 200", round, mode)
			}
			if rec.Code != http.StatusOK {
				var envelope contract.ErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
					t.Fatalf("round %d, fault %s: body is not an error envelope: %s",
						round, mode, truncateBody(rec.Body.String()))
				}
			}
		}
	}

	after := settledGoroutines()
	total := rounds * len(modes)

	if after > baseline+40 {
		t.Errorf("goroutines %d -> %d over %d requests", baseline, after, total)
	}
	if strings.Contains(logs.String(), "dropped_fields") {
		t.Error("a log call site drifted outside the allowlist during the soak")
	}

	// Still healthy at the end.
	fd.set(faultHealthy)
	if rec := faultScan(t, router, synthetic); rec.Code != http.StatusOK {
		t.Errorf("status = %d after the soak, want 200", rec.Code)
	}

	t.Logf("soak: %d requests across %d modes, statuses %v, goroutines %d -> %d",
		total, len(modes), statuses, baseline, after)
}

func waitReachable(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("never became reachable")
}

func probe(t *testing.T, addr, path string) int {
	t.Helper()
	resp, err := http.Get("http://" + addr + path)
	if err != nil {
		t.Fatalf("probe %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// waitForCalls blocks until the faulty detector has received n requests.
func waitForCalls(t *testing.T, fd *faultyDetector, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fd.inFlight() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("only %d of %d requests reached the detector", fd.inFlight(), n)
}
