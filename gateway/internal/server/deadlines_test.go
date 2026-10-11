package server

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/config"
)

// The connection deadlines C32 added.
//
// Each one exists because Go's zero value is wrong for this service in a
// different way, and each failure is quiet: an unbounded read is a slow
// client holding a connection, an unset idle timeout silently inherits the
// read timeout and kills keep-alives, and a write timeout shorter than the
// handler truncates work that has already been paid for.

func newFor(t *testing.T, budget time.Duration) *http.Server {
	t.Helper()
	srv, err := New(Options{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), ScanBudget: budget})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.listener.Close() })
	return srv.http
}

func TestTheWriteDeadlineOutlastsTheScanBudget(t *testing.T) {
	// The expensive failure: a scan completes, costs money, and its response
	// is cut off at the socket because the deadline was sized for a fast
	// request rather than for the slowest legitimate one.
	for _, budget := range []time.Duration{
		5 * time.Second, 15 * time.Second, 60 * time.Second,
	} {
		http := newFor(t, budget)
		if http.WriteTimeout <= budget {
			t.Errorf("budget %s: WriteTimeout = %s, which does not outlast the "+
				"handler and would truncate a completed scan", budget, http.WriteTimeout)
		}
	}
}

func TestAnUnstatedBudgetAssumesTheCeiling(t *testing.T) {
	// Assuming the maximum is the safe direction: too generous a write
	// deadline wastes a connection, too tight a one discards paid work.
	http := newFor(t, 0)
	if http.WriteTimeout <= maxScanBudget {
		t.Errorf("WriteTimeout = %s, want more than the %s ceiling",
			http.WriteTimeout, maxScanBudget)
	}
}

func TestEveryConnectionDeadlineIsSet(t *testing.T) {
	// Asserted as a set rather than individually, because the failure mode
	// is forgetting one - and Go's default for every one of them is "no
	// limit", which is indistinguishable from a deliberate choice in a diff.
	http := newFor(t, 15*time.Second)
	for _, deadline := range []struct {
		name  string
		value time.Duration
	}{
		{"ReadHeaderTimeout", http.ReadHeaderTimeout},
		{"ReadTimeout", http.ReadTimeout},
		{"WriteTimeout", http.WriteTimeout},
		{"IdleTimeout", http.IdleTimeout},
	} {
		if deadline.value <= 0 {
			t.Errorf("%s is unset; a connection with no deadline is one a slow "+
				"client can hold indefinitely", deadline.name)
		}
	}
}

func TestIdleOutlivesReadSoKeepAlivesSurvive(t *testing.T) {
	// Go falls back to ReadTimeout when IdleTimeout is unset. Setting only
	// ReadTimeout would therefore have closed every keep-alive after ten
	// seconds and forced a fresh handshake on each scan - a change nobody
	// would connect to the timeout they had just added.
	http := newFor(t, 15*time.Second)
	if http.IdleTimeout <= http.ReadTimeout {
		t.Errorf("IdleTimeout %s <= ReadTimeout %s; keep-alive connections "+
			"would be closed between scans", http.IdleTimeout, http.ReadTimeout)
	}
}

func TestTheReadDeadlineIsGenerousAgainstTheBodyCap(t *testing.T) {
	// 64 KiB over ten seconds is 6.5 KiB/s, which no honest client is under
	// and a byte-per-minute client is far above.
	http := newFor(t, 15*time.Second)
	const bodyCapBytes = 64 << 10
	bytesPerSecond := float64(bodyCapBytes) / http.ReadTimeout.Seconds()
	if bytesPerSecond > 100<<10 {
		t.Errorf("ReadTimeout %s demands %.0f bytes/second to upload the body "+
			"cap; that is tight enough to refuse a slow but honest client",
			http.ReadTimeout, bytesPerSecond)
	}
}

// TestThePreDrainWindowKeepsServing is the C34 fix, in miniature.
//
// A rolling restart dropped one request in forty because readiness failing
// and the listener closing happened in the same instant. The window between
// them is what an orchestrator needs to withdraw an endpoint, and during it
// the server must still answer normally - a window that refused requests
// would be the same bug with a longer name.
func TestThePreDrainWindowKeepsServing(t *testing.T) {
	var drained atomic.Bool
	srv, err := New(Options{
		Addr: "127.0.0.1:0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		Drain:    2 * time.Second,
		PreDrain: 400 * time.Millisecond,
		OnDrain:  func() { drained.Store(true) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	endpoint := "http://" + srv.Addr() + "/"
	if _, err := http.Get(endpoint); err != nil {
		t.Fatalf("before shutdown: %v", err)
	}

	cancel()

	// Readiness must fail immediately, and the socket must still answer.
	for _, delay := range []time.Duration{20 * time.Millisecond, 250 * time.Millisecond} {
		time.Sleep(delay)
		if !drained.Load() {
			t.Error("readiness was not failed at the start of the window")
		}
		resp, err := http.Get(endpoint)
		if err != nil {
			t.Fatalf("refused a request %s into the pre-drain window: %v", delay, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d during the pre-drain window", resp.StatusCode)
		}
	}

	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
	// And afterwards it is closed.
	if _, err := http.Get(endpoint); err == nil {
		t.Error("the listener is still accepting after the drain completed")
	}
}

// TestZeroPreDrainIsTheSingleProcessDefault keeps the default honest.
func TestZeroPreDrainIsTheSingleProcessDefault(t *testing.T) {
	// Nothing to tell when there is no load balancer, and a delay would make
	// every local Ctrl-C slower for no benefit. The Kubernetes manifest sets
	// it; the library does not.
	if config.DefaultPreDrain != 0 {
		t.Errorf("DefaultPreDrain = %s, want 0", config.DefaultPreDrain)
	}
}
