package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestServer(t *testing.T, handler http.Handler, drain time.Duration, onDrain func()) *Server {
	t.Helper()
	srv, err := New(Options{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Drain:   drain,
		Log:     quietLogger(),
		OnDrain: onDrain,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return srv
}

func TestServesAndStopsCleanly(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), time.Second, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	resp, err := http.Get("http://" + srv.Addr() + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, want 418", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after cancellation")
	}
}

// C07-AC3: shutdown stops accepting new work but lets accepted work finish.
func TestDrainLetsInFlightRequestsFinish(t *testing.T) {
	started := make(chan struct{})
	var completed atomic.Bool

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		completed.Store(true)
		w.WriteHeader(http.StatusOK)
	}), 5*time.Second, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	type result struct {
		code int
		err  error
	}
	responses := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + srv.Addr() + "/slow")
		if err != nil {
			responses <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		responses <- result{code: resp.StatusCode}
	}()

	<-started // the handler is running; now ask the server to stop
	cancel()

	select {
	case got := <-responses:
		if got.err != nil {
			t.Fatalf("in-flight request failed during drain: %v", got.err)
		}
		if got.code != http.StatusOK {
			t.Errorf("in-flight status = %d, want 200", got.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed")
	}

	if !completed.Load() {
		t.Error("handler was cut short by shutdown")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after draining")
	}
}

// A drain budget shorter than the work in flight must surface as an error,
// not a silent clean exit, so a routinely-too-short budget is visible.
func TestDrainBudgetExpiryIsReported(t *testing.T) {
	started := make(chan struct{})
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(800 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}), 50*time.Millisecond, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	go func() {
		resp, err := http.Get("http://" + srv.Addr() + "/slow")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	<-started
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run() = nil, want an error when the drain budget expires")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return")
	}
}

// Readiness must fail as soon as draining begins, so a load balancer stops
// sending new requests while in-flight ones finish.
func TestOnDrainRunsBeforeWaiting(t *testing.T) {
	var drained atomic.Bool
	srv := newTestServer(t, http.NotFoundHandler(), time.Second, func() {
		drained.Store(true)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	resp, err := http.Get("http://" + srv.Addr() + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	if drained.Load() {
		t.Fatal("OnDrain ran before shutdown was requested")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !drained.Load() {
		t.Error("OnDrain never ran")
	}
}

func TestNewReportsPortConflict(t *testing.T) {
	first := newTestServer(t, http.NotFoundHandler(), time.Second, nil)
	defer func() { _ = first.listener.Close() }()

	if _, err := New(Options{Addr: first.Addr(), Handler: http.NotFoundHandler()}); err == nil {
		t.Fatal("New() on a taken port = nil error, want failure at bind time")
	}
}
