// Package server runs the gateway's HTTP listener and owns its shutdown.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

const (
	// maxScanBudget mirrors the configuration ceiling on a scan. Used when a
	// caller does not state a budget, because assuming the maximum is the
	// safe direction for a write deadline.
	maxScanBudget = 60 * time.Second

	// writeMargin is what the response needs after the handler is done:
	// serialisation and the socket write. Generous, because the cost of too
	// much is an idle connection and the cost of too little is a discarded
	// result.
	writeMargin = 10 * time.Second
)

// Server wraps http.Server with a bounded, observable shutdown.
type Server struct {
	http     *http.Server
	listener net.Listener
	drain    time.Duration
	log      *slog.Logger
	onDrain  func()
}

// Options configure New.
type Options struct {
	Addr    string
	Handler http.Handler
	Drain   time.Duration
	Log     *slog.Logger

	// ScanBudget is the longest a handler may legitimately take. It sizes
	// the write deadline, which must outlast the work or a slow-but-valid
	// scan has its response cut off at the socket - a failure that looks
	// like a client bug and is not one.
	//
	// Zero means the ceiling from config, which is the safe assumption: too
	// generous a write deadline wastes a connection, too tight a one
	// discards completed paid work.
	ScanBudget time.Duration

	// OnDrain runs the moment shutdown begins, before in-flight work is
	// awaited. The gateway uses it to fail readiness so a load balancer stops
	// sending new requests while the existing ones finish.
	OnDrain func()
}

// New binds the listening socket immediately, so a port conflict is reported
// by the caller that asked to start rather than asynchronously later.
func New(opts Options) (*Server, error) {
	listener, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", opts.Addr, err)
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	budget := opts.ScanBudget
	if budget <= 0 {
		budget = maxScanBudget
	}

	return &Server{
		http: &http.Server{
			Handler: opts.Handler,
			// Bounds a slow or stalled client.
			ReadHeaderTimeout: 5 * time.Second,

			// # The three deadlines C32 added
			//
			// Until C32 only the header deadline was set, which left three
			// gaps. Go fills none of them by default: with ReadTimeout and
			// WriteTimeout unset a client could send one byte of body per
			// minute forever, and with IdleTimeout unset Go falls back to
			// ReadTimeout - so setting only ReadTimeout would have closed
			// every keep-alive connection after ten seconds and forced a
			// fresh TLS handshake on each scan.
			//
			// ReadTimeout bounds the body. The body cap is 64 KiB
			// (api.MaxRequestBytes), so ten seconds is four orders of
			// magnitude more than any honest client needs and still finite.
			ReadTimeout: 10 * time.Second,

			// WriteTimeout must exceed the longest legitimate handler, or it
			// truncates work that has already been paid for. Go starts this
			// clock when the request headers are read, so it has to cover
			// admission wait, the provider call and serialisation - the
			// whole scan budget, plus margin.
			WriteTimeout: budget + writeMargin,

			// IdleTimeout keeps connections alive between scans. The
			// detector client reuses connections for exactly this reason
			// (C09), and a public caller scanning every minute should not
			// pay a handshake each time.
			IdleTimeout: 120 * time.Second,
			// Headers are bounded as well as bodies. Go's default is 1 MiB,
			// which is generous for a request whose largest legitimate header
			// is a bearer token: 16 KiB is far more than this API needs and
			// far less than a client can use to make the server hold memory
			// before any route has been matched.
			MaxHeaderBytes: 16 << 10,
		},
		listener: listener,
		drain:    opts.Drain,
		log:      log,
		onDrain:  opts.OnDrain,
	}, nil
}

// Addr reports the bound address, which is useful when Addr was ":0".
func (s *Server) Addr() string { return s.listener.Addr().String() }

// Run serves until ctx is cancelled, then stops accepting new connections and
// gives in-flight requests up to the drain budget to finish.
//
// C07-AC3: cancelling ctx must not cut an accepted request short. Shutdown
// closes listeners first and only then waits, so a request already being
// handled runs to completion or to the drain deadline, whichever comes first.
func (s *Server) Run(ctx context.Context) error {
	errs := make(chan error, 1)
	go func() {
		err := s.http.Serve(s.listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errs <- err
	}()

	s.log.Info("gateway listening", "addr", s.Addr())

	select {
	case err := <-errs:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	if s.onDrain != nil {
		s.onDrain()
	}
	s.log.Info("gateway draining", "budget", s.drain.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.drain)
	defer cancel()

	if err := s.http.Shutdown(shutdownCtx); err != nil {
		// The budget expired with work still in flight. Report it rather than
		// exiting zero, so a drain that is routinely too short is visible.
		s.log.Error("gateway drain incomplete", "error", err)
		return fmt.Errorf("drain within %s: %w", s.drain, err)
	}

	if err := <-errs; err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	s.log.Info("gateway stopped")
	return nil
}
