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
	return &Server{
		http: &http.Server{
			Handler: opts.Handler,
			// Bounds a slow or stalled client. Read and write budgets are
			// sized at C32 against measured behaviour; these are development
			// defaults that simply must not be unlimited.
			ReadHeaderTimeout: 5 * time.Second,
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
