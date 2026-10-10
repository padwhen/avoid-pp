// Command server runs the avoid-pp gateway.
//
// At C07 it serves health endpoints only. There is no scan endpoint, no
// detector call and no policy: this commit establishes the lifecycle that
// later behaviour is added to, because configuration validation, readiness
// and bounded shutdown are expensive to retrofit into working handlers.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/padwhen/avoid-pp/gateway/internal/api"
	"github.com/padwhen/avoid-pp/gateway/internal/config"
	"github.com/padwhen/avoid-pp/gateway/internal/server"
)

func main() {
	if err := run(); err != nil {
		// Configuration errors name variables, never values, so this is safe
		// to print. See internal/config.
		fmt.Fprintf(os.Stderr, "gateway: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)
	log.Info("gateway starting",
		"addr", cfg.Addr,
		"detector_url", cfg.Redacted(),
		"scan_timeout", cfg.ScanTimeout.String(),
		"shutdown_timeout", cfg.ShutdownTimeout.String(),
	)

	readiness := api.NewReadiness()

	srv, err := server.New(server.Options{
		Addr:    cfg.Addr,
		Handler: api.NewRouter(readiness),
		Drain:   cfg.ShutdownTimeout,
		Log:     log,
		// Fail readiness the instant draining starts, so new traffic is
		// routed away while accepted requests finish.
		OnDrain: readiness.SetNotReady,
	})
	if err != nil {
		return err
	}

	// Nothing is initialised asynchronously yet. When the detector client
	// arrives at C09, readiness becomes ready only after that succeeds.
	readiness.SetReady()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.Run(ctx)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
