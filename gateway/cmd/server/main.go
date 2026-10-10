// Command server runs the avoid-pp gateway.
//
// It validates its configuration before binding a port, serves health
// endpoints openly and the scan endpoint only to authenticated callers, and
// shuts down by draining rather than cutting accepted requests short.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/padwhen/avoid-pp/gateway/internal/admission"
	"github.com/padwhen/avoid-pp/gateway/internal/api"
	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/config"
	"github.com/padwhen/avoid-pp/gateway/internal/detector"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
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
		"policy_mode", string(cfg.PolicyMode),
		// Names and key counts, never keys. The count is what an operator
		// checks after a rotation to confirm the replaced key is gone.
		"callers", callerNames(cfg.Callers),
		"configured_keys", cfg.Callers.KeyCount(),
	)

	// One bucket per configured caller plus two shared ones, all allocated
	// here. Nothing is created per request, so this is the whole of the
	// limiter's memory for the life of the process.
	callers := make([]string, 0, len(cfg.Callers.Callers()))
	for _, caller := range cfg.Callers.Callers() {
		callers = append(callers, caller.Name)
	}
	limiter, err := limits.New(cfg.Rates, callers)
	if err != nil {
		return fmt.Errorf("rate limits: %w", err)
	}
	log.Info("rate limits configured",
		"rates", limiter.Describe(), "buckets", limiter.BucketCount())

	// Bounds how much inference runs at once. Fixed capacity, allocated here.
	admitter, err := admission.New(cfg.Admission)
	if err != nil {
		return fmt.Errorf("admission control: %w", err)
	}
	log.Info("admission control configured", "bounds", admitter.Describe())

	readiness := api.NewReadiness()

	// One client, reused for every scan: a per-request client would discard
	// its connection pool each time and handshake afresh.
	client := detector.New(cfg.DetectorURL, cfg.ScanTimeout)

	srv, err := server.New(server.Options{
		Addr: cfg.Addr,
		Handler: api.NewRouter(readiness, api.ScanDeps{
			Detector:  client,
			Timeout:   cfg.ScanTimeout,
			Log:       log,
			Mode:      cfg.PolicyMode,
			Callers:   cfg.Callers,
			Limiter:   limiter,
			Admission: admitter,
		}),
		Drain: cfg.ShutdownTimeout,
		Log:   log,
		// Fail readiness the instant draining starts, so new traffic is
		// routed away while accepted requests finish.
		OnDrain: readiness.SetNotReady,
	})
	if err != nil {
		return err
	}

	// The client is constructed eagerly and has nothing to await, so the
	// gateway is ready as soon as it is built. Readiness becomes conditional
	// on a detector health probe when C12 runs both services together.
	readiness.SetReady()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.Run(ctx)
}

// callerNames renders the configured callers for one startup log line.
func callerNames(registry *auth.Registry) []string {
	callers := registry.Callers()
	out := make([]string, len(callers))
	for i, caller := range callers {
		out[i] = caller.Name + "=" + strings.Join(caller.Tasks(), "+")
	}
	return out
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
