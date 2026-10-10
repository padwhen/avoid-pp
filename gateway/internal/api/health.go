// Package api holds the gateway's HTTP handlers.
//
// At C07 only health endpoints exist. The scan endpoint arrives at C09; this
// commit deliberately does not register an empty /v1/scans route, because a
// route that exists but does nothing is indistinguishable from protection
// that silently fails open.
package api

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/padwhen/avoid-pp/gateway/internal/middleware"
)

// Readiness tracks whether initialisation has finished.
//
// Liveness and readiness answer different questions and must not be merged:
// a failed liveness check means "restart this process", while a failed
// readiness check means "route traffic elsewhere, but leave it alone". A
// server waiting on a dependency that reports itself dead gets killed,
// restarted, and waits again.
type Readiness struct {
	ready atomic.Bool
}

// NewReadiness returns a Readiness that reports not-ready until SetReady.
func NewReadiness() *Readiness { return &Readiness{} }

// SetReady marks initialisation complete.
func (r *Readiness) SetReady() { r.ready.Store(true) }

// SetNotReady marks the service unable to serve traffic, as during a drain.
func (r *Readiness) SetNotReady() { r.ready.Store(false) }

// Ready reports the current state.
func (r *Readiness) Ready() bool { return r.ready.Load() }

type healthBody struct {
	Status    string `json:"status"`
	RequestID string `json:"request_id,omitempty"`
}

func writeHealth(w http.ResponseWriter, r *http.Request, code int, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// A health response is tiny and fixed-shape; an encode failure means the
	// client is gone, which is not actionable here.
	_ = json.NewEncoder(w).Encode(healthBody{
		Status:    status,
		RequestID: middleware.RequestID(r.Context()),
	})
}

// Live answers whether the process is running.
//
// C07-AC1: it makes no external call. A liveness probe that reaches a model
// provider costs money on every scrape and reports the process dead whenever
// that provider has a bad minute.
func Live() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeHealth(w, r, http.StatusOK, "ok")
	})
}

// Ready answers whether the service can serve traffic now.
func Ready(readiness *Readiness) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !readiness.Ready() {
			writeHealth(w, r, http.StatusServiceUnavailable, "not_ready")
			return
		}
		writeHealth(w, r, http.StatusOK, "ready")
	})
}

// NewRouter builds the gateway's handler.
//
// When deps.Detector is nil the scan route is not registered at all, so it
// 404s rather than existing as a route that cannot scan. A registered route
// returning nothing is indistinguishable from protection that fails open.
func NewRouter(readiness *Readiness, deps ScanDeps) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", Live())
	mux.Handle("GET /readyz", Ready(readiness))
	if deps.Detector != nil {
		mux.Handle("POST /v1/scans", Scan(deps))
	}
	return middleware.WithRequestIDHeader(mux)
}
