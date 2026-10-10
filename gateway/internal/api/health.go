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
// The scan route is registered only when it can be served safely: a nil
// detector means it cannot scan, a nil caller registry means it cannot tell
// who is asking, a nil limiter means it cannot bound what it spends, and a nil
// admission controller means it cannot bound what it runs at once. In any of
// those cases the route is absent and 404s, rather than existing in a degraded
// form — a route that scans nothing, one that scans for anybody, one that
// scans without limit, or one that scans without bound are all worse than a
// missing route.
//
// Authentication wraps the scan route alone. The health endpoints stay open
// because a load balancer probing readiness holds no credential, and what
// they disclose is whether the process is up, which its open port already
// says.
func NewRouter(readiness *Readiness, deps ScanDeps) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", Live())
	mux.Handle("GET /readyz", Ready(readiness))
	if deps.Detector != nil && deps.Callers != nil &&
		deps.Limiter != nil && deps.Admission != nil {
		// Outermost first: authenticate, then rate limit, then scan. A
		// request refused by either middleware never reaches the parser or
		// the detector.
		mux.Handle("POST /v1/scans",
			Authenticate(deps.Callers, deps.Limiter, deps.Log)(
				RateLimit(deps.Limiter, deps.Log)(
					Scan(deps))))
	}
	return middleware.WithRequestIDHeader(mux)
}
