package api

import (
	"net/http"

	"github.com/padwhen/avoid-pp/gateway/internal/telemetry"
)

// Metrics serves the registry in Prometheus text exposition format.
//
// # Why this route is authenticated
//
// Convention says /metrics is open, usually on a separate port that is not
// routable from outside. This gateway has one listener, and the counters it
// would expose are not neutral for *this* service:
//
//	avoidpp_decisions_total{action="block",...}
//
// That is an oracle. An attacker probing the guard watches the counter and
// learns, per attempt, whether the passage was caught - which is precisely
// the feedback a detection system should not hand out, and far more useful
// than the 200 they get back in monitoring mode. The scan outcome counters
// leak the same thing more coarsely.
//
// So it sits behind the same bearer token as the scan route. A scraper
// configures a key, which Prometheus supports directly, and the cost of
// that is a line of scrape configuration.
//
// The route carries no caller-scoped data, so any configured caller may read
// it; authorisation per task would be meaningless for an aggregate.
func Metrics(registry *telemetry.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The exposition format's own content type, including the version,
		// so a scraper does not have to sniff.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(registry.Expose()))
	})
}
