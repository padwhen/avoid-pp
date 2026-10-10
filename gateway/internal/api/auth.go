package api

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
	"github.com/padwhen/avoid-pp/gateway/internal/middleware"
)

// Authenticate rejects a request whose credential is missing or unrecognised,
// and attaches the resolved caller for the handler behind it.
//
// Authentication happens here; authorisation does not. Which task a request
// asks for is in its body, and the body is not parsed, bounded or validated
// until the handler. Peeking at it from middleware would mean either reading
// it twice or buffering it ahead of the size limit, so the task check lives in
// the handler instead — still before the detector is called.
func Authenticate(
	registry *auth.Registry, limiter *limits.Limiter, log *slog.Logger,
) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller, err := registry.Authenticate(auth.CredentialFrom(r))
			if err != nil {
				// A failed credential is charged against the one bucket all
				// unauthenticated traffic shares. Over the limit, the answer
				// becomes 429 instead of 401 — which costs a legitimate
				// caller nothing, since a legitimate caller authenticates,
				// and discloses less rather than more.
				if decision := limiter.AllowUnauthenticated(time.Now()); !decision.Allowed {
					log.Warn("unauthenticated request rate limited",
						"request_id", middleware.RequestID(r.Context()),
						"remote", r.RemoteAddr,
						"retry_after_seconds", limits.RetryAfterSeconds(decision.RetryAfter))
					writeRateLimited(w, r, decision)
					return
				}
				// Both outcomes produce one response. Distinguishing "no
				// credential" from "wrong credential" tells a prober whether a
				// key exists, and the caller's own fix is the same either way.
				//
				// The log records the reason but never the presented value:
				// a mistyped key is still a key, and a near-miss in a log is
				// a credential in a log.
				log.Warn("scan request rejected: not authenticated",
					"request_id", middleware.RequestID(r.Context()),
					"reason", reasonFor(err),
					"remote", r.RemoteAddr)
				writeError(w, r, http.StatusUnauthorized,
					contract.ErrCodeUnauthenticated, "Valid credentials are required.")
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithCaller(r.Context(), caller)))
		})
	}
}

func reasonFor(err error) string {
	switch {
	case errors.Is(err, auth.ErrNoCredential):
		return "no_credential"
	case errors.Is(err, auth.ErrUnknownCredential):
		return "unknown_credential"
	default:
		return "rejected"
	}
}
