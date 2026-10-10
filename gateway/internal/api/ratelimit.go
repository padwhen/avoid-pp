package api

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
	"github.com/padwhen/avoid-pp/gateway/internal/middleware"
)

// RateLimit refuses an authenticated caller that is over its rate.
//
// It sits after Authenticate, because the caller name it keys on has to come
// from a verified credential rather than from the request. The matching limit
// on unauthenticated traffic lives inside Authenticate instead, since that is
// the only place that knows a credential failed — they are split because the
// information each needs arrives at a different point, not by preference.
//
// It sits before the body is parsed, so a refused request costs no parsing and
// no detector call.
func RateLimit(limiter *limits.Limiter, log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller, authenticated := auth.CallerFrom(r.Context())
			if !authenticated {
				// Unreachable behind Authenticate. Refusing rather than
				// admitting keeps a misordered chain from becoming an
				// unlimited one.
				log.Error("rate limit reached without authentication",
					"request_id", middleware.RequestID(r.Context()))
				writeError(w, r, http.StatusUnauthorized,
					contract.ErrCodeUnauthenticated, "Valid credentials are required.")
				return
			}

			decision := limiter.AllowCaller(caller.Name, time.Now())
			if decision.Allowed {
				next.ServeHTTP(w, r)
				return
			}

			// The scope is logged but never sent. Telling a caller it was the
			// global limit rather than their own discloses that other callers
			// are busy, which is information about traffic that is not theirs.
			log.Warn("scan request rate limited",
				"request_id", middleware.RequestID(r.Context()),
				"caller", caller.Name,
				"scope", string(decision.Scope),
				"retry_after_seconds", limits.RetryAfterSeconds(decision.RetryAfter))
			writeRateLimited(w, r, decision)
		})
	}
}

// writeRateLimited sends a 429 with retry guidance in both the header and the
// body.
//
// The header is what a well-behaved HTTP client and most proxies honour
// automatically; the body field is what an application integrating against
// this contract reads, since many client libraries do not surface response
// headers from an error path. Carrying it twice costs nothing and means the
// guidance is actually seen.
func writeRateLimited(w http.ResponseWriter, r *http.Request, decision limits.Decision) {
	seconds := limits.RetryAfterSeconds(decision.RetryAfter)
	w.Header().Set("Retry-After", strconv.Itoa(seconds))

	writeJSON(w, http.StatusTooManyRequests, contract.ErrorResponse{
		RequestID: middleware.RequestID(r.Context()),
		Error: contract.ErrorBody{
			Code: contract.ErrCodeRateLimited,
			Message: "Too many requests. Retry after the interval in " +
				"retry_after_seconds.",
			RetryAfterSeconds: seconds,
		},
	})
}
