// Package middleware holds cross-cutting HTTP handlers for the gateway.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// HeaderRequestID is both read and written, so a caller that already has a
// correlation id can keep using it across the gateway boundary.
const HeaderRequestID = "X-Request-Id"

// maxRequestIDLen matches the contract's request_id bound
// (contracts/schemas/common.schema.json).
const maxRequestIDLen = 64

type contextKey struct{}

// RequestID returns the id carried by ctx, or "" when there is none.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(contextKey{}).(string)
	return id
}

// WithRequestID stores an id on ctx. Exported for tests and for call sites
// that construct a context outside an HTTP request.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// NewRequestID returns a fresh random identifier.
func NewRequestID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand does not fail on supported platforms; if it ever does,
		// a predictable id is still better than dropping the request.
		return "req-norandom"
	}
	return hex.EncodeToString(buf[:])
}

// acceptable reports whether a caller-supplied id may be reused.
//
// An inbound id is attacker-controlled: it reaches logs, and later traces and
// reports. Accepting it verbatim invites log injection and unbounded
// cardinality, so anything outside a conservative charset and length is
// replaced rather than sanitised — a rewritten id would no longer correlate
// with the caller's own records, which silently defeats the purpose.
func acceptable(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

// WithRequestIDHeader propagates an acceptable inbound request id or issues a
// new one, exposes it on the context, and echoes it on the response.
func WithRequestIDHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderRequestID)
		if !acceptable(id) {
			id = NewRequestID()
		}
		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}
