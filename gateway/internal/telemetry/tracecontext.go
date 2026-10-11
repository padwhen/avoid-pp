// Package telemetry carries trace context across the two services and
// records bounded metrics about what they did.
//
// # Why there is no OpenTelemetry SDK here
//
// C33 asks for "OpenTelemetry spans and low-cardinality metrics", and what
// it asks them to achieve is three things: a request traceable across Go and
// Python, telemetry that distinguishes overload from provider error from
// uncertainty from a policy block, and no passages, secrets or request ids
// in any of it.
//
// This package implements the W3C Trace Context specification - which is the
// propagation format OpenTelemetry itself uses - and a metrics registry whose
// label sets are fixed at compile time. It does not pull in the SDK, for two
// reasons.
//
// The first is proportion: an SDK plus exporters in two languages is a large
// dependency surface for a service with no collector to export to, and
// nothing here would be exercised.
//
// The second is specific to this service and matters more. Auto-instrumentation
// is the usual reason to adopt the SDK, and auto-instrumentation of an HTTP
// server records request attributes by default - which for this gateway means
// a Finnish passage chosen by an attacker. C23 built an allowlisting log
// handler precisely so that a field has to be named before it can be emitted.
// Telemetry that captures by default would undo that, and the fix would be to
// configure the instrumentation to suppress what it collects, which is a
// denylist. So this stays manual and keeps the allowlist.
//
// What is therefore *not* here: span export, span events, baggage, and any
// sampling decision beyond honouring an upstream one. The wire format is
// interoperable, so adding an exporter later is additive rather than a
// rewrite. docs/c33-observability.md says what that would take.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// HeaderTraceparent is the W3C Trace Context header.
//
// One header, not a bespoke one, because the point of a trace identifier is
// that something else can read it.
const HeaderTraceparent = "traceparent"

// Trace context field widths, from the W3C specification.
const (
	traceIDHex = 32 // 16 bytes
	spanIDHex  = 16 // 8 bytes
	flagsHex   = 2
	// version-traceid-spanid-flags, hyphen separated.
	traceparentLen = 2 + 1 + traceIDHex + 1 + spanIDHex + 1 + flagsHex
)

// FlagSampled is the only trace flag this version defines.
const FlagSampled byte = 0x01

// SpanContext identifies one request's position in a trace.
//
// The zero value is deliberately invalid rather than "a new trace": a caller
// that forgot to create one gets something that fails IsValid, not a silent
// orphan trace that looks fine in a dashboard.
type SpanContext struct {
	TraceID string
	SpanID  string
	Sampled bool
	// Remote is true when this context came from an inbound header rather
	// than being created here. Recorded because an inbound trace id is
	// attacker-controlled, and a sampling decision made elsewhere is not the
	// same claim as one made here.
	Remote bool
}

// IsValid reports whether both identifiers are well formed and non-zero.
func (s SpanContext) IsValid() bool {
	return validHex(s.TraceID, traceIDHex) && !allZero(s.TraceID) &&
		validHex(s.SpanID, spanIDHex) && !allZero(s.SpanID)
}

// Traceparent renders the context in W3C form, or "" if it is not valid.
func (s SpanContext) Traceparent() string {
	if !s.IsValid() {
		return ""
	}
	flags := "00"
	if s.Sampled {
		flags = "01"
	}
	return "00-" + s.TraceID + "-" + s.SpanID + "-" + flags
}

// NewTrace starts a fresh trace.
func NewTrace() SpanContext {
	return SpanContext{
		TraceID: randomHex(16),
		SpanID:  randomHex(8),
		// Sampled by default: this gateway records every request anyway, and
		// a sampling scheme nobody configured would only drop evidence.
		Sampled: true,
	}
}

// Child returns a context in the same trace with a fresh span id.
//
// Used for the outbound call to the detector, so the two hops are
// distinguishable rather than sharing one id and collapsing into a single
// span in anything that reads them.
func (s SpanContext) Child() SpanContext {
	if !s.IsValid() {
		return NewTrace()
	}
	return SpanContext{
		TraceID: s.TraceID,
		SpanID:  randomHex(8),
		Sampled: s.Sampled,
		Remote:  false,
	}
}

// ParseTraceparent reads a W3C traceparent header.
//
// Returns false for anything it does not fully understand. The alternative -
// salvaging a trace id from a malformed header - would mean propagating
// attacker-controlled bytes into every log line and trace store downstream
// on the strength of a guess.
//
// The header is attacker-controlled on the public endpoint, so every field is
// validated for length, alphabet and the specification's reserved values. A
// future version (anything but "00") is rejected rather than parsed
// optimistically, because this implementation cannot know what the extra
// fields mean.
func ParseTraceparent(header string) (SpanContext, bool) {
	if len(header) != traceparentLen {
		return SpanContext{}, false
	}
	parts := strings.Split(header, "-")
	if len(parts) != 4 {
		return SpanContext{}, false
	}
	version, traceID, spanID, flags := parts[0], parts[1], parts[2], parts[3]

	if version != "00" {
		return SpanContext{}, false
	}
	if !validHex(traceID, traceIDHex) || allZero(traceID) {
		return SpanContext{}, false
	}
	if !validHex(spanID, spanIDHex) || allZero(spanID) {
		return SpanContext{}, false
	}
	if !validHex(flags, flagsHex) {
		return SpanContext{}, false
	}

	decoded, err := hex.DecodeString(flags)
	if err != nil {
		return SpanContext{}, false
	}
	return SpanContext{
		TraceID: traceID,
		SpanID:  spanID,
		Sampled: decoded[0]&FlagSampled != 0,
		Remote:  true,
	}, true
}

type contextKey struct{}

// WithSpan stores a span context on ctx.
func WithSpan(ctx context.Context, span SpanContext) context.Context {
	return context.WithValue(ctx, contextKey{}, span)
}

// SpanFrom returns the span context carried by ctx, if any.
func SpanFrom(ctx context.Context) (SpanContext, bool) {
	span, ok := ctx.Value(contextKey{}).(SpanContext)
	return span, ok && span.IsValid()
}

// TraceID returns the trace id on ctx, or "" when there is none.
//
// A convenience for log lines, which want the id or nothing rather than a
// struct and a boolean.
func TraceID(ctx context.Context) string {
	if span, ok := SpanFrom(ctx); ok {
		return span.TraceID
	}
	return ""
}

// validHex reports whether s is exactly n lowercase hexadecimal digits.
//
// Lowercase only, as the specification requires. Accepting uppercase would
// make the same trace appear under two identifiers in anything that compares
// them as strings.
func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// allZero reports whether every digit is '0'.
//
// The specification reserves the all-zero trace and span ids as invalid, and
// they are exactly what a buggy upstream emits.
func allZero(s string) bool {
	return strings.Trim(s, "0") == ""
}

func randomHex(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand does not fail on supported platforms. A predictable id
		// correlates worse than a random one but still correlates, which
		// beats dropping the request over telemetry.
		for i := range buf {
			buf[i] = 0x11
		}
	}
	return hex.EncodeToString(buf)
}
