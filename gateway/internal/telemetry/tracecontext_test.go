package telemetry

import (
	"context"
	"strings"
	"testing"
)

// The traceparent header is attacker-controlled on the public endpoint, and
// whatever survives parsing is propagated to the detector and written into
// every log line on both sides. So the parser's job is as much refusing as
// accepting.

func TestARoundTripPreservesTheContext(t *testing.T) {
	original := NewTrace()
	parsed, ok := ParseTraceparent(original.Traceparent())
	if !ok {
		t.Fatalf("a header this package produced did not parse: %q",
			original.Traceparent())
	}
	if parsed.TraceID != original.TraceID || parsed.SpanID != original.SpanID {
		t.Errorf("round trip changed the identifiers: %+v -> %+v", original, parsed)
	}
	if !parsed.Remote {
		t.Error("a parsed context should be marked remote")
	}
	if !parsed.Sampled {
		t.Error("the sampled flag did not survive")
	}
}

func TestMalformedHeadersAreRefused(t *testing.T) {
	valid := NewTrace().Traceparent()

	for name, header := range map[string]string{
		"empty":                   "",
		"truncated":               valid[:len(valid)-1],
		"overlong":                valid + "0",
		"a future version":        "01" + valid[2:],
		"version ff is reserved":  "ff" + valid[2:],
		"uppercase hex":           strings.ToUpper(valid),
		"all-zero trace id":       "00-" + strings.Repeat("0", 32) + "-" + strings.Repeat("a", 16) + "-01",
		"all-zero span id":        "00-" + strings.Repeat("a", 32) + "-" + strings.Repeat("0", 16) + "-01",
		"non-hex trace id":        "00-" + strings.Repeat("g", 32) + "-" + strings.Repeat("a", 16) + "-01",
		"wrong separator":         strings.ReplaceAll(valid, "-", "_"),
		"too many fields":         valid + "-extra",
		"whitespace padded":       " " + valid[1:],
		"an injected log newline": "00-" + strings.Repeat("a", 32) + "-" + strings.Repeat("b", 16) + "-0\n",
	} {
		t.Run(name, func(t *testing.T) {
			if span, ok := ParseTraceparent(header); ok {
				t.Errorf("accepted %q as %+v", header, span)
			}
		})
	}
}

func TestAnUppercaseHeaderIsNotSilentlyLowercased(t *testing.T) {
	// Normalising would be friendlier and wrong: the same trace would then
	// appear under two identifiers in anything that compares them as strings,
	// and a caller would have no way to find its own request.
	upper := strings.ToUpper(NewTrace().Traceparent())
	if _, ok := ParseTraceparent(upper); ok {
		t.Error("an uppercase header was accepted")
	}
}

func TestTheZeroContextIsInvalidRatherThanANewTrace(t *testing.T) {
	// A caller that forgot to create one gets something that fails IsValid,
	// not a silent orphan trace that looks fine in a dashboard.
	var zero SpanContext
	if zero.IsValid() {
		t.Error("the zero SpanContext reports itself as valid")
	}
	if zero.Traceparent() != "" {
		t.Errorf("the zero SpanContext rendered %q", zero.Traceparent())
	}
	if id := TraceID(context.Background()); id != "" {
		t.Errorf("TraceID of an empty context = %q, want empty", id)
	}
}

func TestAChildKeepsTheTraceAndChangesTheSpan(t *testing.T) {
	// The two hops have to be distinguishable or they collapse into one span
	// in anything that reads them.
	parent := NewTrace()
	child := parent.Child()

	if child.TraceID != parent.TraceID {
		t.Errorf("child trace id = %s, want %s", child.TraceID, parent.TraceID)
	}
	if child.SpanID == parent.SpanID {
		t.Error("child reused the parent's span id")
	}
	if child.Remote {
		t.Error("a locally created child is not remote")
	}
	if !child.IsValid() {
		t.Error("child is not valid")
	}
}

func TestAChildOfNothingStartsATrace(t *testing.T) {
	var zero SpanContext
	child := zero.Child()
	if !child.IsValid() {
		t.Error("a child of an invalid context should start a fresh trace")
	}
}

func TestTheSampledFlagIsHonouredNotOverridden(t *testing.T) {
	// An upstream that decided not to sample has made a decision this service
	// is not entitled to reverse.
	unsampled := "00-" + strings.Repeat("a", 32) + "-" + strings.Repeat("b", 16) + "-00"
	span, ok := ParseTraceparent(unsampled)
	if !ok {
		t.Fatal("a valid unsampled header was refused")
	}
	if span.Sampled {
		t.Error("an unsampled upstream decision was overridden")
	}
	if !strings.HasSuffix(span.Traceparent(), "-00") {
		t.Errorf("re-rendered as %q, losing the flag", span.Traceparent())
	}
	if !span.Child().IsValid() || span.Child().Sampled {
		t.Error("the child did not inherit the sampling decision")
	}
}

func TestIdentifiersAreNotPredictable(t *testing.T) {
	// Weak enough to pass on any working CSPRNG and strong enough to catch a
	// constant, which is what a broken fallback looks like.
	seen := map[string]bool{}
	for range 64 {
		span := NewTrace()
		if seen[span.TraceID] {
			t.Fatalf("duplicate trace id %s within 64 draws", span.TraceID)
		}
		seen[span.TraceID] = true
	}
}

func TestContextCarriesTheSpan(t *testing.T) {
	span := NewTrace()
	ctx := WithSpan(context.Background(), span)

	got, ok := SpanFrom(ctx)
	if !ok || got.TraceID != span.TraceID {
		t.Errorf("SpanFrom = %+v, %v; want %+v", got, ok, span)
	}
	if TraceID(ctx) != span.TraceID {
		t.Errorf("TraceID = %s, want %s", TraceID(ctx), span.TraceID)
	}

	// An invalid span stored on a context must not read back as present.
	if _, ok := SpanFrom(WithSpan(context.Background(), SpanContext{})); ok {
		t.Error("an invalid span read back as present")
	}
}
