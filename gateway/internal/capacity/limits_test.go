package capacity

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/api"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
)

// Whether the service's size limits agree with each other.
//
// These run in `make check`, unlike the profile: they are assertions about a
// boundary rather than measurements, and they cost milliseconds.

// TestTheTwoSizeLimitsDisagreeAtTheCeiling records a real incoherence.
//
// Two limits bound a passage, and they are in different units:
//
//	contract.MaxTextChars   32768 characters (the documented ceiling)
//	api.MaxRequestBytes     65536 bytes      (the pre-parse body cap)
//
// Those two numbers are exactly a factor of two apart, so a passage of
// two-byte characters fills the body cap precisely with its text and is
// carried over it by the JSON envelope.
//
// The byte cap's comment reasons that 64 KiB "leaves room for the JSON
// envelope and for multi-byte Finnish". That holds for ordinary Finnish,
// where the ratio measured here is about 1.04 bytes per character. It does
// not hold in general: a passage of 32768 characters that are each two bytes
// is 65536 bytes of text alone, before the envelope, and is refused.
//
// So a caller can send a passage inside the documented character limit and be
// told it is too large. That is not a security problem - it fails closed, and
// the error is accurate about the body size - but it is a documented promise
// the service does not keep, and a caller sizing its chunks by character
// count would hit it unpredictably, depending on how much non-ASCII the text
// happens to contain.
//
// Asserted rather than fixed. Raising the byte cap to 4 × MaxTextChars plus
// an envelope allowance would close it, at the cost of letting a caller
// reserve a 128 KiB buffer; that is a deliberate trade and C32 records it
// rather than making it silently. See docs/c32-capacity.md.
func TestTheTwoSizeLimitsDisagreeAtTheCeiling(t *testing.T) {
	// Every character two bytes, and every character legal Finnish.
	passage := strings.Repeat("ä", contract.MaxTextChars)

	if runes := len([]rune(passage)); runes != contract.MaxTextChars {
		t.Fatalf("passage is %d characters, want exactly the limit", runes)
	}
	// The cap applies to the request body, not to the passage, so the
	// comparison has to be against the encoded body. At exactly two bytes per
	// character the text alone is 65536 bytes - the cap to the byte - and it
	// is the JSON envelope that carries it over. That the two land this close
	// is a coincidence of the chosen limits, and it is why the margin is
	// worth stating rather than assuming.
	body := scanBody(t, passage)
	if len(body) <= api.MaxRequestBytes {
		t.Fatalf("the request body is %d bytes, which no longer exceeds the %d "+
			"byte cap; if the cap was raised deliberately this test should be updated",
			len(body), api.MaxRequestBytes)
	}

	status, code := issue(buildRouter(t), body)
	if status != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", status)
	}
	if code != "payload_too_large" {
		t.Errorf("code = %q, want payload_too_large", code)
	}
}

// TestTheGatewayAcceptsAPassageTheDetectorWillRefuse records the larger
// incoherence, and the one that reaches a caller.
//
// Four bounds apply to one passage, in three units:
//
//	contract.MaxTextChars              32768 characters  public schema
//	api.MaxRequestBytes                65536 bytes       gateway body cap
//	limits.MAX_PASSAGE_BYTES           32768 bytes       detector
//	limits.DEFAULT_MAX_SOURCE_TOKENS    4096 tokens      detector
//
// The token budget binds first by a wide margin. At the detector's own
// conservative 1.3 characters per token it admits 5,324 characters - 16% of
// the documented ceiling. Measured against the real tokenizer at that size
// (C32 provider profile: 3,995 input tokens for 5,324 characters, 1.84
// characters per token) there is room for roughly 7,100, so the limit is
// also tighter than its own safety margin requires.
//
// The gateway does not know about either detector bound, so it accepts the
// passage and forwards it. The detector raises InputTooLarge, which
// claude.py wraps as DetectorUnavailable, which the detector service returns
// as 503, which scan.go maps to `detector_unavailable`.
//
// So a caller sending 6,000 characters - well inside the documented limit -
// is told the detector is unavailable. That is a permanent request-sizing
// error reported as a transient service outage, and the contract already
// defines the right codes for it: `payload_too_large` and the unused
// `token_budget_exceeded`.
//
// This test asserts the gateway half with a stub that enforces nothing, so
// it pins the gap rather than the symptom. The fix is a decision recorded in
// docs/c32-capacity.md, not something this commit makes silently.
func TestTheGatewayAcceptsAPassageTheDetectorWillRefuse(t *testing.T) {
	// Comfortably over the detector's 4096-token budget, comfortably under
	// every limit the gateway enforces.
	passage := finnishOf(6000)
	if len(passage) > api.MaxRequestBytes {
		t.Fatalf("6,000 characters of Finnish is %d bytes, over the gateway cap",
			len(passage))
	}

	status, code := issue(buildRouter(t), scanBody(t, passage))
	if status != http.StatusOK {
		t.Fatalf("status = %d (%s); the gateway now rejects a passage it used "+
			"to forward. If a size check was added, this test documents what it "+
			"should say and should be updated", status, code)
	}
}

// TestTheContractAdvertisesMoreThanTheDetectorAccepts states the ratio.
//
// Kept separate from the behavioural test because it is an arithmetic claim
// about two constants, and it is the claim docs/c32-capacity.md quotes.
func TestTheContractAdvertisesMoreThanTheDetectorAccepts(t *testing.T) {
	// From detector/src/translation_guard/limits.py. Transcribed rather than
	// imported, for the obvious reason, and asserted against the measured
	// behaviour in evals/reports/milestones/c32-provider-profile.json instead.
	const detectorTokenBudget = 4096
	// A var rather than a const: Go will not narrow a constant expression
	// with a fractional result to int, and rounding it in the source would
	// hide which number came from the detector.
	detectorCharsPerToken := 1.3

	effective := int(float64(detectorTokenBudget) * detectorCharsPerToken)
	if effective >= contract.MaxTextChars {
		t.Fatalf("the detector now admits %d characters against a documented "+
			"%d; the limits agree and this test is obsolete",
			effective, contract.MaxTextChars)
	}
	t.Logf("documented %d characters, detector admits about %d (%.0f%%)",
		contract.MaxTextChars, effective,
		100*float64(effective)/float64(contract.MaxTextChars))
}

// TestTheByteRatioOfOrdinaryFinnishIsWhatTheCapAssumes pins the assumption.
//
// api.MaxRequestBytes is justified by a claim about Finnish text. If the
// corpus or the sample sentence drifted to a much higher ratio, the cap's
// reasoning would be wrong before anything else failed.
func TestTheByteRatioOfOrdinaryFinnishIsWhatTheCapAssumes(t *testing.T) {
	passage := finnishOf(10000)
	ratio := float64(len(passage)) / float64(len([]rune(passage)))
	if ratio > 1.3 {
		t.Errorf("bytes per character = %.3f; the 64 KiB cap assumes ordinary "+
			"Finnish stays well under 2", ratio)
	}
}

func buildRouter(t *testing.T) http.Handler {
	t.Helper()
	stub := newStubDetector(t, 0)
	router, _ := newRouter(t, stub, 5*time.Second,
		shippedAdmission(),
		limits.Bucket{PerSecond: 1e6, Burst: 1e6})
	return router
}

// TestAnOversizedPassageReachesTheCallerAsItsOwnProblem is the end-to-end
// half of the C32 error-code fix.
//
// The two unit sides are covered where they live - the detector raises
// distinct exceptions, the client maps distinct sentinels - and this asserts
// the thing a caller actually experiences: the code and status that come out
// of the public API.
//
// Before C32 both of these were 503 `detector_unavailable`.
func TestAnOversizedPassageReachesTheCallerAsItsOwnProblem(t *testing.T) {
	for _, tc := range []struct {
		name           string
		detectorStatus int
		detectorCode   string
		wantStatus     int
		wantCode       string
	}{
		{
			name:           "over the token budget",
			detectorStatus: http.StatusUnprocessableEntity,
			detectorCode:   "token_budget_exceeded",
			wantStatus:     http.StatusUnprocessableEntity,
			wantCode:       "token_budget_exceeded",
		},
		{
			name:           "over the byte ceiling",
			detectorStatus: http.StatusRequestEntityTooLarge,
			detectorCode:   "payload_too_large",
			wantStatus:     http.StatusRequestEntityTooLarge,
			wantCode:       "payload_too_large",
		},
		{
			name:           "a genuine outage is still an outage",
			detectorStatus: http.StatusServiceUnavailable,
			detectorCode:   "detector_unavailable",
			wantStatus:     http.StatusServiceUnavailable,
			wantCode:       "detector_unavailable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newRefusingDetector(t, tc.detectorStatus, tc.detectorCode)
			router, _ := newRouter(t, stub, 5*time.Second,
				shippedAdmission(), limits.Bucket{PerSecond: 1e6, Burst: 1e6})

			status, code := issue(router, scanBody(t, finnishOf(200)))
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
		})
	}
}

// newRefusingDetector answers every assessment with one error envelope.
func newRefusingDetector(t *testing.T, status int, code string) *url.URL {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w,
				`{"request_id":"r","error":{"code":%q,"message":"refused"}}`, code)
		}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse stub URL: %v", err)
	}
	return parsed
}
