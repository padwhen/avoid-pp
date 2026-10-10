package obs

import (
	"context"

	"github.com/padwhen/avoid-pp/gateway/internal/admission"
	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/detector"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

// The errors whose identities are safe to log.
//
// This list is the counterpart to AllowedKeys: it states, error by error, that
// the name carries no request content. An error not listed here is reported
// as its Go type instead, which is still an identifier rather than a message.
//
// Registered in init so the slice is complete before any logging happens and
// is only read thereafter.
func init() {
	for _, pair := range []Sentinel{
		{detector.ErrUnavailable, "detector_unavailable"},
		{detector.ErrInvalidResponse, "detector_invalid_response"},
		{detector.ErrResponseTooLarge, "detector_response_too_large"},
		{detector.ErrDeadlineExceeded, "detector_deadline_exceeded"},
		{admission.ErrQueueFull, "admission_queue_full"},
		{auth.ErrNoCredential, "no_credential"},
		{auth.ErrUnknownCredential, "unknown_credential"},
		{policy.ErrUnknownMode, "policy_unknown_mode"},
		{policy.ErrUnknownLabel, "policy_unknown_label"},
		{context.Canceled, "context_canceled"},
		{context.DeadlineExceeded, "context_deadline_exceeded"},
	} {
		RegisterSentinel(pair.Err, pair.Name)
	}
}
