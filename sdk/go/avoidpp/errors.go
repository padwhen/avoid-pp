package avoidpp

import (
	"errors"
	"fmt"
)

// ErrScanFailed is the sentinel every failure in this package wraps.
//
//	if _, err := client.Scan(ctx, in); err != nil {
//		// errors.Is(err, avoidpp.ErrScanFailed) is true for every failure
//		// this package can report, now and after the contract grows.
//		return err
//	}
//
// It exists so that "refuse unless there is a verdict" can be written once.
// A caller who gets any error from Scan has no decision, and the safe
// behaviour is the same for all of them.
var ErrScanFailed = errors.New("scan failed")

// Reason slugs for a 200 response this client will not use.
//
// Stable identifiers for logs and tests. Branch on these, never on the
// message text.
const (
	ReasonUnreadableBody          = "unreadable_body"
	ReasonMissingField            = "missing_field"
	ReasonScanNotComplete         = "scan_not_complete"
	ReasonCoverageTruncated       = "coverage_truncated"
	ReasonCoveragePartial         = "coverage_partial"
	ReasonCoverageMismatch        = "coverage_mismatch"
	ReasonUnknownLabel            = "unknown_label"
	ReasonAllowContradictsLabel   = "allow_contradicts_label"
	ReasonAllowWithoutCleanReason = "allow_without_clean_reason"
)

// ConfigError means the client was built or used wrongly.
//
// A scan failure rather than a separate kind of problem, so a caller wrapping
// scans in "any error means do not proceed" cannot be bypassed by a
// misconfiguration. Misconfiguration is one of the likelier ways a guard ends
// up not guarding.
type ConfigError struct{ Detail string }

func (e *ConfigError) Error() string { return "avoidpp: " + e.Detail }
func (e *ConfigError) Unwrap() error { return ErrScanFailed }

// TransportError means the request did not complete: connection, TLS,
// context cancellation or the client's own timeout.
//
// CauseType is the provoking error's type, and its message is deliberately
// not carried. An HTTP library's error text embeds the request URL, and a URL
// can carry userinfo.
type TransportError struct {
	CauseType string
	cause     error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("avoidpp: the gateway could not be reached (%s)", e.CauseType)
}

// Unwrap returns both the sentinel and the provoking error, so
// errors.Is(err, context.DeadlineExceeded) still works while
// errors.Is(err, ErrScanFailed) also holds.
func (e *TransportError) Unwrap() []error { return []error{ErrScanFailed, e.cause} }

// ServiceError means the gateway answered with a failure.
//
// Code is always set; CodeUnknown covers a code from a later contract
// version, a body with no code, and a body written by something that is not
// the gateway. There is deliberately no field here for an assessment, a
// decision or an action: a failure has no verdict, so it carries none, and a
// gateway that regressed into attaching one could not hand it to an
// application through this client.
type ServiceError struct {
	Status            int
	Code              ErrorCode
	RequestID         string
	RetryAfterSeconds int
	// HasRetryAfter distinguishes "wait zero seconds" from "no advice given".
	HasRetryAfter bool
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("avoidpp: the gateway returned %d (%s)", e.Status, e.Code)
}

func (e *ServiceError) Unwrap() error { return ErrScanFailed }

// ResponseError means HTTP 200 arrived and no decision could be derived.
//
// Distinct from ServiceError because it means something different: the call
// succeeded and the contract was broken. Retrying would ask the same question
// and get the same contradictory answer, which is why the Reason slug is the
// part worth logging.
type ResponseError struct {
	Reason string
	Detail string
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("avoidpp: the gateway returned an unusable scan (%s): %s",
		e.Reason, e.Detail)
}

func (e *ResponseError) Unwrap() error { return ErrScanFailed }

// Retryable reports whether this client would send the scan again.
//
// The rule is narrow on purpose: retry only where the server has said the
// work definitively did not happen. A scan is a paid provider call, so
// retrying a request that may already have reached the model buys one verdict
// for two prices.
//
// That excludes detector_unavailable, which reads transient but carries no
// retry guidance in the contract; deadline_exceeded, which says nothing about
// whether the provider call completed; and every transport failure, where the
// client cannot tell whether the request arrived. A 429 is retried on the
// status alone, because it is unambiguous about the request not having been
// served, whoever generated it.
//
// False does not mean the condition is permanent. It means retrying is not
// this client's decision to make. See docs/c41-sdk.md.
func Retryable(err error) bool {
	var service *ServiceError
	if !errors.As(err, &service) {
		return false
	}
	if service.Status == 429 {
		return true
	}
	switch service.Code {
	case CodeRateLimited, CodeOverloaded:
		return true
	}
	return false
}
