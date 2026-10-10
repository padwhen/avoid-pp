// Package policy turns a validated assessment into a decision.
//
// The detector assesses; this package decides. Keeping them apart is what
// lets the same detector output drive different behaviour in monitoring and
// enforcement without the detector knowing which mode it is running under —
// and stops a detector from being able to dictate an outcome.
//
// Evaluate is pure: configuration in, decision out, no I/O and no clock. That
// makes the whole policy matrix testable as a table, which is the point of
// C11-AC1.
package policy

import (
	"errors"
	"fmt"

	"github.com/padwhen/avoid-pp/gateway/internal/contract"
)

// Mode selects how a non-clean assessment is treated.
type Mode string

const (
	// ModeMonitoring continues on a non-clean assessment and records it.
	// This is the default, and the only mode available before the quality
	// gates at C30 are met.
	ModeMonitoring Mode = "monitoring"

	// ModeEnforcement stops continuation on a non-clean assessment.
	ModeEnforcement Mode = "enforcement"
)

// Version identifies the policy that produced a decision, so a result in an
// evaluation report can be attributed to the rules in force at the time.
const Version = "1"

// ErrUnknownMode is returned by ParseMode for an unrecognised value.
var ErrUnknownMode = errors.New("unknown policy mode")

// ErrUnknownLabel is returned when an assessment carries a label this build
// does not define.
//
// It is deliberately an error rather than a default branch: a label the policy
// does not understand must not quietly fall through to allow.
var ErrUnknownLabel = errors.New("unknown assessment label")

// ParseMode validates a configured mode.
func ParseMode(value string) (Mode, error) {
	switch Mode(value) {
	case ModeMonitoring:
		return ModeMonitoring, nil
	case ModeEnforcement:
		return ModeEnforcement, nil
	}
	return "", fmt.Errorf("%w: must be %q or %q", ErrUnknownMode, ModeMonitoring, ModeEnforcement)
}

// Identity names the policy for the response's versions block.
func (m Mode) Identity() string { return string(m) + "-" + Version }

// Evaluate maps a validated assessment to a decision.
//
// The full matrix, and the reason each row reads as it does:
//
//	mode         label                   action   why
//	monitoring   no_injection_detected   allow    nothing was found
//	monitoring   suspicious              flag     continue, with telemetry
//	monitoring   uncertain               flag     continue, with telemetry
//	enforcement  no_injection_detected   allow    nothing was found
//	enforcement  suspicious              block    stop continuation
//	enforcement  uncertain               block    an unresolved answer is not a clean one
//
// There is no row producing allow from a non-clean label, in either mode.
//
// Operational failures never reach this function. An unavailable detector, an
// expired deadline or an untrustworthy response is an error envelope decided
// by the caller, because a failure is not an assessment and must not be
// handed to a policy that only knows how to produce actions.
func Evaluate(mode Mode, assessment contract.Assessment) (contract.Decision, error) {
	// An unrecognised mode fails closed rather than falling through to the
	// permissive branch. Callers pass a mode validated by ParseMode, so
	// reaching this is a programming error - but one that would otherwise
	// turn into a silent allow.
	if mode != ModeMonitoring && mode != ModeEnforcement {
		return contract.Decision{}, fmt.Errorf("%w: %q", ErrUnknownMode, string(mode))
	}

	switch assessment.Label {
	case contract.LabelNoInjectionDetected:
		return contract.Decision{
			Action:     contract.ActionAllow,
			ReasonCode: contract.ReasonCleanCompleteScan,
		}, nil

	case contract.LabelSuspicious:
		if mode == ModeEnforcement {
			return contract.Decision{
				Action:     contract.ActionBlock,
				ReasonCode: contract.ReasonSuspiciousEnforced,
			}, nil
		}
		return contract.Decision{
			Action:     contract.ActionFlag,
			ReasonCode: contract.ReasonSuspiciousMonitored,
		}, nil

	case contract.LabelUncertain:
		if mode == ModeEnforcement {
			return contract.Decision{
				Action:     contract.ActionBlock,
				ReasonCode: contract.ReasonUncertainEnforced,
			}, nil
		}
		return contract.Decision{
			Action:     contract.ActionFlag,
			ReasonCode: contract.ReasonUncertainMonitored,
		}, nil
	}

	return contract.Decision{}, fmt.Errorf("%w: %q", ErrUnknownLabel, string(assessment.Label))
}
