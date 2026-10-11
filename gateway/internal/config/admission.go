package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/padwhen/avoid-pp/gateway/internal/admission"
)

// Environment variables for admission control.
const (
	EnvMaxActive = "AVOIDPP_MAX_ACTIVE"
	EnvMaxQueued = "AVOIDPP_MAX_QUEUED"
)

// Defaults sized from measured provider latency, not CPU count.
//
// The work is almost entirely waiting on a network call, so "one per core"
// does not apply - a slot costs a goroutine and a connection.
//
// MaxActive 4 against a measured median scan of 2.833s is a ceiling of 1.41
// scans per second, which the C32 profile reproduces to three decimals.
// Nothing local binds first: a full system holds under 8 MiB. The constraint
// is spend - 1.41 scans per second is roughly USD 1,145 a day sustained.
//
// MaxQueued is 4, lowered from 8 by C32. A request at the back of the queue
// waits for the queue ahead to clear and then needs L of its own, so it only
// completes if that fits the scan budget.
//
// The first derivation modelled the wait as (MaxQueued/MaxActive) x L and
// chose 6. The profile then measured the same 5.670s maximum wait at both 6
// and 8 - two whole batches either way. Under a burst, in-flight requests
// start together and release slots in groups of MaxActive, so the wait is
//
//	ceil(MaxQueued / MaxActive) x L
//
// a step function, and 6 and 8 sit on the same step. At the measured p95 of
// 5.851s against a 15s budget, only ceil(Q/A) = 1 fits, so MaxQueued is 4.
//
// The failure this avoids is the expensive kind: a request admitted with less
// time left than the call needs starts a paid provider call and is cancelled
// mid-flight. At MaxQueued 4 the deepest queued request still finishes at
// p95; at p99 it times out while waiting, which costs nothing.
const (
	DefaultMaxActive = 4
	// Derived above, and a step function rather than a dial: the next value
	// that changes anything is 8, and it changes it for the worse. Re-derive
	// against the scan timeout and the measured p95 before touching it.
	DefaultMaxQueued = 4
)

// parseAdmission reads the concurrency bounds.
func parseAdmission(getenv Getenv) (admission.Config, error) {
	var problems []error

	active, err := wholeNumber(EnvMaxActive, getenv(EnvMaxActive), DefaultMaxActive)
	if err != nil {
		problems = append(problems, err)
	}
	queued, err := wholeNumber(EnvMaxQueued, getenv(EnvMaxQueued), DefaultMaxQueued)
	if err != nil {
		problems = append(problems, err)
	}

	if len(problems) == 0 {
		if active < 1 {
			problems = append(problems, fmt.Errorf(
				"%s: must be at least 1, or nothing is ever admitted", EnvMaxActive))
		}
		if queued < 0 {
			problems = append(problems, fmt.Errorf(
				"%s: must not be negative", EnvMaxQueued))
		}
	}

	if len(problems) > 0 {
		return admission.Config{}, errors.Join(problems...)
	}
	return admission.Config{MaxActive: active, MaxQueued: queued}, nil
}

func wholeNumber(variable, raw string, fallback int) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		// err quotes the offending text; report the requirement instead.
		return 0, fmt.Errorf("%s: must be a whole number", variable)
	}
	return parsed, nil
}
