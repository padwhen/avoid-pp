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

// Defaults sized from measured provider latency rather than from CPU count.
//
// The work here is almost entirely waiting on a network call, so the usual
// "one per core" reasoning does not apply - a slot costs a goroutine and a
// connection, not a core. What bounds it instead is what the dependency can
// be trusted to do and what the budget allows.
//
// # MaxActive
//
// Four slots against a measured median scan of 2.833s is a ceiling of 1.41
// completed scans per second, which the C32 load profile reproduces to three
// decimal places. Nothing local binds before that: at the largest passage
// the service accepts, a request allocates about 755 KiB, so a completely
// full system holds under 8 MiB. The constraint on this number is spend, not
// resources - 1.41 scans per second is roughly USD 1,145 a day sustained.
//
// # MaxQueued, which C32 lowered from 8 to 4
//
// The queue absorbs jitter; it must not accept work it cannot finish. A
// request at the back of it waits for the queue ahead to clear and then needs
// L of its own, so it completes only if that total fits the scan budget.
//
// The first attempt at this derivation modelled the wait as a division,
// (MaxQueued/MaxActive) x L, and chose 6. The load profile then measured a
// maximum wait of 5.670s at MaxQueued 6 and the identical 5.670s at MaxQueued
// 8 - two whole batches of 2.833s in both cases. Under a burst the in-flight
// requests start together and so finish together, releasing slots in groups
// of MaxActive rather than smoothly, and the wait is
//
//	ceil(MaxQueued / MaxActive) x L
//
// which is a step function. Six and eight sit on the same step. Lowering the
// queue from 8 to 6 would have changed nothing and looked like a fix.
//
// At the measured p95 of 5.851s against the 15s budget, only ceil(Q/A) = 1
// fits: 2 x 5.851 = 11.7s, where ceil = 2 gives 17.55s. So MaxQueued is 4.
//
// The failure that avoids is the expensive kind. A request admitted with less
// time left than the call needs starts a *paid* provider call and is
// cancelled in the middle of it - money spent on an answer nobody receives.
// At MaxQueued 4 the deepest queued request still finishes at p95; at p99 it
// exhausts its deadline while waiting, which costs nothing.
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
