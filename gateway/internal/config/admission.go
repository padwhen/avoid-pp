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
// A measured live scan is about 4.4 seconds. Four concurrent slots is
// therefore a little under one completed scan per second, which sits just
// above the global rate limit of two per second so that the rate limiter is
// the thing shaping traffic in normal operation and admission is the thing
// catching the abnormal case - a provider that has slowed down.
//
// The queue is deliberately small. It exists to absorb jitter, not to store
// work: eight waiting requests at 4.4 seconds each is already a worst-case
// wait longer than most callers' patience, and anything larger would be
// latency pretending to be capacity.
const (
	DefaultMaxActive = 4
	DefaultMaxQueued = 8
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
