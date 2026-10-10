package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/padwhen/avoid-pp/gateway/internal/limits"
)

// Environment variables for the rate limits.
const (
	EnvCallerRate = "AVOIDPP_RATE_CALLER"
	EnvGlobalRate = "AVOIDPP_RATE_GLOBAL"
	EnvUnauthRate = "AVOIDPP_RATE_UNAUTHENTICATED"
)

// Defaults, chosen from what a scan costs rather than from habit.
//
// A live Opus scan measured 4.4 seconds and roughly 1,100 input plus 170
// output tokens, which is about $0.01 at the rates recorded in
// evals/live_eval.py. At the global default of 2 requests per second that is
// a ceiling near $1.20 a minute, sustained, if something upstream goes into a
// loop. The usual web-service instinct of "a few hundred per second" would
// put that figure in the thousands.
//
// So these are deliberately low. They are a spend bound first and a fairness
// mechanism second. C32 revises them against measured provider latency.
const (
	DefaultCallerRate = "1/5"
	DefaultGlobalRate = "2/10"
	DefaultUnauthRate = "2/10"
)

// parseBucket reads a "rate/burst" pair, as in "1/5": one request per second
// sustained, up to five arriving at once.
//
// Two numbers in one variable rather than six variables, because the pair is
// meaningless split up — a rate without its burst does not describe a limit,
// and nothing good happens when half of a pair is overridden.
func parseBucket(variable, raw, fallback string) (limits.Bucket, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = fallback
	}

	rate, burst, found := strings.Cut(value, "/")
	if !found {
		return limits.Bucket{}, fmt.Errorf(
			"%s: must be rate/burst, for example %q", variable, fallback)
	}

	perSecond, err := strconv.ParseFloat(strings.TrimSpace(rate), 64)
	if err != nil {
		// err quotes the offending text; report the requirement instead.
		return limits.Bucket{}, fmt.Errorf(
			"%s: rate must be a number, for example %q", variable, fallback)
	}
	size, err := strconv.Atoi(strings.TrimSpace(burst))
	if err != nil {
		return limits.Bucket{}, fmt.Errorf(
			"%s: burst must be a whole number, for example %q", variable, fallback)
	}

	bucket := limits.Bucket{PerSecond: perSecond, Burst: size}
	if perSecond <= 0 {
		return limits.Bucket{}, fmt.Errorf("%s: rate must be greater than zero", variable)
	}
	if size < 1 {
		return limits.Bucket{}, fmt.Errorf(
			"%s: burst must be at least 1, or nothing is ever admitted", variable)
	}
	return bucket, nil
}

// parseRates reads all three buckets, reporting every problem at once.
func parseRates(getenv Getenv) (limits.Config, error) {
	var (
		cfg      limits.Config
		problems []error
	)

	for _, spec := range []struct {
		variable string
		fallback string
		target   *limits.Bucket
	}{
		{EnvCallerRate, DefaultCallerRate, &cfg.PerCaller},
		{EnvGlobalRate, DefaultGlobalRate, &cfg.Global},
		{EnvUnauthRate, DefaultUnauthRate, &cfg.Unauthenticated},
	} {
		bucket, err := parseBucket(spec.variable, getenv(spec.variable), spec.fallback)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		*spec.target = bucket
	}

	if len(problems) > 0 {
		return limits.Config{}, errors.Join(problems...)
	}
	return cfg, nil
}
