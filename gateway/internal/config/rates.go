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
// A live Opus scan measures 2.833s at the median and about 1,176 input plus
// 127 output tokens for a typical passage, which is USD 0.0090. These limits
// are a spend bound first and a fairness mechanism second: the usual
// web-service instinct of "a few hundred per second" would put the daily
// ceiling in six figures.
//
// # What C32 changed, and why
//
// The global rate was 2 per second. Admission completes at most
// MaxActive / 2.833s = 1.41 per second, so the limiter was permitting
// traffic the service could not serve, and the excess was shed by admission
// as `overloaded` instead of by the limiter as `rate_limited`.
//
// Both fail closed, so nothing was unsafe. What was wrong is the signal: a
// service shedding as `overloaded` reads as a capacity incident, and a
// service shedding as `rate_limited` reads as a caller sending too fast. The
// second was the true statement, and the dashboards would have said the
// first. It also made the rate limiter decorative as a spend bound, since
// admission was already the tighter of the two.
//
// So the sustained global rate is now 1 per second, under the measured
// ceiling of 1.41, and the burst is MaxActive + MaxQueued = 8 - exactly
// enough to fill every slot and every queue position once, and no more.
//
// The per-caller rate is unchanged. One caller at 1 per second can consume
// about 71% of the ceiling, which is the right answer for a service with one
// caller and the wrong one for a service with ten; it is noted in
// docs/c32-capacity.md rather than pre-solved for a tenancy that does not
// exist.
const (
	DefaultCallerRate = "1/5"
	// 1 per second sustained, burst MaxActive + MaxQueued. Derived above.
	DefaultGlobalRate = "1/8"
	DefaultUnauthRate = "1/8"
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
