// Package config loads and validates the gateway's settings at startup.
//
// Invalid configuration must stop the process rather than surface later as a
// confusing runtime failure, so Load reports every problem it finds at once
// instead of failing on the first.
//
// One rule governs every message in this package: an error names the variable
// and the requirement, never the value. Configuration carries credentials —
// a detector URL may embed userinfo — and "invalid value \"sk-...\"" is a
// helpful message that has just written a secret into the logs. Tests enforce
// this rather than trusting it.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/admission"
	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

// Environment variables read by Load.
const (
	EnvAddr            = "AVOIDPP_ADDR"
	EnvDetectorURL     = "AVOIDPP_DETECTOR_URL"
	EnvScanTimeout     = "AVOIDPP_SCAN_TIMEOUT"
	EnvShutdownTimeout = "AVOIDPP_SHUTDOWN_TIMEOUT"
	EnvLogLevel        = "AVOIDPP_LOG_LEVEL"
	EnvPolicyMode      = "AVOIDPP_POLICY_MODE"
)

// Defaults are development settings, not promised production behaviour. The
// commit plan revises them against measured provider latency at C32.
const (
	DefaultAddr            = ":8080"
	DefaultScanTimeout     = 15 * time.Second
	DefaultShutdownTimeout = 10 * time.Second
	DefaultLogLevel        = "info"

	// Monitoring is the default and the only mode available before the
	// quality gates at C30 are met. Enforcement must be chosen deliberately.
	DefaultPolicyMode = string(policy.ModeMonitoring)

	// An end-to-end scan budget longer than this is a configuration mistake:
	// it covers admission wait, internal HTTP, provider work and any retry.
	maxScanTimeout = 60 * time.Second
)

var logLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}

// Config is the validated gateway configuration.
type Config struct {
	Addr            string
	DetectorURL     *url.URL
	ScanTimeout     time.Duration
	ShutdownTimeout time.Duration
	LogLevel        string
	PolicyMode      policy.Mode

	// Callers is the authenticated caller set. It holds key digests, not
	// keys, so a Config that reaches a log or a dump carries no credential.
	Callers *auth.Registry

	// Rates bounds how fast requests may arrive. The buckets are allocated
	// from Callers at startup, so the limiter's state cannot grow.
	Rates limits.Config

	// Admission bounds how much inference runs at once, which is a different
	// question from how fast requests arrive.
	Admission admission.Config
}

// Getenv matches os.Getenv and is injected so tests need no process state.
type Getenv func(string) string

// Load reads configuration, applies defaults and validates the result. All
// validation problems are reported together.
func Load(getenv Getenv) (*Config, error) {
	cfg := &Config{
		Addr:            valueOr(getenv(EnvAddr), DefaultAddr),
		ScanTimeout:     DefaultScanTimeout,
		ShutdownTimeout: DefaultShutdownTimeout,
		LogLevel:        valueOr(strings.ToLower(getenv(EnvLogLevel)), DefaultLogLevel),
	}

	var problems []error

	if !strings.Contains(cfg.Addr, ":") {
		problems = append(problems, fmt.Errorf(
			"%s: must include a port, for example %q", EnvAddr, DefaultAddr))
	}

	raw := strings.TrimSpace(getenv(EnvDetectorURL))
	switch {
	case raw == "":
		problems = append(problems, fmt.Errorf(
			"%s: required; the private detector's base URL", EnvDetectorURL))
	default:
		parsed, err := url.Parse(raw)
		switch {
		case err != nil:
			// err embeds the offending URL, so it is deliberately not wrapped.
			problems = append(problems, fmt.Errorf(
				"%s: must be a valid URL", EnvDetectorURL))
		case parsed.Scheme != "http" && parsed.Scheme != "https":
			problems = append(problems, fmt.Errorf(
				"%s: scheme must be http or https", EnvDetectorURL))
		case parsed.Host == "":
			problems = append(problems, fmt.Errorf(
				"%s: must include a host", EnvDetectorURL))
		default:
			cfg.DetectorURL = parsed
		}
	}

	if d, err := duration(getenv(EnvScanTimeout), DefaultScanTimeout); err != nil {
		problems = append(problems, fmt.Errorf("%s: %w", EnvScanTimeout, err))
	} else if d > maxScanTimeout {
		problems = append(problems, fmt.Errorf(
			"%s: must not exceed %s", EnvScanTimeout, maxScanTimeout))
	} else {
		cfg.ScanTimeout = d
	}

	if d, err := duration(getenv(EnvShutdownTimeout), DefaultShutdownTimeout); err != nil {
		problems = append(problems, fmt.Errorf("%s: %w", EnvShutdownTimeout, err))
	} else {
		cfg.ShutdownTimeout = d
	}

	mode, err := policy.ParseMode(valueOr(strings.ToLower(getenv(EnvPolicyMode)), DefaultPolicyMode))
	if err != nil {
		problems = append(problems, fmt.Errorf(
			"%s: must be monitoring or enforcement", EnvPolicyMode))
	} else {
		cfg.PolicyMode = mode
	}

	if specs, err := parseAPIKeys(getenv(EnvAPIKeys)); err != nil {
		problems = append(problems, err)
	} else if registry, err := auth.NewRegistry(specs); err != nil {
		problems = append(problems, fmt.Errorf("%s: %w", EnvAPIKeys, err))
	} else {
		cfg.Callers = registry
	}

	if rates, err := parseRates(getenv); err != nil {
		problems = append(problems, err)
	} else {
		cfg.Rates = rates
	}

	if adm, err := parseAdmission(getenv); err != nil {
		problems = append(problems, err)
	} else {
		cfg.Admission = adm
	}

	if !logLevels[cfg.LogLevel] {
		problems = append(problems, fmt.Errorf(
			"%s: must be one of debug, info, warn, error", EnvLogLevel))
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", errors.Join(problems...))
	}
	return cfg, nil
}

// Redacted renders the detector URL with any userinfo removed, for logging.
func (c *Config) Redacted() string {
	if c.DetectorURL == nil {
		return ""
	}
	clone := *c.DetectorURL
	if clone.User != nil {
		clone.User = url.User("redacted")
	}
	return clone.String()
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func duration(raw string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		// err quotes the raw value; report the requirement instead.
		return 0, errors.New("must be a duration such as 15s")
	}
	if d <= 0 {
		return 0, errors.New("must be greater than zero")
	}
	return d, nil
}
