package config

import (
	"strings"
	"testing"
)

func TestParseRatesDefaults(t *testing.T) {
	cfg, err := parseRates(env(map[string]string{}))
	if err != nil {
		t.Fatalf("parseRates() error = %v", err)
	}
	if cfg.PerCaller.PerSecond != 1 || cfg.PerCaller.Burst != 5 {
		t.Errorf("per-caller = %+v, want 1/5", cfg.PerCaller)
	}
	// 2/10 until C32, which lowered the sustained rate to sit under the
	// measured admission ceiling. coherence_test.go asserts the derivation;
	// this asserts the literal, so both the reasoning and the value are
	// pinned.
	if cfg.Global.PerSecond != 1 || cfg.Global.Burst != 8 {
		t.Errorf("global = %+v, want 1/8", cfg.Global)
	}
	if cfg.Unauthenticated.PerSecond != 1 || cfg.Unauthenticated.Burst != 8 {
		t.Errorf("unauthenticated = %+v, want 1/8", cfg.Unauthenticated)
	}
}

// The defaults must be internally consistent, or every startup fails.
func TestDefaultRatesAreAcceptedByTheLimiter(t *testing.T) {
	cfg, err := Load(env(valid()))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// Mirrors what main.go does: the defaults have to survive limits.New, or
	// the service cannot start without an override.
	if cfg.Rates.Global.PerSecond < cfg.Rates.PerCaller.PerSecond {
		t.Error("the default global rate is below the default per-caller rate")
	}
	if cfg.Rates.Global.Burst < cfg.Rates.PerCaller.Burst {
		t.Error("the default global burst is below the default per-caller burst")
	}
}

func TestParseRatesOverrides(t *testing.T) {
	cfg, err := parseRates(env(map[string]string{
		EnvCallerRate: "0.5/3",
		EnvGlobalRate: "10/20",
		EnvUnauthRate: "4/8",
	}))
	if err != nil {
		t.Fatalf("parseRates() error = %v", err)
	}
	if cfg.PerCaller.PerSecond != 0.5 || cfg.PerCaller.Burst != 3 {
		t.Errorf("per-caller = %+v, want 0.5/3", cfg.PerCaller)
	}
	if cfg.Global.PerSecond != 10 || cfg.Global.Burst != 20 {
		t.Errorf("global = %+v", cfg.Global)
	}
}

func TestParseRatesTolerateSpacing(t *testing.T) {
	cfg, err := parseRates(env(map[string]string{EnvCallerRate: " 2 / 7 "}))
	if err != nil {
		t.Fatalf("parseRates() error = %v", err)
	}
	if cfg.PerCaller.PerSecond != 2 || cfg.PerCaller.Burst != 7 {
		t.Errorf("per-caller = %+v, want 2/7", cfg.PerCaller)
	}
}

func TestParseRatesRejectsMalformedValues(t *testing.T) {
	cases := map[string]string{
		"no separator":     "5",
		"empty rate":       "/5",
		"empty burst":      "5/",
		"a word":           "fast/5",
		"a word burst":     "5/many",
		"zero rate":        "0/5",
		"negative rate":    "-1/5",
		"zero burst":       "1/0",
		"negative burst":   "1/-5",
		"fractional burst": "1/2.5",
		"too many parts":   "1/2/3",
		"just a separator": "/",
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRates(env(map[string]string{EnvCallerRate: value})); err == nil {
				t.Fatalf("parseRates(%q) error = nil, want error", value)
			}
		})
	}
}

// Every problem at once, so fixing configuration is not a guessing game one
// restart at a time.
func TestParseRatesReportsEveryProblem(t *testing.T) {
	_, err := parseRates(env(map[string]string{
		EnvCallerRate: "nope",
		EnvGlobalRate: "0/5",
		EnvUnauthRate: "1/0",
	}))
	if err == nil {
		t.Fatal("parseRates() error = nil, want error")
	}
	for _, variable := range []string{EnvCallerRate, EnvGlobalRate, EnvUnauthRate} {
		if !strings.Contains(err.Error(), variable) {
			t.Errorf("error does not name %s: %v", variable, err)
		}
	}
}

// Rate errors are logged at startup like every other configuration error, so
// they must not echo the value either — a rate variable is unlikely to hold a
// secret, but the rule is cheaper to keep than to make exceptions to.
func TestRateErrorsNeverEchoValues(t *testing.T) {
	const secret = "sk-ant-SUPERSECRET-pasted-into-the-wrong-var"
	_, err := Load(env(map[string]string{
		EnvDetectorURL: "http://d:1",
		EnvAPIKeys:     testKeys,
		EnvCallerRate:  secret,
	}))
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error disclosed a configured value: %q", err)
	}
}
