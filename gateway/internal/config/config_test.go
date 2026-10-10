package config

import (
	"strings"
	"testing"
	"time"
)

func env(pairs map[string]string) Getenv {
	return func(key string) string { return pairs[key] }
}

func valid() map[string]string {
	return map[string]string{EnvDetectorURL: "http://detector:9000"}
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(env(valid()))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Addr != DefaultAddr {
		t.Errorf("Addr = %q, want %q", cfg.Addr, DefaultAddr)
	}
	if cfg.ScanTimeout != DefaultScanTimeout {
		t.Errorf("ScanTimeout = %v, want %v", cfg.ScanTimeout, DefaultScanTimeout)
	}
	if cfg.ShutdownTimeout != DefaultShutdownTimeout {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, DefaultShutdownTimeout)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		EnvAddr:            "127.0.0.1:9999",
		EnvDetectorURL:     "https://detector.internal:8443/base",
		EnvScanTimeout:     "5s",
		EnvShutdownTimeout: "2s",
		EnvLogLevel:        "DEBUG",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Addr != "127.0.0.1:9999" {
		t.Errorf("Addr = %q", cfg.Addr)
	}
	if cfg.ScanTimeout != 5*time.Second {
		t.Errorf("ScanTimeout = %v", cfg.ScanTimeout)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want lowercased", cfg.LogLevel)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	cases := map[string]struct {
		env  map[string]string
		want string
	}{
		"missing detector url": {
			env:  map[string]string{},
			want: EnvDetectorURL,
		},
		"detector url without scheme": {
			env:  map[string]string{EnvDetectorURL: "detector:9000"},
			want: EnvDetectorURL,
		},
		"detector url with unsupported scheme": {
			env:  map[string]string{EnvDetectorURL: "ftp://detector:9000"},
			want: EnvDetectorURL,
		},
		"detector url without host": {
			env:  map[string]string{EnvDetectorURL: "http:///path"},
			want: EnvDetectorURL,
		},
		"addr without port": {
			env:  map[string]string{EnvDetectorURL: "http://d:1", EnvAddr: "localhost"},
			want: EnvAddr,
		},
		"unparseable scan timeout": {
			env:  map[string]string{EnvDetectorURL: "http://d:1", EnvScanTimeout: "soon"},
			want: EnvScanTimeout,
		},
		"negative scan timeout": {
			env:  map[string]string{EnvDetectorURL: "http://d:1", EnvScanTimeout: "-5s"},
			want: EnvScanTimeout,
		},
		"scan timeout beyond the ceiling": {
			env:  map[string]string{EnvDetectorURL: "http://d:1", EnvScanTimeout: "10m"},
			want: EnvScanTimeout,
		},
		"zero shutdown timeout": {
			env:  map[string]string{EnvDetectorURL: "http://d:1", EnvShutdownTimeout: "0s"},
			want: EnvShutdownTimeout,
		},
		"unknown log level": {
			env:  map[string]string{EnvDetectorURL: "http://d:1", EnvLogLevel: "verbose"},
			want: EnvLogLevel,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(env(tc.env))
			if err == nil {
				t.Fatalf("Load() = %+v, want error", cfg)
			}
			if cfg != nil {
				t.Errorf("Load() returned a config alongside an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	_, err := Load(env(map[string]string{
		EnvAddr:        "localhost",
		EnvScanTimeout: "soon",
		EnvLogLevel:    "verbose",
	}))
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	for _, want := range []string{EnvAddr, EnvDetectorURL, EnvScanTimeout, EnvLogLevel} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s; got %q", want, err)
		}
	}
}

// C07-AC2: a startup failure must be useful without disclosing a secret.
// Configuration can embed credentials, so no error may echo a supplied value.
func TestLoadErrorsNeverEchoValues(t *testing.T) {
	const secret = "sk-ant-SUPERSECRET-do-not-log"
	cases := map[string]map[string]string{
		"credentials in detector url": {
			EnvDetectorURL: "ftp://user:" + secret + "@detector:9000",
		},
		"secret pasted into a duration": {
			EnvDetectorURL: "http://d:1",
			EnvScanTimeout: secret,
		},
		"secret pasted into the log level": {
			EnvDetectorURL: "http://d:1",
			EnvLogLevel:    secret,
		},
		"secret pasted into the address": {
			EnvDetectorURL: "http://d:1",
			EnvAddr:        secret,
		},
	}

	for name, environment := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(env(environment))
			if err == nil {
				t.Fatal("Load() error = nil, want error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error disclosed a configured value: %q", err)
			}
			for _, value := range environment {
				if strings.Contains(err.Error(), value) {
					t.Errorf("error echoed the value of a variable: %q", err)
				}
			}
		})
	}
}

func TestRedactedStripsCredentials(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		EnvDetectorURL: "https://user:hunter2@detector.internal:8443/base",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got := cfg.Redacted()
	if strings.Contains(got, "hunter2") {
		t.Fatalf("Redacted() leaked the password: %q", got)
	}
	if !strings.Contains(got, "detector.internal:8443") {
		t.Errorf("Redacted() = %q, want the host preserved", got)
	}
}

func TestRedactedEmptyWithoutURL(t *testing.T) {
	cfg := &Config{}
	if got := cfg.Redacted(); got != "" {
		t.Errorf("Redacted() = %q, want empty", got)
	}
}

func TestLoadPolicyModeDefaultsToMonitoring(t *testing.T) {
	cfg, err := Load(env(valid()))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(cfg.PolicyMode) != DefaultPolicyMode {
		t.Errorf("PolicyMode = %q, want %q", cfg.PolicyMode, DefaultPolicyMode)
	}
}

func TestLoadPolicyModeAcceptsEnforcement(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		EnvDetectorURL: "http://d:1",
		EnvPolicyMode:  "ENFORCEMENT",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(cfg.PolicyMode) != "enforcement" {
		t.Errorf("PolicyMode = %q, want enforcement (case-insensitive)", cfg.PolicyMode)
	}
}

// Enforcement must be chosen deliberately. A typo must stop startup rather
// than silently leaving the gateway in the permissive mode.
func TestLoadRejectsUnknownPolicyMode(t *testing.T) {
	for _, mode := range []string{"enforce", "on", "strict", "allow_all", "block"} {
		_, err := Load(env(map[string]string{
			EnvDetectorURL: "http://d:1",
			EnvPolicyMode:  mode,
		}))
		if err == nil {
			t.Errorf("Load() accepted policy mode %q", mode)
			continue
		}
		if !strings.Contains(err.Error(), EnvPolicyMode) {
			t.Errorf("error does not name %s: %v", EnvPolicyMode, err)
		}
	}
}
