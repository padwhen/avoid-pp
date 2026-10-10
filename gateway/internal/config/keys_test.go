package config

import (
	"strings"
	"testing"

	"github.com/padwhen/avoid-pp/gateway/internal/contract"
)

const goodKey = "a-generated-development-key-xxxxxxxxxxxx"

func TestParseAPIKeys(t *testing.T) {
	specs, err := parseAPIKeys(
		"lukea:translate_fi_en_v1:" + goodKey + ",evals:translate_fi_en_v1:" + goodKey + "-2")
	if err != nil {
		t.Fatalf("parseAPIKeys() error = %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2", len(specs))
	}
	if specs[0].Name != "lukea" || specs[0].Key != goodKey {
		t.Errorf("first spec = %+v", specs[0].Name)
	}
	if len(specs[0].Tasks) != 1 || specs[0].Tasks[0] != contract.TaskTranslateFiEnV1 {
		t.Errorf("tasks = %v", specs[0].Tasks)
	}
}

func TestParseAPIKeysAcceptsSeveralTasks(t *testing.T) {
	specs, err := parseAPIKeys("lukea:translate_fi_en_v1+translate_sv_en_v1:" + goodKey)
	if err != nil {
		t.Fatalf("parseAPIKeys() error = %v", err)
	}
	if len(specs[0].Tasks) != 2 {
		t.Fatalf("tasks = %v, want 2", specs[0].Tasks)
	}
}

func TestParseAPIKeysTrimsSurroundingSpace(t *testing.T) {
	// A multi-line value in a .env file or a Compose manifest arrives with
	// whitespace around entries, and that is a formatting accident rather
	// than an operator saying something different.
	specs, err := parseAPIKeys("  lukea : translate_fi_en_v1 : " + goodKey + " ")
	if err != nil {
		t.Fatalf("parseAPIKeys() error = %v", err)
	}
	if specs[0].Key != goodKey {
		t.Errorf("key = %q, want the trimmed value", specs[0].Key)
	}
}

func TestParseAPIKeysRejectsMalformedValues(t *testing.T) {
	cases := map[string]string{
		"empty":                  "",
		"only whitespace":        "   ",
		"no fields":              goodKey,
		"two fields":             "lukea:" + goodKey,
		"four fields":            "lukea:translate_fi_en_v1:" + goodKey + ":extra",
		"a colon inside the key": "lukea:translate_fi_en_v1:sk:" + goodKey,
		"an empty caller name":   ":translate_fi_en_v1:" + goodKey,
		"an empty key":           "lukea:translate_fi_en_v1:",
		"no tasks":               "lukea::" + goodKey,
		"a trailing comma":       "lukea:translate_fi_en_v1:" + goodKey + ",",
		"an empty middle entry":  "lukea:translate_fi_en_v1:" + goodKey + ",,evals:translate_fi_en_v1:" + goodKey,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseAPIKeys(raw); err == nil {
				t.Fatalf("parseAPIKeys(%q) error = nil, want error", name)
			}
		})
	}
}

// Every problem is reported at once: an operator fixing a packed variable
// should not have to restart the service to discover the next mistake.
func TestParseAPIKeysReportsEveryProblem(t *testing.T) {
	_, err := parseAPIKeys(":translate_fi_en_v1:" + goodKey + ",lukea::" + goodKey)
	if err == nil {
		t.Fatal("parseAPIKeys() error = nil, want error")
	}
	message := err.Error()
	if !strings.Contains(message, "entry 1") || !strings.Contains(message, "entry 2") {
		t.Errorf("error names only some entries: %q", message)
	}
}

// C19-AC3: these messages are logged at startup, so none may quote a key.
func TestParseAPIKeysErrorsNeverEchoTheKey(t *testing.T) {
	const secret = "sk-ant-SUPERSECRET-do-not-log-abcdefghij"

	for name, raw := range map[string]string{
		"a bare key":              secret,
		"a key with no tasks":     "lukea::" + secret,
		"a key with no name":      ":translate_fi_en_v1:" + secret,
		"a key containing colons": "lukea:translate_fi_en_v1:" + secret + ":more",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseAPIKeys(raw)
			if err == nil {
				t.Fatal("parseAPIKeys() error = nil, want error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error disclosed a key: %q", err)
			}
			if strings.Contains(err.Error(), secret[:12]) {
				t.Fatalf("error disclosed part of a key: %q", err)
			}
		})
	}
}

// The loaded Config must not carry the plaintext keys anywhere a dump or a
// log line could reach them.
func TestLoadedConfigHoldsNoPlaintextKey(t *testing.T) {
	const key = "a-configured-development-key-zzzzzzzzzzz"
	cfg, err := Load(env(map[string]string{
		EnvDetectorURL: "http://detector:9000",
		EnvAPIKeys:     "lukea:translate_fi_en_v1:" + key,
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// %+v on the Config renders the registry's exported surface. The entries
	// hold digests, and Caller holds a name and an unexported task set.
	rendered := strings.Join([]string{
		cfg.Addr, cfg.LogLevel, string(cfg.PolicyMode), cfg.Redacted(),
	}, " ")
	for _, caller := range cfg.Callers.Callers() {
		rendered += " " + caller.Name + " " + strings.Join(caller.Tasks(), "+")
	}
	if strings.Contains(rendered, key) {
		t.Fatalf("configuration rendering contains the key: %q", rendered)
	}

	if _, err := cfg.Callers.Authenticate(key); err != nil {
		t.Errorf("the configured key does not authenticate: %v", err)
	}
}
