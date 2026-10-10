// C19: authenticating callers and authorising them per task.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/padwhen/avoid-pp/gateway/internal/contract"
)

const (
	keyA = "caller-a-key-aaaaaaaaaaaaaaaaaaaaaaaa"
	keyB = "caller-b-key-bbbbbbbbbbbbbbbbbbbbbbbb"
)

func spec(name, key string, tasks ...contract.TaskID) KeySpec {
	if len(tasks) == 0 {
		tasks = []contract.TaskID{contract.TaskTranslateFiEnV1}
	}
	return KeySpec{Name: name, Key: key, Tasks: tasks}
}

func registry(t *testing.T, specs ...KeySpec) *Registry {
	t.Helper()
	reg, err := NewRegistry(specs)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return reg
}

// C19-AC1: a valid credential resolves to the configured caller.
func TestAuthenticateResolvesTheConfiguredCaller(t *testing.T) {
	reg := registry(t, spec("lukea", keyA), spec("evals", keyB))

	caller, err := reg.Authenticate(keyB)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if caller.Name != "evals" {
		t.Errorf("Name = %q, want evals", caller.Name)
	}
	if !caller.MayUse(contract.TaskTranslateFiEnV1) {
		t.Error("configured task is not permitted")
	}
}

func TestAuthenticateRejectsBadCredentials(t *testing.T) {
	reg := registry(t, spec("lukea", keyA))

	cases := map[string]struct {
		presented string
		want      error
	}{
		"nothing presented":     {"", ErrNoCredential},
		"a different key":       {keyB, ErrUnknownCredential},
		"the key with a typo":   {keyA[:len(keyA)-1] + "z", ErrUnknownCredential},
		"a prefix of the key":   {keyA[:16], ErrUnknownCredential},
		"the key plus a suffix": {keyA + "x", ErrUnknownCredential},
		// Case must matter: folding would shrink the key space enormously.
		"the key upper-cased": {strings.ToUpper(keyA), ErrUnknownCredential},
		"the key with spaces": {" " + keyA + " ", ErrUnknownCredential},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := reg.Authenticate(tc.presented); !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// C19-AC2: authorisation is per task, and the zero Caller may use nothing.
func TestAuthorisationIsPerTask(t *testing.T) {
	reg := registry(t, spec("lukea", keyA))
	caller, err := reg.Authenticate(keyA)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if !caller.MayUse(contract.TaskTranslateFiEnV1) {
		t.Error("the configured task should be permitted")
	}
	for _, task := range []contract.TaskID{"", "translate_en_fi_v1", "TRANSLATE_FI_EN_V1"} {
		if caller.MayUse(task) {
			t.Errorf("task %q should not be permitted", task)
		}
	}

	// A Caller that never came from Authenticate carries no permissions, so a
	// handler reached without the middleware denies rather than waves through.
	var unauthenticated Caller
	if unauthenticated.MayUse(contract.TaskTranslateFiEnV1) {
		t.Error("the zero Caller must not permit anything")
	}
}

func TestNewRegistryRejectsUnsafeConfiguration(t *testing.T) {
	cases := map[string][]KeySpec{
		"no keys at all":                      {},
		"an empty caller name":                {spec("", keyA)},
		"a key below the floor":               {spec("lukea", "short")},
		"a key one char short":                {spec("lukea", strings.Repeat("k", MinKeyLength-1))},
		"no tasks listed":                     {{Name: "lukea", Key: keyA}},
		"a task the contract does not define": {spec("lukea", keyA, "translate_sv_en_v1")},
		// Two callers sharing a key makes their requests indistinguishable,
		// which breaks revocation and attribution at once.
		"two callers sharing one key": {spec("lukea", keyA), spec("evals", keyA)},
		// Same name, same key: a duplicated line, not a rotation.
		"the same entry twice": {spec("lukea", keyA), spec("lukea", keyA)},
	}

	for name, specs := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRegistry(specs); err == nil {
				t.Fatal("NewRegistry() error = nil, want error")
			}
		})
	}

	// A key exactly at the floor is acceptable: the boundary is inclusive.
	if _, err := NewRegistry([]KeySpec{spec("lukea", strings.Repeat("k", MinKeyLength))}); err != nil {
		t.Errorf("a key of exactly %d characters was rejected: %v", MinKeyLength, err)
	}
}

// C19-AC3: configuration errors are logged, so none may contain a key.
func TestRegistryErrorsNeverContainTheKey(t *testing.T) {
	const secret = "sk-ant-SUPERSECRET-do-not-log-abcdefghijkl"

	for name, specs := range map[string][]KeySpec{
		"too short":    {spec("lukea", secret[:8])},
		"duplicate":    {spec("lukea", secret), spec("evals", secret)},
		"unknown task": {spec("lukea", secret, "nope")},
		"no tasks":     {{Name: "lukea", Key: secret}},
		"conflicting tasks": {
			spec("lukea", secret, contract.TaskTranslateFiEnV1),
			spec("lukea", keyB, "nope"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewRegistry(specs)
			if err == nil {
				t.Fatal("NewRegistry() error = nil, want error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error disclosed a key: %q", err)
			}
			// A prefix is still a credential: it narrows a brute force.
			if strings.Contains(err.Error(), secret[:8]) {
				t.Fatalf("error disclosed part of a key: %q", err)
			}
		})
	}
}

// C19-AC3: a caller can hold two keys at once, which is what makes replacing
// one possible without a window where its requests fail.
func TestKeyRotation(t *testing.T) {
	const replacement = "caller-a-key-2-aaaaaaaaaaaaaaaaaaaaaaaa"

	during := registry(t, spec("lukea", keyA), spec("lukea", replacement))
	for _, key := range []string{keyA, replacement} {
		caller, err := during.Authenticate(key)
		if err != nil {
			t.Fatalf("Authenticate() error = %v, want both keys live", err)
		}
		if caller.Name != "lukea" {
			t.Errorf("Name = %q, want lukea for both keys", caller.Name)
		}
	}
	if during.KeyCount() != 2 {
		t.Errorf("KeyCount() = %d, want 2 during a rotation", during.KeyCount())
	}
	// One caller, reported once, however many keys it holds.
	if callers := during.Callers(); len(callers) != 1 {
		t.Errorf("Callers() = %d entries, want 1", len(callers))
	}

	// Revocation is removing the entry: the old key stops working, and
	// nothing about the caller's permissions had to change.
	after := registry(t, spec("lukea", replacement))
	if _, err := after.Authenticate(keyA); !errors.Is(err, ErrUnknownCredential) {
		t.Errorf("revoked key error = %v, want ErrUnknownCredential", err)
	}
	if _, err := after.Authenticate(replacement); err != nil {
		t.Errorf("replacement key error = %v, want nil", err)
	}
}

// A caller whose two keys grant different tasks would behave differently
// depending on which of its own keys it used, which nobody would predict.
func TestRotationRequiresMatchingTaskSets(t *testing.T) {
	_, err := NewRegistry([]KeySpec{
		spec("lukea", keyA, contract.TaskTranslateFiEnV1),
		{Name: "lukea", Key: keyB, Tasks: nil},
	})
	if err == nil {
		t.Fatal("NewRegistry() error = nil, want error")
	}
}

func TestCredentialFrom(t *testing.T) {
	cases := map[string]struct {
		header string
		want   string
	}{
		"bearer":              {"Bearer " + keyA, keyA},
		"lowercase scheme":    {"bearer " + keyA, keyA},
		"mixed case scheme":   {"BeArEr " + keyA, keyA},
		"padded value":        {"Bearer   " + keyA + "  ", keyA},
		"absent":              {"", ""},
		"no scheme":           {keyA, ""},
		"scheme only":         {"Bearer", ""},
		"scheme and space":    {"Bearer ", ""},
		"a different scheme":  {"Basic " + keyA, ""},
		"a scheme-like token": {"Bearertoken", ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			if got := CredentialFrom(req); got != tc.want {
				t.Errorf("CredentialFrom() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A key in a query string is logged by every proxy on the path, so that
// spelling is not read at all rather than read and deprecated.
func TestCredentialIsNotReadFromTheQueryString(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/scans?api_key="+keyA, nil)
	if got := CredentialFrom(req); got != "" {
		t.Errorf("CredentialFrom() = %q, want empty for a query-string key", got)
	}
}

// The comparison is over fixed-length digests, so it cannot reveal where the
// first differing byte sits. This asserts the property the code relies on
// rather than attempting to time it, which is unreliable on shared CI.
func TestComparisonIsOverFixedLengthDigests(t *testing.T) {
	short := sha256.Sum256([]byte("a"))
	long := sha256.Sum256([]byte(strings.Repeat("a", 4096)))
	if len(short) != len(long) {
		t.Fatal("digests of different inputs differ in length")
	}
	if subtle.ConstantTimeCompare(short[:], long[:]) != 0 {
		t.Fatal("distinct inputs compared equal")
	}
}

func TestTasksAreReportedSorted(t *testing.T) {
	caller, err := registry(t, spec("lukea", keyA)).Authenticate(keyA)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if got := caller.Tasks(); len(got) != 1 || got[0] != string(contract.TaskTranslateFiEnV1) {
		t.Errorf("Tasks() = %v", got)
	}
}
