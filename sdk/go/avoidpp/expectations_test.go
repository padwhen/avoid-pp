package avoidpp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/sdk/go/avoidpp"
)

// The Go half of the cross-language contract test.
//
// Every assertion comes from sdk/contract-expectations.json, which the Python
// suite reads too. Two test suites that merely agree are two opinions; one
// table and two implementations of it is a contract test, and a disagreement
// between the clients fails here rather than being discovered by whichever
// caller hits it first.

const (
	tablePath    = "../../contract-expectations.json"
	fixturesPath = "../../../contracts/fixtures"
)

type expectation struct {
	Outcome            string `json:"outcome"`
	Action             string `json:"action"`
	Label              string `json:"label"`
	ReasonCode         string `json:"reason_code"`
	UnrecognisedAction string `json:"unrecognised_action"`
	Code               string `json:"code"`
	Retries            *bool  `json:"retries"`
	RetryAfterSeconds  *int   `json:"retry_after_seconds"`
	Reason             string `json:"reason"`
	NoFieldNamed       string `json:"no_field_named"`
}

type tableCase struct {
	Name        string            `json:"name"`
	Fixture     string            `json:"fixture"`
	Status      int               `json:"status"`
	Body        json.RawMessage   `json:"body"`
	RawBody     *string           `json:"raw_body"`
	Headers     map[string]string `json:"headers"`
	RequestText *string           `json:"request_text"`
	Expect      expectation       `json:"expect"`
}

type table struct {
	Harness struct {
		DefaultRequestText string `json:"default_request_text"`
	} `json:"harness"`
	Cases []tableCase `json:"cases"`
}

// body returns what the stub server should send, and the passage to send it.
func (c tableCase) resolve(t *testing.T, defaultText string) (string, string) {
	t.Helper()

	var raw string
	switch {
	case c.Fixture != "":
		content, err := os.ReadFile(filepath.Join(fixturesPath, c.Fixture))
		if err != nil {
			t.Fatalf("reading fixture %s: %v", c.Fixture, err)
		}
		raw = string(content)
	case len(c.Body) > 0:
		raw = string(c.Body)
	case c.RawBody != nil:
		raw = *c.RawBody
	default:
		t.Fatalf("case %q has no body", c.Name)
	}

	if c.RequestText != nil {
		return raw, *c.RequestText
	}

	// A passage of exactly the byte count the response claims, so the
	// client's byte cross-check participates in the case rather than being
	// the thing that trips every fixture.
	var probe struct {
		Coverage *struct {
			OriginalUTF8Bytes int `json:"original_utf8_bytes"`
		} `json:"coverage"`
	}
	if json.Unmarshal([]byte(raw), &probe) == nil && probe.Coverage != nil {
		return raw, strings.Repeat("a", probe.Coverage.OriginalUTF8Bytes)
	}
	return raw, defaultText
}

func loadTable(t *testing.T) table {
	t.Helper()
	content, err := os.ReadFile(tablePath)
	if err != nil {
		t.Fatalf("reading the expectations table: %v", err)
	}
	var parsed table
	if err := json.Unmarshal(content, &parsed); err != nil {
		t.Fatalf("parsing the expectations table: %v", err)
	}
	if len(parsed.Cases) == 0 {
		t.Fatal("the expectations table has no cases")
	}
	return parsed
}

func TestContractExpectations(t *testing.T) {
	parsed := loadTable(t)

	for _, testCase := range parsed.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			body, passage := testCase.resolve(t, parsed.Harness.DefaultRequestText)

			server := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					for name, value := range testCase.Headers {
						w.Header().Set(name, value)
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(testCase.Status)
					_, _ = w.Write([]byte(body))
				}))
			defer server.Close()

			client, err := avoidpp.New(avoidpp.Options{
				BaseURL: server.URL,
				APIKey:  strings.Repeat("k", 32),
				Timeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			verdict, scanErr := client.Scan(context.Background(),
				avoidpp.Input{Text: passage, ContentID: "case-1"})

			switch testCase.Expect.Outcome {
			case "verdict":
				assertVerdict(t, verdict, scanErr, testCase.Expect, passage)
			case "error":
				assertServiceError(t, verdict, scanErr, testCase.Expect, testCase.Status)
			case "rejected":
				assertRejected(t, verdict, scanErr, testCase.Expect)
			default:
				t.Fatalf("unknown expected outcome %q", testCase.Expect.Outcome)
			}
		})
	}
}

func assertVerdict(
	t *testing.T, verdict avoidpp.Verdict, err error, expect expectation, passage string,
) {
	t.Helper()
	if err != nil {
		t.Fatalf("Scan returned %v, want a verdict", err)
	}
	if got, want := string(verdict.Action), expect.Action; got != want {
		t.Errorf("action = %q, want %q", got, want)
	}
	if got, want := string(verdict.Label), expect.Label; got != want {
		t.Errorf("label = %q, want %q", got, want)
	}
	if got, want := string(verdict.ReasonCode), expect.ReasonCode; got != want {
		t.Errorf("reason_code = %q, want %q", got, want)
	}
	if got, want := verdict.UnrecognisedAction, expect.UnrecognisedAction; got != want {
		t.Errorf("unrecognised action = %q, want %q", got, want)
	}
	// The verdict is about the passage that was sent, and says so.
	if !verdict.Covers(passage) {
		t.Error("the verdict does not cover the passage that was sent")
	}
	if verdict.Covers(passage + " ") {
		t.Error("the verdict covers a passage with a trailing space appended")
	}
	if expect.NoFieldNamed != "" {
		assertNoField(t, reflect.TypeOf(verdict), expect.NoFieldNamed)
	}
}

func assertServiceError(
	t *testing.T, verdict avoidpp.Verdict, err error, expect expectation, status int,
) {
	t.Helper()
	var service *avoidpp.ServiceError
	if !errors.As(err, &service) {
		t.Fatalf("Scan returned %v, want a *ServiceError", err)
	}
	if got, want := string(service.Code), expect.Code; got != want {
		t.Errorf("code = %q, want %q", got, want)
	}
	if service.Status != status {
		t.Errorf("status = %d, want %d", service.Status, status)
	}
	if expect.Retries != nil {
		if got := avoidpp.Retryable(err); got != *expect.Retries {
			t.Errorf("Retryable = %v, want %v", got, *expect.Retries)
		}
	}
	if expect.RetryAfterSeconds != nil {
		if !service.HasRetryAfter || service.RetryAfterSeconds != *expect.RetryAfterSeconds {
			t.Errorf("retry_after = %d (present %v), want %d",
				service.RetryAfterSeconds, service.HasRetryAfter, *expect.RetryAfterSeconds)
		}
	}
	if expect.NoFieldNamed != "" {
		assertNoField(t, reflect.TypeOf(*service), expect.NoFieldNamed)
	}
	// A failure yields the zero Verdict, and the zero Verdict permits nothing.
	assertPermitsNothing(t, verdict)
}

func assertRejected(
	t *testing.T, verdict avoidpp.Verdict, err error, expect expectation,
) {
	t.Helper()
	var rejected *avoidpp.ResponseError
	if !errors.As(err, &rejected) {
		t.Fatalf("Scan returned %v, want a *ResponseError", err)
	}
	if rejected.Reason != expect.Reason {
		t.Errorf("reason = %q, want %q", rejected.Reason, expect.Reason)
	}
	// Retrying would ask the same question and get the same answer.
	if avoidpp.Retryable(err) {
		t.Error("an unusable response was reported as retryable")
	}
	assertPermitsNothing(t, verdict)
}

func assertPermitsNothing(t *testing.T, verdict avoidpp.Verdict) {
	t.Helper()
	// Both policies, because a caller who ignores the error gets this value
	// and the strict reading must hold under the permissive policy too.
	if verdict.PermitsTranslation(false) || verdict.PermitsTranslation(true) {
		t.Error("the verdict returned alongside a failure permits translation")
	}
	if verdict.Covers("") {
		t.Error("the zero verdict claims to cover the empty string")
	}
}

func assertNoField(t *testing.T, typ reflect.Type, name string) {
	t.Helper()
	for i := range typ.NumField() {
		if strings.EqualFold(typ.Field(i).Name, name) {
			t.Errorf("%s has a field named %q and must not", typ.Name(), name)
		}
	}
}

func TestEveryContractFixtureHasAnExpectation(t *testing.T) {
	// Without this, adding a fixture to contracts/fixtures/ would leave both
	// clients untested against it, and the omission would look exactly like
	// coverage.
	listed := map[string]bool{}
	for _, testCase := range loadTable(t).Cases {
		if testCase.Fixture != "" {
			listed[testCase.Fixture] = true
		}
	}

	for _, kind := range []string{"valid", "invalid"} {
		entries, err := os.ReadDir(filepath.Join(fixturesPath, kind))
		if err != nil {
			t.Fatalf("reading fixtures: %v", err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			if !strings.HasPrefix(name, "scan-response.") && !strings.HasPrefix(name, "error.") {
				continue
			}
			key := kind + "/" + name
			if !listed[key] {
				t.Errorf("fixture %s has no client expectation", key)
			}
			delete(listed, key)
		}
	}
	for stale := range listed {
		t.Errorf("the table names %s, which is not on disk", stale)
	}
}
