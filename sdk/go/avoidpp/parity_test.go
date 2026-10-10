package avoidpp_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/padwhen/avoid-pp/sdk/go/avoidpp"
)

// The SDK's constants against the normative schema.
//
// These constants are a hand transcription of contracts/schemas/*.json, and a
// hand transcription drifts. C28 found exactly that: the gateway's Go struct
// had been missing two response fields since C18, and nothing failed because
// the only path exercising them was the live one.
//
// So the schema is read and compared rather than trusted to match, in both
// directions - a value added to the contract and not here, and a value here
// the contract never defined.

const schemaDir = "../../../contracts/schemas"

func commonDefs(t *testing.T) map[string]struct {
	Enum      []string `json:"enum"`
	MaxLength int      `json:"maxLength"`
} {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(schemaDir, "common.schema.json"))
	if err != nil {
		t.Fatalf("reading common.schema.json: %v", err)
	}
	var schema struct {
		Defs map[string]struct {
			Enum      []string `json:"enum"`
			MaxLength int      `json:"maxLength"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(content, &schema); err != nil {
		t.Fatalf("parsing common.schema.json: %v", err)
	}
	return schema.Defs
}

func assertSameSet(t *testing.T, name string, declared, implemented []string) {
	t.Helper()
	want := map[string]bool{}
	for _, value := range declared {
		want[value] = true
	}
	for _, value := range implemented {
		if !want[value] {
			t.Errorf("%s: this client defines %q and the schema does not", name, value)
		}
		delete(want, value)
	}
	for value := range want {
		t.Errorf("%s: the schema defines %q and this client does not", name, value)
	}
}

func TestEnumsMatchTheSchema(t *testing.T) {
	defs := commonDefs(t)

	actions := make([]string, 0, len(avoidpp.Actions()))
	for _, a := range avoidpp.Actions() {
		actions = append(actions, string(a))
	}
	assertSameSet(t, "action", defs["action"].Enum, actions)

	labels := make([]string, 0, len(avoidpp.Labels()))
	for _, l := range avoidpp.Labels() {
		if !l.Known() {
			t.Errorf("label %q is listed and not Known()", l)
		}
		labels = append(labels, string(l))
	}
	assertSameSet(t, "label", defs["label"].Enum, labels)

	categories := make([]string, 0, len(avoidpp.Categories()))
	for _, c := range avoidpp.Categories() {
		if !c.Known() {
			t.Errorf("category %q is listed and not Known()", c)
		}
		categories = append(categories, string(c))
	}
	assertSameSet(t, "category", defs["category"].Enum, categories)

	reasons := make([]string, 0, len(avoidpp.ReasonCodes()))
	for _, r := range avoidpp.ReasonCodes() {
		if !r.Known() {
			t.Errorf("reason code %q is listed and not Known()", r)
		}
		reasons = append(reasons, string(r))
	}
	assertSameSet(t, "reason_code", defs["reason_code"].Enum, reasons)

	tasks := make([]string, 0, len(avoidpp.TaskIDs()))
	for _, task := range avoidpp.TaskIDs() {
		tasks = append(tasks, string(task))
	}
	assertSameSet(t, "task_id", defs["task_id"].Enum, tasks)

	sources := make([]string, 0, len(avoidpp.SourceTypes()))
	for _, source := range avoidpp.SourceTypes() {
		sources = append(sources, string(source))
	}
	assertSameSet(t, "source_type", defs["source_type"].Enum, sources)
}

func TestErrorCodesCoverTheSchemaExactlyPlusUnknown(t *testing.T) {
	// Every contract code, and exactly one addition. CodeUnknown is this
	// client's own: a failure carrying a code from a later version is still a
	// failure, and must be a value to branch on rather than an empty string
	// that reads as no error. Pinning the set means a code quietly dropped
	// here - or an invented one added - fails.
	content, err := os.ReadFile(filepath.Join(schemaDir, "error.schema.json"))
	if err != nil {
		t.Fatalf("reading error.schema.json: %v", err)
	}
	var schema struct {
		Properties struct {
			Error struct {
				Properties struct {
					Code struct {
						Enum []string `json:"enum"`
					} `json:"code"`
				} `json:"properties"`
			} `json:"error"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(content, &schema); err != nil {
		t.Fatalf("parsing error.schema.json: %v", err)
	}

	declared := append([]string{}, schema.Properties.Error.Properties.Code.Enum...)
	declared = append(declared, string(avoidpp.CodeUnknown))

	implemented := make([]string, 0, len(avoidpp.ErrorCodes()))
	for _, code := range avoidpp.ErrorCodes() {
		implemented = append(implemented, string(code))
	}
	assertSameSet(t, "error code", declared, implemented)

	// Known() must say no to exactly one of them, and it must be the one this
	// client invented.
	for _, code := range avoidpp.ErrorCodes() {
		if code == avoidpp.CodeUnknown {
			if code.Known() {
				t.Error("CodeUnknown reports itself as a contract code")
			}
			continue
		}
		if !code.Known() {
			t.Errorf("error code %q is listed and not Known()", code)
		}
	}
}

func TestBoundsMatchTheSchema(t *testing.T) {
	defs := commonDefs(t)
	if got, want := avoidpp.MaxContentIDChars, defs["content_id"].MaxLength; got != want {
		t.Errorf("MaxContentIDChars = %d, want %d", got, want)
	}
	if got, want := avoidpp.MaxRequestIDChars, defs["request_id"].MaxLength; got != want {
		t.Errorf("MaxRequestIDChars = %d, want %d", got, want)
	}

	content, err := os.ReadFile(filepath.Join(schemaDir, "scan-request.schema.json"))
	if err != nil {
		t.Fatalf("reading scan-request.schema.json: %v", err)
	}
	var request struct {
		Properties struct {
			Content struct {
				Properties struct {
					Text struct {
						MaxLength int `json:"maxLength"`
					} `json:"text"`
				} `json:"properties"`
			} `json:"content"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(content, &request); err != nil {
		t.Fatalf("parsing scan-request.schema.json: %v", err)
	}
	if got, want := avoidpp.MaxTextChars, request.Properties.Content.Properties.Text.MaxLength; got != want {
		t.Errorf("MaxTextChars = %d, want %d", got, want)
	}
}

func TestTheContractVersionMatchesTheGateway(t *testing.T) {
	// One string, two places, and a report quotes it. A client claiming a
	// different version would make versions.contract in a scan response
	// unattributable.
	content, err := os.ReadFile(
		filepath.Join("..", "..", "..", "gateway", "internal", "contract", "contract.go"))
	if err != nil {
		t.Fatalf("reading the gateway's contract package: %v", err)
	}
	want := `const Version = "` + avoidpp.Version + `"`
	if !strings.Contains(string(content), want) {
		t.Errorf("the gateway does not declare %s", want)
	}
}
