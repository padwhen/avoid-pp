package detector

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestDecoderAcceptsEverySchemaField guards the drift that produced a 503 on
// every live scan.
//
// The gateway's decoder uses DisallowUnknownFields, which is the right choice
// - it caught a real disagreement between two services. What was missing was
// anything checking this struct against the schema that defines what the
// detector may send. C18 added two fields to the detector and to the schema;
// the Go struct did not get them; every gateway test used a fake detector
// that emitted neither; and the first live end-to-end run returned
// detector_invalid_response for every passage.
//
// This reads the normative schema and fails if it permits a property the
// struct would reject.
func TestDecoderAcceptsEverySchemaField(t *testing.T) {
	schemaPath := filepath.Join(
		"..", "..", "..", "contracts", "schemas", "assessment-response.schema.json",
	)
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	var schema struct {
		Properties map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	if len(schema.Properties) == 0 {
		t.Fatal("the schema declared no properties; the path or shape has changed")
	}

	// Build a response containing every property the schema permits, at every
	// level the struct models, and decode it strictly.
	body := map[string]any{
		"request_id": "req-parity",
		"assessment": map[string]any{
			"label":      "no_injection_detected",
			"categories": []string{},
			"evidence":   []any{},
		},
		"coverage": map[string]any{
			"original_utf8_bytes": 10,
			"scanned_utf8_bytes":  10,
			"truncated":           false,
		},
		"versions":    map[string]any{},
		"diagnostics": map[string]any{},
	}

	// Fill versions and diagnostics from the schema rather than from a list
	// here, so a property added to the schema is covered without editing this
	// test.
	for _, block := range []string{"versions", "diagnostics"} {
		spec, declared := schema.Properties[block]
		if !declared {
			continue
		}
		filled := map[string]any{}
		for name := range spec.Properties {
			filled[name] = sampleFor(name)
		}
		body[block] = filled
		if len(filled) == 0 {
			t.Errorf("the schema declares %s with no properties", block)
		}
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var parsed AssessmentResponse
	if err := decoder.Decode(&parsed); err != nil {
		t.Fatalf(
			"the decoder rejects a response the schema permits: %v\n"+
				"AssessmentResponse is missing a field the detector may send, "+
				"which makes every such scan a 503.\nbody: %s",
			err, encoded,
		)
	}

	// Deliberately no assertions on specific field names. Referencing
	// parsed.Versions.PromptFingerprint here made removing the field a
	// compile error rather than a test failure - which CI still catches, but
	// with a message about an unknown selector instead of one explaining
	// that the decoder rejects a response the schema permits. The
	// schema-driven decode above is the whole test.
}

// sampleFor produces a value of the right JSON kind for a schema property,
// chosen by name because the schema's own type information is nested deeper
// than this test needs to read.
func sampleFor(name string) any {
	switch name {
	case "prompt_fingerprint":
		// 64 hex characters, matching the schema's pattern.
		return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	case "latency_ms", "input_tokens", "output_tokens", "attempts", "max_tokens":
		return 1
	default:
		return "sample"
	}
}
