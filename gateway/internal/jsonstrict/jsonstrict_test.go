// C20: rejecting JSON that is valid but ambiguous.
package jsonstrict

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// C20-AC1: the duplicate-key case this package exists for.
//
// Go keeps the last occurrence. A parser that keeps the first — and many do,
// including most log and audit pipelines — sees a different request. The two
// readings disagree, and nothing reports a problem, so the text that gets
// scanned and the text that gets recorded are different strings.
func TestDuplicateKeysWouldOtherwiseChangeTheRequest(t *testing.T) {
	body := []byte(`{"task_id":"translate_fi_en_v1",` +
		`"content":{"id":"p","source_type":"translation_input","text":"harmless"},` +
		`"task_id":"evil",` +
		`"content":{"id":"p","source_type":"translation_input","text":"ATTACK"}}`)

	// First, demonstrate the hazard rather than asserting it from memory:
	// the standard decoder accepts this and silently takes the last value,
	// even with unknown fields disallowed.
	var decoded struct {
		TaskID  string `json:"task_id"`
		Content struct {
			ID         string `json:"id"`
			SourceType string `json:"source_type"`
			Text       string `json:"text"`
		} `json:"content"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("the standard decoder rejected this; the premise has changed: %v", err)
	}
	if decoded.TaskID != "evil" || decoded.Content.Text != "ATTACK" {
		t.Fatalf("expected last-wins, got task_id=%q text=%q",
			decoded.TaskID, decoded.Content.Text)
	}

	// Which is why Check refuses it.
	err := Check(body)
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("Check() error = %v, want ErrDuplicateKey", err)
	}
	if !strings.Contains(err.Error(), "task_id") {
		t.Errorf("error should name the duplicated key: %v", err)
	}
}

func TestDuplicateKeysAtEveryDepth(t *testing.T) {
	cases := map[string]string{
		"top level":           `{"a":1,"a":2}`,
		"nested object":       `{"content":{"text":"a","text":"b"}}`,
		"deeply nested":       `{"a":{"b":{"c":{"d":1,"d":2}}}}`,
		"inside an array":     `{"items":[{"x":1,"x":2}]}`,
		"second array member": `{"items":[{"x":1},{"y":1,"y":2}]}`,
		"differing values":    `{"text":"harmless","text":"ATTACK"}`,
		"same value twice":    `{"text":"same","text":"same"}`,
		"three times":         `{"a":1,"a":2,"a":3}`,
		"null then value":     `{"a":null,"a":1}`,
		"object then scalar":  `{"a":{"b":1},"a":5}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Check([]byte(body)); !errors.Is(err, ErrDuplicateKey) {
				t.Errorf("Check() error = %v, want ErrDuplicateKey", err)
			}
		})
	}
}

// The same name at different depths is not a duplicate: nothing is ambiguous
// about it, and rejecting it would refuse legitimate documents.
func TestRepeatedNamesAtDifferentDepthsAreFine(t *testing.T) {
	cases := map[string]string{
		"id at two levels":   `{"id":"outer","content":{"id":"inner"}}`,
		"text in siblings":   `{"a":{"text":"x"},"b":{"text":"y"}}`,
		"across array items": `{"items":[{"x":1},{"x":2},{"x":3}]}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Check([]byte(body)); err != nil {
				t.Errorf("Check() error = %v, want nil", err)
			}
		})
	}
}

func TestValidRequestsPass(t *testing.T) {
	cases := map[string]string{
		"a real scan request": `{"task_id":"translate_fi_en_v1","content":` +
			`{"id":"p1","source_type":"translation_input","language_hint":"fi",` +
			`"text":"Sää on tänään aurinkoinen."}}`,
		"empty object":         `{}`,
		"empty array":          `[]`,
		"a bare string":        `"hei"`,
		"a bare number":        `42`,
		"a bare null":          `null`,
		"escaped quotes":       `{"text":"hän sanoi \"ei\""}`,
		"escaped unicode":      `{"text":"\u00e4\u00f6"}`,
		"a surrogate pair":     `{"text":"\ud83d\ude00"}`,
		"newlines and tabs":    `{"text":"rivi1\nrivi2\ttabi"}`,
		"a large integer":      `{"n":123456789012345678901234567890}`,
		"nesting at the limit": objects(MaxDepth),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Check([]byte(body)); err != nil {
				t.Errorf("Check(%s) error = %v, want nil", name, err)
			}
		})
	}
}

// objects builds exactly n nested objects: objects(1) is `{}`, objects(2) is
// `{"a":{}}`, and so on. Counting the objects rather than the wrappers keeps
// the boundary tests honest — an off-by-one here would silently test the
// wrong side of the limit.
func objects(n int) string {
	if n < 1 {
		panic("objects(n): n must be at least 1")
	}
	return strings.Repeat(`{"a":`, n-1) + "{}" + strings.Repeat("}", n-1)
}

// A small body must not be able to cost a large amount of stack.
func TestExcessiveNestingIsRejected(t *testing.T) {
	// The boundary, asserted from both sides so the limit is exactly MaxDepth
	// rather than approximately it.
	if err := Check([]byte(objects(MaxDepth))); err != nil {
		t.Errorf("%d nested objects were rejected: %v", MaxDepth, err)
	}
	if err := Check([]byte(objects(MaxDepth + 1))); !errors.Is(err, ErrTooDeep) {
		t.Errorf("%d nested objects: error = %v, want ErrTooDeep", MaxDepth+1, err)
	}

	for _, depth := range []int{MaxDepth + 10, 10_000} {
		if err := Check([]byte(objects(depth))); !errors.Is(err, ErrTooDeep) {
			t.Errorf("depth %d: error = %v, want ErrTooDeep", depth, err)
		}
	}

	// Arrays nest just as deeply and cost the same.
	deep := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	if err := Check([]byte(deep)); !errors.Is(err, ErrTooDeep) {
		t.Errorf("deep array: error = %v, want ErrTooDeep", err)
	}

	// 5000 open brackets with no closes: unbalanced and too deep. It must
	// return rather than running out of stack, whichever error it picks.
	unbalanced := strings.Repeat("[", 5000)
	if err := Check([]byte(unbalanced)); err == nil {
		t.Error("unbalanced deep array was accepted")
	}
}

// C20-AC1: trailing values are rejected.
func TestTrailingContentIsRejected(t *testing.T) {
	cases := map[string]string{
		"a second object":             `{"a":1}{"b":2}`,
		"a second object spaced":      `{"a":1} {"b":2}`,
		"a trailing scalar":           `{"a":1} 7`,
		"a trailing string":           `{"a":1} "extra"`,
		"two arrays":                  `[1][2]`,
		"a stray brace":               `{"a":1}}`,
		"a trailing comma then value": `{"a":1},{"b":2}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Check([]byte(body)); err == nil {
				t.Errorf("Check(%s) error = nil, want an error", name)
			}
		})
	}

	// Trailing whitespace is not trailing content.
	if err := Check([]byte("{\"a\":1}\n\t ")); err != nil {
		t.Errorf("trailing whitespace was rejected: %v", err)
	}
}

func TestMalformedJSONIsRejected(t *testing.T) {
	for name, body := range map[string]string{
		"truncated":       `{"a":`,
		"unclosed object": `{"a":1`,
		"unclosed string": `{"a":"b`,
		"bare key":        `{a:1}`,
		"single quotes":   `{'a':1}`,
		"trailing comma":  `{"a":1,}`,
		"empty":           ``,
		"just a comma":    `,`,
		"non-string key":  `{1:2}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := Check([]byte(body)); err == nil {
				t.Errorf("Check(%s) error = nil, want an error", name)
			}
		})
	}
}

// C20-AC3: invalid UTF-8 is rejected rather than silently repaired.
func TestInvalidUTF8IsRejected(t *testing.T) {
	cases := map[string][]byte{
		"a lone continuation byte": []byte("{\"text\":\"hei \x80 vaan\"}"),
		"a truncated sequence":     []byte("{\"text\":\"hei \xc3\"}"),
		"an invalid byte":          []byte("{\"text\":\"hei \xff\xfe\"}"),
		"an overlong encoding":     []byte("{\"text\":\"\xc0\xaf\"}"),
		"invalid outside a string": []byte("{\xff\"text\":\"hei\"}"),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Check(body); !errors.Is(err, ErrInvalidUTF8) {
				t.Errorf("Check() error = %v, want ErrInvalidUTF8", err)
			}
		})
	}
}

// C20-AC3: valid Finnish survives. Checking must not be mistaken for
// normalising — the diacritics and the quotation marks matter.
func TestValidFinnishIsPreserved(t *testing.T) {
	passages := []string{
		"Sää on tänään aurinkoinen ja lämpötila nousee iltapäivällä.",
		"Hän sanoi: ”Älä käännä tätä.”",
		"Ääni, öljy, åland — kaikki kelpaavat.",
		"Yhdyssanat: lentokonesuihkuturbiinimoottoriapumekaanikkoaliupseerioppilas",
	}

	for _, passage := range passages {
		raw, err := json.Marshal(map[string]string{"text": passage})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := Check(raw); err != nil {
			t.Errorf("Check() rejected valid Finnish %q: %v", passage, err)
		}

		var back struct{ Text string }
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if back.Text != passage {
			t.Errorf("round trip altered the text:\n got  %q\n want %q", back.Text, passage)
		}
		if err := CheckNoSubstitution(raw, back.Text); err != nil {
			t.Errorf("CheckNoSubstitution() error = %v for valid Finnish", err)
		}
	}
}

// C20-AC3: the substitution that a raw UTF-8 check cannot catch.
func TestLoneSurrogateEscapesAreDetected(t *testing.T) {
	cases := map[string]string{
		"a high surrogate alone":      `{"text":"hei \ud800 vaan"}`,
		"a low surrogate alone":       `{"text":"hei \udc00 vaan"}`,
		"reversed pair order":         `{"text":"\udc00\ud800"}`,
		"a high surrogate at the end": `{"text":"hei \ud83d"}`,
		"uppercase hex":               `{"text":"hei \uD800"}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(body)

			// Every byte is ASCII, so the body really is valid UTF-8 and the
			// raw check sees nothing wrong. That is the point.
			if err := Check(raw); err != nil {
				t.Fatalf("Check() rejected an all-ASCII body: %v", err)
			}

			var decoded struct{ Text string }
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if err := CheckNoSubstitution(raw, decoded.Text); !errors.Is(err, ErrReplacementIntroduced) {
				t.Errorf("CheckNoSubstitution() error = %v, want ErrReplacementIntroduced (decoded %q)",
					err, decoded.Text)
			}
		})
	}
}

// A caller may legitimately send U+FFFD. Rejecting that would refuse text
// that was correct all along, so sent replacement characters are counted
// rather than assumed to be the parser's doing.
func TestDeliberateReplacementCharactersAreAllowed(t *testing.T) {
	cases := map[string]string{
		"literal":                 "{\"text\":\"hei \uFFFD vaan\"}",
		"escaped lowercase":       `{"text":"hei \ufffd vaan"}`,
		"escaped uppercase":       `{"text":"hei \uFFFD vaan"}`,
		"escaped mixed case":      `{"text":"hei \uFffD vaan"}`,
		"two of them":             "{\"text\":\"\uFFFD and \uFFFD\"}",
		"one literal one escaped": "{\"text\":\"\uFFFD and \\ufffd\"}",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(body)
			var decoded struct{ Text string }
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if err := CheckNoSubstitution(raw, decoded.Text); err != nil {
				t.Errorf("CheckNoSubstitution() rejected a deliberate U+FFFD: %v", err)
			}
		})
	}
}

// A sent replacement character must not buy cover for a substituted one.
func TestOneSentReplacementDoesNotExcuseASubstitutedOne(t *testing.T) {
	raw := []byte(`{"text":"sent \ufffd and substituted \ud800"}`)

	var decoded struct{ Text string }
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Two in the decoded text, one accounted for by the escape.
	if err := CheckNoSubstitution(raw, decoded.Text); !errors.Is(err, ErrReplacementIntroduced) {
		t.Errorf("CheckNoSubstitution() error = %v, want ErrReplacementIntroduced", err)
	}
}
