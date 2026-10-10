package jsonstrict

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzCheck asserts the properties Check must hold for arbitrary input.
//
// The point is not to find a crash — though it would — but to pin the
// invariant that makes this package worth having: anything Check accepts must
// decode the same way under any reasonable parser. The seed corpus is the
// list from the acceptance criteria: duplicate fields, invalid UTF-8 and
// boundary-sized bodies.
func FuzzCheck(f *testing.F) {
	seeds := []string{
		// Well-formed.
		`{"task_id":"translate_fi_en_v1","content":{"id":"p","source_type":"translation_input","text":"Sää on tänään aurinkoinen."}}`,
		`{}`,
		`[]`,
		`null`,
		`"hei"`,
		`0`,

		// Duplicate fields.
		`{"a":1,"a":2}`,
		`{"task_id":"a","task_id":"b"}`,
		`{"content":{"text":"a","text":"b"}}`,
		`{"a":[{"x":1,"x":2}]}`,

		// Trailing content.
		`{"a":1}{"b":2}`,
		`[1][2]`,
		`{"a":1} 7`,

		// Malformed.
		`{"a":`,
		`{a:1}`,
		`{"a":1,}`,
		``,
		`,`,

		// Invalid UTF-8.
		"{\"text\":\"\x80\"}",
		"{\"text\":\"\xff\xfe\"}",
		"{\"text\":\"\xc3\"}",

		// Escapes that decode to a substitution.
		`{"text":"\ud800"}`,
		`{"text":"\udc00"}`,
		`{"text":"😀"}`,

		// Boundary-sized and boundary-nested.
		objects(MaxDepth),
		objects(MaxDepth + 1),
		strings.Repeat("[", 64) + strings.Repeat("]", 64),
		`{"text":"` + strings.Repeat("ä", 1000) + `"}`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		err := Check(data)
		if err != nil {
			// Rejection is always an acceptable answer. Check is a filter, and
			// being stricter than necessary is not a bug here.
			return
		}

		// Property 1: accepted input is valid UTF-8. Nothing downstream has to
		// wonder whether the bytes it was handed are well-formed text.
		if !utf8.Valid(data) {
			t.Fatalf("accepted invalid UTF-8: %q", data)
		}

		// Property 2: accepted input is valid JSON by the standard library's
		// reckoning. Check is only ever stricter, never differently permissive
		// — otherwise it would accept something the decoder then rejects, and
		// the caller would get a confusing error from the wrong layer.
		if !json.Valid(data) {
			t.Fatalf("accepted input the standard library calls invalid: %q", data)
		}

		// Property 3: no duplicate keys survive, so there is exactly one way
		// to read the document. This is the invariant the whole package is
		// for, re-derived independently of the implementation.
		if key, found := findDuplicateKey(data); found {
			t.Fatalf("accepted a duplicate key %q: %q", key, data)
		}

		// Property 4: Check is deterministic. A filter whose answer depends on
		// anything but its input cannot be reasoned about.
		if second := Check(data); second != nil {
			t.Fatalf("Check() accepted then rejected the same input: %v", second)
		}
	})
}

// findDuplicateKey re-derives the duplicate-key question from the raw bytes,
// deliberately without calling into this package. A property test that uses
// the implementation to check the implementation proves only that it is
// self-consistent.
//
// Distinguishing a key from a string value needs a little state: inside an
// object, tokens alternate key, value, key, value. Without tracking which is
// expected, the string value in {"a":"b"} reads as a second key.
func findDuplicateKey(data []byte) (string, bool) {
	type frame struct {
		isObject  bool
		expectKey bool
		keys      map[string]bool
	}

	decoder := json.NewDecoder(strings.NewReader(string(data)))
	var stack []*frame

	// valueRead advances the innermost object past the value it just consumed.
	valueRead := func() {
		if n := len(stack); n > 0 && stack[n-1].isObject {
			stack[n-1].expectKey = true
		}
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			// io.EOF or a parse error: either way there is nothing more to
			// read, and malformed input is not this function's question.
			return "", false
		}

		if delim, isDelim := token.(json.Delim); isDelim {
			switch delim {
			case '{':
				stack = append(stack, &frame{
					isObject:  true,
					expectKey: true,
					keys:      map[string]bool{},
				})
			case '[':
				stack = append(stack, &frame{})
			case '}', ']':
				if len(stack) == 0 {
					return "", false
				}
				stack = stack[:len(stack)-1]
				// The container that just closed was itself a value.
				valueRead()
			}
			continue
		}

		// A scalar. In an object it is either the next key or the current
		// key's value.
		if n := len(stack); n > 0 && stack[n-1].isObject && stack[n-1].expectKey {
			key, ok := token.(string)
			if !ok {
				// A non-string key is malformed JSON, not a duplicate.
				return "", false
			}
			if stack[n-1].keys[key] {
				return key, true
			}
			stack[n-1].keys[key] = true
			stack[n-1].expectKey = false
			continue
		}
		valueRead()
	}
}
