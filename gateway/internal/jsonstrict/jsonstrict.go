// Package jsonstrict rejects JSON that is syntactically valid but ambiguous.
//
// The motivating case is a duplicate object key. encoding/json accepts one
// silently and keeps the last occurrence, so this body:
//
//	{"task_id":"translate_fi_en_v1","content":{"text":"harmless"},
//	 "task_id":"evil","content":{"text":"ATTACK"}}
//
// decodes with task_id "evil" and text "ATTACK" — and DisallowUnknownFields
// does not object, because every key is a known one. Anything in the path that
// read the first occurrence instead, as many parsers and most log pipelines do,
// recorded "harmless". That disagreement is the whole attack: the text that
// gets scanned and the text that gets audited are different strings, and
// nothing reports a problem.
//
// There is no correct interpretation to pick here. RFC 8259 says names
// "SHOULD be unique" and leaves the behaviour undefined when they are not, so
// any choice this code made would differ from some other parser in the chain.
// The only safe answer is to refuse the request.
//
// Duplicates are rejected at every depth, not only for fields that look
// security-relevant. Deciding which keys matter is a judgment that has to be
// revisited every time the schema grows, and the cost of getting it wrong is
// silent — which is exactly the failure mode being closed here.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// MaxDepth bounds how deeply objects and arrays may nest.
//
// The contract's deepest legal request is three levels. 32 leaves room for the
// schema to grow without ever approaching a limit that exists to stop a small
// body from costing a large amount of stack: a few hundred bytes of "[[[[" is
// otherwise enough to recurse as far as the parser will go.
const MaxDepth = 32

var (
	// ErrDuplicateKey reports a repeated name within one object.
	ErrDuplicateKey = errors.New("duplicate object key")
	// ErrTooDeep reports nesting past MaxDepth.
	ErrTooDeep = errors.New("json nesting too deep")
	// ErrTrailingContent reports anything after the first top-level value.
	ErrTrailingContent = errors.New("trailing content after the json value")
	// ErrInvalidUTF8 reports a string that is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("json contains invalid utf-8")
)

// Check reports whether data is a single unambiguous JSON value.
//
// It validates structure only. Whether the value matches the contract is a
// separate question, answered by decoding it.
func Check(data []byte) error {
	// encoding/json substitutes U+FFFD for malformed UTF-8 when it unmarshals
	// a string, silently repairing input rather than refusing it. So the check
	// is on the raw bytes, before decoding can alter them: a check afterwards
	// would always pass, because it would be examining repaired text rather
	// than what arrived. Either the caller's bytes are what gets scanned, or
	// the request fails.
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	// Numbers are not converted to float64, so a large integer literal is not
	// quietly rounded on the way through this check.
	decoder.UseNumber()

	if err := checkValue(decoder, 0); err != nil {
		return err
	}

	// Exactly one value. A second one means the sender and this parser
	// disagree about where the request ended.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("%w: %v", ErrTrailingContent, err)
		}
		return ErrTrailingContent
	}
	return nil
}

// checkValue consumes exactly one value from the token stream.
func checkValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delim, isDelim := token.(json.Delim)
	if !isDelim {
		// A scalar: string, number, bool or null. Nothing to check.
		return nil
	}

	if depth >= MaxDepth {
		return fmt.Errorf("%w: more than %d levels", ErrTooDeep, MaxDepth)
	}

	switch delim {
	case '{':
		return checkObject(decoder, depth+1)
	case '[':
		return checkArray(decoder, depth+1)
	default:
		// A closing delimiter where a value was expected. The decoder would
		// not normally produce this, so it is a bug rather than bad input.
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
}

func checkObject(decoder *json.Decoder, depth int) error {
	// Keys are collected per object, so the same name at two different depths
	// is fine; the same name twice in one object is not.
	seen := map[string]bool{}

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("object key is %T, not a string", token)
		}
		if seen[key] {
			// The key name is echoed because it is a field name from the
			// published contract, not caller data. Values never are.
			return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
		}
		seen[key] = true

		if err := checkValue(decoder, depth); err != nil {
			return err
		}
	}

	// Consume the closing brace.
	_, err := decoder.Token()
	return err
}

func checkArray(decoder *json.Decoder, depth int) error {
	for decoder.More() {
		if err := checkValue(decoder, depth); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

// ErrReplacementIntroduced reports that decoding substituted U+FFFD for input
// the caller actually sent.
var ErrReplacementIntroduced = errors.New("decoding substituted a replacement character")

// CheckNoSubstitution reports whether decoding altered the caller's text.
//
// Validating the raw bytes with utf8.Valid is necessary but not sufficient,
// because there are two distinct ways to arrive at a silently repaired string
// and that check only catches one:
//
//   - Raw malformed UTF-8 inside a JSON string. encoding/json substitutes
//     U+FFFD and returns no error. Checking the decoded string afterwards is
//     useless: U+FFFD is itself valid UTF-8, so utf8.ValidString reports true
//     on the repaired text and the check passes every time.
//   - A lone surrogate escape such as "\ud800". Every byte of that is ASCII,
//     so the body is perfectly valid UTF-8 and a raw check sees nothing wrong.
//     The decoder still produces U+FFFD, because an unpaired surrogate has no
//     UTF-8 encoding.
//
// So the invariant checked here is not "is the text valid" but "did the parser
// introduce a character the caller did not send". A caller may legitimately
// send U+FFFD, literally or escaped, and that is counted rather than assumed
// away — otherwise this would reject text that was always correct.
func CheckNoSubstitution(raw []byte, decoded string) error {
	const replacement = '�'

	produced := strings.Count(decoded, string(replacement))
	if produced == 0 {
		return nil
	}

	// What the caller could have sent deliberately: the literal three-byte
	// encoding, or a \uFFFD escape. JSON hex escapes are case-insensitive, so
	// the escape is counted against a lowercased copy rather than against the
	// sixteen spellings of those four digits. Lowercasing cannot disturb the
	// literal count: U+FFFD encodes as EF BF BD, which holds no ASCII letters.
	sent := bytes.Count(raw, []byte(string(replacement)))
	sent += bytes.Count(bytes.ToLower(raw), []byte(`\ufffd`))

	if produced > sent {
		return fmt.Errorf("%w: %d introduced", ErrReplacementIntroduced, produced-sent)
	}
	return nil
}
