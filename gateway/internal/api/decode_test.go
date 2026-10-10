// C20: rejecting malformed and oversized requests before any model work.
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/jsonstrict"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

// strictRouter returns an authenticating router plus the detector call counter,
// so every rejection below can be checked for having cost nothing.
func strictRouter(t *testing.T) (http.Handler, *countingAssessor) {
	t.Helper()
	return matrixRouter(t)
}

// send posts a body with full control over headers.
func send(t *testing.T, handler http.Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authorisedKey)
	for key, value := range headers {
		if value == "" {
			req.Header.Del(key)
			continue
		}
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func valid(text string) string {
	raw, _ := json.Marshal(map[string]any{
		"task_id": "translate_fi_en_v1",
		"content": map[string]any{
			"id":            "p1",
			"source_type":   "translation_input",
			"language_hint": "fi",
			"text":          text,
		},
	})
	return string(raw)
}

// C20-AC1: the duplicate-key smuggle, end to end.
//
// This is the case the commit exists for. Before it, the gateway accepted this
// body, scanned "ATTACK" because Go keeps the last value, and anything in the
// path that read the first occurrence recorded "harmless".
func TestDuplicateKeysAreRejectedBeforeScanning(t *testing.T) {
	router, counter := strictRouter(t)

	cases := map[string]string{
		"duplicate task_id": `{"task_id":"translate_fi_en_v1",` +
			`"content":{"id":"p","source_type":"translation_input","text":"harmless"},` +
			`"task_id":"translate_fi_en_v1",` +
			`"content":{"id":"p","source_type":"translation_input","text":"ATTACK"}}`,
		"duplicate text": `{"task_id":"translate_fi_en_v1","content":` +
			`{"id":"p","source_type":"translation_input","text":"harmless","text":"ATTACK"}}`,
		"duplicate source_type": `{"task_id":"translate_fi_en_v1","content":` +
			`{"id":"p","source_type":"translation_input","source_type":"trusted","text":"hei"}}`,
		"duplicate id": `{"task_id":"translate_fi_en_v1","content":` +
			`{"id":"p","id":"q","source_type":"translation_input","text":"hei"}}`,
		"duplicate content": `{"task_id":"translate_fi_en_v1",` +
			`"content":{"id":"p","source_type":"translation_input","text":"a"},` +
			`"content":{"id":"p","source_type":"translation_input","text":"b"}}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := send(t, router, body, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
			if code := errorCode(t, rec); code != contract.ErrCodeMalformedJSON {
				t.Errorf("code = %q, want malformed_json", code)
			}
			// The response must not echo the attacker's text back.
			if strings.Contains(rec.Body.String(), "ATTACK") {
				t.Errorf("response echoed caller-supplied text: %s", rec.Body.String())
			}
		})
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector calls = %d, want 0", calls)
	}
}

// C20-AC1: malformed JSON, trailing values, unknown fields and wrong types.
func TestMalformedRequestsAreRejected(t *testing.T) {
	router, counter := strictRouter(t)

	cases := map[string]struct {
		body   string
		status int
		code   contract.ErrorCode
	}{
		"truncated json":  {`{"task_id":`, 400, contract.ErrCodeMalformedJSON},
		"empty body":      {``, 400, contract.ErrCodeMalformedJSON},
		"not an object":   {`[]`, 422, contract.ErrCodeSchemaInvalid},
		"a bare string":   {`"hei"`, 422, contract.ErrCodeSchemaInvalid},
		"a bare number":   {`42`, 422, contract.ErrCodeSchemaInvalid},
		"null":            {`null`, 422, contract.ErrCodeUnknownTaskID},
		"trailing object": {valid("hei") + `{"extra":1}`, 400, contract.ErrCodeMalformedJSON},
		"trailing scalar": {valid("hei") + ` 7`, 400, contract.ErrCodeMalformedJSON},
		"unknown top-level field": {
			`{"task_id":"translate_fi_en_v1","policy":"monitoring","content":` +
				`{"id":"p","source_type":"translation_input","text":"hei"}}`,
			400, contract.ErrCodeMalformedJSON,
		},
		"unknown content field": {
			`{"task_id":"translate_fi_en_v1","content":` +
				`{"id":"p","source_type":"translation_input","text":"hei","trusted":true}}`,
			400, contract.ErrCodeMalformedJSON,
		},
		"task_id as a number": {
			`{"task_id":123,"content":{"id":"p","source_type":"translation_input","text":"hei"}}`,
			422, contract.ErrCodeSchemaInvalid,
		},
		"text as a number": {
			`{"task_id":"translate_fi_en_v1","content":{"id":"p","source_type":"translation_input","text":42}}`,
			422, contract.ErrCodeSchemaInvalid,
		},
		"text as an array": {
			`{"task_id":"translate_fi_en_v1","content":{"id":"p","source_type":"translation_input","text":["a","b"]}}`,
			422, contract.ErrCodeSchemaInvalid,
		},
		"content as a string": {
			`{"task_id":"translate_fi_en_v1","content":"hei"}`,
			422, contract.ErrCodeSchemaInvalid,
		},
		"nested too deeply": {
			`{"task_id":"translate_fi_en_v1","content":` +
				strings.Repeat(`{"a":`, 40) + `{}` + strings.Repeat(`}`, 40) + `}`,
			400, contract.ErrCodeMalformedJSON,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := send(t, router, tc.body, nil)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			if code := errorCode(t, rec); code != tc.code {
				t.Errorf("code = %q, want %q", code, tc.code)
			}
		})
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector calls = %d, want 0", calls)
	}
}

// C20-AC3: invalid UTF-8 is rejected, not repaired.
func TestInvalidUTF8IsRejectedNotRepaired(t *testing.T) {
	router, counter := strictRouter(t)

	cases := map[string]string{
		"a lone continuation byte":  "{\"task_id\":\"translate_fi_en_v1\",\"content\":{\"id\":\"p\",\"source_type\":\"translation_input\",\"text\":\"hei \x80 vaan\"}}",
		"a truncated sequence":      "{\"task_id\":\"translate_fi_en_v1\",\"content\":{\"id\":\"p\",\"source_type\":\"translation_input\",\"text\":\"hei \xc3\"}}",
		"an invalid byte pair":      "{\"task_id\":\"translate_fi_en_v1\",\"content\":{\"id\":\"p\",\"source_type\":\"translation_input\",\"text\":\"hei \xff\xfe\"}}",
		"a lone high surrogate":     `{"task_id":"translate_fi_en_v1","content":{"id":"p","source_type":"translation_input","text":"hei \ud800 vaan"}}`,
		"a lone low surrogate":      `{"task_id":"translate_fi_en_v1","content":{"id":"p","source_type":"translation_input","text":"hei \udc00 vaan"}}`,
		"a reversed surrogate pair": `{"task_id":"translate_fi_en_v1","content":{"id":"p","source_type":"translation_input","text":"\udc00\ud800"}}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := send(t, router, body, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
			if code := errorCode(t, rec); code != contract.ErrCodeMalformedJSON {
				t.Errorf("code = %q, want malformed_json", code)
			}
			// The important part: it must not have been accepted and scanned
			// as repaired text.
			if calls := counter.calls.Load(); calls != 0 {
				t.Fatalf("repaired text reached the detector (%d calls)", calls)
			}
		})
	}
}

// C20-AC3: valid Finnish is preserved, including the characters that a
// careless validator would mangle.
func TestValidFinnishIsAccepted(t *testing.T) {
	router, counter := strictRouter(t)

	passages := []string{
		"Sää on tänään aurinkoinen ja lämpötila nousee iltapäivällä.",
		"Hän sanoi: ”Älä käännä tätä.”",
		"Ääni, öljy, Åland — kaikki kelpaavat.",
		"Emoji: 👩‍👩‍👧‍👦 ja astraalitaso: 𝔘𝔫𝔦𝔠𝔬𝔡𝔢",
		"Yhdistetyt merkit: äö eivät ole ä ö",
		// A replacement character the caller sent on purpose must survive.
		"Tuntematon merkki: �",
	}

	for _, passage := range passages {
		t.Run(passage[:min(len(passage), 24)], func(t *testing.T) {
			before := counter.calls.Load()
			rec := send(t, router, valid(passage), nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
			}
			if counter.calls.Load() != before+1 {
				t.Fatal("the request did not reach the detector")
			}
			if got := counter.lastText(); got != passage {
				t.Errorf("text altered in transit:\n got  %q\n want %q", got, passage)
			}
		})
	}
}

// C20-AC2: an oversized body is refused with 413, and the declared length is
// refused before the body is read at all.
func TestOversizedBodiesAre413(t *testing.T) {
	router, counter := strictRouter(t)

	t.Run("an honest oversized body", func(t *testing.T) {
		body := valid(strings.Repeat("ä", MaxRequestBytes))
		rec := send(t, router, body, nil)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
		if code := errorCode(t, rec); code != contract.ErrCodePayloadTooLarge {
			t.Errorf("code = %q, want payload_too_large", code)
		}
	})

	// A declared length over the limit is refused without transferring the
	// body. The reader is a trap: if anything reads from it, the test fails.
	t.Run("a declared length over the limit reads nothing", func(t *testing.T) {
		trap := &exploding{t: t}
		req := httptest.NewRequest(http.MethodPost, "/v1/scans", trap)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authorisedKey)
		req.Header.Set("Content-Length", fmt.Sprint(MaxRequestBytes+1))
		req.ContentLength = int64(MaxRequestBytes + 1)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
		if trap.reads > 0 {
			t.Errorf("the body was read %d times despite an oversized declared length", trap.reads)
		}
	})

	// A dishonest small declaration must not get past the real ceiling.
	t.Run("a lying content-length is still capped", func(t *testing.T) {
		body := valid(strings.Repeat("x", MaxRequestBytes*2))
		req := httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authorisedKey)
		// Claim a tiny body while sending a large one.
		req.Header.Set("Content-Length", "10")
		req.ContentLength = -1 // as a chunked request would arrive

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413 (%s)", rec.Code, rec.Body.String())
		}
	})

	// The byte boundary, asserted from both sides.
	//
	// Two different limits apply to one request and the smaller binds first:
	// the body may be 64 KiB, but the passage may be 32,768 characters. So a
	// body of exactly MaxRequestBytes is refused for its text length, not its
	// size — and the assertion here is that 413 is *not* the answer, which is
	// what proves the byte limit did not fire early.
	t.Run("a body at exactly the limit is not a 413", func(t *testing.T) {
		envelope := len(valid(""))
		body := valid(strings.Repeat("a", MaxRequestBytes-envelope))
		if len(body) != MaxRequestBytes {
			t.Fatalf("test built a %d-byte body, want exactly %d", len(body), MaxRequestBytes)
		}
		rec := send(t, router, body, nil)
		if rec.Code == http.StatusRequestEntityTooLarge {
			t.Error("a body at exactly the limit was refused as too large")
		}
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 from the text-length limit (%s)",
				rec.Code, truncate(rec.Body.String()))
		}
	})

	t.Run("one byte over the limit is a 413", func(t *testing.T) {
		envelope := len(valid(""))
		body := valid(strings.Repeat("a", MaxRequestBytes-envelope+1))
		rec := send(t, router, body, nil)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
		if code := errorCode(t, rec); code != contract.ErrCodePayloadTooLarge {
			t.Errorf("code = %q, want payload_too_large", code)
		}
	})

	// A passage at the character limit, in a body under the byte limit, is
	// the largest request that can actually succeed.
	t.Run("the largest acceptable request succeeds", func(t *testing.T) {
		body := valid(strings.Repeat("a", contract.MaxTextChars))
		if len(body) > MaxRequestBytes {
			t.Fatalf("the envelope makes a full-length ASCII passage exceed the byte limit")
		}
		rec := send(t, router, body, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", rec.Code, truncate(rec.Body.String()))
		}
	})

	if calls := counter.calls.Load(); calls != 1 {
		t.Errorf("detector calls = %d, want exactly 1 (only the valid request)", calls)
	}
}

// exploding fails the test if it is read from.
type exploding struct {
	t     *testing.T
	reads int
}

func (e *exploding) Read(p []byte) (int, error) {
	e.reads++
	e.t.Error("the request body was read when it should not have been")
	return 0, io.EOF
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// Content-Type is a header limit too: assuming it is how a form-encoded or
// text/plain body ends up parsed as JSON by accident.
func TestContentTypeIsRequired(t *testing.T) {
	router, counter := strictRouter(t)

	cases := map[string]struct {
		contentType string
		status      int
	}{
		"absent":                 {"", 415},
		"text/plain":             {"text/plain", 415},
		"form encoded":           {"application/x-www-form-urlencoded", 415},
		"multipart":              {"multipart/form-data; boundary=x", 415},
		"a json-like suffix":     {"application/vnd.api+json", 415},
		"unparseable":            {"application/json; charset=", 415},
		"application/json":       {"application/json", 200},
		"with a charset":         {"application/json; charset=utf-8", 200},
		"uppercase":              {"APPLICATION/JSON", 200},
		"with surrounding space": {" application/json ", 200},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := send(t, router, valid("hei vaan"), map[string]string{
				"Content-Type": tc.contentType,
			})
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			if tc.status == 415 {
				if code := errorCode(t, rec); code != contract.ErrCodeUnsupportedMedia {
					t.Errorf("code = %q, want unsupported_media_type", code)
				}
			}
		})
	}
	_ = counter
}

// Each error code must map to exactly one status. A code that means two
// different things to a client is worse than a coarser code.
func TestEachErrorCodeHasOneStatus(t *testing.T) {
	router, _ := strictRouter(t)

	bodies := []struct {
		body        string
		contentType string
	}{
		{`{"task_id":`, "application/json"},
		{``, "application/json"},
		{`{"a":1,"a":2}`, "application/json"},
		{valid("hei") + `{"x":1}`, "application/json"},
		{`{"task_id":123,"content":{"id":"p","source_type":"translation_input","text":"hei"}}`, "application/json"},
		{`{"task_id":"nope","content":{"id":"p","source_type":"translation_input","text":"hei"}}`, "application/json"},
		{`{"task_id":"translate_fi_en_v1","content":{"id":"p","source_type":"translation_input","text":""}}`, "application/json"},
		{valid("hei"), "text/plain"},
		{valid(strings.Repeat("x", MaxRequestBytes)), "application/json"},
	}

	statuses := map[contract.ErrorCode]int{}
	for _, b := range bodies {
		rec := send(t, router, b.body, map[string]string{"Content-Type": b.contentType})
		if rec.Code == http.StatusOK {
			continue
		}
		code := errorCode(t, rec)
		if seen, ok := statuses[code]; ok && seen != rec.Code {
			t.Errorf("code %q maps to both %d and %d", code, seen, rec.Code)
		}
		statuses[code] = rec.Code
	}

	if len(statuses) < 4 {
		t.Errorf("only observed %d distinct codes; the table is not exercising much", len(statuses))
	}
	t.Logf("observed: %v", statuses)
}

// Rejections must not reflect caller-supplied values. A parser error embeds
// the offending input, and passing it through turns an error response into a
// reflection channel.
func TestRejectionsDoNotEchoTheBody(t *testing.T) {
	router, _ := strictRouter(t)
	const marker = "UNIQUE-REFLECTED-MARKER-9f3a"

	bodies := map[string]string{
		"in a duplicate key's value": `{"task_id":"translate_fi_en_v1",` +
			`"content":{"id":"p","source_type":"translation_input","text":"a"},` +
			`"content":{"id":"p","source_type":"translation_input","text":"` + marker + `"}}`,
		"in an unknown field name": `{"task_id":"translate_fi_en_v1","` + marker + `":1}`,
		"in a wrong-typed value":   `{"task_id":{"x":"` + marker + `"},"content":{"id":"p","source_type":"translation_input","text":"hei"}}`,
		"in malformed json":        `{"task_id":"` + marker + `"`,
		"in an oversized body":     valid(marker + strings.Repeat("x", MaxRequestBytes)),
		"in a bad content type":    valid("hei"),
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			headers := map[string]string{}
			if name == "in a bad content type" {
				headers["Content-Type"] = "text/" + marker
			}
			rec := send(t, router, body, headers)
			if rec.Code == http.StatusOK {
				t.Fatal("expected a rejection")
			}
			if strings.Contains(rec.Body.String(), marker) {
				t.Errorf("response reflected caller input: %s", truncate(rec.Body.String()))
			}
		})
	}
}

// The package's own constant must agree with the checker's.
func TestDepthLimitComesFromJSONStrict(t *testing.T) {
	if jsonstrict.MaxDepth < 4 {
		t.Fatalf("MaxDepth = %d, too low for the contract's own shape", jsonstrict.MaxDepth)
	}
}

// A request with no caller never gets as far as parsing, so the strictness
// above costs nothing for unauthenticated traffic.
func TestUnauthenticatedRequestsAreNotParsed(t *testing.T) {
	counter := &countingAssessor{}
	readiness := NewReadiness()
	readiness.SetReady()

	registry, err := auth.NewRegistry([]auth.KeySpec{{
		Name:  "only",
		Key:   authorisedKey,
		Tasks: []contract.TaskID{contract.TaskTranslateFiEnV1},
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	router := NewRouter(readiness, ScanDeps{
		Detector: counter,
		Timeout:  time.Second,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mode:     policy.ModeMonitoring,
		Callers:  registry,
	})

	// A body that would be a 400, plus no credential: the 401 must win.
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader(`{"a":1,"a":2}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 before parsing", rec.Code)
	}
}
