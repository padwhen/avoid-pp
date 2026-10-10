package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/jsonstrict"
)

// MaxRequestBytes bounds the public request body before any parsing.
//
// 64 KiB against a 32 KiB passage ceiling leaves room for the JSON envelope
// and for multi-byte Finnish, without letting a caller reserve a large buffer
// by claiming a large body.
const MaxRequestBytes = 64 << 10

// decodeFailure carries a rejection that is safe to send back.
//
// The message is written here rather than derived from the parser's error,
// because parser messages embed the offending input — an attacker-controlled
// string — and echoing it turns an error response into a reflection channel.
type decodeFailure struct {
	status  int
	code    contract.ErrorCode
	message string
	// reason is logged, never sent. It names the structural problem so a real
	// integration bug is diagnosable without disclosing the body.
	reason string
}

func (f decodeFailure) Error() string { return f.reason }

// decodeScanRequest reads, bounds and strictly parses the public request body.
//
// The order is deliberate, cheapest and most conclusive first:
//
//  1. Content-Type, which costs nothing to check.
//  2. The declared Content-Length, so an oversized body is refused before a
//     byte of it is read.
//  3. The actual body, read through a hard ceiling, because Content-Length is
//     a claim and a chunked request makes no claim at all.
//  4. Structural strictness: duplicate keys, nesting depth, trailing content,
//     raw UTF-8.
//  5. Contract shape: unknown fields and types.
//  6. Whether decoding altered the text.
func decodeScanRequest(w http.ResponseWriter, r *http.Request) (contract.ScanRequest, error) {
	var req contract.ScanRequest

	if err := checkContentType(r); err != nil {
		return req, err
	}

	// A declared length over the limit is refused outright. Reading it first
	// to "confirm" would mean transferring a body already known to be too
	// large, which is the cost the limit exists to avoid.
	if declared := r.Header.Get("Content-Length"); declared != "" {
		if n, err := strconv.ParseInt(declared, 10, 64); err == nil && n > MaxRequestBytes {
			return req, decodeFailure{
				status:  http.StatusRequestEntityTooLarge,
				code:    contract.ErrCodePayloadTooLarge,
				message: "Request body exceeds the configured limit.",
				reason:  fmt.Sprintf("declared content-length %d over limit %d", n, MaxRequestBytes),
			}
		}
	}

	// MaxBytesReader is the real enforcement: it caps what can be read whether
	// or not Content-Length was honest, and closes the connection rather than
	// letting a lying sender stream indefinitely.
	//
	// The body is read into memory, which is safe precisely because it is
	// bounded here. Duplicate-key detection needs the original bytes, and so
	// does the substitution check further down — neither can be done against
	// a stream that has already been consumed by the decoder.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return req, decodeFailure{
				status:  http.StatusRequestEntityTooLarge,
				code:    contract.ErrCodePayloadTooLarge,
				message: "Request body exceeds the configured limit.",
				reason:  fmt.Sprintf("body exceeded limit %d while reading", MaxRequestBytes),
			}
		}
		return req, decodeFailure{
			status:  http.StatusBadRequest,
			code:    contract.ErrCodeMalformedJSON,
			message: "Request body could not be read.",
			reason:  "read body: " + err.Error(),
		}
	}

	if len(body) == 0 {
		return req, decodeFailure{
			status:  http.StatusBadRequest,
			code:    contract.ErrCodeMalformedJSON,
			message: "Request body is empty.",
			reason:  "empty body",
		}
	}

	if err := jsonstrict.Check(body); err != nil {
		return req, structuralFailure(err)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	// A caller must not be able to smuggle a policy, mode, tenant or trust
	// field past validation by having it silently ignored.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, contractFailure(err)
	}

	// jsonstrict.Check already rejected trailing content, so this cannot fire
	// on input. It stays as a guard on the two staying in agreement.
	if decoder.More() {
		return req, decodeFailure{
			status:  http.StatusBadRequest,
			code:    contract.ErrCodeMalformedJSON,
			message: "Request body contains trailing content.",
			reason:  "trailing content after decode",
		}
	}

	// The text that gets scanned must be the text that was sent. A silently
	// substituted character would mean the caller is told a passage was
	// examined when a different passage was.
	if err := jsonstrict.CheckNoSubstitution(body, req.Content.Text); err != nil {
		return req, decodeFailure{
			status:  http.StatusBadRequest,
			code:    contract.ErrCodeMalformedJSON,
			message: "Request body contains text that cannot be decoded without alteration.",
			reason:  err.Error(),
		}
	}

	return req, nil
}

// checkContentType requires application/json.
//
// Parameters are allowed, so "application/json; charset=utf-8" is accepted;
// JSON is UTF-8 by definition and the charset is redundant rather than wrong.
// An absent header is refused rather than assumed, because assuming it is how
// a form-encoded or text/plain body ends up parsed as JSON by accident.
func checkContentType(r *http.Request) error {
	reject := func(reason string) error {
		return decodeFailure{
			status:  http.StatusUnsupportedMediaType,
			code:    contract.ErrCodeUnsupportedMedia,
			message: "Content-Type must be application/json.",
			reason:  reason,
		}
	}

	header := r.Header.Get("Content-Type")
	if header == "" {
		return reject("no content-type")
	}
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		// err quotes the header, which the caller controls, so it is not sent.
		return reject("unparseable content-type")
	}
	if !strings.EqualFold(mediaType, "application/json") {
		// The media type is echoed in the log only. It is caller-supplied, but
		// bounded and already parsed, and knowing what was sent is most of
		// diagnosing this particular mistake.
		return reject("content-type " + mediaType)
	}
	return nil
}

// structuralFailure maps a strictness violation to a response.
func structuralFailure(err error) error {
	switch {
	case errors.Is(err, jsonstrict.ErrDuplicateKey):
		return decodeFailure{
			status: http.StatusBadRequest,
			code:   contract.ErrCodeMalformedJSON,
			// The key name is a published contract field, not caller data, so
			// naming it is safe and saves the caller guessing. The error from
			// jsonstrict already contains it.
			message: "Request body contains a duplicate key. " +
				"Object names must be unique.",
			reason: err.Error(),
		}
	case errors.Is(err, jsonstrict.ErrTooDeep):
		return decodeFailure{
			status:  http.StatusBadRequest,
			code:    contract.ErrCodeMalformedJSON,
			message: "Request body is nested too deeply.",
			reason:  err.Error(),
		}
	case errors.Is(err, jsonstrict.ErrTrailingContent):
		return decodeFailure{
			status:  http.StatusBadRequest,
			code:    contract.ErrCodeMalformedJSON,
			message: "Request body contains trailing content.",
			reason:  "trailing content",
		}
	case errors.Is(err, jsonstrict.ErrInvalidUTF8):
		return decodeFailure{
			status:  http.StatusBadRequest,
			code:    contract.ErrCodeMalformedJSON,
			message: "Request body is not valid UTF-8.",
			reason:  "invalid utf-8 in body",
		}
	default:
		return decodeFailure{
			status:  http.StatusBadRequest,
			code:    contract.ErrCodeMalformedJSON,
			message: "Request body is not valid JSON for this schema.",
			reason:  "malformed json",
		}
	}
}

// contractFailure maps a decode error to a response.
//
// A wrong type is reported as a schema problem with the field named, because
// the field names are published contract and "task_id must be a string" is
// the difference between a five-minute fix and an afternoon. The offending
// value is never included.
func contractFailure(err error) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		// 422 rather than 400, so each error code maps to exactly one status.
		// A test asserts that, because a code meaning two different things to
		// a client is worse than a coarser code.
		failure := decodeFailure{
			status: http.StatusUnprocessableEntity,
			code:   contract.ErrCodeSchemaInvalid,
		}

		// typeErr.Type is a Go type such as contract.ScanRequest. Putting that
		// in a response tells the caller about this implementation rather than
		// about their request, and names an internal package for no benefit.
		// The JSON kind they sent is the useful half, and it is their own.
		if typeErr.Field == "" {
			failure.message = "Request body must be a JSON object."
			failure.reason = fmt.Sprintf("body is %s, want an object", typeErr.Value)
			return failure
		}
		failure.message = fmt.Sprintf(
			"Field %q has the wrong type: got %s.", typeErr.Field, typeErr.Value)
		failure.reason = fmt.Sprintf(
			"wrong type for %s: got %s, want %s", typeErr.Field, typeErr.Value, typeErr.Type)
		return failure
	}

	// Unknown fields arrive as a plain error whose text is the only signal.
	// The field name in it is one the caller sent, so the message is rewritten
	// rather than passed through.
	if strings.Contains(err.Error(), "unknown field") {
		return decodeFailure{
			status: http.StatusBadRequest,
			code:   contract.ErrCodeMalformedJSON,
			message: "Request body contains a field this API does not define. " +
				"There is no request field for policy, mode, caller or trust level.",
			reason: "unknown field",
		}
	}

	return decodeFailure{
		status:  http.StatusBadRequest,
		code:    contract.ErrCodeMalformedJSON,
		message: "Request body is not valid JSON for this schema.",
		reason:  "decode: " + err.Error(),
	}
}
