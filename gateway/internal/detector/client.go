// Package detector calls the private assessment service.
//
// Three properties of this client are load-bearing rather than incidental:
//
//   - One http.Client is reused for every call. A client constructed per
//     request gets its own connection pool, which is discarded immediately,
//     so every scan pays a fresh TCP and TLS handshake and sockets accumulate
//     in TIME_WAIT under load.
//   - Response bodies are read through a limit and always drained and closed.
//     An unbounded read lets a compromised or malfunctioning detector exhaust
//     the gateway's memory with a single reply.
//   - Anything unexpected is an error, never a verdict. A malformed body, an
//     unknown enum, an oversized reply and a timeout all surface as failures.
//     None of them may become an allow.
package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/contract"
)

// MaxResponseBytes bounds a detector reply. An assessment carries a label,
// a few categories and at most eight bounded quotations; a megabyte is
// already far more than a well-behaved detector can justify.
const MaxResponseBytes = 1 << 20 // 1 MiB

// Sentinel errors. Callers map these to HTTP status codes; none of them is
// ever convertible into a clean assessment.
var (
	// ErrUnavailable means the detector could not be reached or refused.
	ErrUnavailable = errors.New("detector unavailable")
	// ErrInvalidResponse means the reply could not be trusted: malformed
	// JSON, unknown fields, an unknown enum, or a mismatched request id.
	ErrInvalidResponse = errors.New("detector returned an invalid response")
	// ErrResponseTooLarge means the reply exceeded MaxResponseBytes.
	ErrResponseTooLarge = errors.New("detector response too large")
	// ErrDeadlineExceeded means the budget expired before an answer arrived.
	ErrDeadlineExceeded = errors.New("detector deadline exceeded")

	// ErrPassageTooLarge and ErrTokenBudgetExceeded mean the detector
	// refused the passage for its size.
	//
	// Separate from ErrUnavailable because they are the caller's problem and
	// not the service's, and the difference is the difference between "retry
	// in a moment" and "send less text". Until C32 every detector non-200
	// became ErrUnavailable, so a passage merely too long was reported as an
	// outage - a permanent condition dressed as a transient one, which a
	// well-behaved client will retry forever.
	ErrPassageTooLarge     = errors.New("detector refused the passage size")
	ErrTokenBudgetExceeded = errors.New("detector refused the passage token count")
)

// detectorErrorCode reads the stable code from an error envelope.
//
// Takes the bytes already read rather than the response body: by the time
// the status is examined the body has been consumed into `payload`, and a
// first draft of this read from the drained stream and silently saw nothing.
// The test for the 422 case is what caught it.
//
// An unreadable body yields "", which falls through to the conservative
// branch rather than to a specific one.
func detectorErrorCode(payload []byte) string {
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(payload, &envelope) != nil {
		return ""
	}
	return envelope.Error.Code
}

// AssessmentRequest is the private request body.
type AssessmentRequest struct {
	RequestID  string           `json:"request_id"`
	TaskID     contract.TaskID  `json:"task_id"`
	Content    contract.Content `json:"content"`
	DeadlineMS int              `json:"deadline_ms,omitempty"`
}

// AssessmentResponse is the private 200 body.
//
// Every field assessment-response.schema.json permits must appear here, even
// when the gateway does not forward it. The decoder uses
// DisallowUnknownFields, so a field the detector may legitimately send and
// this struct does not declare is a 503 - and that is exactly what happened:
// C18 added prompt_fingerprint and diagnostics to the detector, the schema
// permitted them, and this struct did not. Every gateway test used a fake
// detector that emitted neither, so the live path was the only place it
// showed, and nothing exercised the live path end to end until C28.
//
// The strictness is kept rather than relaxed. It caught a real drift between
// two services; the failure was that nothing checked this struct against the
// schema, which TestDecoderAcceptsEverySchemaField now does.
type AssessmentResponse struct {
	RequestID  string              `json:"request_id"`
	Assessment contract.Assessment `json:"assessment"`
	Coverage   contract.Coverage   `json:"coverage"`
	Versions   struct {
		Detector string `json:"detector"`
		Prompt   string `json:"prompt"`
		// Accepted, and not forwarded to the public response: adding it
		// there is a public contract change and belongs in its own commit.
		// Accepting it is required, because the detector sends it.
		PromptFingerprint string `json:"prompt_fingerprint,omitempty"`
	} `json:"versions"`

	// Non-authoritative provider metrics from C18. Accepted so the detector
	// can report them, read by nothing here - the gateway's own logging
	// records what it measured itself, which is the number it can stand
	// behind.
	Diagnostics *struct {
		Model        string `json:"model,omitempty"`
		LatencyMS    int    `json:"latency_ms,omitempty"`
		InputTokens  int    `json:"input_tokens,omitempty"`
		OutputTokens int    `json:"output_tokens,omitempty"`
		Attempts     int    `json:"attempts,omitempty"`
		MaxTokens    int    `json:"max_tokens,omitempty"`
	} `json:"diagnostics,omitempty"`
}

// Client calls the private assessment endpoint.
type Client struct {
	base *url.URL
	http *http.Client
}

// New builds a Client with a reused connection pool.
func New(base *url.URL, timeout time.Duration) *Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &Client{
		base: base,
		// No Timeout here: the per-request deadline comes from the caller's
		// context, so one budget covers the whole scan rather than this hop
		// restarting a fresh clock.
		http: &http.Client{Transport: transport},
	}
}

// Assess sends one passage and returns a validated assessment.
func (c *Client) Assess(ctx context.Context, req AssessmentRequest) (*AssessmentResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode assessment request: %w", err)
	}

	endpoint := c.base.JoinPath("internal", "v1", "assessments")
	httpReq, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build assessment request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %v", ErrDeadlineExceeded, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// Drain before closing so the connection returns to the pool instead of
	// being torn down, and bound the drain so a hostile body cannot stall us.
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponseBytes))
		_ = resp.Body.Close()
	}()

	// Read one byte past the limit so the overflow is detectable rather than
	// silently truncated into valid-looking JSON.
	limited := io.LimitReader(resp.Body, MaxResponseBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if len(payload) > MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}

	if resp.StatusCode != http.StatusOK {
		// Two statuses carry information the caller can act on; everything
		// else is an outage from the gateway's point of view. The error code
		// in the body is read rather than inferred from the status, because
		// 422 covers more than one condition in this contract.
		switch resp.StatusCode {
		case http.StatusRequestEntityTooLarge:
			return nil, fmt.Errorf("%w: detector returned 413", ErrPassageTooLarge)
		case http.StatusUnprocessableEntity:
			if detectorErrorCode(payload) == "token_budget_exceeded" {
				return nil, fmt.Errorf("%w: detector returned 422", ErrTokenBudgetExceeded)
			}
			// A 422 that is not about size means the gateway sent something
			// the detector could not parse, which is this service's bug and
			// not the caller's.
			return nil, fmt.Errorf("%w: detector returned 422", ErrInvalidResponse)
		}
		return nil, fmt.Errorf("%w: detector returned %d", ErrUnavailable, resp.StatusCode)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	// A field the gateway does not know about must not be ignored: it may be
	// a detector trying to smuggle a decision past the policy layer.
	decoder.DisallowUnknownFields()

	var parsed AssessmentResponse
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: trailing content after the JSON body", ErrInvalidResponse)
	}

	if parsed.RequestID != req.RequestID {
		// A mismatched id means the reply does not belong to this request.
		return nil, fmt.Errorf("%w: request id mismatch", ErrInvalidResponse)
	}
	if err := contract.ValidateAssessment(parsed.Assessment); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if parsed.Versions.Detector == "" || parsed.Versions.Prompt == "" {
		return nil, fmt.Errorf("%w: missing detector or prompt version", ErrInvalidResponse)
	}
	if parsed.Coverage.Truncated ||
		parsed.Coverage.ScannedUTF8Bytes != parsed.Coverage.OriginalUTF8Bytes {
		// A partial scan is not a complete one, whatever the detector says.
		return nil, fmt.Errorf("%w: incomplete coverage", ErrInvalidResponse)
	}

	return &parsed, nil
}
