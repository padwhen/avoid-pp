package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/padwhen/avoid-pp/gateway/internal/admission"
	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/detector"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
	"github.com/padwhen/avoid-pp/gateway/internal/middleware"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

// Assessor is the detector dependency, narrowed to what the handler needs so
// tests can substitute a fake without an HTTP server.
type Assessor interface {
	Assess(ctx context.Context, req detector.AssessmentRequest) (*detector.AssessmentResponse, error)
}

// ScanDeps are the scan handler's collaborators.
type ScanDeps struct {
	Detector Assessor
	Timeout  time.Duration
	Log      *slog.Logger

	// Mode selects monitoring or enforcement. It comes from server
	// configuration and is never read from a request, so a caller cannot
	// choose the policy it is judged under. An empty value is rejected by
	// the evaluator rather than defaulting to the permissive branch.
	Mode policy.Mode

	// Callers authenticates requests. Like Mode it is configuration: a
	// request cannot name its own caller, tenant or permitted tasks.
	Callers *auth.Registry

	// Limiter bounds the arrival rate. Its buckets are allocated from
	// Callers, so it holds a fixed amount of state.
	Limiter *limits.Limiter

	// Admission bounds how much inference runs at once. A rate limit says
	// nothing about how many calls are still in flight, which is the number
	// that actually matters against a dependency measured in seconds.
	Admission *admission.Controller
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// overloadedRetryAfterSeconds is the hint on a shed request.
//
// Unlike a rate limit, there is no bucket to compute an exact wait from: how
// long until a slot frees depends on the provider, which is the thing that is
// slow. One second is short enough to recover quickly from a brief spike and
// long enough not to amplify a sustained one into a retry storm.
const overloadedRetryAfterSeconds = 1

// writeRetryableError writes an error envelope carrying retry guidance in
// both the header and the body, the same way a 429 does.
func writeRetryableError(
	w http.ResponseWriter, r *http.Request, status int,
	code contract.ErrorCode, message string, retryAfter int,
) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeJSON(w, status, contract.ErrorResponse{
		RequestID: middleware.RequestID(r.Context()),
		Error: contract.ErrorBody{
			Code:              code,
			Message:           message,
			RetryAfterSeconds: retryAfter,
		},
	})
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code contract.ErrorCode, message string) {
	writeJSON(w, status, contract.ErrorResponse{
		RequestID: middleware.RequestID(r.Context()),
		Error:     contract.ErrorBody{Code: code, Message: message},
	})
}

// Scan handles POST /v1/scans.
func Scan(deps ScanDeps) http.Handler {
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := middleware.RequestID(r.Context())
		started := time.Now()

		// One line per request, whatever the outcome. The fields are the ones
		// a routine failure is diagnosed from: which request, what happened,
		// how long it took, how big the passage was, and what produced the
		// answer. Sizes are counts; none of this is passage text.
		//
		// The handler's logger goes through the allowlisting handler, so a
		// field added here that is not on the list is dropped and named
		// rather than emitted.
		outcome := func(name string, attrs ...any) {
			log.Info("scan "+name, append([]any{
				"request_id", requestID,
				"outcome", name,
				"duration_ms", time.Since(started).Milliseconds(),
			}, attrs...)...)
		}

		req, err := decodeScanRequest(w, r)
		if err != nil {
			var failure decodeFailure
			if errors.As(err, &failure) {
				// The reason is logged; the message is what the caller sees.
				// They are different strings on purpose: parser errors embed
				// the offending input, and echoing that back would turn an
				// error response into a reflection channel.
				outcome("rejected",
					"status", failure.status,
					"code", string(failure.code),
					// The reason is developer-written and names the structural
					// problem; it never contains the offending input, which is
					// why decode.go builds it separately from the message.
					"reason", failure.reason)
				writeError(w, r, failure.status, failure.code, failure.message)
				return
			}
			outcome("decode_error", "error", err)
			writeError(w, r, http.StatusBadRequest,
				contract.ErrCodeMalformedJSON, "Request body is not valid JSON for this schema.")
			return
		}

		if code, message, ok := validateScanRequest(req); !ok {
			writeError(w, r, http.StatusUnprocessableEntity, code, message)
			return
		}

		// Authorisation, now that the task is known and valid.
		//
		// A caller that reached here without passing through Authenticate is
		// refused rather than treated as anonymous: a route wired up without
		// the middleware must fail loudly, not serve unauthenticated scans.
		caller, authenticated := auth.CallerFrom(r.Context())
		if !authenticated {
			outcome("unauthenticated")
			writeError(w, r, http.StatusUnauthorized,
				contract.ErrCodeUnauthenticated, "Valid credentials are required.")
			return
		}
		if !caller.MayUse(req.TaskID) {
			// The caller is known, so naming the task it asked for discloses
			// nothing it did not already send.
			outcome("unauthorized_task",
				"caller", caller.Name, "task_id", string(req.TaskID))
			writeError(w, r, http.StatusForbidden,
				contract.ErrCodeUnauthorizedTask,
				"This caller is not authorized for the requested task.")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), deps.Timeout)
		defer cancel()

		// Admission is taken here rather than around the whole handler, so a
		// request that was going to be refused for a malformed body never
		// occupies a slot that a well-formed one could use. The scarce
		// resource is the provider call, not the parser.
		//
		// The context is the one carrying the scan deadline, so a request
		// that runs out of budget while queued gives up its place instead of
		// waiting for a slot it could no longer use.
		release, err := deps.Admission.Acquire(ctx)
		if err != nil {
			switch {
			case errors.Is(err, admission.ErrQueueFull):
				// Both the slots and the queue are full. A 503 now is better
				// information than a response that may arrive in two minutes.
				stats := deps.Admission.Stats()
				outcome("shed",
					"error", err,
					"active", stats.Active, "queued", stats.Queued,
					"max_active", stats.MaxActive, "max_queued", stats.MaxQueued)
				writeRetryableError(w, r, http.StatusServiceUnavailable,
					contract.ErrCodeOverloaded,
					"The service is at capacity. Retry after the interval in "+
						"retry_after_seconds.", overloadedRetryAfterSeconds)
			case errors.Is(err, context.DeadlineExceeded):
				outcome("deadline_exceeded", "error", err)
				writeError(w, r, http.StatusGatewayTimeout,
					contract.ErrCodeDeadlineExceeded, "Scan exceeded its deadline.")
			default:
				// The caller hung up. Nothing useful can be written to a
				// connection that is gone, but the outcome is recorded.
				//
				// The error is passed as a value, not as err.Error(): the
				// handler reduces it to an identity, whereas a pre-rendered
				// string would be emitted as written.
				outcome("abandoned", "error", err)
				writeError(w, r, http.StatusServiceUnavailable,
					contract.ErrCodeDetectorUnavailable, "Scan was not admitted.")
			}
			return
		}

		assessment, err := deps.Detector.Assess(ctx, detector.AssessmentRequest{
			RequestID:  requestID,
			TaskID:     req.TaskID,
			Content:    req.Content,
			DeadlineMS: int(deps.Timeout.Milliseconds()),
		})
		// Released as soon as the provider call returns, on every path
		// including failure. Policy evaluation and serialisation are
		// microseconds and do not need to hold capacity.
		release()
		if err != nil {
			// Every failure below is an error envelope. None becomes an allow.
			switch {
			case errors.Is(err, detector.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
				outcome("deadline_exceeded", "error", err)
				writeError(w, r, http.StatusGatewayTimeout,
					contract.ErrCodeDeadlineExceeded, "Scan exceeded its deadline.")
			case errors.Is(err, detector.ErrPassageTooLarge):
				// The caller's problem, not the service's. Reported as such
				// so a client stops rather than retries: 413 is permanent
				// for this body, and the previous 503 was not.
				outcome("passage_too_large", "error", err)
				writeError(w, r, http.StatusRequestEntityTooLarge,
					contract.ErrCodePayloadTooLarge,
					"Passage exceeds the size limit for one scan.")
			case errors.Is(err, detector.ErrTokenBudgetExceeded):
				// The code the contract has defined since C03 and nothing
				// emitted until C32.
				outcome("token_budget_exceeded", "error", err)
				writeError(w, r, http.StatusUnprocessableEntity,
					contract.ErrCodeTokenBudgetExceeded,
					"Passage exceeds the token budget for one scan.")
			case errors.Is(err, detector.ErrResponseTooLarge), errors.Is(err, detector.ErrInvalidResponse):
				// The detector answered, but not in a way that can be trusted.
				outcome("invalid_response", "error", err)
				writeError(w, r, http.StatusServiceUnavailable,
					contract.ErrCodeDetectorUnavailable, "Detector response could not be validated.")
			default:
				outcome("detector_unavailable", "error", err)
				writeError(w, r, http.StatusServiceUnavailable,
					contract.ErrCodeDetectorUnavailable, "Detector is not available.")
			}
			return
		}

		decision, err := policy.Evaluate(deps.Mode, assessment.Assessment)
		if err != nil {
			// A label or mode the policy cannot evaluate is a failure, not a
			// permissive default. The scan does not become an allow because
			// the gateway did not understand the answer.
			outcome("policy_error", "error", err, "label", string(assessment.Assessment.Label))
			writeError(w, r, http.StatusServiceUnavailable,
				contract.ErrCodeDetectorUnavailable, "Assessment could not be evaluated.")
			return
		}

		outcome("complete",
			"caller", caller.Name,
			"task_id", string(req.TaskID),
			// The label and action are outcomes with a handful of possible
			// values. The evidence quotations are the thing that must never
			// be logged, and they are not here.
			"label", string(assessment.Assessment.Label),
			"action", string(decision.Action),
			"reason_code", string(decision.ReasonCode),
			"passage_bytes", assessment.Coverage.OriginalUTF8Bytes,
			"scanned_bytes", assessment.Coverage.ScannedUTF8Bytes,
			"detector", assessment.Versions.Detector,
			"prompt", assessment.Versions.Prompt,
			"policy", deps.Mode.Identity())

		writeJSON(w, http.StatusOK, contract.ScanResponse{
			RequestID:  requestID,
			ScanStatus: contract.ScanStatusComplete,
			Assessment: assessment.Assessment,
			Decision:   decision,
			Coverage:   assessment.Coverage,
			Versions: contract.Versions{
				Contract: contract.Version,
				Detector: assessment.Versions.Detector,
				Prompt:   assessment.Versions.Prompt,
				Policy:   deps.Mode.Identity(),
			},
		})
	})
}

func validateScanRequest(req contract.ScanRequest) (contract.ErrorCode, string, bool) {
	if !req.TaskID.Valid() {
		return contract.ErrCodeUnknownTaskID, "Unknown task_id.", false
	}
	if req.Content.SourceType != contract.SourceTranslationInput {
		return contract.ErrCodeSchemaInvalid, "Unsupported content.source_type.", false
	}
	if req.Content.ID == "" || len(req.Content.ID) > contract.MaxContentIDChars {
		return contract.ErrCodeSchemaInvalid, "content.id is missing or too long.", false
	}
	if req.Content.Text == "" {
		return contract.ErrCodeSchemaInvalid, "content.text must not be empty.", false
	}
	if utf8.RuneCountInString(req.Content.Text) > contract.MaxTextChars {
		return contract.ErrCodeSchemaInvalid, "content.text exceeds the supported length.", false
	}
	// There is deliberately no utf8.ValidString check here. It would be dead
	// code: by this point encoding/json has already substituted U+FFFD for
	// anything malformed, and U+FFFD is valid UTF-8, so the check would pass
	// on repaired text every time. The real guard runs against the raw body
	// before decoding, in decode.go.
	if hint := req.Content.LanguageHint; hint != "" {
		if len(hint) < 2 || len(hint) > 3 {
			return contract.ErrCodeSchemaInvalid, "content.language_hint must be a 2-3 letter code.", false
		}
		for _, r := range hint {
			if r < 'a' || r > 'z' {
				return contract.ErrCodeSchemaInvalid, "content.language_hint must be lowercase letters.", false
			}
		}
	}
	return "", "", true
}
