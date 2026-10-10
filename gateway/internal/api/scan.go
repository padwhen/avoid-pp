package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/detector"
	"github.com/padwhen/avoid-pp/gateway/internal/middleware"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

// MaxRequestBytes bounds the public request body before any parsing.
const MaxRequestBytes = 64 << 10 // 64 KiB

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
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
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

		// Bound the body before reading a byte of it.
		body := http.MaxBytesReader(w, r.Body, MaxRequestBytes)
		decoder := json.NewDecoder(body)
		// A caller must not be able to smuggle a policy or mode field past
		// validation by having it silently ignored.
		decoder.DisallowUnknownFields()

		var req contract.ScanRequest
		if err := decoder.Decode(&req); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeError(w, r, http.StatusRequestEntityTooLarge,
					contract.ErrCodePayloadTooLarge, "Request body exceeds the configured limit.")
				return
			}
			// The decoder's message embeds the offending input, which is
			// attacker-controlled, so it is not echoed.
			writeError(w, r, http.StatusBadRequest,
				contract.ErrCodeMalformedJSON, "Request body is not valid JSON for this schema.")
			return
		}
		if decoder.More() {
			writeError(w, r, http.StatusBadRequest,
				contract.ErrCodeMalformedJSON, "Request body contains trailing content.")
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
			log.Error("scan handler reached without authentication",
				"request_id", requestID)
			writeError(w, r, http.StatusUnauthorized,
				contract.ErrCodeUnauthenticated, "Valid credentials are required.")
			return
		}
		if !caller.MayUse(req.TaskID) {
			// The caller is known, so naming the task it asked for discloses
			// nothing it did not already send.
			log.Warn("scan request rejected: task not permitted",
				"request_id", requestID, "caller", caller.Name, "task_id", req.TaskID)
			writeError(w, r, http.StatusForbidden,
				contract.ErrCodeUnauthorizedTask,
				"This caller is not authorized for the requested task.")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), deps.Timeout)
		defer cancel()

		assessment, err := deps.Detector.Assess(ctx, detector.AssessmentRequest{
			RequestID:  requestID,
			TaskID:     req.TaskID,
			Content:    req.Content,
			DeadlineMS: int(deps.Timeout.Milliseconds()),
		})
		if err != nil {
			// Every failure below is an error envelope. None becomes an allow.
			switch {
			case errors.Is(err, detector.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
				log.Warn("scan deadline exceeded", "request_id", requestID)
				writeError(w, r, http.StatusGatewayTimeout,
					contract.ErrCodeDeadlineExceeded, "Scan exceeded its deadline.")
			case errors.Is(err, detector.ErrResponseTooLarge), errors.Is(err, detector.ErrInvalidResponse):
				// The detector answered, but not in a way that can be trusted.
				log.Error("detector response rejected", "request_id", requestID, "error", err)
				writeError(w, r, http.StatusServiceUnavailable,
					contract.ErrCodeDetectorUnavailable, "Detector response could not be validated.")
			default:
				log.Error("detector unavailable", "request_id", requestID, "error", err)
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
			log.Error("policy could not evaluate the assessment",
				"request_id", requestID, "error", err)
			writeError(w, r, http.StatusServiceUnavailable,
				contract.ErrCodeDetectorUnavailable, "Assessment could not be evaluated.")
			return
		}

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
	// Invalid UTF-8 is rejected rather than repaired: a silently replaced byte
	// changes the passage the caller believes was scanned.
	if !utf8.ValidString(req.Content.Text) {
		return contract.ErrCodeSchemaInvalid, "content.text is not valid UTF-8.", false
	}
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
