// Package contract holds the wire types for the public scan API and the
// private assessment API, mirroring contracts/schemas/*.json.
//
// The JSON Schema remains normative. These types are its Go-side enforcement,
// and every enum validates explicitly rather than relying on the decoder: Go
// will happily unmarshal any string into a `type Label string`, so an unknown
// value from the detector would otherwise flow straight through into a
// decision.
package contract

import "fmt"

// Version of the contract these types implement.
const Version = "1.0.0"

// Bounds mirror contracts/schemas/common.schema.json.
const (
	MaxTextChars      = 32768
	MaxQuoteChars     = 512
	MaxRequestIDChars = 64
	MaxContentIDChars = 128
)

// Label is the detector's assessment of a passage. It is not a decision.
type Label string

const (
	LabelNoInjectionDetected Label = "no_injection_detected"
	LabelSuspicious          Label = "suspicious"
	LabelUncertain           Label = "uncertain"
)

// Valid reports whether the label is one this contract version defines.
//
// An unrecognised label must never be treated as benign. Callers turn a false
// result into a downstream error, never into an allow.
func (l Label) Valid() bool {
	switch l {
	case LabelNoInjectionDetected, LabelSuspicious, LabelUncertain:
		return true
	}
	return false
}

// Action is what the caller must do.
//
// Clients must treat any unrecognised action as Block. The enum is
// append-only; "verify" is reserved for a future output-verification action
// and is never emitted today.
type Action string

const (
	ActionAllow Action = "allow"
	ActionFlag  Action = "flag"
	ActionBlock Action = "block"
)

// Category is a coarse reason a passage looked like task redirection.
type Category string

const (
	CategoryTaskRedirection        Category = "task_redirection"
	CategoryDetectorTargeting      Category = "detector_targeting"
	CategorySystemPromptExtraction Category = "system_prompt_extraction"
	CategoryOutputFormatHijack     Category = "output_format_hijack"
)

// Valid reports whether the category is defined by this contract version.
func (c Category) Valid() bool {
	switch c {
	case CategoryTaskRedirection, CategoryDetectorTargeting,
		CategorySystemPromptExtraction, CategoryOutputFormatHijack:
		return true
	}
	return false
}

// ScanStatus has exactly one legal value. An unavailable, timed-out or
// truncated outcome is an error envelope, not a scan response, so it cannot
// be expressed in this type at all.
type ScanStatus string

const ScanStatusComplete ScanStatus = "complete"

// ReasonCode explains an action for telemetry and client branching.
type ReasonCode string

const (
	ReasonCleanCompleteScan   ReasonCode = "clean_complete_scan"
	ReasonSuspiciousMonitored ReasonCode = "suspicious_monitoring"
	ReasonSuspiciousEnforced  ReasonCode = "suspicious_enforced"
	ReasonUncertainMonitored  ReasonCode = "uncertain_monitoring"
	ReasonUncertainEnforced   ReasonCode = "uncertain_enforced"
)

// ErrorCode is the stable machine-readable failure identifier.
type ErrorCode string

const (
	ErrCodeMalformedJSON    ErrorCode = "malformed_json"
	ErrCodeSchemaInvalid    ErrorCode = "schema_invalid"
	ErrCodeUnknownTaskID    ErrorCode = "unknown_task_id"
	ErrCodeUnauthenticated  ErrorCode = "unauthenticated"
	ErrCodeUnauthorizedTask ErrorCode = "unauthorized_task"
	ErrCodePayloadTooLarge  ErrorCode = "payload_too_large"
	ErrCodeUnsupportedMedia ErrorCode = "unsupported_media_type"
	// Defined by error.schema.json since C03 and emitted since C32, when
	// measuring capacity found that an over-budget passage was being
	// reported as a detector outage.
	ErrCodeTokenBudgetExceeded ErrorCode = "token_budget_exceeded"
	ErrCodeRateLimited         ErrorCode = "rate_limited"
	ErrCodeOverloaded          ErrorCode = "overloaded"
	ErrCodeDetectorUnavailable ErrorCode = "detector_unavailable"
	ErrCodeDeadlineExceeded    ErrorCode = "deadline_exceeded"
	ErrCodeInternalError       ErrorCode = "internal_error"
)

// TaskID names a server-resolved task configuration.
type TaskID string

const TaskTranslateFiEnV1 TaskID = "translate_fi_en_v1"

// Valid reports whether this contract version defines the task.
//
// Go unmarshals any string into a named string type without complaint, so
// an unrecognised task has to be rejected explicitly or it travels onward
// looking well-typed.
func (t TaskID) Valid() bool { return t == TaskTranslateFiEnV1 }

// SourceType describes what a passage is. It never widens trust.
type SourceType string

const SourceTranslationInput SourceType = "translation_input"

// Content is one bounded passage, untrusted for its entire length.
type Content struct {
	ID           string     `json:"id"`
	SourceType   SourceType `json:"source_type"`
	LanguageHint string     `json:"language_hint,omitempty"`
	Text         string     `json:"text"`
}

// ScanRequest is the public request body.
//
// There is deliberately no field for policy, mode, instructions or trust
// level. Unknown fields are rejected by the decoder, so an attempt to add one
// fails rather than being ignored.
type ScanRequest struct {
	TaskID  TaskID  `json:"task_id"`
	Content Content `json:"content"`
}

// EvidenceItem is an exact, bounded quotation from the original passage.
type EvidenceItem struct {
	ContentID string   `json:"content_id"`
	Quote     string   `json:"quote"`
	Category  Category `json:"category,omitempty"`
}

// Assessment is the detector's verdict and its evidence.
type Assessment struct {
	Label      Label          `json:"label"`
	Categories []Category     `json:"categories"`
	Evidence   []EvidenceItem `json:"evidence"`
}

// Decision is the gateway's policy outcome.
type Decision struct {
	Action     Action     `json:"action"`
	ReasonCode ReasonCode `json:"reason_code"`
}

// Coverage is byte accounting for the scan.
type Coverage struct {
	OriginalUTF8Bytes int  `json:"original_utf8_bytes"`
	ScannedUTF8Bytes  int  `json:"scanned_utf8_bytes"`
	Truncated         bool `json:"truncated"`
}

// Versions identifies exactly what produced a result.
type Versions struct {
	Contract string `json:"contract"`
	Detector string `json:"detector"`
	Prompt   string `json:"prompt"`
	Policy   string `json:"policy"`
}

// ScanResponse is the public 200 body. It exists only for completed scans.
type ScanResponse struct {
	RequestID  string     `json:"request_id"`
	ScanStatus ScanStatus `json:"scan_status"`
	Assessment Assessment `json:"assessment"`
	Decision   Decision   `json:"decision"`
	Coverage   Coverage   `json:"coverage"`
	Versions   Versions   `json:"versions"`
}

// ErrorBody carries the stable code and a safe message.
type ErrorBody struct {
	Code              ErrorCode `json:"code"`
	Message           string    `json:"message"`
	RetryAfterSeconds int       `json:"retry_after_seconds,omitempty"`
}

// ErrorResponse is every non-200 outcome. It has no assessment field, so no
// failure path can present itself as a clean scan.
type ErrorResponse struct {
	RequestID string    `json:"request_id"`
	Error     ErrorBody `json:"error"`
}

// ValidateAssessment rejects an assessment carrying any value this contract
// version does not define.
//
// This runs on data received from the detector. Go unmarshals any string into
// a named string type without complaint, so without this an unknown label
// would reach the policy layer and be compared against known constants —
// matching none of them, and falling into whatever the default branch does.
func ValidateAssessment(a Assessment) error {
	if !a.Label.Valid() {
		return fmt.Errorf("unknown assessment label %q", string(a.Label))
	}
	for _, c := range a.Categories {
		if !c.Valid() {
			return fmt.Errorf("unknown assessment category %q", string(c))
		}
	}
	for i, e := range a.Evidence {
		if e.ContentID == "" {
			return fmt.Errorf("evidence[%d]: missing content_id", i)
		}
		if e.Quote == "" {
			return fmt.Errorf("evidence[%d]: empty quote", i)
		}
		if len(e.Quote) > MaxQuoteChars {
			return fmt.Errorf("evidence[%d]: quote exceeds %d bytes", i, MaxQuoteChars)
		}
		if e.Category != "" && !e.Category.Valid() {
			return fmt.Errorf("evidence[%d]: unknown category %q", i, string(e.Category))
		}
	}
	return nil
}
