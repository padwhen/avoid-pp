// Package avoidpp is a typed client for the avoid-pp scan API.
//
//	client, err := avoidpp.New(avoidpp.Options{
//		BaseURL: "https://gateway.internal",
//		APIKey:  key,
//		Timeout: 20 * time.Second,
//	})
//
//	verdict, err := client.Scan(ctx, avoidpp.Input{Text: passage, ContentID: "doc-17"})
//	if err != nil {
//		return err // a scan that did not happen is not an allow
//	}
//	if verdict.PermitsTranslation(false) && verdict.Covers(passage) {
//		translate(passage)
//	}
//
// Three properties shape the whole package:
//
//   - allow, flag and block are three answers. Monitoring mode is the only
//     mode this service can run in before its quality gates are met, and
//     monitoring produces flags. A client offering IsSafe() would make every
//     caller settle the flag question once, silently, at the call site.
//   - a failure is not an answer. No code path returns a usable Verdict from
//     anything but a complete, internally consistent HTTP 200 body, and the
//     zero Verdict permits nothing - so a caller who ignores the error gets
//     a refusal rather than an allow.
//   - an unrecognised value is not a benign value. Which way to fail depends
//     on the field, and the contract says so per field; see ParseVerdict.
//
// The wire shapes mirror contracts/schemas/*.json, which stays normative, and
// parity_test.go reads those schemas rather than trusting this transcription.
package avoidpp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Version of the contract these types implement.
const Version = "1.0.0"

// Bounds mirror contracts/schemas/common.schema.json.
const (
	MaxTextChars      = 32768
	MaxContentIDChars = 128
	MaxRequestIDChars = 64
)

// Action is what the caller must do.
//
// The zero value is the empty string, which is not Allow. That matters more
// than it looks: a caller who ignores the error from Scan holds a zero
// Verdict, and every permission check on it is false.
type Action string

// Actions defined by this contract version.
const (
	ActionAllow Action = "allow"
	ActionFlag  Action = "flag"
	ActionBlock Action = "block"
)

// Label is the detector's assessment. It is not a decision.
type Label string

// Labels defined by this contract version.
const (
	LabelNoInjectionDetected Label = "no_injection_detected"
	LabelSuspicious          Label = "suspicious"
	LabelUncertain           Label = "uncertain"
)

// Known reports whether this contract version defines the label.
func (l Label) Known() bool {
	switch l {
	case LabelNoInjectionDetected, LabelSuspicious, LabelUncertain:
		return true
	}
	return false
}

// Category is a coarse reason a passage looked like task redirection.
type Category string

// Categories defined by this contract version.
const (
	CategoryTaskRedirection        Category = "task_redirection"
	CategoryDetectorTargeting      Category = "detector_targeting"
	CategorySystemPromptExtraction Category = "system_prompt_extraction"
	CategoryOutputFormatHijack     Category = "output_format_hijack"
)

// Known reports whether this contract version defines the category.
func (c Category) Known() bool {
	switch c {
	case CategoryTaskRedirection, CategoryDetectorTargeting,
		CategorySystemPromptExtraction, CategoryOutputFormatHijack:
		return true
	}
	return false
}

// ReasonCode explains an action, for telemetry and branching.
type ReasonCode string

// Reason codes defined by this contract version.
const (
	ReasonCleanCompleteScan   ReasonCode = "clean_complete_scan"
	ReasonSuspiciousMonitored ReasonCode = "suspicious_monitoring"
	ReasonSuspiciousEnforced  ReasonCode = "suspicious_enforced"
	ReasonUncertainMonitored  ReasonCode = "uncertain_monitoring"
	ReasonUncertainEnforced   ReasonCode = "uncertain_enforced"
)

// Known reports whether this contract version defines the reason code.
//
// An unknown one is not fatal: the reason code is telemetry and the action
// carries the decision.
func (r ReasonCode) Known() bool {
	switch r {
	case ReasonCleanCompleteScan, ReasonSuspiciousMonitored,
		ReasonSuspiciousEnforced, ReasonUncertainMonitored,
		ReasonUncertainEnforced:
		return true
	}
	return false
}

// ErrorCode is the stable identifier for a failure.
type ErrorCode string

// Error codes. All but CodeUnknown come from contracts/schemas/error.schema.json.
const (
	CodeMalformedJSON        ErrorCode = "malformed_json"
	CodeSchemaInvalid        ErrorCode = "schema_invalid"
	CodeUnknownTaskID        ErrorCode = "unknown_task_id"
	CodeUnauthenticated      ErrorCode = "unauthenticated"
	CodeUnauthorizedTask     ErrorCode = "unauthorized_task"
	CodePayloadTooLarge      ErrorCode = "payload_too_large"
	CodeUnsupportedMediaType ErrorCode = "unsupported_media_type"
	CodeTokenBudgetExceeded  ErrorCode = "token_budget_exceeded"
	CodeRateLimited          ErrorCode = "rate_limited"
	CodeDetectorUnavailable  ErrorCode = "detector_unavailable"
	CodeOverloaded           ErrorCode = "overloaded"
	CodeDeadlineExceeded     ErrorCode = "deadline_exceeded"
	CodeInternalError        ErrorCode = "internal_error"

	// CodeUnknown is this client's own, and is not in the schema. It covers a
	// code from a later contract version, a failure body with no code, and a
	// body written by something that is not the gateway. It exists so that
	// "the call failed and we cannot say why" is a value to branch on rather
	// than an empty string that reads as no error.
	CodeUnknown ErrorCode = "unknown"
)

// Known reports whether this contract version defines the error code.
func (c ErrorCode) Known() bool {
	switch c {
	case CodeMalformedJSON, CodeSchemaInvalid, CodeUnknownTaskID,
		CodeUnauthenticated, CodeUnauthorizedTask, CodePayloadTooLarge,
		CodeUnsupportedMediaType, CodeTokenBudgetExceeded, CodeRateLimited,
		CodeDetectorUnavailable, CodeOverloaded, CodeDeadlineExceeded,
		CodeInternalError:
		return true
	}
	return false
}

// TaskID names a server-resolved task configuration. A caller names a task;
// it never supplies the instructions, the target language or the policy.
type TaskID string

// TaskTranslateFiEnV1 is the only task this contract version defines.
const TaskTranslateFiEnV1 TaskID = "translate_fi_en_v1"

// SourceType describes what a passage is. It never widens trust.
type SourceType string

// SourceTranslationInput is the only source type this contract version defines.
const SourceTranslationInput SourceType = "translation_input"

// Evidence is an exact quotation from the passage.
//
// Verified to occur in the passage before it left the detector, so a
// fabricated citation cannot arrive here. Still untrusted text: it is a
// fragment of an attacker-controlled passage, and rendering it needs the same
// escaping the passage would.
type Evidence struct {
	ContentID string   `json:"content_id"`
	Quote     string   `json:"quote"`
	Category  Category `json:"category,omitempty"`
}

// Coverage is byte accounting for the scan.
type Coverage struct {
	OriginalUTF8Bytes int   `json:"original_utf8_bytes"`
	ScannedUTF8Bytes  int   `json:"scanned_utf8_bytes"`
	Truncated         *bool `json:"truncated"`
}

// Versions identifies what produced a result.
type Versions struct {
	Contract string `json:"contract"`
	Detector string `json:"detector"`
	Prompt   string `json:"prompt"`
	Policy   string `json:"policy"`
}

// Verdict is a usable decision about a specific passage.
//
// There is deliberately no confidence field. The schema forbids the server
// sending one because an LLM-invented probability is not calibrated, and the
// absence here is the second line of that: a gateway that regressed could not
// publish a number through this client, because there is nowhere to put it.
type Verdict struct {
	Action     Action
	Label      Label
	ReasonCode ReasonCode
	RequestID  string
	Categories []Category
	Evidence   []Evidence
	Coverage   Coverage
	Versions   Versions

	// ScannedDigest is SHA-256 over the exact UTF-8 bytes that were sent.
	ScannedDigest string

	// UnrecognisedAction holds what arrived when the gateway sent an action
	// from a later contract version. Action is then ActionBlock, per the
	// contract's client rule, and this says why - so telemetry can show that
	// the enum moved rather than that the passage was hostile.
	UnrecognisedAction string
}

// Covers reports whether this verdict is about exactly these bytes.
//
// The check an integration needs immediately before acting on a verdict. A
// scan and a translation can both be real while being about different text,
// and every realistic bug of that shape - a trim before display, a retry
// carrying an edit, an excerpt scanned and a document used - is this
// returning false.
//
// The zero Verdict covers nothing, including the empty string.
func (v Verdict) Covers(text string) bool {
	if v.ScannedDigest == "" {
		return false
	}
	return DigestOf(text) == v.ScannedDigest
}

// PermitsTranslation reports whether an application may act on this verdict.
//
// translateOnFlag is a required argument rather than a field or a default,
// because whether a flag proceeds is a property of the deployment and not of
// the verdict. A method with a default would have made that default the
// policy of every caller who did not know there was a question.
//
// Written as an allowlist: an action this build does not recognise does not
// translate, so an action added to the contract has to be considered here
// deliberately.
func (v Verdict) PermitsTranslation(translateOnFlag bool) bool {
	switch v.Action {
	case ActionAllow:
		return true
	case ActionFlag:
		return translateOnFlag
	default:
		return false
	}
}

// DigestOf returns SHA-256 over the exact UTF-8 bytes of text.
//
// Not a normalised form, and that is the point. A digest that folded
// whitespace, case or Unicode composition would let a visually identical but
// different passage pass as the one that was scanned, which is exactly the
// careless pipeline this is here to catch.
func DigestOf(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// wireResponse is the HTTP 200 body as it arrives.
//
// Pointers on the required fields so that absent and zero are distinguishable:
// a body with no decision at all must be refused, and `{}` would otherwise
// decode into a struct whose Action is "" and look merely unrecognised.
type wireResponse struct {
	RequestID  *string `json:"request_id"`
	ScanStatus *string `json:"scan_status"`
	Assessment *struct {
		Label      *Label     `json:"label"`
		Categories []Category `json:"categories"`
		Evidence   []Evidence `json:"evidence"`
	} `json:"assessment"`
	Decision *struct {
		Action     *string     `json:"action"`
		ReasonCode *ReasonCode `json:"reason_code"`
	} `json:"decision"`
	Coverage *Coverage `json:"coverage"`
	Versions *Versions `json:"versions"`
}

// ParseVerdict turns a 200 body into a Verdict, or reports why it will not.
//
// The checks run in a fixed order, and the order is the contract's reasoning
// rather than convenience:
//
//  1. Shape. A body that is not an object carrying the required fields is not
//     a scan response. An error envelope served with 200 lands here, which is
//     what a proxy rewriting a status looks like.
//
//     A field that is absent is a missing field; a field carrying the wrong
//     JSON type makes the whole body unreadable, because this decoder cannot
//     get far enough to say anything more specific. The Python client states
//     the same rule explicitly - without it the two would classify the same
//     malformed response differently, which is the divergence the shared
//     expectations table exists to catch, and did.
//
//  2. Status. scan_status has one legal value; anything else forbids a clean
//     verdict, so there is no verdict to read.
//
//  3. Coverage. A scan of part of a passage is not a verdict about the
//     passage, and a verdict about a different number of bytes is not about
//     what was sent. This check is why the client, rather than every caller,
//     carries the scan-translate divergence problem.
//
//  4. Label. An unrecognised label is refused outright, because the
//     consistency check in step 6 cannot be performed against a label whose
//     meaning is unknown. An unknown label is not a fourth kind of clean.
//
//  5. Action. An unrecognised action becomes ActionBlock. This is the one
//     place the contract tells clients what to do with data they cannot
//     understand, and it says so explicitly, so the enum can grow without
//     every deployed client failing closed into an outage.
//
//  6. Consistency, in one direction only. A non-clean label with an allow
//     action is the exact failure this service exists to prevent, arriving as
//     a well-formed response; it is refused. The mirror case - a clean label
//     blocked anyway - is honoured, because a server stricter than its own
//     schema is not a safety problem, and overriding it would be this client
//     second-guessing a server-side decision.
func ParseVerdict(body []byte, sentText string) (Verdict, error) {
	var wire wireResponse
	if err := json.Unmarshal(body, &wire); err != nil {
		return Verdict{}, &ResponseError{
			Reason: ReasonUnreadableBody,
			Detail: "the response body is not a JSON object",
		}
	}
	switch {
	case wire.RequestID == nil:
		return Verdict{}, missingField("request_id")
	case wire.ScanStatus == nil:
		return Verdict{}, missingField("scan_status")
	case wire.Assessment == nil:
		return Verdict{}, missingField("assessment")
	case wire.Decision == nil:
		return Verdict{}, missingField("decision")
	case wire.Coverage == nil:
		return Verdict{}, missingField("coverage")
	}

	if *wire.ScanStatus != "complete" {
		return Verdict{}, &ResponseError{
			Reason: ReasonScanNotComplete,
			Detail: "scan_status is not \"complete\", so no clean verdict is possible",
		}
	}

	coverage := *wire.Coverage
	if coverage.Truncated == nil {
		// Absent, which is not the same claim as false: "we do not know
		// whether this was truncated" must not read as "it was not".
		return Verdict{}, missingField("coverage.truncated")
	}
	sentBytes := len(sentText)
	switch {
	case *coverage.Truncated:
		return Verdict{}, &ResponseError{
			Reason: ReasonCoverageTruncated,
			Detail: "the gateway reported the passage truncated",
		}
	case coverage.ScannedUTF8Bytes != coverage.OriginalUTF8Bytes:
		return Verdict{}, &ResponseError{
			Reason: ReasonCoveragePartial,
			Detail: fmt.Sprintf("%d of %d bytes were scanned",
				coverage.ScannedUTF8Bytes, coverage.OriginalUTF8Bytes),
		}
	case coverage.OriginalUTF8Bytes != sentBytes:
		return Verdict{}, &ResponseError{
			Reason: ReasonCoverageMismatch,
			Detail: fmt.Sprintf(
				"the gateway scanned %d bytes and %d were sent, so this "+
					"verdict is about other text",
				coverage.OriginalUTF8Bytes, sentBytes),
		}
	}

	if wire.Assessment.Label == nil {
		return Verdict{}, missingField("assessment.label")
	}
	if !wire.Assessment.Label.Known() {
		return Verdict{}, &ResponseError{
			Reason: ReasonUnknownLabel,
			Detail: "the assessment label is not one this client defines",
		}
	}
	label := *wire.Assessment.Label

	if wire.Decision.Action == nil {
		return Verdict{}, missingField("decision.action")
	}
	if wire.Decision.ReasonCode == nil || *wire.Decision.ReasonCode == "" {
		return Verdict{}, missingField("decision.reason_code")
	}
	reason := *wire.Decision.ReasonCode

	action := Action(*wire.Decision.Action)
	unrecognised := ""
	switch action {
	case ActionAllow, ActionFlag, ActionBlock:
	default:
		// common.schema.json: "any value not recognized by the client MUST be
		// treated as block". Not an error and not a rejection - a block.
		unrecognised = string(action)
		action = ActionBlock
	}

	if action == ActionAllow {
		if label != LabelNoInjectionDetected {
			return Verdict{}, &ResponseError{
				Reason: ReasonAllowContradictsLabel,
				Detail: fmt.Sprintf("the action is allow and the label is %q", label),
			}
		}
		if reason != ReasonCleanCompleteScan {
			return Verdict{}, &ResponseError{
				Reason: ReasonAllowWithoutCleanReason,
				Detail: fmt.Sprintf(
					"the action is allow and the reason code is %q", reason),
			}
		}
	}

	return Verdict{
		Action:             action,
		Label:              label,
		ReasonCode:         reason,
		RequestID:          *wire.RequestID,
		Categories:         knownCategories(wire.Assessment.Categories),
		Evidence:           wire.Assessment.Evidence,
		Coverage:           coverage,
		Versions:           versionsOf(wire.Versions),
		ScannedDigest:      DigestOf(sentText),
		UnrecognisedAction: unrecognised,
	}, nil
}

func missingField(name string) error {
	return &ResponseError{
		Reason: ReasonMissingField,
		Detail: "the response has no " + name,
	}
}

// knownCategories drops categories from a later contract version.
//
// Safe to drop in a way the action is not: categories are advisory, and no
// branch anywhere becomes permissive through one being absent.
func knownCategories(in []Category) []Category {
	if len(in) == 0 {
		return nil
	}
	out := make([]Category, 0, len(in))
	for _, c := range in {
		if c.Known() {
			out = append(out, c)
		}
	}
	return out
}

// versionsOf fills absent version strings with "unknown".
//
// Not fatal, because versions identify a result rather than authorise
// anything. Not silently blank either: a report that cannot say which
// detector and prompt produced a number is not a report.
func versionsOf(in *Versions) Versions {
	out := Versions{}
	if in != nil {
		out = *in
	}
	for _, field := range []*string{&out.Contract, &out.Detector, &out.Prompt, &out.Policy} {
		if *field == "" {
			*field = "unknown"
		}
	}
	return out
}

// Actions returns every action this contract version defines.
//
// These accessors return a fresh slice each call rather than exposing package
// variables, so a caller cannot reorder or empty the set another caller is
// about to range over. They exist mainly so parity_test.go can compare this
// transcription against contracts/schemas/common.schema.json in both
// directions - a value in the schema and missing here, and a value here that
// the schema never defined.
func Actions() []Action {
	return []Action{ActionAllow, ActionFlag, ActionBlock}
}

// Labels returns every label this contract version defines.
func Labels() []Label {
	return []Label{LabelNoInjectionDetected, LabelSuspicious, LabelUncertain}
}

// Categories returns every category this contract version defines.
func Categories() []Category {
	return []Category{
		CategoryTaskRedirection,
		CategoryDetectorTargeting,
		CategorySystemPromptExtraction,
		CategoryOutputFormatHijack,
	}
}

// ReasonCodes returns every reason code this contract version defines.
func ReasonCodes() []ReasonCode {
	return []ReasonCode{
		ReasonCleanCompleteScan,
		ReasonSuspiciousMonitored,
		ReasonSuspiciousEnforced,
		ReasonUncertainMonitored,
		ReasonUncertainEnforced,
	}
}

// ErrorCodes returns every error code from the contract, and CodeUnknown.
func ErrorCodes() []ErrorCode {
	return []ErrorCode{
		CodeMalformedJSON, CodeSchemaInvalid, CodeUnknownTaskID,
		CodeUnauthenticated, CodeUnauthorizedTask, CodePayloadTooLarge,
		CodeUnsupportedMediaType, CodeTokenBudgetExceeded, CodeRateLimited,
		CodeDetectorUnavailable, CodeOverloaded, CodeDeadlineExceeded,
		CodeInternalError, CodeUnknown,
	}
}

// TaskIDs returns every task this contract version defines.
func TaskIDs() []TaskID { return []TaskID{TaskTranslateFiEnV1} }

// SourceTypes returns every source type this contract version defines.
func SourceTypes() []SourceType { return []SourceType{SourceTranslationInput} }
