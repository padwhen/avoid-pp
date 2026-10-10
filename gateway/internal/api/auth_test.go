// C19: the HTTP authentication and authorisation matrix.
//
// The assertion that matters most here is not the status code. It is that a
// rejected request never reaches the detector: authentication that returns 401
// after spending a provider call has protected nothing.
package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/detector"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

// countingAssessor records every call it receives and would answer cleanly.
// A rejected request reaching it is a silent failure otherwise: the response
// would still be a 401 while the provider bill went up.
type countingAssessor struct {
	calls atomic.Int64
	// text records the passage of the most recent call, so a test can assert
	// what actually reached the detector rather than what was sent.
	mu   sync.Mutex
	text string
}

// lastText returns the passage the detector most recently received.
func (c *countingAssessor) lastText() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.text
}

func (c *countingAssessor) Assess(
	_ context.Context, req detector.AssessmentRequest,
) (*detector.AssessmentResponse, error) {
	c.calls.Add(1)
	c.mu.Lock()
	c.text = req.Content.Text
	c.mu.Unlock()
	response := &detector.AssessmentResponse{
		Assessment: contract.Assessment{
			Label:      contract.LabelNoInjectionDetected,
			Categories: []contract.Category{},
			Evidence:   []contract.EvidenceItem{},
		},
		Coverage: contract.Coverage{
			OriginalUTF8Bytes: len(req.Content.Text),
			ScannedUTF8Bytes:  len(req.Content.Text),
		},
	}
	response.Versions.Detector = "counting-fake"
	response.Versions.Prompt = "none"
	return response, nil
}

// Fixed development credentials, local to this file and not secrets.
const (
	authorisedKey   = "authorised-key-aaaaaaaaaaaaaaaaaaaaaa"
	unauthorisedKey = "second-caller-key-bbbbbbbbbbbbbbbbbbbb"
)

// matrixRouter returns a router whose only caller permitted to translate is
// "authorised", alongside the detector call counter.
func matrixRouter(t *testing.T) (http.Handler, *countingAssessor) {
	t.Helper()

	// Both callers are granted the one task this contract version defines.
	// There is no configuration that grants less and still starts, which is
	// why the 403 branch is driven at the handler instead; see the test.
	registry, err := auth.NewRegistry([]auth.KeySpec{
		{
			Name:  "authorised",
			Key:   authorisedKey,
			Tasks: []contract.TaskID{contract.TaskTranslateFiEnV1},
		},
		{
			Name:  "second-caller",
			Key:   unauthorisedKey,
			Tasks: []contract.TaskID{contract.TaskTranslateFiEnV1},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	counter := &countingAssessor{}
	readiness := NewReadiness()
	readiness.SetReady()
	return NewRouter(readiness, ScanDeps{
		Detector:  counter,
		Timeout:   2 * time.Second,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mode:      policy.ModeMonitoring,
		Callers:   registry,
		Limiter:   permissiveLimits(t, "authorised", "second-caller"),
		Admission: permissiveAdmission(),
	}), counter
}

func taskBody(task string) string {
	raw, _ := json.Marshal(map[string]any{
		"task_id": task,
		"content": map[string]any{
			"id":          "passage-1",
			"source_type": "translation_input",
			"text":        "Käännä tämä teksti englanniksi.",
		},
	})
	return string(raw)
}

func post(t *testing.T, handler http.Handler, header, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) contract.ErrorCode {
	t.Helper()
	var body contract.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v (body %q)", err, rec.Body.String())
	}
	return body.Error.Code
}

// C19-AC1: missing or invalid credentials receive 401.
func TestMissingOrInvalidCredentialsAre401(t *testing.T) {
	cases := map[string]string{
		"no authorization header": "",
		"empty bearer":            "Bearer ",
		"unknown key":             "Bearer " + strings.Repeat("z", 40),
		"a key with one byte changed": "Bearer " +
			authorisedKey[:len(authorisedKey)-1] + "Z",
		"a prefix of a real key":      "Bearer " + authorisedKey[:20],
		"the right key, wrong scheme": "Basic " + authorisedKey,
		"no scheme at all":            authorisedKey,
	}

	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			router, counter := matrixRouter(t)
			rec := post(t, router, header, taskBody("translate_fi_en_v1"))

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if code := errorCode(t, rec); code != contract.ErrCodeUnauthenticated {
				t.Errorf("code = %q, want unauthenticated", code)
			}
			// The verification the acceptance criteria ask for.
			if calls := counter.calls.Load(); calls != 0 {
				t.Errorf("detector was called %d times for a rejected request", calls)
			}
		})
	}
}

// C19-AC1: a valid caller requesting a task it may not use receives 403.
//
// This branch is not reachable through configuration today, and saying so is
// more useful than a test that pretends otherwise: the contract defines
// exactly one task, NewRegistry refuses a caller granted no tasks, and an
// unrecognised task is refused as 422 before authorisation is consulted. So
// the only caller that can be granted anything is granted everything there is.
//
// The branch is still exercised, by driving the handler with a caller whose
// grant is empty. It exists for the second task, and a permission check that
// was never run even once is a permission check nobody should trust.
func TestAnAuthenticatedCallerWithoutTheTaskIs403(t *testing.T) {
	counter := &countingAssessor{}
	handler := Scan(ScanDeps{
		Detector: counter,
		Timeout:  2 * time.Second,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mode:     policy.ModeMonitoring,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/scans",
		strings.NewReader(taskBody("translate_fi_en_v1")))
	req.Header.Set("Content-Type", "application/json")
	// Authenticated — the context carries a caller — but granted nothing.
	req = req.WithContext(auth.WithCaller(req.Context(), auth.Caller{Name: "granted-nothing"}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rec.Code, rec.Body.String())
	}
	if code := errorCode(t, rec); code != contract.ErrCodeUnauthorizedTask {
		t.Errorf("code = %q, want unauthorized_task", code)
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector was called %d times for a forbidden request", calls)
	}
}

// A handler reached without the middleware denies rather than treating the
// absent caller as anonymous. This is what makes a misrouted endpoint a 401
// instead of an open one.
func TestHandlerWithoutAuthenticationDenies(t *testing.T) {
	counter := &countingAssessor{}
	handler := Scan(ScanDeps{
		Detector: counter,
		Timeout:  2 * time.Second,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mode:     policy.ModeMonitoring,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/scans",
		strings.NewReader(taskBody("translate_fi_en_v1")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector calls = %d, want 0", calls)
	}
}

// An unknown task is 422, not 403. The task list is published contract, so
// "that task does not exist" discloses nothing, and reporting it as a
// permission problem would send a caller chasing an access request for a
// task that was simply misspelled.
func TestUnknownTaskIs422ForAnAuthorisedCaller(t *testing.T) {
	router, counter := matrixRouter(t)

	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_sv_en_v1"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", rec.Code)
	}
	if code := errorCode(t, rec); code != contract.ErrCodeUnknownTaskID {
		t.Errorf("code = %q, want unknown_task_id", code)
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector calls = %d, want 0", calls)
	}
}

// The matrix is not uniformly closed: an authorised caller is served.
func TestAuthorisedCallerIsServed(t *testing.T) {
	router, counter := matrixRouter(t)

	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if calls := counter.calls.Load(); calls != 1 {
		t.Errorf("detector calls = %d, want exactly 1", calls)
	}

	// Both configured callers are served, so the happy path does not depend
	// on being first in the registry.
	rec = post(t, router, "Bearer "+unauthorisedKey, taskBody("translate_fi_en_v1"))
	if rec.Code != http.StatusOK {
		t.Errorf("second caller status = %d, want 200", rec.Code)
	}
}

// C19-AC2: identity and permissions come from configuration, so a body field
// claiming a caller, tenant or role cannot grant anything.
func TestBodyCannotSupplyIdentity(t *testing.T) {
	router, counter := matrixRouter(t)

	for name, body := range map[string]string{
		"a caller field": `{"task_id":"translate_fi_en_v1","caller":"authorised",
			"content":{"id":"p","source_type":"translation_input","text":"Moi."}}`,
		"a tenant field": `{"task_id":"translate_fi_en_v1","tenant":"admin",
			"content":{"id":"p","source_type":"translation_input","text":"Moi."}}`,
		"a role field": `{"task_id":"translate_fi_en_v1","role":"admin",
			"content":{"id":"p","source_type":"translation_input","text":"Moi."}}`,
		"an api_key field": `{"task_id":"translate_fi_en_v1","api_key":"` + authorisedKey + `",
			"content":{"id":"p","source_type":"translation_input","text":"Moi."}}`,
	} {
		t.Run(name, func(t *testing.T) {
			// Unauthenticated: the field must not stand in for a credential.
			rec := post(t, router, "", body)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}

			// Authenticated: the field must be rejected rather than ignored,
			// so an attempt to add one fails loudly.
			rec = post(t, router, "Bearer "+authorisedKey, body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("authenticated status = %d, want 400 for an unknown field", rec.Code)
			}
		})
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector calls = %d, want 0", calls)
	}
}

// Health endpoints stay open: a load balancer probing readiness holds no
// credential, and what they disclose is already implied by an open port.
func TestHealthEndpointsNeedNoCredential(t *testing.T) {
	router, _ := matrixRouter(t)

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, rec.Code)
		}
	}
}

// Fail closed: a router built without a caller registry must not serve scans
// at all, rather than serving them to everybody.
func TestScanRouteIsAbsentWithoutARegistry(t *testing.T) {
	readiness := NewReadiness()
	readiness.SetReady()
	counter := &countingAssessor{}
	router := NewRouter(readiness, ScanDeps{
		Detector:  counter,
		Timeout:   time.Second,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mode:      policy.ModeMonitoring,
		Limiter:   permissiveLimits(t, "authorised"),
		Admission: permissiveAdmission(),
		// Callers deliberately nil.
	})

	rec := post(t, router, "Bearer "+authorisedKey, taskBody("translate_fi_en_v1"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when no registry is configured", rec.Code)
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector calls = %d, want 0", calls)
	}
}

// Authentication precedes parsing: an unauthenticated caller learns nothing
// about the request schema, and a malformed body from a stranger costs no work.
func TestAuthenticationPrecedesParsing(t *testing.T) {
	router, counter := matrixRouter(t)

	for name, body := range map[string]string{
		"not json":     "}{",
		"empty":        "",
		"wrong shape":  `{"task_id":123}`,
		"unknown task": taskBody("translate_sv_en_v1"),
		"oversized": `{"task_id":"translate_fi_en_v1","content":{"id":"p",` +
			`"source_type":"translation_input","text":"` + strings.Repeat("x", 100_000) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := post(t, router, "", body)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 before any parsing", rec.Code)
			}
			if code := errorCode(t, rec); code != contract.ErrCodeUnauthenticated {
				t.Errorf("code = %q, want unauthenticated", code)
			}
		})
	}
	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("detector calls = %d, want 0", calls)
	}
}

// A 401 must not say which half failed: distinguishing "no key" from "wrong
// key" tells a prober whether a credential exists.
func TestUnauthenticatedResponsesAreIndistinguishable(t *testing.T) {
	router, _ := matrixRouter(t)

	absent := post(t, router, "", taskBody("translate_fi_en_v1"))
	wrong := post(t, router, "Bearer "+strings.Repeat("z", 40), taskBody("translate_fi_en_v1"))

	if absent.Code != wrong.Code {
		t.Errorf("status differs: absent %d, wrong %d", absent.Code, wrong.Code)
	}

	var a, b contract.ErrorResponse
	_ = json.Unmarshal(absent.Body.Bytes(), &a)
	_ = json.Unmarshal(wrong.Body.Bytes(), &b)
	if a.Error != b.Error {
		t.Errorf("error bodies differ:\n absent %+v\n wrong  %+v", a.Error, b.Error)
	}
}

// C19-AC3: a rejection must not echo the credential it rejected, in any field.
func TestRejectionNeverEchoesTheCredential(t *testing.T) {
	router, _ := matrixRouter(t)
	const presented = "sk-ant-SUPERSECRET-presented-by-mistake"

	rec := post(t, router, "Bearer "+presented, taskBody("translate_fi_en_v1"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), presented) {
		t.Errorf("response echoed the presented credential: %q", rec.Body.String())
	}
	for key, values := range rec.Header() {
		for _, value := range values {
			if strings.Contains(value, presented) {
				t.Errorf("header %s echoed the presented credential", key)
			}
		}
	}
}

// A rejected caller still needs a request id: without it they cannot ask
// about the rejection, and the log line recording it is unfindable.
func TestRejectionsCarryARequestID(t *testing.T) {
	router, _ := matrixRouter(t)

	for name, header := range map[string]string{
		"unauthenticated": "",
		"unknown key":     "Bearer " + strings.Repeat("z", 40),
	} {
		t.Run(name, func(t *testing.T) {
			rec := post(t, router, header, taskBody("translate_fi_en_v1"))

			var body contract.ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.RequestID == "" {
				t.Error("error response carries no request_id")
			}
			if got := rec.Header().Get("X-Request-Id"); got != body.RequestID {
				t.Errorf("header request id %q does not match the body %q", got, body.RequestID)
			}
		})
	}
}

// permissiveLimits is a rate high enough that no behaviour test is
// accidentally about rate limiting. The limiter's own behaviour is tested in
// ratelimit_test.go against tight limits and an injected clock, so that the
// assertions there are exact rather than dependent on how fast the suite runs.
func permissiveLimits(t *testing.T, callers ...string) *limits.Limiter {
	t.Helper()
	if len(callers) == 0 {
		callers = []string{"tests"}
	}
	big := limits.Bucket{PerSecond: 1e6, Burst: 1e6}
	limiter, err := limits.New(
		limits.Config{PerCaller: big, Global: big, Unauthenticated: big}, callers)
	if err != nil {
		t.Fatalf("limits.New: %v", err)
	}
	return limiter
}
