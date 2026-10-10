// C24: cross-service failure behaviour.
//
// Every test here drives the real scan handler through the real detector
// client over a real HTTP connection, against a stand-in service built to
// misbehave. Substituting a fake Assessor would skip the client — and the
// client is where timeouts, size limits, body draining and connection reuse
// live, which is most of what can go wrong between two services.
//
// The single invariant underneath all of it: **no failure becomes an allow.**
// A guard that fails open has not failed, it has stopped guarding, and that is
// indistinguishable from success in every log and dashboard.
package integration

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/admission"
	"github.com/padwhen/avoid-pp/gateway/internal/api"
	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
	"github.com/padwhen/avoid-pp/gateway/internal/detector"
	"github.com/padwhen/avoid-pp/gateway/internal/limits"
	"github.com/padwhen/avoid-pp/gateway/internal/obs"
	"github.com/padwhen/avoid-pp/gateway/internal/policy"
)

// fault names a way the detector service can misbehave.
type fault string

const (
	faultHealthy fault = "healthy"
	// Transport and timing.
	faultSlow        fault = "slow"         // answers, but after the deadline
	faultHang        fault = "hang"         // never answers at all
	faultHangupEarly fault = "hangup_early" // closes before any bytes
	faultHangupMid   fault = "hangup_mid"   // closes mid-body
	faultEmptyBody   fault = "empty_body"   // 200 with nothing in it
	// Shape.
	faultMalformedJSON      fault = "malformed_json"
	faultTruncatedJSON      fault = "truncated_json"
	faultTrailingJSON       fault = "trailing_json"
	faultHugeBody           fault = "huge_body"
	faultWrongRequestID     fault = "wrong_request_id"
	faultUnknownLabel       fault = "unknown_label"
	faultUnknownCategory    fault = "unknown_category"
	faultMissingVersions    fault = "missing_versions"
	faultIncompleteCoverage fault = "incomplete_coverage"
	faultNotJSON            fault = "not_json"
	// Status.
	faultStatus500 fault = "status_500"
	faultStatus502 fault = "status_502"
	faultStatus429 fault = "status_429"
	faultStatus401 fault = "status_401"
	faultStatus204 fault = "status_204"
	// The nastiest one: a well-formed reply that says the passage is clean,
	// delivered where an error was expected. This is the case that would
	// silently become an allow if anything downstream trusted a 200 blindly.
	faultCleanButWrongShape fault = "clean_but_wrong_shape"
)

// faultyDetector is an HTTP server that answers however it is told to.
//
// The mode is swapped between requests rather than configured once, so one
// test can walk the whole matrix against a single gateway and assert that
// state does not accumulate across failures.
type faultyDetector struct {
	server *httptest.Server
	mu     sync.Mutex
	mode   fault
	calls  int
	// inflight counts requests currently inside the handler, so a shutdown
	// test can wait for work to be provably in flight rather than guess.
	inflight int
	// release, when non-nil, holds every request until it is closed. This is
	// how a drain test keeps work in flight across the shutdown signal
	// without depending on timing.
	release chan struct{}
}

func newFaultyDetector(t *testing.T) *faultyDetector {
	t.Helper()
	fd := &faultyDetector{mode: faultHealthy}
	fd.server = httptest.NewServer(http.HandlerFunc(fd.serve))
	t.Cleanup(fd.server.Close)
	return fd
}

func (f *faultyDetector) set(mode fault) {
	f.mu.Lock()
	f.mode = mode
	f.mu.Unlock()
}

func (f *faultyDetector) current() fault {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.mode
}

func (f *faultyDetector) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// hold makes every subsequent request block until release is closed.
func (f *faultyDetector) hold(release chan struct{}) {
	f.mu.Lock()
	f.release = release
	f.mu.Unlock()
}

// inFlight reports how many requests are currently inside the handler.
func (f *faultyDetector) inFlight() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inflight
}

func (f *faultyDetector) enter() chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inflight++
	return f.release
}

func (f *faultyDetector) leave() {
	f.mu.Lock()
	f.inflight--
	f.mu.Unlock()
}

func (f *faultyDetector) url(t *testing.T) *url.URL {
	t.Helper()
	parsed, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return parsed
}

func (f *faultyDetector) serve(w http.ResponseWriter, r *http.Request) {
	release := f.enter()
	// Decremented exactly once, on every path. The first draft decremented
	// twice on the cancelled branch, which made inFlight go negative and the
	// shutdown test wait for a count it could never see.
	defer f.leave()
	if release != nil {
		// Held until the test lets go, so work is provably in flight.
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
	}

	var request detector.AssessmentRequest
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &request)

	clean := func(requestID string) map[string]any {
		size := len(request.Content.Text)
		return map[string]any{
			"request_id": requestID,
			"assessment": map[string]any{
				"label":      "no_injection_detected",
				"categories": []string{},
				"evidence":   []any{},
			},
			"coverage": map[string]any{
				"original_utf8_bytes": size,
				"scanned_utf8_bytes":  size,
				"truncated":           false,
			},
			"versions": map[string]any{"detector": "faulty-fake", "prompt": "none"},
		}
	}

	switch f.current() {
	case faultHealthy:
		writeJSON(w, http.StatusOK, clean(request.RequestID))

	case faultSlow:
		// Longer than any deadline the tests configure, but abandoned as soon
		// as the client gives up. A plain Sleep would keep the handler busy
		// after the client had gone, and httptest.Server.Close waits for
		// outstanding requests — so the suite would pay for every timeout
		// twice. A real server notices a hangup, and so does this one.
		if !sleepUnlessCancelled(r, 2*time.Second) {
			return
		}
		writeJSON(w, http.StatusOK, clean(request.RequestID))

	case faultHang:
		// Hold the connection open with no reply at all, bounded for the same
		// reason.
		sleepUnlessCancelled(r, 3*time.Second)

	case faultHangupEarly:
		hijackAndClose(w, 0)

	case faultHangupMid:
		// Promise a length, send part of it, then close. This is the case a
		// naive client treats as a short read rather than a failure.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"request_id":"` + request.RequestID + `","assess`))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		hijackAndClose(w, 0)

	case faultEmptyBody:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

	case faultMalformedJSON:
		writeRaw(w, http.StatusOK, `{"request_id": }{`)

	case faultTruncatedJSON:
		writeRaw(w, http.StatusOK, `{"request_id":"`+request.RequestID+`","assessment":{`)

	case faultTrailingJSON:
		payload, _ := json.Marshal(clean(request.RequestID))
		writeRaw(w, http.StatusOK, string(payload)+`{"extra":1}`)

	case faultHugeBody:
		// Past MaxResponseBytes. The client must stop reading rather than
		// buffer it, which is what the size limit exists for.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("a", 64<<10)
		for written := 0; written < detector.MaxResponseBytes*3; written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}

	case faultWrongRequestID:
		writeJSON(w, http.StatusOK, clean("not-the-request-id"))

	case faultUnknownLabel:
		payload := clean(request.RequestID)
		payload["assessment"].(map[string]any)["label"] = "probably_fine"
		writeJSON(w, http.StatusOK, payload)

	case faultUnknownCategory:
		payload := clean(request.RequestID)
		payload["assessment"].(map[string]any)["categories"] = []string{"vibes"}
		writeJSON(w, http.StatusOK, payload)

	case faultMissingVersions:
		payload := clean(request.RequestID)
		payload["versions"] = map[string]any{"detector": "", "prompt": ""}
		writeJSON(w, http.StatusOK, payload)

	case faultIncompleteCoverage:
		payload := clean(request.RequestID)
		// Claims a complete scan while reporting it read ten of N bytes. The
		// contract makes this unrepresentable; the client must agree.
		payload["coverage"] = map[string]any{
			"original_utf8_bytes": len(request.Content.Text),
			"scanned_utf8_bytes":  10,
			"truncated":           false,
		}
		writeJSON(w, http.StatusOK, payload)

	case faultNotJSON:
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))

	case faultStatus500:
		writeRaw(w, http.StatusInternalServerError, `{"error":"boom"}`)
	case faultStatus502:
		writeRaw(w, http.StatusBadGateway, `<html>bad gateway</html>`)
	case faultStatus429:
		w.Header().Set("Retry-After", "30")
		writeRaw(w, http.StatusTooManyRequests, `{"error":"slow down"}`)
	case faultStatus401:
		writeRaw(w, http.StatusUnauthorized, `{"error":"nope"}`)
	case faultStatus204:
		w.WriteHeader(http.StatusNoContent)

	case faultCleanButWrongShape:
		// A clean verdict in a body the contract does not define. The danger
		// is a client that finds "no_injection_detected" somewhere and acts
		// on it; the contract requires the whole shape or nothing.
		writeRaw(w, http.StatusOK,
			`{"verdict":"no_injection_detected","ok":true,"allow":true}`)
	}
}

// sleepUnlessCancelled waits, returning false if the client gave up first.
func sleepUnlessCancelled(r *http.Request, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-r.Context().Done():
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeRaw(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// hijackAndClose takes the connection and closes it, which is the only way to
// produce a mid-response disconnect from a Go handler.
func hijackAndClose(w http.ResponseWriter, _ int) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	_ = buffered.Flush()
	_ = conn.(*net.TCPConn).SetLinger(0)
	_ = conn.Close()
}

// faultRouter wires the real handler and real client against the faulty
// service, with generous limits so the only thing under test is failure
// behaviour.
func faultRouter(
	t *testing.T, fd *faultyDetector, timeout time.Duration,
) (http.Handler, *strings.Builder) {
	t.Helper()

	registry, err := auth.NewRegistry([]auth.KeySpec{{
		Name:  "faults",
		Key:   "fault-test-key-aaaaaaaaaaaaaaaaaaaaaa",
		Tasks: []contract.TaskID{contract.TaskTranslateFiEnV1},
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	big := limits.Bucket{PerSecond: 1e6, Burst: 1e6}
	limiter, err := limits.New(
		limits.Config{PerCaller: big, Global: big, Unauthenticated: big},
		[]string{"faults"})
	if err != nil {
		t.Fatalf("limits.New: %v", err)
	}
	controller, err := admission.New(admission.Config{MaxActive: 4, MaxQueued: 8})
	if err != nil {
		t.Fatalf("admission.New: %v", err)
	}

	logs := &strings.Builder{}
	readiness := api.NewReadiness()
	readiness.SetReady()
	return api.NewRouter(readiness, api.ScanDeps{
		Detector:  detector.New(fd.url(t), timeout),
		Timeout:   timeout,
		Log:       slog.New(obs.NewHandler(logs, slog.LevelDebug)),
		Mode:      policy.ModeEnforcement,
		Callers:   registry,
		Limiter:   limiter,
		Admission: controller,
	}), logs
}

const faultKey = "fault-test-key-aaaaaaaaaaaaaaaaaaaaaa"

func faultScan(t *testing.T, router http.Handler, text string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"task_id": "translate_fi_en_v1",
		"content": map[string]any{
			"id":            "p-fault",
			"source_type":   "translation_input",
			"language_hint": "fi",
			"text":          text,
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+faultKey)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

const synthetic = "Sää on tänään aurinkoinen ja lämpötila nousee iltapäivällä."
