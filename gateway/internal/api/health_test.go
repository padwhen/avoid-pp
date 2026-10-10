package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/padwhen/avoid-pp/gateway/internal/middleware"
)

// healthRouter builds a router with no detector, so only health routes exist.
func healthRouter(readiness *Readiness) http.Handler {
	return NewRouter(readiness, ScanDeps{})
}

func get(t *testing.T, handler http.Handler, path string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func body(t *testing.T, rec *httptest.ResponseRecorder) healthBody {
	t.Helper()
	var parsed healthBody
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response is not JSON: %v (%q)", err, rec.Body.String())
	}
	return parsed
}

// C07-AC1: liveness answers regardless of initialisation state and makes no
// external call. A probe that depends on a model provider bills on every
// scrape and declares the process dead when that provider wobbles.
func TestLivenessIgnoresReadiness(t *testing.T) {
	readiness := NewReadiness()
	router := healthRouter(readiness)

	rec := get(t, router, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("liveness before init = %d, want 200", rec.Code)
	}
	if got := body(t, rec).Status; got != "ok" {
		t.Errorf("status = %q, want ok", got)
	}

	readiness.SetReady()
	if rec := get(t, router, "/healthz", nil); rec.Code != http.StatusOK {
		t.Errorf("liveness after init = %d, want 200", rec.Code)
	}
}

// C07-AC1: readiness reflects initialisation status.
func TestReadinessTracksInitialisation(t *testing.T) {
	readiness := NewReadiness()
	router := healthRouter(readiness)

	rec := get(t, router, "/readyz", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness before init = %d, want 503", rec.Code)
	}
	if got := body(t, rec).Status; got != "not_ready" {
		t.Errorf("status = %q, want not_ready", got)
	}

	readiness.SetReady()
	rec = get(t, router, "/readyz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("readiness after init = %d, want 200", rec.Code)
	}
	if got := body(t, rec).Status; got != "ready" {
		t.Errorf("status = %q, want ready", got)
	}

	readiness.SetNotReady()
	if rec := get(t, router, "/readyz", nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readiness after drain = %d, want 503", rec.Code)
	}
}

// C07 asserted this endpoint did not exist yet. It exists from C09 - but only
// when a detector is configured. Without one the route is not registered at
// all, so it 404s rather than answering without the ability to scan.
func TestScanRouteAbsentWithoutADetector(t *testing.T) {
	rec := get(t, healthRouter(NewReadiness()), "/v1/scans", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /v1/scans without a detector = %d, want 404", rec.Code)
	}
}

func TestRequestIDIsGeneratedAndEchoed(t *testing.T) {
	rec := get(t, healthRouter(NewReadiness()), "/healthz", nil)
	id := rec.Header().Get(middleware.HeaderRequestID)
	if id == "" {
		t.Fatal("no request id on the response")
	}
	if got := body(t, rec).RequestID; got != id {
		t.Errorf("body request_id = %q, header = %q; want equal", got, id)
	}
}

func TestRequestIDPropagationAndRejection(t *testing.T) {
	cases := map[string]struct {
		inbound string
		reused  bool
	}{
		"plain id is reused":       {"abc-123_x.y:z", true},
		"empty is replaced":        {"", false},
		"newline is replaced":      {"abc\ninjected log line", false},
		"space is replaced":        {"abc 123", false},
		"over-long is replaced":    {string(make([]byte, 0, 65)) + "0123456789012345678901234567890123456789012345678901234567890123456789", false},
		"control char is replaced": {"abc\x00def", false},
		"ansi escape is replaced":  {"abc\x1b[31m", false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := get(t, healthRouter(NewReadiness()), "/healthz",
				map[string]string{middleware.HeaderRequestID: tc.inbound})
			got := rec.Header().Get(middleware.HeaderRequestID)
			if tc.reused && got != tc.inbound {
				t.Fatalf("request id = %q, want the inbound %q", got, tc.inbound)
			}
			if !tc.reused && got == tc.inbound {
				t.Fatalf("unsafe inbound id %q was reused verbatim", tc.inbound)
			}
			if got == "" {
				t.Fatal("no request id issued")
			}
		})
	}
}
