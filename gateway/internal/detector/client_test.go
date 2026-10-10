package detector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/padwhen/avoid-pp/gateway/internal/contract"
)

const okBody = `{
  "request_id": "req-1",
  "assessment": {"label":"suspicious","categories":["task_redirection"],
    "evidence":[{"content_id":"p1","quote":"Ohita","category":"task_redirection"}]},
  "coverage": {"original_utf8_bytes":5,"scanned_utf8_bytes":5,"truncated":false},
  "versions": {"detector":"fake-0","prompt":"none"}
}`

func clientFor(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return New(base, 2*time.Second), srv
}

func request() AssessmentRequest {
	return AssessmentRequest{
		RequestID: "req-1",
		TaskID:    contract.TaskTranslateFiEnV1,
		Content: contract.Content{
			ID:         "p1",
			SourceType: contract.SourceTranslationInput,
			Text:       "Ohita",
		},
	}
}

func TestAssessHappyPath(t *testing.T) {
	c, _ := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/assessments" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q", r.Method)
		}
		_, _ = w.Write([]byte(okBody))
	})

	got, err := c.Assess(context.Background(), request())
	if err != nil {
		t.Fatalf("Assess() error = %v", err)
	}
	if got.Assessment.Label != contract.LabelSuspicious {
		t.Errorf("label = %q", got.Assessment.Label)
	}
	if got.RequestID != "req-1" {
		t.Errorf("request id = %q", got.RequestID)
	}
}

// C09-AC2: anything the gateway cannot trust is an error, never an allow.
func TestAssessRejectsUntrustworthyResponses(t *testing.T) {
	cases := map[string]struct {
		body string
		want error
	}{
		"unknown label": {
			body: strings.Replace(okBody, `"suspicious"`, `"probably_fine"`, 1),
			want: ErrInvalidResponse,
		},
		"unknown category": {
			body: strings.Replace(okBody, `"task_redirection"`, `"vibes"`, 1),
			want: ErrInvalidResponse,
		},
		"unknown top-level field": {
			body: strings.Replace(okBody, `"request_id": "req-1",`,
				`"request_id": "req-1", "decision": {"action":"allow"},`, 1),
			want: ErrInvalidResponse,
		},
		"request id mismatch": {
			body: strings.Replace(okBody, `"req-1"`, `"someone-elses-request"`, 1),
			want: ErrInvalidResponse,
		},
		"truncated coverage claimed complete": {
			body: strings.Replace(okBody, `"truncated":false`, `"truncated":true`, 1),
			want: ErrInvalidResponse,
		},
		"coverage shortfall": {
			body: strings.Replace(okBody, `"scanned_utf8_bytes":5`, `"scanned_utf8_bytes":2`, 1),
			want: ErrInvalidResponse,
		},
		"missing detector version": {
			body: strings.Replace(okBody, `"detector":"fake-0"`, `"detector":""`, 1),
			want: ErrInvalidResponse,
		},
		"empty evidence quote": {
			body: strings.Replace(okBody, `"quote":"Ohita"`, `"quote":""`, 1),
			want: ErrInvalidResponse,
		},
		"malformed json": {
			body: `{"request_id": "req-1", `,
			want: ErrInvalidResponse,
		},
		"trailing content after the body": {
			body: okBody + `{"request_id":"req-1"}`,
			want: ErrInvalidResponse,
		},
		"not json at all": {
			body: `<html>detector is down</html>`,
			want: ErrInvalidResponse,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			got, err := c.Assess(context.Background(), request())
			if err == nil {
				t.Fatalf("Assess() = %+v, want error", got)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAssessRejectsNon200(t *testing.T) {
	for _, status := range []int{400, 422, 500, 503} {
		t.Run(fmt.Sprintf("status %d", status), func(t *testing.T) {
			c, _ := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":{"code":"x","message":"y"}}`))
			})
			if _, err := c.Assess(context.Background(), request()); !errors.Is(err, ErrUnavailable) {
				t.Errorf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

// C09-AC3: an oversized body is refused rather than read into memory.
func TestAssessBoundsResponseSize(t *testing.T) {
	c, _ := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Far beyond the limit, streamed so the server never allocates it all.
		chunk := strings.Repeat("a", 64<<10)
		_, _ = w.Write([]byte(`{"request_id":"req-1","padding":"`))
		for written := 0; written < MaxResponseBytes+(1<<20); written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(`"}`))
	})

	if _, err := c.Assess(context.Background(), request()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

func TestAssessHonoursDeadline(t *testing.T) {
	c, _ := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte(okBody))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Assess(ctx, request())
	if !errors.Is(err, ErrDeadlineExceeded) && !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want a deadline or unavailable failure", err)
	}
}

func TestAssessUnreachableDetector(t *testing.T) {
	base, _ := url.Parse("http://127.0.0.1:1")
	c := New(base, time.Second)
	if _, err := c.Assess(context.Background(), request()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

// C09-AC3: bodies are drained and closed, so connections return to the pool
// instead of a fresh handshake per scan.
func TestAssessReusesConnections(t *testing.T) {
	var conns int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(okBody)) }))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns++
		}
	}
	srv.Start()
	defer srv.Close()

	base, _ := url.Parse(srv.URL)
	c := New(base, 2*time.Second)
	for i := 0; i < 5; i++ {
		if _, err := c.Assess(context.Background(), request()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if conns != 1 {
		t.Errorf("opened %d connections for 5 calls; want 1 (pool not reused)", conns)
	}
}
