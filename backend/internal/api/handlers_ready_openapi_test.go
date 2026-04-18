package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthMiddleware_NewExemptPaths(t *testing.T) {
	mux := http.NewServeMux()
	for _, p := range []string{"/api/ready", "/api/openapi.json"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	h := authMiddleware("secret-token", mux)
	srv := httptest.NewServer(h)
	defer srv.Close()
	for _, path := range []string{"/api/ready", "/api/openapi.json"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for exempt %s, got %d", path, resp.StatusCode)
		}
	}
}

func TestRequestLoggingMiddleware_PropagatesAndGeneratesRequestID(t *testing.T) {
	called := false
	h := requestLoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Generated when no header is supplied.
	resp, err := http.Get(srv.URL + "/api/scan")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if !called {
		t.Fatal("downstream handler not invoked")
	}
	if got := resp.Header.Get(requestIDHeader); got == "" {
		t.Errorf("expected generated %s header", requestIDHeader)
	}
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("expected 418, got %d", resp.StatusCode)
	}

	// Propagated when caller supplies a value.
	req, _ := http.NewRequest("GET", srv.URL+"/api/scan", nil)
	req.Header.Set(requestIDHeader, "trace-abc")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get(requestIDHeader); got != "trace-abc" {
		t.Errorf("expected propagated request id 'trace-abc', got %q", got)
	}
}

type stubPinger struct{ err error }

func (s stubPinger) Ping(_ context.Context) error { return s.err }

type stubRepoOK struct{ Repository }

func (stubRepoOK) Ping(_ context.Context) error { return nil }

type stubRepoBad struct{ Repository }

func (stubRepoBad) Ping(_ context.Context) error { return errors.New("db down") }

func TestHandleReady_OK(t *testing.T) {
	s := &Server{repo: stubRepoOK{}}
	req := httptest.NewRequest("GET", "/api/ready", nil)
	rr := httptest.NewRecorder()
	s.handleReady(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), `"status":"ready"`) {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestHandleReady_DBDown(t *testing.T) {
	s := &Server{repo: stubRepoBad{}}
	req := httptest.NewRequest("GET", "/api/ready", nil)
	rr := httptest.NewRecorder()
	s.handleReady(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), `"status":"not_ready"`) {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestHandleOpenAPI_ReturnsValidDoc(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/api/openapi.json", nil)
	rr := httptest.NewRecorder()
	s.handleOpenAPI(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Errorf("expected openapi=3.1.0, got %v", doc["openapi"])
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatal("expected paths object")
	}
	for _, p := range []string{"/api/health", "/api/ready", "/api/scan", "/api/suppressions", "/metrics"} {
		if _, ok := paths[p]; !ok {
			t.Errorf("openapi missing path %s", p)
		}
	}
}

// Compile-time assertion that stubPinger satisfies the Pinger interface
// even though it isn't used directly above; this keeps the interface
// stable as the Repository interface evolves.
var _ Pinger = stubPinger{}
