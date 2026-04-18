package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// helper: build a minimal mux that exposes only handleToolsUpdates so the
// test doesn't drag in the full Server.Routes() chain (which requires a
// repo, ml service, etc.).
func newToolsUpdatesServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := &Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tools/updates", s.handleToolsUpdates)
	return httptest.NewServer(mux)
}

func TestHandleToolsUpdates_MissingReportReturns503(t *testing.T) {
	t.Setenv("TOOL_UPDATES_REPORT_PATH", filepath.Join(t.TempDir(), "missing.json"))
	srv := newToolsUpdatesServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/tools/updates")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when report is missing, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] == "" || body["hint"] == "" {
		t.Fatalf("expected error+hint in 503 body, got %v", body)
	}
}

func TestHandleToolsUpdates_ReturnsReportVerbatim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	payload := `{"generatedAt":"2026-04-18T00:00:00Z","summary":{"outdated":1,"current":2,"failed":0},"tools":[{"name":"nuclei","status":"current"}]}`
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Setenv("TOOL_UPDATES_REPORT_PATH", path)

	srv := newToolsUpdatesServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/tools/updates")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != payload {
		t.Fatalf("expected report served verbatim; got %q", string(body))
	}
}

func TestHandleToolsUpdates_InvalidJSONReturns500(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Setenv("TOOL_UPDATES_REPORT_PATH", path)

	srv := newToolsUpdatesServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/tools/updates")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 for malformed report, got %d", resp.StatusCode)
	}
}

func TestHandleToolsUpdates_RejectsNonGET(t *testing.T) {
	srv := newToolsUpdatesServer(t)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/tools/updates", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}
