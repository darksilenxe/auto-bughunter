package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunToolsHealthUsesBackendHeaders(t *testing.T) {
	t.Setenv("AUTOBUGHUNTER_BACKEND_URL", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tools/health" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "test-key" {
			t.Fatalf("expected API key header, got %q", got)
		}
		if got := r.Header.Get("X-Workspace-ID"); got != "workspace-a" {
			t.Fatalf("expected workspace header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"checkedAt":"2026-04-28T00:00:00Z","tools":[{"name":"nuclei","binary":"nuclei","installed":true,"category":"vuln-scanning"}]}`)
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"tools", "health", "-backend-base", srv.URL, "-api-key", "test-key", "-workspace-id", "workspace-a"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), `"name": "nuclei"`) {
		t.Fatalf("expected JSON response, got %s", stdout.String())
	}
}

func TestRunMLDatasetExportIncludesLimitQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ml/engagements" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "7" {
			t.Fatalf("expected limit=7, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"records":[{"scanId":"scan-1"}]}`)
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"ml", "dataset", "export", "-backend-base", srv.URL, "-limit", "7", "-format", "text"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "Exported 1 engagement records" {
		t.Fatalf("unexpected text output %q", got)
	}
}

func TestRunMLScoreFindingsWrapsArrayInputAndToken(t *testing.T) {
	inputDir := t.TempDir()
	inputPath := filepath.Join(inputDir, "findings.json")
	if err := os.WriteFile(inputPath, []byte(`[{"id":"f-1","severity":"high","title":"Potential SQL injection"}]`), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/score-findings" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sidecar-secret" {
			t.Fatalf("expected sidecar token, got %q", got)
		}
		var payload map[string][]map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if len(payload["findings"]) != 1 {
			t.Fatalf("expected one wrapped finding, got %#v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"scoredFindings":[{"finding":{"title":"Potential SQL injection","severity":"high","category":"input_validation"},"score":0.91,"confidence":0.86,"exploitability":"high"}]}`)
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"ml", "score-findings", "-ml-base", srv.URL, "-sidecar-token", "sidecar-secret", "-input", inputPath, "-format", "text"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "Scored 1 findings") {
		t.Fatalf("unexpected output %q", stdout.String())
	}
}

func TestNormalizeMLRequestSupportsSingleFindingObject(t *testing.T) {
	body, err := normalizeMLRequest("false-positive-candidates", []byte(`{"title":"Header missing","severity":"low"}`), -1)
	if err != nil {
		t.Fatalf("normalizeMLRequest returned error: %v", err)
	}
	var payload map[string][]map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if len(payload["findings"]) != 1 {
		t.Fatalf("expected wrapped single finding, got %#v", payload)
	}
}
