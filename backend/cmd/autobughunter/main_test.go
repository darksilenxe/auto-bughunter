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

	"auto-bughunter/backend/internal/model"
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

func TestRunScanStartMergesInputAndFlags(t *testing.T) {
	inputDir := t.TempDir()
	inputPath := filepath.Join(inputDir, "scan-request.json")
	if err := os.WriteFile(inputPath, []byte(`{"target":"https://old.example","options":{"passiveOnly":true}}`), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/scan" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		var req model.ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.Target != "https://override.example" {
			t.Fatalf("expected overridden target, got %q", req.Target)
		}
		if !req.Options.PassiveOnly {
			t.Fatalf("expected passiveOnly=true, got %#v", req.Options)
		}
		if req.Options.AutomationMode != "conservative" {
			t.Fatalf("expected automationMode override, got %q", req.Options.AutomationMode)
		}
		if req.IdempotencyKey != "scan-key" {
			t.Fatalf("expected idempotency key, got %q", req.IdempotencyKey)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"scan-1","status":"queued"}`)
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{
		"scan", "start",
		"-backend-base", srv.URL,
		"-input", inputPath,
		"-target", "https://override.example",
		"-automation-mode", "conservative",
		"-idempotency-key", "scan-key",
		"-format", "text",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "Queued scan scan-1 (status=queued)" {
		t.Fatalf("unexpected output %q", got)
	}
}

func TestRunScanRunWaitsForCompletion(t *testing.T) {
	var getCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/scan":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"id":"scan-99","status":"queued"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/scan/scan-99":
			getCalls++
			w.Header().Set("Content-Type", "application/json")
			if getCalls == 1 {
				io.WriteString(w, `{"id":"scan-99","target":"https://app.example","status":"running"}`)
				return
			}
			io.WriteString(w, `{"id":"scan-99","target":"https://app.example","status":"completed","completedAt":"2026-04-28T00:00:00Z","findings":[{"severity":"high","category":"input_validation","title":"Potential SQL injection"},{"severity":"low","category":"headers","title":"Missing CSP"}]}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{
		"scan", "run",
		"-backend-base", srv.URL,
		"-target", "https://app.example",
		"-poll-interval", "1ms",
		"-wait-timeout", "1s",
		"-format", "text",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "Scan scan-99 for https://app.example: completed") {
		t.Fatalf("expected completed summary, got %q", out)
	}
	if !strings.Contains(out, "Findings: 2 (high=1 medium=0 low=1 info=0)") {
		t.Fatalf("expected findings summary, got %q", out)
	}
	if getCalls < 2 {
		t.Fatalf("expected polling, got %d GET calls", getCalls)
	}
}

func TestRunScanRunReturnsFinalFailedScanError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/scan":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"id":"scan-fail","status":"queued"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/scan/scan-fail":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"id":"scan-fail","target":"https://app.example","status":"failed","error":"boom"}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{
		"scan", "run",
		"-backend-base", srv.URL,
		"-target", "https://app.example",
		"-poll-interval", "1ms",
		"-wait-timeout", "1s",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected run to return an error for failed scan")
	}
	if !strings.Contains(err.Error(), "scan scan-fail failed: boom") {
		t.Fatalf("unexpected error %v", err)
	}
	if !strings.Contains(stdout.String(), `"status": "failed"`) {
		t.Fatalf("expected final failed scan JSON output, got %q", stdout.String())
	}
}
