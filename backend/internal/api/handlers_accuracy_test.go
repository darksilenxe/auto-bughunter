package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func writeCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// One vulnerable target with an expected SQLi and one clean target.
	manifest := map[string]any{
		"target":      "juice-shop",
		"description": "test target",
		"baseUrl":     "https://example.com",
		"expectedFindings": []map[string]any{
			{
				"category": "sqli",
				"endpoint": "/rest/products/search",
				"parameter": "q",
			},
		},
		"safeEndpoints": []map[string]any{
			{"category": "xss", "endpoint": "/health"},
		},
	}
	clean := map[string]any{
		"target":           "clean-json-api",
		"description":      "no known vulns",
		"expectedFindings": []map[string]any{},
	}
	for name, m := range map[string]map[string]any{"juice-shop.json": manifest, "clean-json-api.json": clean} {
		b, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
	}
	return dir
}

func TestHandleAccuracyCorpus(t *testing.T) {
	dir := writeCorpus(t)
	t.Setenv("ACCURACY_CORPUS_DIR", dir)

	s := &Server{}
	req := authRequest(http.MethodGet, "/api/accuracy/corpus", nil)
	rec := httptest.NewRecorder()
	s.handleAccuracyCorpus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		CorpusDir string                    `json:"corpusDir"`
		Manifests []accuracyManifestSummary `json:"manifests"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.CorpusDir != dir {
		t.Errorf("expected corpusDir=%q, got %q", dir, body.CorpusDir)
	}
	if len(body.Manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(body.Manifests))
	}
	// Sorted by target ("clean-json-api" then "juice-shop").
	if body.Manifests[0].Target != "clean-json-api" || body.Manifests[1].Target != "juice-shop" {
		t.Errorf("unexpected ordering: %+v", body.Manifests)
	}
	if body.Manifests[1].ExpectedFindingsCount != 1 {
		t.Errorf("expected juice-shop to list 1 expected finding, got %d", body.Manifests[1].ExpectedFindingsCount)
	}
	if body.Manifests[1].SafeEndpointsCount != 1 {
		t.Errorf("expected juice-shop to list 1 safe endpoint, got %d", body.Manifests[1].SafeEndpointsCount)
	}
	if len(body.Manifests[1].Categories) != 1 || body.Manifests[1].Categories[0] != "sqli" {
		t.Errorf("expected juice-shop categories=[sqli], got %+v", body.Manifests[1].Categories)
	}
}

func TestHandleAccuracyRun(t *testing.T) {
	dir := writeCorpus(t)
	t.Setenv("ACCURACY_CORPUS_DIR", dir)

	completed := time.Now().UTC()
	jobs := map[string]*model.ScanJob{
		"scan-vuln": {
			ID:          "scan-vuln",
			Target:      "https://juice-shop.example.com",
			WorkspaceID: "default",
			Status:      "completed",
			CompletedAt: &completed,
			Findings: []model.Finding{
				{
					ID:                "sqli-hit",
					Category:          "sqli",
					Severity:          model.SeverityHigh,
					Title:             "SQL injection",
					AffectedURL:       "https://juice-shop.example.com/rest/products/search",
					AffectedParameter: "q",
				},
			},
		},
		"scan-clean": {
			ID:          "scan-clean",
			Target:      "https://clean-json-api.example.com",
			WorkspaceID: "default",
			Status:      "completed",
			CompletedAt: &completed,
			Findings:    []model.Finding{},
		},
	}
	s := &Server{repo: &reportTestRepo{jobs: jobs}}

	body := []byte(`{"actuals":[
		{"target":"juice-shop","scanId":"scan-vuln","preReportVerificationPassRate":0.95},
		{"target":"clean-json-api","scanId":"scan-clean"}
	]}`)
	req := authRequest(http.MethodPost, "/api/accuracy/run", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleAccuracyRun(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Report struct {
			TruePositives  int     `json:"truePositives"`
			FalsePositives int     `json:"falsePositives"`
			FalseNegatives int     `json:"falseNegatives"`
			Precision      float64 `json:"precision"`
			Recall         float64 `json:"recall"`
		} `json:"report"`
		Markdown  string            `json:"markdown"`
		UsedScans map[string]string `json:"usedScans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Report.TruePositives != 1 || resp.Report.FalsePositives != 0 || resp.Report.FalseNegatives != 0 {
		t.Errorf("expected 1TP/0FP/0FN, got %+v", resp.Report)
	}
	if resp.Report.Precision != 1 || resp.Report.Recall != 1 {
		t.Errorf("expected precision=recall=1, got %+v", resp.Report)
	}
	if resp.UsedScans["juice-shop"] != "scan-vuln" || resp.UsedScans["clean-json-api"] != "scan-clean" {
		t.Errorf("unexpected usedScans: %+v", resp.UsedScans)
	}
	if resp.Markdown == "" {
		t.Errorf("expected markdown report")
	}
}

func TestHandleAccuracyRun_UnknownScan(t *testing.T) {
	dir := writeCorpus(t)
	t.Setenv("ACCURACY_CORPUS_DIR", dir)

	s := &Server{repo: &reportTestRepo{jobs: map[string]*model.ScanJob{}}}
	body := []byte(`{"actuals":[{"target":"juice-shop","scanId":"does-not-exist"}]}`)
	req := authRequest(http.MethodPost, "/api/accuracy/run", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleAccuracyRun(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAccuracyRun_MissingBody(t *testing.T) {
	dir := writeCorpus(t)
	t.Setenv("ACCURACY_CORPUS_DIR", dir)

	s := &Server{repo: &reportTestRepo{jobs: map[string]*model.ScanJob{}}}
	req := authRequest(http.MethodPost, "/api/accuracy/run", bytes.NewReader([]byte(`{"actuals":[]}`)))
	rec := httptest.NewRecorder()
	s.handleAccuracyRun(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
