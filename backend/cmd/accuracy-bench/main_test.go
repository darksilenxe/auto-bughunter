package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/accuracybench"
	"auto-bughunter/backend/internal/model"
)

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus")
	actuals := filepath.Join(dir, "actuals")
	writeJSONFile(t, filepath.Join(corpus, "t.json"), accuracybench.Manifest{
		Target: "t",
		ExpectedFindings: []accuracybench.ExpectedFinding{
			{Category: "sqli", Endpoint: "/a"},
		},
	})
	writeJSONFile(t, filepath.Join(actuals, "t.json"), accuracybench.ActualScan{
		Target:                        "t",
		Findings:                      []model.Finding{{Category: "sqli", AffectedURL: "/a"}},
		PreReportVerificationPassRate: 1.0,
	})

	out := filepath.Join(dir, "report.json")
	md := filepath.Join(dir, "report.md")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-corpus", corpus, "-actuals", actuals, "-output-json", out, "-output-md", md}, &stdout, &stderr); err != nil {
		t.Fatalf("run failed: %v (stderr=%s)", err, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"truePositives": 1`)) {
		t.Fatalf("expected 1 TP in JSON, got:\n%s", data)
	}
	mdData, err := os.ReadFile(md)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mdData), "Aggregate") {
		t.Fatalf("markdown missing Aggregate section:\n%s", mdData)
	}
}

func TestRunFailOnRegression(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus")
	actuals := filepath.Join(dir, "actuals")
	writeJSONFile(t, filepath.Join(corpus, "t.json"), accuracybench.Manifest{
		Target: "t",
		ExpectedFindings: []accuracybench.ExpectedFinding{
			{Category: "sqli", Endpoint: "/a"},
			{Category: "sqli", Endpoint: "/b"},
		},
	})
	// Actual scan misses /b — precision 1.0, recall 0.5.
	writeJSONFile(t, filepath.Join(actuals, "t.json"), accuracybench.ActualScan{
		Target:                        "t",
		Findings:                      []model.Finding{{Category: "sqli", AffectedURL: "/a"}},
		PreReportVerificationPassRate: 1.0,
	})
	// Baseline says recall was 1.0 — expect a regression.
	baseline := accuracybench.Report{
		Precision: 1.0, Recall: 1.0, F1: 1.0,
		MeanPreReportVerificationPassRate: 1.0,
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	writeJSONFile(t, baselinePath, baseline)

	out := filepath.Join(dir, "report.json")
	deltaMD := filepath.Join(dir, "delta.md")
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"-corpus", corpus,
		"-actuals", actuals,
		"-output-json", out,
		"-baseline", baselinePath,
		"-delta-output-md", deltaMD,
		"-fail-on-regression",
		"-tolerance", "0.01",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected regression failure, got nil")
	}
	if !strings.Contains(err.Error(), "regression") {
		t.Fatalf("expected regression error, got %v", err)
	}
	if _, err := os.Stat(deltaMD); err != nil {
		t.Fatalf("expected delta markdown to be written: %v", err)
	}
}

func TestRunNoRegressionWithinTolerance(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus")
	actuals := filepath.Join(dir, "actuals")
	writeJSONFile(t, filepath.Join(corpus, "t.json"), accuracybench.Manifest{
		Target:           "t",
		ExpectedFindings: []accuracybench.ExpectedFinding{{Category: "sqli", Endpoint: "/a"}},
	})
	writeJSONFile(t, filepath.Join(actuals, "t.json"), accuracybench.ActualScan{
		Target:                        "t",
		Findings:                      []model.Finding{{Category: "sqli", AffectedURL: "/a"}},
		PreReportVerificationPassRate: 0.99,
	})
	baseline := accuracybench.Report{Precision: 1.0, Recall: 1.0, F1: 1.0, MeanPreReportVerificationPassRate: 1.0}
	baselinePath := filepath.Join(dir, "baseline.json")
	writeJSONFile(t, baselinePath, baseline)

	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"-corpus", corpus, "-actuals", actuals,
		"-baseline", baselinePath,
		"-fail-on-regression",
		"-tolerance", "0.05",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("expected no failure within tolerance, got %v", err)
	}
}

func TestRunMissingCorpusFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-actuals", "/tmp"}, &stdout, &stderr); err == nil {
		t.Fatal("expected error when -corpus missing")
	}
}
