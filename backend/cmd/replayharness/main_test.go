package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHistoricalRunFixture(t *testing.T, dir, payload string) string {
	t.Helper()
	path := filepath.Join(dir, "history.json")
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestRunPassesGateThresholds(t *testing.T) {
	dir := t.TempDir()
	input := writeHistoricalRunFixture(t, dir, `{
  "scanId": "scan-1",
  "target": "https://example.com",
  "availableAgents": ["analysis", "reconnaissance", "scanning", "input_validation"],
  "runs": [
    {"agentName": "reconnaissance"},
    {"agentName": "scanning"},
    {"agentName": "input_validation"},
    {"agentName": "analysis"}
  ]
}
`)
	var stdout, stderr bytes.Buffer

	err := run([]string{
		"-input", input,
		"-baseline", "static",
		"-candidate", "recorded",
		"-min-candidate-match-rate", "1.0",
		"-min-candidate-first-choice-rate", "1.0",
		"-max-candidate-early-stops", "0",
		"-require-candidate-not-worse",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("expected success, got err=%v stderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"candidate"`) {
		t.Fatalf("expected JSON output containing candidate report, got: %s", stdout.String())
	}
}

func TestRunFailsWhenCandidateRegresses(t *testing.T) {
	dir := t.TempDir()
	input := writeHistoricalRunFixture(t, dir, `{
  "scanId": "scan-2",
  "target": "https://example.com",
  "availableAgents": ["analysis", "reconnaissance", "scanning", "input_validation"],
  "runs": [
    {"agentName": "reconnaissance"},
    {"agentName": "scanning"},
    {"agentName": "input_validation"},
    {"agentName": "analysis"}
  ]
}
`)
	var stdout, stderr bytes.Buffer

	err := run([]string{
		"-input", input,
		"-baseline", "recorded",
		"-candidate", "static",
		"-require-candidate-not-worse",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected regression gate to fail")
	}
	if !strings.Contains(err.Error(), "regressed from baseline") {
		t.Fatalf("expected regression error, got: %v", err)
	}
}

func TestRunFailsOnEarlyStopCeiling(t *testing.T) {
	dir := t.TempDir()
	input := writeHistoricalRunFixture(t, dir, `{
  "scanId": "scan-3",
  "target": "https://example.com",
  "availableAgents": [],
  "runs": [
    {"agentName": "reconnaissance"}
  ]
}
`)
	var stdout, stderr bytes.Buffer

	err := run([]string{
		"-input", input,
		"-baseline", "static",
		"-candidate", "static",
		"-max-candidate-early-stops", "0",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected early-stop ceiling to fail")
	}
	if !strings.Contains(err.Error(), "early stops") {
		t.Fatalf("expected early stop error, got: %v", err)
	}
}
