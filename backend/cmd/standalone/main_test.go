package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunToolsHealthTextQuiet(t *testing.T) {
	t.Setenv("STANDALONE_PORT", "")
	t.Setenv("ENABLE_AUTONOMOUS_ORCHESTRATION", "false")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"-quiet", "tools", "health", "-format", "text"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "Tool health at ") {
		t.Fatalf("expected tools health text output, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected quiet mode to suppress startup output, got %q", stderr.String())
	}
}

func TestRunHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"help"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "abh [-quiet] scan") {
		t.Fatalf("expected help output, got %q", stdout.String())
	}
}

func TestParseStandaloneRuntimeConfigEnablesGoToolPreset(t *testing.T) {
	cfg, err := parseStandaloneRuntimeConfig([]string{"scan", "run", "-all-go-tools", "-allow-destructive"})
	if err != nil {
		t.Fatalf("parseStandaloneRuntimeConfig returned error: %v", err)
	}
	if !cfg.AllowDestructive {
		t.Fatal("expected allow destructive to be enabled")
	}
	if !cfg.EnableSubfinder || !cfg.EnableAmass || !cfg.EnableNikto || !cfg.EnableSQLMap || !cfg.EnableGobuster {
		t.Fatalf("expected Go tool preset to enable integrations, got %#v", cfg)
	}
}

func TestParseStandaloneRuntimeConfigEnablesForceFullScanPreset(t *testing.T) {
	cfg, err := parseStandaloneRuntimeConfig([]string{"scan", "run", "-force-full-scan"})
	if err != nil {
		t.Fatalf("parseStandaloneRuntimeConfig returned error: %v", err)
	}
	if !cfg.EnableSubfinder || !cfg.EnableAmass || !cfg.EnableNikto || !cfg.EnableSQLMap || !cfg.EnableGobuster {
		t.Fatalf("expected force full scan preset to enable integrations, got %#v", cfg)
	}
}

func TestBuildScanRequestBodyAppliesFullScanFlags(t *testing.T) {
	inputDir := t.TempDir()
	inputPath := filepath.Join(inputDir, "scan-request.json")
	if err := os.WriteFile(inputPath, []byte(`{"target":"https://old.example","options":{"passiveOnly":true}}`), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	body, err := buildScanRequestBody(scanFlagValues{
		inputPath:              inputPath,
		target:                 "https://override.example",
		idempotencyKey:         "scan-key",
		automationMode:         "conservative",
		fullScan:               true,
		useMLTriage:            true,
		useAttackPath:          true,
		useFalsePositiveReview: true,
		useRemediationPlanner:  true,
		wafBypass:              true,
		strictReporting:        true,
		minReportConfidence:    0.9,
	})
	if err != nil {
		t.Fatalf("buildScanRequestBody returned error: %v", err)
	}

	var req model.ScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if req.Target != "https://override.example" {
		t.Fatalf("expected target override, got %q", req.Target)
	}
	if req.IdempotencyKey != "scan-key" || req.Options.AutomationMode != "conservative" {
		t.Fatalf("expected CLI overrides, got %#v", req)
	}
	if !req.Options.UseNucleiIntegration || !req.Options.UseZAPBaselineIntegration || !req.Options.UseXSSMapIntegration {
		t.Fatalf("expected full scan to enable primary integrations, got %#v", req.Options)
	}
	if !req.Options.UseSubfinderIntegration || !req.Options.UseAmassIntegration || !req.Options.UseNiktoIntegration || !req.Options.UseSQLMapIntegration || !req.Options.UseGobusterIntegration {
		t.Fatalf("expected full scan to enable Go tool integrations, got %#v", req.Options)
	}
	if !req.Options.UseMLTriageAgent || !req.Options.UseAttackPathAgent || !req.Options.UseFalsePositiveReview || !req.Options.UseRemediationPlanner {
		t.Fatalf("expected ML/reporting flags to be applied, got %#v", req.Options)
	}
	if !req.Options.WAFBypass || !req.Options.StrictReporting || req.Options.MinReportConfidence != 0.9 {
		t.Fatalf("expected reporting/security flags to be applied, got %#v", req.Options)
	}
}

func TestBuildScanRequestBodyForceFullScanOverridesPassiveOnly(t *testing.T) {
	inputDir := t.TempDir()
	inputPath := filepath.Join(inputDir, "scan-request.json")
	if err := os.WriteFile(inputPath, []byte(`{"target":"https://old.example","options":{"passiveOnly":true}}`), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	body, err := buildScanRequestBody(scanFlagValues{
		inputPath:     inputPath,
		target:        "https://override.example",
		forceFullScan: true,
	})
	if err != nil {
		t.Fatalf("buildScanRequestBody returned error: %v", err)
	}

	var req model.ScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if req.Options.PassiveOnly {
		t.Fatalf("expected force full scan to disable passive-only mode, got %#v", req.Options)
	}
	if !req.Options.UseZAPBaselineIntegration || !req.Options.UseXSSMapIntegration || !req.Options.UseSubfinderIntegration {
		t.Fatalf("expected force full scan to enable full-scan integrations, got %#v", req.Options)
	}
}
