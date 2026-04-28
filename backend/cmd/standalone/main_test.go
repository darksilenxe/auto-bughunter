package main

import (
	"bytes"
	"strings"
	"testing"
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
