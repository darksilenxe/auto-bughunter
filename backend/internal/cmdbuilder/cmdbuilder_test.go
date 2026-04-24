package cmdbuilder

import (
	"strings"
	"testing"
)

func TestValidate_RejectsBashBinary(t *testing.T) {
	err := Validate(CommandSpec{
		Binary: "bash",
		Args:   []string{"-c", "echo hi"},
	}, "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "approved tool list") {
		t.Fatalf("expected bash to be rejected, got %v", err)
	}
}

func TestValidate_RejectsUnsafePythonInvocationFlag(t *testing.T) {
	err := Validate(CommandSpec{
		Binary: "python3",
		Args:   []string{"-c", "print(1)"},
	}, "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "python commands must execute a script") {
		t.Fatalf("expected python -c to be rejected, got %v", err)
	}
}

func TestValidate_RejectsPythonScriptOutsideScratchDir(t *testing.T) {
	err := Validate(CommandSpec{
		Binary: "python3",
		Args:   []string{"/tmp/other/script.py", "https://example.com"},
	}, "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "python commands must execute a script") {
		t.Fatalf("expected non-scratch python script to be rejected, got %v", err)
	}
}

func TestValidate_AllowsSafePythonInvocation(t *testing.T) {
	err := Validate(CommandSpec{
		Binary: "python3",
		Args:   []string{"/tmp/auto-bughunter/tools/test_probe.py", "https://example.com"},
	}, "https://example.com")
	if err != nil {
		t.Fatalf("expected safe python invocation to pass validation, got %v", err)
	}
}
