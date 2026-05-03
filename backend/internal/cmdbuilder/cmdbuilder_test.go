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

func TestValidate_RejectsUnknownFlagInSafeMode(t *testing.T) {
	err := ValidateWithPolicy(CommandSpec{
		Binary: "sqlmap",
		Args:   []string{"-u", "https://example.com?id=1", "--totally-unknown-flag"},
	}, "https://example.com", ValidationPolicy{})
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("expected unknown flag rejection, got %v", err)
	}
}

func TestValidate_AllowsKnownFlagsInSafeMode(t *testing.T) {
	err := ValidateWithPolicy(CommandSpec{
		Binary: "sqlmap",
		Args:   []string{"-u", "https://example.com?id=1", "--batch", "--threads=2", "--level=2"},
	}, "https://example.com", ValidationPolicy{})
	if err != nil {
		t.Fatalf("expected known sqlmap flags to pass validation, got %v", err)
	}
}

func TestValidate_AllowsUnknownFlagInUnsafeMode(t *testing.T) {
	err := ValidateWithPolicy(CommandSpec{
		Binary: "sqlmap",
		Args:   []string{"-u", "https://example.com?id=1", "--totally-unknown-flag"},
	}, "https://example.com", ValidationPolicy{UnsafeMode: true})
	if err != nil {
		t.Fatalf("expected unknown flag to pass in unsafe mode, got %v", err)
	}
}

func TestValidate_UnsafeModeStillBlocksInjectionPatterns(t *testing.T) {
	err := ValidateWithPolicy(CommandSpec{
		Binary: "sqlmap",
		Args:   []string{"-u", "https://example.com?id=1", "x;id"},
	}, "https://example.com", ValidationPolicy{UnsafeMode: true})
	if err == nil || !strings.Contains(err.Error(), "blocked pattern") {
		t.Fatalf("expected blocked pattern rejection in unsafe mode, got %v", err)
	}
}

func TestValidate_AllowsCloudlistHostScopedFlags(t *testing.T) {
	err := ValidateWithPolicy(CommandSpec{
		Binary: "cloudlist",
		Args:   []string{"-silent", "-host", "-id", "example.com"},
	}, "https://example.com", ValidationPolicy{})
	if err != nil {
		t.Fatalf("expected cloudlist host-scoped flags to pass validation, got %v", err)
	}
}

func TestValidate_AllowsVulnxSearchSubcommand(t *testing.T) {
	err := ValidateWithPolicy(CommandSpec{
		Binary: "vulnx",
		Args:   []string{"search", "--limit", "20", "--silent", "example.com"},
	}, "https://example.com", ValidationPolicy{})
	if err != nil {
		t.Fatalf("expected vulnx search command to pass validation, got %v", err)
	}
}
