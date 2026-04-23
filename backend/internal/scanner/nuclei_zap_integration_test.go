package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

// writeFakeNuclei writes a minimal shell stub that mimics the nuclei CLI.
// When the stub receives a "-version" flag it prints a version string; for
// any other invocation it echoes the provided output body to stdout. The
// stub exits 0 unless body is the empty string, in which case it exits 1 so
// that the error-path is exercisable. The test is skipped on Windows.
func writeFakeNuclei(t *testing.T, outputBody string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake binary stub uses /bin/sh which is unavailable on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "nuclei")
	exitStr := "0"
	if exitCode != 0 {
		exitStr = "1"
	}
	script := "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = \"-version\" ] && echo 'nuclei v3.0.0' && exit 0; done\n"
	if outputBody != "" {
		script += "cat <<'NUCLEI_EOF'\n" + outputBody + "\nNUCLEI_EOF\n"
	}
	script += "exit " + exitStr + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}
	return path
}

// writeFakeZAPBaseline writes a minimal shell stub that mimics zap-baseline.py.
// The test is skipped on Windows.
func writeFakeZAPBaseline(t *testing.T, outputBody string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake binary stub uses /bin/sh which is unavailable on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "zap-baseline.py")
	exitStr := "0"
	if exitCode != 0 {
		exitStr = "1"
	}
	script := "#!/bin/sh\n"
	if outputBody != "" {
		script += "cat <<'ZAP_EOF'\n" + outputBody + "\nZAP_EOF\n"
	}
	script += "exit " + exitStr + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake zap-baseline.py: %v", err)
	}
	return path
}

// ---- Nuclei exec-mode tests ----

func TestRunNucleiExec_BinaryMissing(t *testing.T) {
	svc := NewService(Config{
		NucleiBinary:       "/nonexistent/path/nuclei-does-not-exist",
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runNucleiExec(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "nuclei-binary-missing" {
		t.Fatalf("expected nuclei-binary-missing finding, got %+v", findings)
	}
}

func TestRunNucleiExec_NoFindings(t *testing.T) {
	bin := writeFakeNuclei(t, "", 0)
	svc := NewService(Config{
		NucleiBinary:       bin,
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runNucleiExec(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "nuclei-summary" {
		t.Fatalf("expected nuclei-summary finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityInfo {
		t.Errorf("expected info severity for zero findings, got %v", findings[0].Severity)
	}
}

func TestRunNucleiExec_WithFindings(t *testing.T) {
	output := "[medium] [http] [cve-2021-1234] https://example.com/vuln\n[high] [http] [misconfiguration] https://example.com/other"
	bin := writeFakeNuclei(t, output, 0)
	svc := NewService(Config{
		NucleiBinary:       bin,
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runNucleiExec(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "nuclei-summary" {
		t.Fatalf("expected nuclei-summary finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityMedium {
		t.Errorf("expected medium severity for non-empty output, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Evidence, "matches=2") {
		t.Errorf("expected matches=2 in evidence, got %q", findings[0].Evidence)
	}
}

func TestRunNucleiExec_ExecutionError(t *testing.T) {
	bin := writeFakeNuclei(t, "", 1)
	svc := NewService(Config{
		NucleiBinary:       bin,
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runNucleiExec(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "nuclei-execution-error" {
		t.Fatalf("expected nuclei-execution-error finding, got %+v", findings)
	}
}

// ---- ZAP exec-mode tests ----

func TestRunZAPBaselineExec_BinaryMissing(t *testing.T) {
	svc := NewService(Config{
		ZAPBaselineBinary:  "/nonexistent/path/zap-baseline-does-not-exist.py",
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runZAPBaselineExec(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "zap-baseline-binary-missing" {
		t.Fatalf("expected zap-baseline-binary-missing finding, got %+v", findings)
	}
}

func TestRunZAPBaselineExec_NoWarnings(t *testing.T) {
	bin := writeFakeZAPBaseline(t, "PASS: no issues found", 0)
	svc := NewService(Config{
		ZAPBaselineBinary:  bin,
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runZAPBaselineExec(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "zap-baseline-summary" {
		t.Fatalf("expected zap-baseline-summary finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityInfo {
		t.Errorf("expected info severity for no warnings, got %v", findings[0].Severity)
	}
}

func TestRunZAPBaselineExec_WithWarnMarkers(t *testing.T) {
	output := "WARN-NEW: Content Security Policy (CSP) Header Not Set [10038]\nWARN-NEW: X-Content-Type-Options Header Missing [10021]"
	bin := writeFakeZAPBaseline(t, output, 1)
	svc := NewService(Config{
		ZAPBaselineBinary:  bin,
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runZAPBaselineExec(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "zap-baseline-summary" {
		t.Fatalf("expected zap-baseline-summary finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityMedium {
		t.Errorf("expected medium severity for warn markers, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Evidence, "warnMarkers=2") {
		t.Errorf("expected warnMarkers=2 in evidence, got %q", findings[0].Evidence)
	}
}

func TestRunZAPBaselineExec_WithFailMarkers(t *testing.T) {
	output := "FAIL-NEW: SQL Injection [40018]\nWARN-NEW: Missing HSTS [10035]"
	bin := writeFakeZAPBaseline(t, output, 1)
	svc := NewService(Config{
		ZAPBaselineBinary:  bin,
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runZAPBaselineExec(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "zap-baseline-summary" {
		t.Fatalf("expected zap-baseline-summary finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityHigh {
		t.Errorf("expected high severity for fail markers, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Evidence, "failMarkers=1") {
		t.Errorf("expected failMarkers=1 in evidence, got %q", findings[0].Evidence)
	}
}

func TestRunZAPBaselineExec_ExecutionError(t *testing.T) {
	bin := writeFakeZAPBaseline(t, "", 1)
	svc := NewService(Config{
		ZAPBaselineBinary:  bin,
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runZAPBaselineExec(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "zap-baseline-execution-error" {
		t.Fatalf("expected zap-baseline-execution-error finding, got %+v", findings)
	}
}
