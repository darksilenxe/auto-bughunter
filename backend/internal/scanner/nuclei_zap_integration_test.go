package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func writeBrokenTool(t *testing.T, name, stderr string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake binary stub uses /bin/sh which is unavailable on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\n"
	if stderr != "" {
		script += "cat <<'STDERR_EOF' >&2\n" + stderr + "\nSTDERR_EOF\n"
	}
	script += "exit 127\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write broken tool stub: %v", err)
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

func TestRunNuclei_FallsBackToHTTPWhenExecUnavailable(t *testing.T) {
	t.Setenv("USE_HTTP_TOOL_SERVICES", "false")
	mockSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/execute":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stdout":    "[medium] [http] [test] https://example.com/\n",
				"stderr":    "",
				"exit_code": 0,
				"timed_out": false,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockSvc.Close()
	t.Setenv("NUCLEI_SERVICE_URL", mockSvc.URL)

	svc := NewService(Config{
		NucleiBinary:       writeBrokenTool(t, "nuclei", "sidecar-exec: docker CLI not found"),
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runNuclei(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "nuclei-summary" {
		t.Fatalf("expected nuclei-summary finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityMedium {
		t.Fatalf("expected medium severity from HTTP fallback, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Evidence, "(via HTTP service)") {
		t.Fatalf("expected HTTP fallback evidence, got %q", findings[0].Evidence)
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

func TestRunZAPBaseline_FallsBackToHTTPWhenExecUnavailable(t *testing.T) {
	t.Setenv("USE_HTTP_TOOL_SERVICES", "false")
	mockSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/execute":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"stdout":    "WARN-NEW: Missing CSP [10038]\n",
				"stderr":    "",
				"exit_code": 1,
				"timed_out": false,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockSvc.Close()
	t.Setenv("ZAP_SERVICE_URL", mockSvc.URL)

	svc := NewService(Config{
		ZAPBaselineBinary:  writeBrokenTool(t, "zap-baseline.py", "sidecar-exec: docker CLI not found"),
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runZAPBaseline(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "zap-baseline-summary" {
		t.Fatalf("expected zap-baseline-summary finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityMedium {
		t.Fatalf("expected medium severity from HTTP fallback, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Evidence, "(via HTTP service)") {
		t.Fatalf("expected HTTP fallback evidence, got %q", findings[0].Evidence)
	}
}

// ---- Centralized post-Nuclei cooldown tests ----

// TestCooldownAfterNuclei_ContextCancelledDuringCooldown verifies that when the
// scan context is cancelled while the post-Nuclei cooldown is active the
// function returns early with the expected informational finding and does not
// attempt to run Vulnx, ZAP Baseline, or XSSMap.
func TestCooldownAfterNuclei_ContextCancelledDuringCooldown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake binary stub uses /bin/sh which is unavailable on Windows")
	}
	nucleiBin := writeFakeNuclei(t, "", 0)

	svc := NewService(Config{
		NucleiBinary:       nucleiBin,
		IntegrationTimeout: 5 * time.Second,
	})

	// Create a context that we cancel immediately after starting the scan so
	// that it expires during the cooldown window (which is 5s by default).
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		// A tiny sleep ensures the Nuclei stub has time to "run" before we
		// cancel; the cooldown fires after Nuclei returns so this is safe.
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	input := RunInput{
		Target: "https://example.com/",
		Options: model.ScanOptions{
			UseNucleiIntegration:      true,
			UseZAPBaselineIntegration: true,
			UseVulnxIntegration:       true,
		},
	}

	findings := svc.runOptionalIntegrations(ctx, input)

	// We must see the context-ended finding, meaning the cooldown fired and
	// the remaining Phase 7 tools were skipped.
	foundSkipped := false
	for _, f := range findings {
		if f.ID == "phase7-skipped-nuclei-cooldown-context-ended" {
			foundSkipped = true
			if f.Severity != model.SeverityInfo {
				t.Errorf("expected info severity for skipped finding, got %v", f.Severity)
			}
			break
		}
	}
	if !foundSkipped {
		ids := make([]string, 0, len(findings))
		for _, f := range findings {
			ids = append(ids, f.ID)
		}
		t.Errorf("expected phase7-skipped-nuclei-cooldown-context-ended finding; got IDs: %v", ids)
	}
}

// TestCooldownAfterNuclei_NotAppliedWithoutNuclei confirms that the post-Nuclei
// cooldown is not inserted when Nuclei was not part of the scan (i.e. only ZAP
// is requested).
func TestCooldownAfterNuclei_NotAppliedWithoutNuclei(t *testing.T) {
	svc := NewService(Config{
		ZAPBaselineBinary:  "/nonexistent/zap-baseline.py",
		IntegrationTimeout: 5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	input := RunInput{
		Target: "https://example.com/",
		Options: model.ScanOptions{
			UseZAPBaselineIntegration: true,
		},
	}

	svc.runOptionalIntegrations(ctx, input)
	elapsed := time.Since(start)

	// The cooldown is 5s; if it were applied incorrectly the test context
	// would time out (2 s) and elapsed would be >= 2 s.  Without the cooldown
	// the ZAP binary-missing path returns almost instantly.
	if elapsed >= 1500*time.Millisecond {
		t.Errorf("cooldown was applied even though Nuclei did not run (elapsed %v)", elapsed)
	}
}
