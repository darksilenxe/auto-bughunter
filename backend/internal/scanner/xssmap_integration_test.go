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

// writeFakeXSSMap writes a tiny POSIX shell script that emulates the
// `xssmap` CLI by echoing a fixed JSON document to stdout (or the body the
// caller asked it to print). Returns the absolute path to the script. The
// test is skipped on Windows where /bin/sh is not available.
func writeFakeXSSMap(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake binary stub uses /bin/sh which is unavailable on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "xssmap")
	script := "#!/bin/sh\ncat <<'XSSMAP_EOF'\n" + body + "\nXSSMAP_EOF\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake xssmap: %v", err)
	}
	return path
}

func TestRunXSSMap_ParsesVulnerabilitiesIntoFindings(t *testing.T) {
	bin := writeFakeXSSMap(t, `{"vulnerabilities":[
		{"url":"https://example.com/?q=1","parameter":"q","payload":"<svg/onload=alert(1)>","type":"reflected","severity":"high","evidence":"reflected in body"},
		{"url":"https://example.com/#x","parameter":"hash","payload":"javascript:alert(1)","type":"dom","severity":"medium"}
	]}`)
	svc := NewService(Config{
		XSSMapBinary:       bin,
		IntegrationTimeout: 10 * time.Second,
	})

	findings := svc.runXSSMap(context.Background(), "https://example.com/")
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (2 vulns + summary), got %d: %+v", len(findings), findings)
	}

	if findings[0].Category != "xss" || findings[0].Severity != model.SeverityHigh {
		t.Errorf("first finding category/severity wrong: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Evidence, "payload=<svg/onload=alert(1)>") {
		t.Errorf("first finding evidence missing payload: %q", findings[0].Evidence)
	}
	if !strings.Contains(findings[0].Title, "reflected") {
		t.Errorf("first finding title missing type: %q", findings[0].Title)
	}
	if findings[1].Severity != model.SeverityMedium {
		t.Errorf("second finding severity wrong: %v", findings[1].Severity)
	}
	if findings[2].ID != "xssmap-summary" {
		t.Errorf("expected last finding to be summary, got %q", findings[2].ID)
	}
}

func TestRunXSSMap_NoVulnerabilities(t *testing.T) {
	bin := writeFakeXSSMap(t, `{"vulnerabilities":[]}`)
	svc := NewService(Config{
		XSSMapBinary:       bin,
		IntegrationTimeout: 10 * time.Second,
	})

	findings := svc.runXSSMap(context.Background(), "https://example.com/")
	if len(findings) != 1 {
		t.Fatalf("expected 1 summary finding, got %d", len(findings))
	}
	if findings[0].ID != "xssmap-summary" || findings[0].Severity != model.SeverityInfo {
		t.Errorf("unexpected summary finding: %+v", findings[0])
	}
}

func TestRunXSSMap_BinaryMissing(t *testing.T) {
	svc := NewService(Config{
		XSSMapBinary:       "/nonexistent/path/xssmap-does-not-exist",
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runXSSMap(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "xssmap-binary-missing" {
		t.Fatalf("expected xssmap-binary-missing finding, got %+v", findings)
	}
}

func TestRunXSSMap_UnparsableOutput(t *testing.T) {
	bin := writeFakeXSSMap(t, "not-json garbage")
	svc := NewService(Config{
		XSSMapBinary:       bin,
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runXSSMap(context.Background(), "https://example.com/")
	if len(findings) != 1 || findings[0].ID != "xssmap-summary" {
		t.Fatalf("expected single fallback summary finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Evidence, "parse_error=") {
		t.Errorf("expected parse_error evidence, got %q", findings[0].Evidence)
	}
}

func TestRunOptionalIntegrations_XSSMapBlockedBySafetyPolicy(t *testing.T) {
	bin := writeFakeXSSMap(t, `{"vulnerabilities":[]}`)
	svc := NewService(Config{
		XSSMapBinary:       bin,
		IntegrationTimeout: 10 * time.Second,
		AllowDestructive:   false,
	})
	findings := svc.runOptionalIntegrations(context.Background(), RunInput{
		Target:  "https://example.com/",
		Options: model.ScanOptions{UseXSSMapIntegration: true},
	})
	var found bool
	for _, f := range findings {
		if f.ID == "xssmap-blocked-by-safety-policy" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected xssmap-blocked-by-safety-policy finding when AllowDestructive=false; got %+v", findings)
	}
}
