package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestRunKiterunner_Disabled(t *testing.T) {
	svc := NewService(Config{
		EnableKiterunner:   false,
		KiterunnerBinary:   "kr",
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runKiterunner(context.Background(), "https://example.com/", model.ScanScope{}, nil)
	if len(findings) != 1 || findings[0].ID != "kiterunner-disabled" {
		t.Fatalf("expected kiterunner-disabled finding, got %+v", findings)
	}
}

func TestRunKiterunner_BinaryMissing(t *testing.T) {
	svc := NewService(Config{
		EnableKiterunner:   true,
		KiterunnerBinary:   "/nonexistent/path/kr-does-not-exist",
		IntegrationTimeout: 10 * time.Second,
	})
	findings := svc.runKiterunner(context.Background(), "https://example.com/", model.ScanScope{}, nil)
	if len(findings) != 1 || findings[0].ID != "kiterunner-binary-missing" {
		t.Fatalf("expected kiterunner-binary-missing finding, got %+v", findings)
	}
}

func TestParseKiterunnerHits_ExtractsURLColumn(t *testing.T) {
	// kr text output places the method/status first; the URL is a later
	// whitespace field. parseKiterunnerHits must isolate the URL, not the
	// leading method token.
	output := `GET     200 [    363,   10,   1] https://example.com/api/v1/users 0cf6841
POST    405 [     12,    2,   1] https://example.com/api/v1/orders abc1234`
	scanScope := model.ScanScope{IncludeHosts: []string{"example.com"}}
	paths := parseKiterunnerHits(output, "https://example.com/", scanScope)
	if len(paths) != 2 {
		t.Fatalf("expected 2 in-scope paths, got %d: %v", len(paths), paths)
	}
	want := map[string]bool{"/api/v1/users": true, "/api/v1/orders": true}
	for _, p := range paths {
		if !want[p] {
			t.Errorf("unexpected path %q (method token should not be captured) in %v", p, paths)
		}
	}
}

func TestParseKiterunnerHits_IgnoresNonResultLines(t *testing.T) {
	output := `[*] Scanning https://example.com with 1 routes
GET     200 [ 10, 1, 1] https://example.com/health x

[!] done`
	scanScope := model.ScanScope{IncludeHosts: []string{"example.com"}}
	paths := parseKiterunnerHits(output, "https://example.com/", scanScope)
	if len(paths) != 1 || paths[0] != "/health" {
		t.Fatalf("expected [/health], got %v", paths)
	}
}

func TestFindKiterunnerWordlistFile_PrefersKite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "routes.txt"), []byte("/a\n"), 0o644); err != nil {
		t.Fatalf("write txt: %v", err)
	}
	sub := filepath.Join(dir, "kiterunner")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	kite := filepath.Join(sub, "apiroutes.kite")
	if err := os.WriteFile(kite, []byte("binary"), 0o644); err != nil {
		t.Fatalf("write kite: %v", err)
	}
	got := findKiterunnerWordlistFile(dir)
	if got != kite {
		t.Fatalf("expected to prefer .kite file %q, got %q", kite, got)
	}
}

func TestFindKiterunnerWordlistFile_FallsBackToTxt(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "routes.txt")
	if err := os.WriteFile(txt, []byte("/a\n"), 0o644); err != nil {
		t.Fatalf("write txt: %v", err)
	}
	if got := findKiterunnerWordlistFile(dir); got != txt {
		t.Fatalf("expected txt fallback %q, got %q", txt, got)
	}
}

func TestFindKiterunnerWordlistFile_MissingDir(t *testing.T) {
	if got := findKiterunnerWordlistFile(filepath.Join(t.TempDir(), "does-not-exist")); got != "" {
		t.Fatalf("expected empty result for missing dir, got %q", got)
	}
}
