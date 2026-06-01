package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScratchDirDefaultsToTempDir(t *testing.T) {
	t.Setenv(scratchDirEnv, "")
	got := ScratchDir()
	want := filepath.Join(os.TempDir(), "auto-bughunter")
	if got != want {
		t.Fatalf("ScratchDir() = %q, want %q", got, want)
	}
}

func TestScratchDirHonoursEnvOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "custom-scratch")
	t.Setenv(scratchDirEnv, override)
	if got := ScratchDir(); got != filepath.Clean(override) {
		t.Fatalf("ScratchDir() = %q, want %q", got, filepath.Clean(override))
	}
}

func TestToolsAndSQLMapDirsAreUnderScratch(t *testing.T) {
	override := filepath.Join(t.TempDir(), "scratch")
	t.Setenv(scratchDirEnv, override)
	if got, want := ToolsDir(), filepath.Join(override, "tools"); got != want {
		t.Fatalf("ToolsDir() = %q, want %q", got, want)
	}
	if got, want := SQLMapDir(), filepath.Join(override, "sqlmap"); got != want {
		t.Fatalf("SQLMapDir() = %q, want %q", got, want)
	}
}

func TestDataDirHonoursEnvOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "data")
	t.Setenv(dataDirEnv, override)
	if got := DataDir(); got != filepath.Clean(override) {
		t.Fatalf("DataDir() = %q, want %q", got, filepath.Clean(override))
	}
	report := ToolUpdatesReportPath()
	if !strings.HasPrefix(report, filepath.Clean(override)) {
		t.Fatalf("ToolUpdatesReportPath() = %q, want prefix %q", report, filepath.Clean(override))
	}
	if filepath.Base(report) != "report.json" {
		t.Fatalf("ToolUpdatesReportPath() base = %q, want report.json", filepath.Base(report))
	}
}
