// Package paths centralizes the backend-local filesystem locations that the
// scanner writes to and reads from at runtime (generated tool scripts, sqlmap
// output, the tool-update report). Historically these were hardcoded POSIX
// literals such as "/tmp/auto-bughunter/tools" and
// "/var/lib/auto-bughunter/updates", which only resolve on Linux hosts and
// ignore $TMPDIR even there. Deriving them from os.TempDir() keeps the scanner
// correct across platforms and honours container temp overrides on Linux.
//
// These helpers describe paths owned by the backend process itself. Paths that
// belong to external scanner tools (e.g. SecLists wordlist roots consumed by
// gobuster/ffuf) are intentionally NOT defined here: those resolve inside the
// tool's own environment and have their own dedicated env overrides.
package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// Environment variables that let operators override the derived defaults.
const (
	// scratchDirEnv overrides the root scratch directory for transient
	// runtime artifacts (generated tool scripts, sqlmap output, ...).
	scratchDirEnv = "AUTO_BUGHUNTER_SCRATCH_DIR"
	// dataDirEnv overrides the root directory for persistent data shared
	// with sidecars (e.g. the tool-updater report).
	dataDirEnv = "AUTO_BUGHUNTER_DATA_DIR"
)

// ScratchDir returns the root directory for transient runtime artifacts.
// It honours AUTO_BUGHUNTER_SCRATCH_DIR, then falls back to a per-platform
// temp location (os.TempDir()/auto-bughunter), which respects $TMPDIR on Linux.
func ScratchDir() string {
	if v := strings.TrimSpace(os.Getenv(scratchDirEnv)); v != "" {
		return filepath.Clean(v)
	}
	return filepath.Join(os.TempDir(), "auto-bughunter")
}

// ToolsDir returns the scratch directory where generated tool scripts
// (jwt_probe.py, graphql_probe.py, ...) are written and executed from.
func ToolsDir() string {
	return filepath.Join(ScratchDir(), "tools")
}

// SQLMapDir returns the scratch directory sqlmap is told to write its output to.
func SQLMapDir() string {
	return filepath.Join(ScratchDir(), "sqlmap")
}

// DataDir returns the root directory for persistent data shared with sidecars.
// It honours AUTO_BUGHUNTER_DATA_DIR, then falls back to the conventional Linux
// location on Linux hosts and to a temp-based path elsewhere so non-Linux dev
// runs do not point at an unwritable /var/lib.
func DataDir() string {
	if v := strings.TrimSpace(os.Getenv(dataDirEnv)); v != "" {
		return filepath.Clean(v)
	}
	if os.PathSeparator == '/' && dirExists("/var/lib") {
		return filepath.FromSlash("/var/lib/auto-bughunter")
	}
	return filepath.Join(os.TempDir(), "auto-bughunter", "data")
}

// ToolUpdatesReportPath returns the default path of the tool-updater report.
func ToolUpdatesReportPath() string {
	return filepath.Join(DataDir(), "updates", "report.json")
}

// dirExists reports whether a directory exists, used to prefer the conventional
// /var/lib location only when the platform actually provides it.
func dirExists(root string) bool {
	info, err := os.Stat(root)
	return err == nil && info.IsDir()
}
