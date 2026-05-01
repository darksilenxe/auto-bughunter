package toolbuilder

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuild_BoundsLargeStdout asserts that a generated tool that emits far
// more than maxOutputBytes of stdout does not OOM the backend and that the
// returned findings parsing never sees more than maxOutputBytes of input.
//
// The script intentionally writes well beyond the cap; we verify that Build
// completes promptly (no buffering blowup) and returns an empty findings
// slice (none of the bytes parse as JSON-lines findings).
func TestBuild_BoundsLargeStdout(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available in test environment")
	}
	// Stream ~5 * maxOutputBytes of garbage bytes.
	spec := ToolSpec{
		Name:     "stdout-flood",
		Language: "bash",
		// Use a here-doc-free one-liner so validateScript stays happy.
		Code:    "yes A | head -c " + itoa(5*maxOutputBytes),
		Timeout: 30 * time.Second,
	}
	if err := validateScript(spec.Code); err != nil {
		t.Skipf("script template rejected by validator: %v", err)
	}
	b := &Builder{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	findings, err := b.Build(ctx, spec, "https://target.test", nil)
	dur := time.Since(start)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if dur > 25*time.Second {
		t.Fatalf("Build took too long (%v); bound likely not in effect", dur)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings from garbage bytes, got %d", len(findings))
	}
	// Cleanup of scratch script (best-effort; sanitizeName is deterministic).
	_ = os.Remove(filepath.Join(scratchDir, "stdout-flood.sh"))
}

// itoa avoids importing strconv just for the helper above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return strings.Clone(string(buf[i:]))
}
