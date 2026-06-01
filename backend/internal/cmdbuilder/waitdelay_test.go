package cmdbuilder

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// TestWaitDelayUnblocksOnInheritedPipe reproduces the platform-specific hang
// that left the scan "stuck at the Analysis step" on Linux but not Windows.
//
// When a command spawns a grandchild that inherits (and keeps open) the
// stdout pipe, killing the direct child on context timeout is not enough:
// cmd.Wait blocks until every writer closes the pipe, so cmd.Run/cmd.Output
// would hang for as long as the grandchild lives. Setting cmd.WaitDelay (as
// RunWithPolicy now does) forces the pipe closed shortly after the kill so the
// call returns promptly.
func TestWaitDelayUnblocksOnInheritedPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scenario reproduces the inherited-pipe hang on POSIX systems")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Background a long-lived grandchild that inherits stdout, then have the
	// direct child exit. Without WaitDelay, cmd.Run would block for the full
	// 60s sleep because the grandchild keeps the stdout pipe open.
	cmd := exec.CommandContext(ctx, "sh", "-c", "sleep 60 & exit 0")
	cmd.WaitDelay = commandWaitDelay

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- cmd.Run() }()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > commandWaitDelay+5*time.Second {
			t.Fatalf("cmd.Run returned but took too long (%s); WaitDelay not effective", elapsed)
		}
	case <-time.After(commandWaitDelay + 5*time.Second):
		t.Fatalf("cmd.Run hung past WaitDelay; inherited-pipe deadlock not mitigated")
	}
}
