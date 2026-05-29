package logbuffer

import (
	"bytes"
	"strings"
	"testing"
)

func TestBufferRetainsRecentBytesWithinLimit(t *testing.T) {
	b := NewBuffer(100)
	if _, err := b.Write([]byte("hello ")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := b.Write([]byte("world")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(b.Snapshot()); got != "hello world" {
		t.Fatalf("snapshot = %q, want %q", got, "hello world")
	}
}

func TestBufferTrimsOldestBytesWhenFull(t *testing.T) {
	b := NewBuffer(5)
	if _, err := b.Write([]byte("abc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := b.Write([]byte("defg")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Total written is "abcdefg" (7 bytes); only the trailing 5 are retained.
	if got := string(b.Snapshot()); got != "cdefg" {
		t.Fatalf("snapshot = %q, want %q", got, "cdefg")
	}
}

func TestBufferKeepsTailOfOversizedSingleWrite(t *testing.T) {
	b := NewBuffer(4)
	if _, err := b.Write([]byte("0123456789")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(b.Snapshot()); got != "6789" {
		t.Fatalf("snapshot = %q, want %q", got, "6789")
	}
}

func TestWriteReportsFullLength(t *testing.T) {
	b := NewBuffer(4)
	payload := []byte(strings.Repeat("x", 10))
	n, err := b.Write(payload)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("n = %d, want %d", n, len(payload))
	}
}

func TestSnapshotReturnsCopy(t *testing.T) {
	b := NewBuffer(10)
	if _, err := b.Write([]byte("abc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	snap := b.Snapshot()
	snap[0] = 'Z'
	if got := b.Snapshot(); !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("snapshot mutated underlying buffer: %q", got)
	}
}
