// Package logbuffer provides a bounded, in-memory ring buffer that captures
// the most recent output written to Go's standard logger. It lets operators
// download recent system logs over the API without requiring access to the
// container's stdout/stderr or an external log aggregator.
package logbuffer

import (
	"io"
	"log"
	"os"
	"sync"
)

// DefaultMaxBytes is the default size of the in-memory log ring buffer.
const DefaultMaxBytes = 1 << 20 // 1 MiB

// Buffer is a concurrency-safe, byte-bounded ring buffer that retains the most
// recently written bytes up to maxBytes. Once full, the oldest bytes are
// discarded to make room for new writes. It implements io.Writer so it can be
// attached to the standard logger via log.SetOutput.
type Buffer struct {
	mu       sync.Mutex
	data     []byte
	maxBytes int
}

// NewBuffer returns a Buffer that retains at most maxBytes of log output. A
// non-positive maxBytes falls back to DefaultMaxBytes.
func NewBuffer(maxBytes int) *Buffer {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	return &Buffer{maxBytes: maxBytes}
}

// Write appends p to the buffer, trimming the oldest bytes so the retained
// content never exceeds maxBytes. It always reports the full length of p as
// written so it composes cleanly with io.MultiWriter.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if n >= b.maxBytes {
		// Keep only the trailing maxBytes of this write.
		b.data = append(b.data[:0], p[n-b.maxBytes:]...)
		return n, nil
	}
	b.data = append(b.data, p...)
	if len(b.data) > b.maxBytes {
		overflow := len(b.data) - b.maxBytes
		b.data = append(b.data[:0], b.data[overflow:]...)
	}
	return n, nil
}

// Snapshot returns a copy of the currently retained log bytes.
func (b *Buffer) Snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, len(b.data))
	copy(out, b.data)
	return out
}

// Default is the process-wide log buffer populated by Install.
var Default = NewBuffer(DefaultMaxBytes)

// Install redirects the standard logger to write to both the original
// destination (typically os.Stderr) and the Default in-memory buffer, so log
// output remains visible on the console while also being retained for download.
func Install() {
	log.SetOutput(io.MultiWriter(os.Stderr, Default))
}
