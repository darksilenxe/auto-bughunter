// Package memory provides a cross-scan episodic finding memory backed by
// pgvector.  Each confirmed finding is encoded as a 64-dimensional float32
// embedding and upserted into the vector store.  At hypothesis-generation
// time, the agent queries the store for the K most similar past findings
// on the same or related targets, enriching the prompt context with real
// evidence from previous scans.
package memory

import (
	"context"
	"time"
)

// FindingMemory is a single episodic memory entry derived from one confirmed
// scanner finding.
type FindingMemory struct {
	// ID is a stable identifier for this memory, typically derived from the
	// finding's fingerprint so re-running the same scan is idempotent.
	ID string
	// Target is the scan target URL.
	Target string
	// ScanID is the originating scan job identifier.
	ScanID string
	// Category is the vulnerability category (e.g. "sqli", "xss").
	Category string
	// Title is the finding title.
	Title string
	// Severity is the finding severity string.
	Severity string
	// Embedding is the 64-dimensional float32 vector representation.
	Embedding []float32
	// CreatedAt is when this memory was first stored.
	CreatedAt time.Time
}

// Store is the interface for the episodic memory backend.
type Store interface {
	// UpsertFinding stores or updates a finding embedding.  The ID field
	// is used as the primary key, so re-inserting the same finding is safe.
	UpsertFinding(ctx context.Context, mem FindingMemory) error

	// SearchSimilar returns the topK most similar FindingMemory entries to
	// the given embedding, ordered by cosine similarity descending.
	SearchSimilar(ctx context.Context, embedding []float32, topK int) ([]FindingMemory, error)

	// SearchByTarget returns the most recent topK findings for a given
	// target, ordered by created_at descending.
	SearchByTarget(ctx context.Context, target string, topK int) ([]FindingMemory, error)

	// Close releases underlying resources.
	Close() error
}
