package memory

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PgvectorStore implements Store using PostgreSQL with the pgvector extension.
// The pgvector extension must be installed in the target database
// (available in the pgvector/pgvector Docker image or via
// "CREATE EXTENSION IF NOT EXISTS vector" on a supported PostgreSQL build).
type PgvectorStore struct {
	db *sql.DB
}

// NewPgvectorStore opens a connection to the given PostgreSQL DSN and runs
// the required schema migrations.  Returns an error when the vector extension
// is not available in the database.
func NewPgvectorStore(ctx context.Context, dsn string) (*PgvectorStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("memory pgvector: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("memory pgvector: ping: %w", err)
	}
	s := &PgvectorStore{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("memory pgvector: migrate: %w", err)
	}
	return s, nil
}

func (s *PgvectorStore) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS vector`,
		`CREATE TABLE IF NOT EXISTS finding_embeddings (
			id         TEXT PRIMARY KEY,
			target     TEXT NOT NULL DEFAULT '',
			scan_id    TEXT NOT NULL DEFAULT '',
			category   TEXT NOT NULL DEFAULT '',
			title      TEXT NOT NULL DEFAULT '',
			severity   TEXT NOT NULL DEFAULT '',
			embedding  vector(64) NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_finding_embeddings_target
			ON finding_embeddings(target)`,
		// IVFFlat index for approximate nearest-neighbour search.
		// lists=10 is suitable for tables up to ~100 000 rows.
		`CREATE INDEX IF NOT EXISTS idx_finding_embeddings_vec
			ON finding_embeddings USING ivfflat (embedding vector_cosine_ops)
			WITH (lists = 10)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate stmt %q: %w", stmt[:min(40, len(stmt))], err)
		}
	}
	return nil
}

// UpsertFinding inserts or updates a finding embedding.
func (s *PgvectorStore) UpsertFinding(ctx context.Context, mem FindingMemory) error {
	if len(mem.Embedding) != embeddingDims {
		return fmt.Errorf("memory pgvector: embedding must be %d dimensions, got %d", embeddingDims, len(mem.Embedding))
	}
	vecStr := formatVector(mem.Embedding)
	createdAt := mem.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	// nosemgrep -- static SQL with parameterized $N placeholders; no string concatenation of user input.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO finding_embeddings (id, target, scan_id, category, title, severity, embedding, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::vector, $8)
		ON CONFLICT (id) DO UPDATE SET
			target     = EXCLUDED.target,
			scan_id    = EXCLUDED.scan_id,
			category   = EXCLUDED.category,
			title      = EXCLUDED.title,
			severity   = EXCLUDED.severity,
			embedding  = EXCLUDED.embedding,
			created_at = EXCLUDED.created_at
	`, mem.ID, mem.Target, mem.ScanID, mem.Category, mem.Title, mem.Severity, vecStr, createdAt)
	return err
}

// SearchSimilar returns the topK most similar findings by cosine similarity.
func (s *PgvectorStore) SearchSimilar(ctx context.Context, embedding []float32, topK int) ([]FindingMemory, error) {
	if topK <= 0 {
		topK = 5
	}
	vecStr := formatVector(embedding)
	// nosemgrep -- static SQL with parameterized $N placeholders; no string concatenation of user input.
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target, scan_id, category, title, severity, created_at
		FROM finding_embeddings
		ORDER BY embedding <=> $1::vector
		LIMIT $2
	`, vecStr, topK)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMemoryRows(rows)
}

// SearchByTarget returns the most recent topK findings for a given target.
func (s *PgvectorStore) SearchByTarget(ctx context.Context, target string, topK int) ([]FindingMemory, error) {
	if topK <= 0 {
		topK = 10
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target, scan_id, category, title, severity, created_at
		FROM finding_embeddings
		WHERE target = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, target, topK)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMemoryRows(rows)
}

// Close releases the database connection pool.
func (s *PgvectorStore) Close() error { return s.db.Close() }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func scanMemoryRows(rows *sql.Rows) ([]FindingMemory, error) {
	var out []FindingMemory
	for rows.Next() {
		var m FindingMemory
		if err := rows.Scan(&m.ID, &m.Target, &m.ScanID, &m.Category, &m.Title, &m.Severity, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// formatVector formats a float32 slice as a pgvector literal, e.g. "[0.1,0.2,…]".
func formatVector(v []float32) string {
	parts := make([]string, len(v))
	for i, f := range v {
		parts[i] = strconv.FormatFloat(float64(f), 'f', 8, 32)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
