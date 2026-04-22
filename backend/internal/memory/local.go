package memory

import (
	"context"
	"sort"
	"sync"
	"time"
)

// LocalStore is an in-memory fallback implementation of Store that persists
// findings only for the lifetime of the process.  It is intended for
// development/testing environments where PostgreSQL with the pgvector
// extension is not available.
//
// Similarity search uses exact cosine similarity over all stored entries.
type LocalStore struct {
	mu      sync.RWMutex
	entries map[string]FindingMemory
}

// NewLocalStore creates an empty LocalStore.
func NewLocalStore() *LocalStore {
	return &LocalStore{entries: make(map[string]FindingMemory)}
}

// UpsertFinding stores or replaces a finding.
func (s *LocalStore) UpsertFinding(_ context.Context, mem FindingMemory) error {
	if mem.CreatedAt.IsZero() {
		mem.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	s.entries[mem.ID] = mem
	s.mu.Unlock()
	return nil
}

// SearchSimilar returns the topK most similar findings by cosine similarity.
func (s *LocalStore) SearchSimilar(_ context.Context, embedding []float32, topK int) ([]FindingMemory, error) {
	if topK <= 0 {
		topK = 5
	}
	s.mu.RLock()
	all := make([]FindingMemory, 0, len(s.entries))
	for _, m := range s.entries {
		all = append(all, m)
	}
	s.mu.RUnlock()

	type scored struct {
		m     FindingMemory
		score float32
	}
	ranked := make([]scored, 0, len(all))
	for _, m := range all {
		ranked = append(ranked, scored{m: m, score: CosineSimilarity(embedding, m.Embedding)})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].score > ranked[j].score })
	if topK > len(ranked) {
		topK = len(ranked)
	}
	out := make([]FindingMemory, topK)
	for i := range out {
		out[i] = ranked[i].m
	}
	return out, nil
}

// SearchByTarget returns the most recent topK findings for a given target.
func (s *LocalStore) SearchByTarget(_ context.Context, target string, topK int) ([]FindingMemory, error) {
	if topK <= 0 {
		topK = 10
	}
	s.mu.RLock()
	all := make([]FindingMemory, 0)
	for _, m := range s.entries {
		if m.Target == target {
			all = append(all, m)
		}
	}
	s.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	if topK > len(all) {
		topK = len(all)
	}
	return all[:topK], nil
}

// Close is a no-op for the in-memory store.
func (s *LocalStore) Close() error { return nil }
