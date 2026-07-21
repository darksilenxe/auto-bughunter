package memory

// Neo4jVectorStore implements Store using Neo4j 5.x native vector indexes.
// Each finding is stored as a (:MemoryFinding) node and each probe as a
// (:MemoryProbe) node. Graph relationships connect them to their parent
// (:MemoryScan) and (:MemoryTarget) nodes, enabling combined vector-similarity
// queries ("find findings like X") AND graph-traversal queries ("what findings
// are connected to this probe chain?").
//
// Neo4j 5.x vector index syntax:
//
//	CREATE VECTOR INDEX <name> IF NOT EXISTS
//	FOR (n:<Label>) ON n.embedding
//	OPTIONS {indexConfig: {`vector.dimensions`: 64, `vector.similarity_function`: 'cosine'}}
//
// Query:
//
//	CALL db.index.vector.queryNodes('<name>', $topK, $embedding)
//	YIELD node, score
//
// Requires NEO4J_URI to be set; the store is nil-safe (all methods are no-ops
// when the driver is nil) so callers can use it unconditionally.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const (
	vectorDims         = 64
	findingVectorIndex = "memory_finding_embeddings"
	probeVectorIndex   = "memory_probe_embeddings"
)

// Neo4jVectorStore implements memory.Store backed by Neo4j.
type Neo4jVectorStore struct {
	driver   neo4j.DriverWithContext
	database string
}

// NewNeo4jVectorStore connects to Neo4j using the supplied driver config and
// creates the required schema (vector indexes + constraints) if absent.
// uri, username, password, database are passed directly so the caller
// (cmd/server/main.go) can read them from env vars without this package
// importing os.
func NewNeo4jVectorStore(ctx context.Context, uri, username, password, database string) (*Neo4jVectorStore, error) {
	if strings.TrimSpace(uri) == "" {
		return nil, fmt.Errorf("neo4j vector store: NEO4J_URI is empty")
	}
	if strings.TrimSpace(database) == "" {
		database = "neo4j"
	}

	var auth neo4j.AuthToken
	if strings.TrimSpace(username) == "" {
		auth = neo4j.NoAuth()
	} else {
		auth = neo4j.BasicAuth(username, password, "")
	}

	driver, err := neo4j.NewDriverWithContext(uri, auth)
	if err != nil {
		return nil, fmt.Errorf("neo4j vector store: create driver: %w", err)
	}

	verifyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := driver.VerifyConnectivity(verifyCtx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("neo4j vector store: connectivity check: %w", err)
	}

	s := &Neo4jVectorStore{driver: driver, database: database}
	if err := s.migrate(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("neo4j vector store: migrate: %w", err)
	}
	return s, nil
}

// migrate creates labels, constraints and vector indexes if they do not exist.
func (s *Neo4jVectorStore) migrate(ctx context.Context) error {
	stmts := []string{
		// Uniqueness constraints (also create backing indexes).
		`CREATE CONSTRAINT memory_finding_id IF NOT EXISTS FOR (n:MemoryFinding) REQUIRE n.id IS UNIQUE`,
		`CREATE CONSTRAINT memory_probe_id   IF NOT EXISTS FOR (n:MemoryProbe)   REQUIRE n.id IS UNIQUE`,
		`CREATE CONSTRAINT memory_target_url IF NOT EXISTS FOR (n:MemoryTarget)  REQUIRE n.url IS UNIQUE`,
		`CREATE CONSTRAINT memory_scan_id    IF NOT EXISTS FOR (n:MemoryScan)    REQUIRE n.id IS UNIQUE`,

		// Vector indexes for approximate nearest-neighbour search.
		// Neo4j 5.x requires the embedding to be stored as a List<Float>.
		fmt.Sprintf(`CREATE VECTOR INDEX %s IF NOT EXISTS
FOR (n:MemoryFinding) ON n.embedding
OPTIONS {indexConfig: {`+"`vector.dimensions`"+`: %d, `+"`vector.similarity_function`"+`: 'cosine'}}`,
			findingVectorIndex, vectorDims),

		fmt.Sprintf(`CREATE VECTOR INDEX %s IF NOT EXISTS
FOR (n:MemoryProbe) ON n.embedding
OPTIONS {indexConfig: {`+"`vector.dimensions`"+`: %d, `+"`vector.similarity_function`"+`: 'cosine'}}`,
			probeVectorIndex, vectorDims),
	}

	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(ctx)

	for _, stmt := range stmts {
		if _, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			_, err := tx.Run(ctx, stmt, nil)
			return nil, err
		}); err != nil {
			return fmt.Errorf("migrate %q: %w", firstN(stmt, 60), err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Store interface — findings
// ---------------------------------------------------------------------------

// UpsertFinding stores or updates a MemoryFinding node and attaches it to its
// MemoryTarget and MemoryScan nodes via graph relationships.
func (s *Neo4jVectorStore) UpsertFinding(ctx context.Context, mem FindingMemory) error {
	if s == nil || s.driver == nil {
		return nil
	}
	if len(mem.Embedding) != vectorDims {
		return fmt.Errorf("neo4j vector store: finding embedding must be %d dims, got %d", vectorDims, len(mem.Embedding))
	}
	createdAt := mem.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	embList := float32SliceToInterface(mem.Embedding)

	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, `
MERGE (t:MemoryTarget {url: $target})
MERGE (sc:MemoryScan  {id: $scanId})
  ON CREATE SET sc.target = $target, sc.createdAt = $createdAt
MERGE (f:MemoryFinding {id: $id})
  ON CREATE SET
    f.target    = $target,
    f.scanId    = $scanId,
    f.category  = $category,
    f.title     = $title,
    f.severity  = $severity,
    f.embedding = $embedding,
    f.createdAt = $createdAt
  ON MATCH SET
    f.target    = $target,
    f.scanId    = $scanId,
    f.category  = $category,
    f.title     = $title,
    f.severity  = $severity,
    f.embedding = $embedding,
    f.createdAt = $createdAt
MERGE (f)-[:FROM_TARGET]->(t)
MERGE (sc)-[:HAS_FINDING]->(f)
`, map[string]any{
			"id":        mem.ID,
			"target":    mem.Target,
			"scanId":    mem.ScanID,
			"category":  mem.Category,
			"title":     mem.Title,
			"severity":  mem.Severity,
			"embedding": embList,
			"createdAt": createdAt.Format(time.RFC3339),
		})
		return nil, err
	})
	return err
}

// SearchSimilar returns the topK most similar MemoryFinding nodes by cosine
// similarity using the Neo4j vector index.
func (s *Neo4jVectorStore) SearchSimilar(ctx context.Context, embedding []float32, topK int) ([]FindingMemory, error) {
	if s == nil || s.driver == nil {
		return nil, nil
	}
	if topK <= 0 {
		topK = 5
	}
	embList := float32SliceToInterface(embedding)

	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, fmt.Sprintf(`
CALL db.index.vector.queryNodes('%s', $topK, $embedding)
YIELD node AS f, score
RETURN f.id        AS id,
       f.target    AS target,
       f.scanId    AS scanId,
       f.category  AS category,
       f.title     AS title,
       f.severity  AS severity,
       f.createdAt AS createdAt,
       score
ORDER BY score DESC
`, findingVectorIndex), map[string]any{
			"topK":      topK,
			"embedding": embList,
		})
		if err != nil {
			return nil, err
		}
		return collectFindingRows(ctx, rows)
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]FindingMemory), nil
}

// SearchByTarget returns the most recent topK MemoryFinding nodes for a
// given target, traversing the graph from MemoryTarget outward.
func (s *Neo4jVectorStore) SearchByTarget(ctx context.Context, target string, topK int) ([]FindingMemory, error) {
	if s == nil || s.driver == nil {
		return nil, nil
	}
	if topK <= 0 {
		topK = 10
	}

	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, `
MATCH (f:MemoryFinding)-[:FROM_TARGET]->(t:MemoryTarget {url: $target})
RETURN f.id        AS id,
       f.target    AS target,
       f.scanId    AS scanId,
       f.category  AS category,
       f.title     AS title,
       f.severity  AS severity,
       f.createdAt AS createdAt
ORDER BY f.createdAt DESC
LIMIT $topK
`, map[string]any{"target": target, "topK": topK})
		if err != nil {
			return nil, err
		}
		return collectFindingRows(ctx, rows)
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]FindingMemory), nil
}

// ---------------------------------------------------------------------------
// Store interface — probes
// ---------------------------------------------------------------------------

// UpsertProbe stores or updates a MemoryProbe node and, when the outcome is
// "confirmed", creates a CONFIRMED_FINDING relationship to any MemoryFinding
// node with the same (target, category).
func (s *Neo4jVectorStore) UpsertProbe(ctx context.Context, mem ProbeMemory) error {
	if s == nil || s.driver == nil {
		return nil
	}
	if len(mem.Embedding) != vectorDims {
		return fmt.Errorf("neo4j vector store: probe embedding must be %d dims, got %d", vectorDims, len(mem.Embedding))
	}
	createdAt := mem.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	embList := float32SliceToInterface(mem.Embedding)

	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, `
MERGE (t:MemoryTarget {url: $target})
MERGE (p:MemoryProbe {id: $id})
  ON CREATE SET
    p.target    = $target,
    p.scanId    = $scanId,
    p.category  = $category,
    p.endpoint  = $endpoint,
    p.payload   = $payload,
    p.outcome   = $outcome,
    p.embedding = $embedding,
    p.createdAt = $createdAt
  ON MATCH SET
    p.target    = $target,
    p.scanId    = $scanId,
    p.category  = $category,
    p.endpoint  = $endpoint,
    p.payload   = $payload,
    p.outcome   = $outcome,
    p.embedding = $embedding,
    p.createdAt = $createdAt
MERGE (p)-[:PROBED_TARGET]->(t)
WITH p, t
// When confirmed, link the probe to any finding on the same target+category.
OPTIONAL MATCH (f:MemoryFinding {target: $target, category: $category})
WHERE $outcome = 'confirmed' AND f IS NOT NULL
FOREACH (_ IN CASE WHEN f IS NOT NULL THEN [1] ELSE [] END |
  MERGE (p)-[:LED_TO_FINDING]->(f)
)
`, map[string]any{
			"id":        mem.ID,
			"target":    mem.Target,
			"scanId":    mem.ScanID,
			"category":  mem.Category,
			"endpoint":  mem.Endpoint,
			"payload":   mem.Payload,
			"outcome":   mem.Outcome,
			"embedding": embList,
			"createdAt": createdAt.Format(time.RFC3339),
		})
		return nil, err
	})
	return err
}

// SearchSimilarProbes returns the topK most similar MemoryProbe nodes.
// When outcome is non-empty, only probes matching that outcome are returned.
func (s *Neo4jVectorStore) SearchSimilarProbes(ctx context.Context, embedding []float32, outcome string, topK int) ([]ProbeMemory, error) {
	if s == nil || s.driver == nil {
		return nil, nil
	}
	if topK <= 0 {
		topK = 5
	}
	embList := float32SliceToInterface(embedding)

	// Build optional WHERE clause for outcome filter.
	outcomeFilter := ""
	params := map[string]any{
		"topK":      topK,
		"embedding": embList,
	}
	if strings.TrimSpace(outcome) != "" {
		outcomeFilter = "WHERE p.outcome = $outcome"
		params["outcome"] = strings.TrimSpace(outcome)
	}

	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, fmt.Sprintf(`
CALL db.index.vector.queryNodes('%s', $topK, $embedding)
YIELD node AS p, score
%s
RETURN p.id        AS id,
       p.target    AS target,
       p.scanId    AS scanId,
       p.category  AS category,
       p.endpoint  AS endpoint,
       p.payload   AS payload,
       p.outcome   AS outcome,
       p.createdAt AS createdAt,
       score
ORDER BY score DESC
`, probeVectorIndex, outcomeFilter), params)
		if err != nil {
			return nil, err
		}
		return collectProbeRows(ctx, rows)
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]ProbeMemory), nil
}

// ---------------------------------------------------------------------------
// Graph-traversal bonus methods (not on the Store interface)
// ---------------------------------------------------------------------------

// FindRelatedFindings returns findings on the same target that are connected
// to the probe chain that confirmed similar findings. This is the "vector graph"
// payoff: combine ANN similarity with graph traversal in one query.
//
// It first finds the topK most similar MemoryFinding nodes by embedding, then
// follows LED_TO_FINDING relationships backward from MemoryProbe nodes to
// surface related probes and their sibling findings on the same scan.
func (s *Neo4jVectorStore) FindRelatedFindings(ctx context.Context, embedding []float32, target string, topK int) ([]FindingMemory, error) {
	if s == nil || s.driver == nil {
		return nil, nil
	}
	if topK <= 0 {
		topK = 5
	}
	embList := float32SliceToInterface(embedding)

	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, fmt.Sprintf(`
// Step 1: ANN vector search for similar findings.
CALL db.index.vector.queryNodes('%s', $topK, $embedding)
YIELD node AS seed, score

// Step 2: expand via probe→finding graph edges to find related findings
// on the same target (cross-scan context).
OPTIONAL MATCH (p:MemoryProbe)-[:LED_TO_FINDING]->(seed)
OPTIONAL MATCH (p)-[:LED_TO_FINDING]->(related:MemoryFinding)
  WHERE related.target = $target AND related.id <> seed.id

WITH seed, related, score
// Collect seed + related, dedup by ID.
WITH collect(DISTINCT seed) + collect(DISTINCT related) AS all_findings
UNWIND all_findings AS f
WHERE f IS NOT NULL
RETURN DISTINCT
       f.id        AS id,
       f.target    AS target,
       f.scanId    AS scanId,
       f.category  AS category,
       f.title     AS title,
       f.severity  AS severity,
       f.createdAt AS createdAt
LIMIT $topK
`, findingVectorIndex), map[string]any{
			"topK":      topK,
			"embedding": embList,
			"target":    target,
		})
		if err != nil {
			return nil, err
		}
		return collectFindingRows(ctx, rows)
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]FindingMemory), nil
}

// Close shuts down the Neo4j driver.
func (s *Neo4jVectorStore) Close() error {
	if s == nil || s.driver == nil {
		return nil
	}
	return s.driver.Close(context.Background())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// float32SliceToInterface converts []float32 to []any for the Neo4j driver,
// which requires List<Float> parameters for vector operations.
func float32SliceToInterface(v []float32) []any {
	out := make([]any, len(v))
	for i, f := range v {
		out[i] = float64(f)
	}
	return out
}

// collectFindingRows scans a Neo4j result set into []FindingMemory.
func collectFindingRows(ctx context.Context, rows neo4j.ResultWithContext) ([]FindingMemory, error) {
	var out []FindingMemory
	for rows.Next(ctx) {
		rec := rows.Record()
		var m FindingMemory
		if v, ok := rec.Get("id"); ok {
			m.ID, _ = v.(string)
		}
		if v, ok := rec.Get("target"); ok {
			m.Target, _ = v.(string)
		}
		if v, ok := rec.Get("scanId"); ok {
			m.ScanID, _ = v.(string)
		}
		if v, ok := rec.Get("category"); ok {
			m.Category, _ = v.(string)
		}
		if v, ok := rec.Get("title"); ok {
			m.Title, _ = v.(string)
		}
		if v, ok := rec.Get("severity"); ok {
			m.Severity, _ = v.(string)
		}
		if v, ok := rec.Get("createdAt"); ok {
			if ts, ok := v.(string); ok {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					m.CreatedAt = t
				}
			}
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// collectProbeRows scans a Neo4j result set into []ProbeMemory.
func collectProbeRows(ctx context.Context, rows neo4j.ResultWithContext) ([]ProbeMemory, error) {
	var out []ProbeMemory
	for rows.Next(ctx) {
		rec := rows.Record()
		var m ProbeMemory
		if v, ok := rec.Get("id"); ok {
			m.ID, _ = v.(string)
		}
		if v, ok := rec.Get("target"); ok {
			m.Target, _ = v.(string)
		}
		if v, ok := rec.Get("scanId"); ok {
			m.ScanID, _ = v.(string)
		}
		if v, ok := rec.Get("category"); ok {
			m.Category, _ = v.(string)
		}
		if v, ok := rec.Get("endpoint"); ok {
			m.Endpoint, _ = v.(string)
		}
		if v, ok := rec.Get("payload"); ok {
			m.Payload, _ = v.(string)
		}
		if v, ok := rec.Get("outcome"); ok {
			m.Outcome, _ = v.(string)
		}
		if v, ok := rec.Get("createdAt"); ok {
			if ts, ok := v.(string); ok {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					m.CreatedAt = t
				}
			}
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// firstN returns the first n bytes of s for use in error messages.
func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
