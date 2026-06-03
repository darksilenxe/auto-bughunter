package graphdb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Neo4jStore struct {
	driver   neo4j.DriverWithContext
	database string
}

func NewNeo4jStore(ctx context.Context) (*Neo4jStore, error) {
	uri := strings.TrimSpace(os.Getenv("NEO4J_URI"))
	if uri == "" {
		return nil, nil
	}
	username := strings.TrimSpace(os.Getenv("NEO4J_USERNAME"))
	password := os.Getenv("NEO4J_PASSWORD")
	database := strings.TrimSpace(os.Getenv("NEO4J_DATABASE"))
	if database == "" {
		database = "neo4j"
	}

	var auth neo4j.AuthToken
	if username == "" {
		auth = neo4j.NoAuth()
	} else {
		auth = neo4j.BasicAuth(username, password, "")
	}
	driver, err := neo4j.NewDriverWithContext(uri, auth)
	if err != nil {
		return nil, fmt.Errorf("create neo4j driver: %w", err)
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := driver.VerifyConnectivity(verifyCtx); err != nil {
		_ = driver.Close(verifyCtx)
		return nil, fmt.Errorf("verify neo4j connectivity: %w", err)
	}

	return &Neo4jStore{
		driver:   driver,
		database: database,
	}, nil
}

func (s *Neo4jStore) Close(ctx context.Context) error {
	if s == nil || s.driver == nil {
		return nil
	}
	return s.driver.Close(ctx)
}

func (s *Neo4jStore) SaveAttackGraph(ctx context.Context, scanID, target string, graph *model.AttackGraphData) error {
	if s == nil || s.driver == nil || graph == nil || scanID == "" {
		return nil
	}
	raw, err := json.Marshal(graph)
	if err != nil {
		return fmt.Errorf("marshal attack graph: %w", err)
	}
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(ctx)

	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, runErr := tx.Run(ctx, `
MERGE (s:AttackScan {id: $scanId})
SET s.target = $target,
    s.status = $status,
    s.graph = $graph,
    s.updatedAt = datetime()
`, map[string]any{
			"scanId": scanID,
			"target": target,
			"status": strings.TrimSpace(graph.Status),
			"graph":  string(raw),
		})
		return nil, runErr
	})
	if err != nil {
		return fmt.Errorf("save attack graph to neo4j: %w", err)
	}
	return nil
}

func (s *Neo4jStore) LoadAttackGraph(ctx context.Context, scanID string) (*model.AttackGraphData, error) {
	if s == nil || s.driver == nil || scanID == "" {
		return nil, nil
	}
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, runErr := tx.Run(ctx, `
MATCH (s:AttackScan {id: $scanId})
RETURN s.graph AS graph
LIMIT 1
`, map[string]any{"scanId": scanID})
		if runErr != nil {
			return nil, runErr
		}
		if rows.Next(ctx) {
			return rows.Record().Values[0], nil
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return nil, fmt.Errorf("load attack graph from neo4j: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	raw, ok := result.(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var graph model.AttackGraphData
	if err := json.Unmarshal([]byte(raw), &graph); err != nil {
		return nil, fmt.Errorf("unmarshal neo4j attack graph: %w", err)
	}
	return &graph, nil
}
