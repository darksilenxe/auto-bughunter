package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Postgres struct {
	db *sql.DB
}

func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	repo := &Postgres{db: db}
	if err := repo.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return repo, nil
}

func (p *Postgres) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

func (p *Postgres) CreateJob(ctx context.Context, job *model.ScanJob) error {
	findingsJSON, err := json.Marshal(job.Findings)
	if err != nil {
		return err
	}
	summaryJSON, err := json.Marshal(job.AuthProfileSummary)
	if err != nil {
		return err
	}
	optionsJSON, err := json.Marshal(job.Options)
	if err != nil {
		return err
	}
	scopeJSON, err := json.Marshal(job.Scope)
	if err != nil {
		return err
	}
	agentRunsJSON, err := json.Marshal(job.AgentRuns)
	if err != nil {
		return err
	}
	assetLinksJSON, err := json.Marshal(job.AssetLinks)
	if err != nil {
		return err
	}
	dashboardJSON, err := json.Marshal(job.Dashboard)
	if err != nil {
		return err
	}
	nextActionsJSON, err := json.Marshal(job.NextActions)
	if err != nil {
		return err
	}

	_, err = p.db.ExecContext(ctx, `
		INSERT INTO scans (
			id, target, status, started_at, completed_at, findings, ai_summary, error, auth_profile_summary, options, scope, agent_runs, asset_links, dashboard, next_actions, automated_report
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
	`, job.ID, job.Target, job.Status, job.StartedAt, job.CompletedAt, findingsJSON, job.AISummary, job.Error, summaryJSON, optionsJSON, scopeJSON, agentRunsJSON, assetLinksJSON, dashboardJSON, nextActionsJSON, job.AutomatedReport)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}
	return nil
}

func (p *Postgres) UpdateJob(ctx context.Context, job *model.ScanJob) error {
	findingsJSON, err := json.Marshal(job.Findings)
	if err != nil {
		return err
	}
	summaryJSON, err := json.Marshal(job.AuthProfileSummary)
	if err != nil {
		return err
	}
	optionsJSON, err := json.Marshal(job.Options)
	if err != nil {
		return err
	}
	scopeJSON, err := json.Marshal(job.Scope)
	if err != nil {
		return err
	}
	agentRunsJSON, err := json.Marshal(job.AgentRuns)
	if err != nil {
		return err
	}
	assetLinksJSON, err := json.Marshal(job.AssetLinks)
	if err != nil {
		return err
	}
	dashboardJSON, err := json.Marshal(job.Dashboard)
	if err != nil {
		return err
	}
	nextActionsJSON, err := json.Marshal(job.NextActions)
	if err != nil {
		return err
	}

	res, err := p.db.ExecContext(ctx, `
		UPDATE scans
		SET status = $2,
			completed_at = $3,
			findings = $4,
			ai_summary = $5,
			error = $6,
			auth_profile_summary = $7,
			options = $8,
			scope = $9,
			agent_runs = $10,
			asset_links = $11,
			dashboard = $12,
			next_actions = $13,
			automated_report = $14
		WHERE id = $1
	`, job.ID, job.Status, job.CompletedAt, findingsJSON, job.AISummary, job.Error, summaryJSON, optionsJSON, scopeJSON, agentRunsJSON, assetLinksJSON, dashboardJSON, nextActionsJSON, job.AutomatedReport)
	if err != nil {
		return fmt.Errorf("update scan: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (p *Postgres) GetJob(ctx context.Context, id string) (*model.ScanJob, error) {
	row := p.db.QueryRowContext(ctx, `
		SELECT id, target, status, started_at, completed_at, findings, ai_summary, error, auth_profile_summary, options, scope, agent_runs, asset_links, dashboard, next_actions, automated_report
		FROM scans
		WHERE id = $1
	`, id)

	var job model.ScanJob
	var findingsRaw []byte
	var summaryRaw []byte
	var optionsRaw []byte
	var scopeRaw []byte
	var agentRunsRaw []byte
	var assetLinksRaw []byte
	var dashboardRaw []byte
	var nextActionsRaw []byte
	if err := row.Scan(
		&job.ID,
		&job.Target,
		&job.Status,
		&job.StartedAt,
		&job.CompletedAt,
		&findingsRaw,
		&job.AISummary,
		&job.Error,
		&summaryRaw,
		&optionsRaw,
		&scopeRaw,
		&agentRunsRaw,
		&assetLinksRaw,
		&dashboardRaw,
		&nextActionsRaw,
		&job.AutomatedReport,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("select scan: %w", err)
	}

	if len(findingsRaw) > 0 {
		_ = json.Unmarshal(findingsRaw, &job.Findings)
	}
	if len(summaryRaw) > 0 && string(summaryRaw) != "null" {
		var summary model.ScanAuthProfileSummary
		if err := json.Unmarshal(summaryRaw, &summary); err == nil {
			job.AuthProfileSummary = &summary
		}
	}
	if len(optionsRaw) > 0 {
		_ = json.Unmarshal(optionsRaw, &job.Options)
	}
	if len(scopeRaw) > 0 {
		_ = json.Unmarshal(scopeRaw, &job.Scope)
	}
	if len(agentRunsRaw) > 0 {
		_ = json.Unmarshal(agentRunsRaw, &job.AgentRuns)
	}
	if len(assetLinksRaw) > 0 {
		_ = json.Unmarshal(assetLinksRaw, &job.AssetLinks)
	}
	if len(dashboardRaw) > 0 && string(dashboardRaw) != "null" {
		var dashboard model.DecisionDashboard
		if err := json.Unmarshal(dashboardRaw, &dashboard); err == nil {
			job.Dashboard = &dashboard
		}
	}
	if len(nextActionsRaw) > 0 {
		_ = json.Unmarshal(nextActionsRaw, &job.NextActions)
	}
	job.Assets, _ = p.GetAssetsByScanID(ctx, job.ID)
	job.AuditTrail, _ = p.ListAuditEvents(ctx, job.ID)

	return &job, nil
}

func (p *Postgres) migrate(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			status TEXT NOT NULL,
			started_at TIMESTAMPTZ NOT NULL,
			completed_at TIMESTAMPTZ NULL,
			findings JSONB NOT NULL DEFAULT '[]'::jsonb,
			ai_summary TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			auth_profile_summary JSONB NULL,
			options JSONB NOT NULL DEFAULT '{}'::jsonb,
			scope JSONB NOT NULL DEFAULT '{}'::jsonb
			,agent_runs JSONB NOT NULL DEFAULT '[]'::jsonb
			,asset_links JSONB NOT NULL DEFAULT '[]'::jsonb
			,dashboard JSONB NULL
			,next_actions JSONB NOT NULL DEFAULT '[]'::jsonb
			,automated_report TEXT NOT NULL DEFAULT ''
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate scans table: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS scope JSONB NOT NULL DEFAULT '{}'::jsonb`); err != nil {
		return fmt.Errorf("migrate scans.scope column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS agent_runs JSONB NOT NULL DEFAULT '[]'::jsonb`); err != nil {
		return fmt.Errorf("migrate scans.agent_runs column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS asset_links JSONB NOT NULL DEFAULT '[]'::jsonb`); err != nil {
		return fmt.Errorf("migrate scans.asset_links column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS dashboard JSONB NULL`); err != nil {
		return fmt.Errorf("migrate scans.dashboard column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS next_actions JSONB NOT NULL DEFAULT '[]'::jsonb`); err != nil {
		return fmt.Errorf("migrate scans.next_actions column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS automated_report TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate scans.automated_report column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS scan_assets (
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			asset_type TEXT NOT NULL,
			asset_key TEXT NOT NULL,
			asset_value TEXT NOT NULL DEFAULT '',
			discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (scan_id, asset_type, asset_key)
		)
	`); err != nil {
		return fmt.Errorf("migrate scan_assets table: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS scan_events (
			id BIGSERIAL PRIMARY KEY,
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			stage TEXT NOT NULL,
			message TEXT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("migrate scan_events table: %w", err)
	}

	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS proxy_requests (
			id TEXT PRIMARY KEY,
			captured_at TIMESTAMPTZ NOT NULL,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			request_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
			request_body TEXT NOT NULL DEFAULT '',
			response_status INTEGER NOT NULL DEFAULT 0,
			response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
			response_body TEXT NOT NULL DEFAULT '',
			notes TEXT NOT NULL DEFAULT ''
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate proxy_requests table: %w", err)
	}
	return nil
}

func (p *Postgres) GetLatestCompletedJobByTarget(ctx context.Context, target, excludeID string) (*model.ScanJob, error) {
	row := p.db.QueryRowContext(ctx, `
		SELECT id, target, status, started_at, completed_at, findings, ai_summary, error, auth_profile_summary, options, scope, agent_runs, asset_links, dashboard, next_actions, automated_report
		FROM scans
		WHERE target = $1 AND status = 'completed' AND id <> $2
		ORDER BY completed_at DESC NULLS LAST, started_at DESC
		LIMIT 1
	`, target, excludeID)

	var job model.ScanJob
	var findingsRaw, summaryRaw, optionsRaw, scopeRaw, agentRunsRaw, assetLinksRaw, dashboardRaw, nextActionsRaw []byte
	if err := row.Scan(
		&job.ID,
		&job.Target,
		&job.Status,
		&job.StartedAt,
		&job.CompletedAt,
		&findingsRaw,
		&job.AISummary,
		&job.Error,
		&summaryRaw,
		&optionsRaw,
		&scopeRaw,
		&agentRunsRaw,
		&assetLinksRaw,
		&dashboardRaw,
		&nextActionsRaw,
		&job.AutomatedReport,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("select latest completed scan: %w", err)
	}

	if len(findingsRaw) > 0 {
		_ = json.Unmarshal(findingsRaw, &job.Findings)
	}
	if len(summaryRaw) > 0 && string(summaryRaw) != "null" {
		var summary model.ScanAuthProfileSummary
		if err := json.Unmarshal(summaryRaw, &summary); err == nil {
			job.AuthProfileSummary = &summary
		}
	}
	if len(optionsRaw) > 0 {
		_ = json.Unmarshal(optionsRaw, &job.Options)
	}
	if len(scopeRaw) > 0 {
		_ = json.Unmarshal(scopeRaw, &job.Scope)
	}
	if len(agentRunsRaw) > 0 {
		_ = json.Unmarshal(agentRunsRaw, &job.AgentRuns)
	}
	if len(assetLinksRaw) > 0 {
		_ = json.Unmarshal(assetLinksRaw, &job.AssetLinks)
	}
	if len(dashboardRaw) > 0 && string(dashboardRaw) != "null" {
		var dashboard model.DecisionDashboard
		if err := json.Unmarshal(dashboardRaw, &dashboard); err == nil {
			job.Dashboard = &dashboard
		}
	}
	if len(nextActionsRaw) > 0 {
		_ = json.Unmarshal(nextActionsRaw, &job.NextActions)
	}
	job.Assets, _ = p.GetAssetsByScanID(ctx, job.ID)
	job.AuditTrail, _ = p.ListAuditEvents(ctx, job.ID)

	return &job, nil
}

func (p *Postgres) SaveAssets(ctx context.Context, scanID string, assets []model.ScanAsset) error {
	if strings.TrimSpace(scanID) == "" {
		return errors.New("scanID is required")
	}
	if _, err := p.db.ExecContext(ctx, `DELETE FROM scan_assets WHERE scan_id = $1`, scanID); err != nil {
		return fmt.Errorf("clear scan assets: %w", err)
	}
	if len(assets) == 0 {
		return nil
	}
	for _, asset := range assets {
		discoveredAt := asset.DiscoveredAt
		if discoveredAt.IsZero() {
			discoveredAt = time.Now().UTC()
		}
		_, err := p.db.ExecContext(ctx, `
			INSERT INTO scan_assets (scan_id, asset_type, asset_key, asset_value, discovered_at)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (scan_id, asset_type, asset_key)
			DO UPDATE SET asset_value = EXCLUDED.asset_value, discovered_at = EXCLUDED.discovered_at
		`, scanID, asset.AssetType, asset.AssetKey, asset.AssetValue, discoveredAt)
		if err != nil {
			return fmt.Errorf("insert scan asset: %w", err)
		}
	}
	return nil
}

func (p *Postgres) GetAssetsByScanID(ctx context.Context, scanID string) ([]model.ScanAsset, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT asset_type, asset_key, asset_value, discovered_at
		FROM scan_assets
		WHERE scan_id = $1
		ORDER BY asset_type, asset_key
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list scan assets: %w", err)
	}
	defer rows.Close()
	var out []model.ScanAsset
	for rows.Next() {
		var asset model.ScanAsset
		if err := rows.Scan(&asset.AssetType, &asset.AssetKey, &asset.AssetValue, &asset.DiscoveredAt); err != nil {
			return nil, fmt.Errorf("scan scan asset row: %w", err)
		}
		out = append(out, asset)
	}
	return out, rows.Err()
}

func (p *Postgres) AppendAuditEvent(ctx context.Context, scanID string, event model.ScanAuditEvent) error {
	if strings.TrimSpace(scanID) == "" {
		return errors.New("scanID is required")
	}
	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO scan_events (scan_id, stage, message, timestamp)
		VALUES ($1,$2,$3,$4)
	`, scanID, strings.TrimSpace(event.Stage), strings.TrimSpace(event.Message), ts)
	if err != nil {
		return fmt.Errorf("insert scan event: %w", err)
	}
	return nil
}

func (p *Postgres) ListAuditEvents(ctx context.Context, scanID string) ([]model.ScanAuditEvent, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT stage, message, timestamp
		FROM scan_events
		WHERE scan_id = $1
		ORDER BY timestamp ASC, id ASC
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list scan events: %w", err)
	}
	defer rows.Close()
	var out []model.ScanAuditEvent
	for rows.Next() {
		var event model.ScanAuditEvent
		if err := rows.Scan(&event.Stage, &event.Message, &event.Timestamp); err != nil {
			return nil, fmt.Errorf("scan scan event row: %w", err)
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

// SaveProxyRequest persists a new captured proxy request/response pair.
func (p *Postgres) SaveProxyRequest(ctx context.Context, req *model.ProxyRequest) error {
	reqHeadersJSON, err := json.Marshal(req.RequestHeaders)
	if err != nil {
		return err
	}
	respHeadersJSON, err := json.Marshal(req.ResponseHeaders)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO proxy_requests
			(id, captured_at, method, url, request_headers, request_body, response_status, response_headers, response_body, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, req.ID, req.CapturedAt, req.Method, req.URL,
		reqHeadersJSON, req.RequestBody,
		req.ResponseStatus,
		respHeadersJSON, req.ResponseBody, req.Notes)
	if err != nil {
		return fmt.Errorf("insert proxy_request: %w", err)
	}
	return nil
}

// ListProxyRequests returns all captured proxy requests ordered by capture time descending.
func (p *Postgres) ListProxyRequests(ctx context.Context) ([]*model.ProxyRequest, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, captured_at, method, url, request_headers, request_body,
		       response_status, response_headers, response_body, notes
		FROM proxy_requests
		ORDER BY captured_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list proxy_requests: %w", err)
	}
	defer rows.Close()

	var out []*model.ProxyRequest
	for rows.Next() {
		pr, err := scanProxyRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, rows.Err()
}

// GetProxyRequest returns a single proxy request by ID.
func (p *Postgres) GetProxyRequest(ctx context.Context, id string) (*model.ProxyRequest, error) {
	row := p.db.QueryRowContext(ctx, `
		SELECT id, captured_at, method, url, request_headers, request_body,
		       response_status, response_headers, response_body, notes
		FROM proxy_requests
		WHERE id = $1
	`, id)
	pr, err := scanProxyRequest(row)
	if err != nil {
		return nil, fmt.Errorf("get proxy_request %s: %w", id, err)
	}
	return pr, nil
}

// ClearProxyRequests deletes all captured proxy requests.
func (p *Postgres) ClearProxyRequests(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM proxy_requests`)
	if err != nil {
		return fmt.Errorf("clear proxy_requests: %w", err)
	}
	return nil
}

// scanner is a minimal interface for sql.Row and sql.Rows scan.
type scanner interface {
	Scan(dest ...any) error
}

func scanProxyRequest(s scanner) (*model.ProxyRequest, error) {
	var pr model.ProxyRequest
	var reqHeadersRaw, respHeadersRaw []byte
	if err := s.Scan(
		&pr.ID, &pr.CapturedAt, &pr.Method, &pr.URL,
		&reqHeadersRaw, &pr.RequestBody,
		&pr.ResponseStatus,
		&respHeadersRaw, &pr.ResponseBody, &pr.Notes,
	); err != nil {
		return nil, err
	}
	if len(reqHeadersRaw) > 0 {
		_ = json.Unmarshal(reqHeadersRaw, &pr.RequestHeaders)
	}
	if len(respHeadersRaw) > 0 {
		_ = json.Unmarshal(respHeadersRaw, &pr.ResponseHeaders)
	}
	return &pr, nil
}
