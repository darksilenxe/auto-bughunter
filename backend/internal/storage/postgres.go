package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

type Postgres struct {
	db             *sql.DB
	proxyRetention time.Duration
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

	repo := &Postgres{db: db, proxyRetention: proxyRetentionFromEnv()}
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

func proxyRetentionFromEnv() time.Duration {
	v := strings.TrimSpace(os.Getenv("PROXY_RETENTION_HOURS"))
	if v == "" {
		return 7 * 24 * time.Hour
	}
	hours, err := strconv.Atoi(v)
	if err != nil || hours <= 0 {
		return 7 * 24 * time.Hour
	}
	return time.Duration(hours) * time.Hour
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
	modelRecommendationsJSON, err := json.Marshal(job.ModelRecommendations)
	if err != nil {
		return err
	}
	disallowedTestsJSON, err := json.Marshal(job.DisallowedTestTypes)
	if err != nil {
		return err
	}

	_, err = p.db.ExecContext(ctx, `
		INSERT INTO scans (
			id, target, workspace_id, requested_by, policy_pack, status, started_at, completed_at, findings, ai_summary, model_recommendations, error, auth_profile_summary, options, scope, agent_runs, asset_links, dashboard, next_actions, automated_report, program_name, program_policy_version, disallowed_test_types
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
	`, job.ID, job.Target, job.WorkspaceID, job.RequestedBy, job.PolicyPack, job.Status, job.StartedAt, job.CompletedAt, findingsJSON, job.AISummary, modelRecommendationsJSON, job.Error, summaryJSON, optionsJSON, scopeJSON, agentRunsJSON, assetLinksJSON, dashboardJSON, nextActionsJSON, job.AutomatedReport, job.ProgramName, job.ProgramPolicyVersion, disallowedTestsJSON)
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
	modelRecommendationsJSON, err := json.Marshal(job.ModelRecommendations)
	if err != nil {
		return err
	}
	disallowedTestsJSON, err := json.Marshal(job.DisallowedTestTypes)
	if err != nil {
		return err
	}

	res, err := p.db.ExecContext(ctx, `
		UPDATE scans
		SET status = $2,
			completed_at = $3,
			findings = $4,
			ai_summary = $5,
			model_recommendations = $6,
			error = $7,
			auth_profile_summary = $8,
			options = $9,
			scope = $10,
			agent_runs = $11,
			asset_links = $12,
			dashboard = $13,
			next_actions = $14,
			automated_report = $15,
			program_name = $16,
			program_policy_version = $17,
			disallowed_test_types = $18,
			workspace_id = $19,
			requested_by = $20,
			policy_pack = $21
		WHERE id = $1
	`, job.ID, job.Status, job.CompletedAt, findingsJSON, job.AISummary, modelRecommendationsJSON, job.Error, summaryJSON, optionsJSON, scopeJSON, agentRunsJSON, assetLinksJSON, dashboardJSON, nextActionsJSON, job.AutomatedReport, job.ProgramName, job.ProgramPolicyVersion, disallowedTestsJSON, job.WorkspaceID, job.RequestedBy, job.PolicyPack)
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
		SELECT id, target, workspace_id, requested_by, policy_pack, status, started_at, completed_at, findings, ai_summary, model_recommendations, error, auth_profile_summary, options, scope, agent_runs, asset_links, dashboard, next_actions, automated_report, program_name, program_policy_version, disallowed_test_types
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
	var modelRecommendationsRaw []byte
	var disallowedTestsRaw []byte
	if err := row.Scan(
		&job.ID,
		&job.Target,
		&job.WorkspaceID,
		&job.RequestedBy,
		&job.PolicyPack,
		&job.Status,
		&job.StartedAt,
		&job.CompletedAt,
		&findingsRaw,
		&job.AISummary,
		&modelRecommendationsRaw,
		&job.Error,
		&summaryRaw,
		&optionsRaw,
		&scopeRaw,
		&agentRunsRaw,
		&assetLinksRaw,
		&dashboardRaw,
		&nextActionsRaw,
		&job.AutomatedReport,
		&job.ProgramName,
		&job.ProgramPolicyVersion,
		&disallowedTestsRaw,
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
	if len(modelRecommendationsRaw) > 0 && string(modelRecommendationsRaw) != "null" {
		var modelRecommendations model.ModelRecommendations
		if err := json.Unmarshal(modelRecommendationsRaw, &modelRecommendations); err == nil {
			job.ModelRecommendations = &modelRecommendations
		}
	}
	if len(disallowedTestsRaw) > 0 {
		_ = json.Unmarshal(disallowedTestsRaw, &job.DisallowedTestTypes)
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
			workspace_id TEXT NOT NULL DEFAULT 'default',
			requested_by TEXT NOT NULL DEFAULT '',
			policy_pack TEXT NOT NULL DEFAULT 'internal',
			status TEXT NOT NULL,
			started_at TIMESTAMPTZ NOT NULL,
			completed_at TIMESTAMPTZ NULL,
			findings JSONB NOT NULL DEFAULT '[]'::jsonb,
			ai_summary TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			model_recommendations JSONB NULL,
			auth_profile_summary JSONB NULL,
			options JSONB NOT NULL DEFAULT '{}'::jsonb,
			scope JSONB NOT NULL DEFAULT '{}'::jsonb
			,agent_runs JSONB NOT NULL DEFAULT '[]'::jsonb
			,asset_links JSONB NOT NULL DEFAULT '[]'::jsonb
			,dashboard JSONB NULL
			,next_actions JSONB NOT NULL DEFAULT '[]'::jsonb
			,automated_report TEXT NOT NULL DEFAULT ''
			,program_name TEXT NOT NULL DEFAULT ''
			,program_policy_version TEXT NOT NULL DEFAULT ''
			,disallowed_test_types JSONB NOT NULL DEFAULT '[]'::jsonb
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
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS model_recommendations JSONB NULL`); err != nil {
		return fmt.Errorf("migrate scans.model_recommendations column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS program_name TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate scans.program_name column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS program_policy_version TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate scans.program_policy_version column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS disallowed_test_types JSONB NOT NULL DEFAULT '[]'::jsonb`); err != nil {
		return fmt.Errorf("migrate scans.disallowed_test_types column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT 'default'`); err != nil {
		return fmt.Errorf("migrate scans.workspace_id column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS requested_by TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate scans.requested_by column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE scans ADD COLUMN IF NOT EXISTS policy_pack TEXT NOT NULL DEFAULT 'internal'`); err != nil {
		return fmt.Errorf("migrate scans.policy_pack column: %w", err)
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
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS report_feedback (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			finding_id TEXT NOT NULL,
			category TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL DEFAULT '',
			program_name TEXT NOT NULL DEFAULT '',
			outcome TEXT NOT NULL,
			payout_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
			notes TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate report_feedback table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS finding_verifications (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			finding_id TEXT NOT NULL,
			status TEXT NOT NULL,
			notes TEXT NOT NULL DEFAULT '',
			verified_by TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate finding_verifications table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS suppression_rules (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL DEFAULT '',
			finding_id TEXT NOT NULL DEFAULT '',
			category TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate suppression_rules table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS scan_states (
			target TEXT PRIMARY KEY,
			last_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			session_instability INTEGER NOT NULL DEFAULT 0,
			known_runtime_endpoints JSONB NOT NULL DEFAULT '[]'::jsonb
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate scan_states table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS scan_idempotency (
			idempotency_key TEXT NOT NULL,
			target TEXT NOT NULL,
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (idempotency_key, target)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate scan_idempotency table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS automation_tickets (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL,
			owner TEXT NOT NULL DEFAULT '',
			sla_due_at TIMESTAMPTZ NULL,
			first_seen_at TIMESTAMPTZ NOT NULL,
			last_seen_at TIMESTAMPTZ NOT NULL,
			resolved_at TIMESTAMPTZ NULL,
			UNIQUE(target, fingerprint)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate automation_tickets table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL,
			name TEXT NOT NULL,
			role TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			key_prefix TEXT NOT NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			rotated_at TIMESTAMPTZ NULL,
			revoked_at TIMESTAMPTZ NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate api_keys table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS automation_campaigns (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			workspace_id TEXT NOT NULL DEFAULT 'default',
			requested_by TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '',
			interval_min INTEGER NOT NULL,
			next_run_at TIMESTAMPTZ NULL,
			last_run_at TIMESTAMPTZ NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			auth_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
			options JSONB NOT NULL DEFAULT '{}'::jsonb,
			scope JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate automation_campaigns table: %w", err)
	}
	return nil
}

func (p *Postgres) GetLatestCompletedJobByTarget(ctx context.Context, target, excludeID string) (*model.ScanJob, error) {
	row := p.db.QueryRowContext(ctx, `
		SELECT id, target, workspace_id, requested_by, policy_pack, status, started_at, completed_at, findings, ai_summary, model_recommendations, error, auth_profile_summary, options, scope, agent_runs, asset_links, dashboard, next_actions, automated_report, program_name, program_policy_version, disallowed_test_types
		FROM scans
		WHERE target = $1 AND status = 'completed' AND id <> $2
		ORDER BY completed_at DESC NULLS LAST, started_at DESC
		LIMIT 1
	`, target, excludeID)

	var job model.ScanJob
	var findingsRaw, summaryRaw, optionsRaw, scopeRaw, agentRunsRaw, assetLinksRaw, dashboardRaw, nextActionsRaw, modelRecommendationsRaw, disallowedTestsRaw []byte
	if err := row.Scan(
		&job.ID,
		&job.Target,
		&job.WorkspaceID,
		&job.RequestedBy,
		&job.PolicyPack,
		&job.Status,
		&job.StartedAt,
		&job.CompletedAt,
		&findingsRaw,
		&job.AISummary,
		&modelRecommendationsRaw,
		&job.Error,
		&summaryRaw,
		&optionsRaw,
		&scopeRaw,
		&agentRunsRaw,
		&assetLinksRaw,
		&dashboardRaw,
		&nextActionsRaw,
		&job.AutomatedReport,
		&job.ProgramName,
		&job.ProgramPolicyVersion,
		&disallowedTestsRaw,
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
	if len(modelRecommendationsRaw) > 0 && string(modelRecommendationsRaw) != "null" {
		var modelRecommendations model.ModelRecommendations
		if err := json.Unmarshal(modelRecommendationsRaw, &modelRecommendations); err == nil {
			job.ModelRecommendations = &modelRecommendations
		}
	}
	if len(disallowedTestsRaw) > 0 {
		_ = json.Unmarshal(disallowedTestsRaw, &job.DisallowedTestTypes)
	}
	job.Assets, _ = p.GetAssetsByScanID(ctx, job.ID)
	job.AuditTrail, _ = p.ListAuditEvents(ctx, job.ID)

	return &job, nil
}

func (p *Postgres) ListCompletedJobs(ctx context.Context, limit int) ([]*model.ScanJob, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, target, workspace_id, requested_by, policy_pack, status, started_at, completed_at, findings, ai_summary, model_recommendations, error, auth_profile_summary, options, scope, agent_runs, asset_links, dashboard, next_actions, automated_report, program_name, program_policy_version, disallowed_test_types
		FROM scans
		WHERE status = 'completed'
		ORDER BY completed_at DESC NULLS LAST, started_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list completed scans: %w", err)
	}
	defer rows.Close()

	out := make([]*model.ScanJob, 0)
	for rows.Next() {
		var job model.ScanJob
		var findingsRaw, summaryRaw, optionsRaw, scopeRaw, agentRunsRaw, assetLinksRaw, dashboardRaw, nextActionsRaw, modelRecommendationsRaw, disallowedTestsRaw []byte
		if err := rows.Scan(
			&job.ID,
			&job.Target,
			&job.WorkspaceID,
			&job.RequestedBy,
			&job.PolicyPack,
			&job.Status,
			&job.StartedAt,
			&job.CompletedAt,
			&findingsRaw,
			&job.AISummary,
			&modelRecommendationsRaw,
			&job.Error,
			&summaryRaw,
			&optionsRaw,
			&scopeRaw,
			&agentRunsRaw,
			&assetLinksRaw,
			&dashboardRaw,
			&nextActionsRaw,
			&job.AutomatedReport,
			&job.ProgramName,
			&job.ProgramPolicyVersion,
			&disallowedTestsRaw,
		); err != nil {
			return nil, fmt.Errorf("scan completed scan row: %w", err)
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
		if len(modelRecommendationsRaw) > 0 && string(modelRecommendationsRaw) != "null" {
			var modelRecommendations model.ModelRecommendations
			if err := json.Unmarshal(modelRecommendationsRaw, &modelRecommendations); err == nil {
				job.ModelRecommendations = &modelRecommendations
			}
		}
		if len(disallowedTestsRaw) > 0 {
			_ = json.Unmarshal(disallowedTestsRaw, &job.DisallowedTestTypes)
		}
		out = append(out, &job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate completed scans: %w", err)
	}
	return out, nil
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
	if req == nil {
		return errors.New("proxy request is required")
	}
	sanitized := *req
	sanitized.RequestHeaders = redactHeaders(req.RequestHeaders)
	sanitized.ResponseHeaders = redactHeaders(req.ResponseHeaders)
	sanitized.RequestBody = redactText(req.RequestBody)
	sanitized.ResponseBody = redactText(req.ResponseBody)

	if p.proxyRetention > 0 {
		cutoff := time.Now().UTC().Add(-p.proxyRetention)
		_, _ = p.db.ExecContext(ctx, `DELETE FROM proxy_requests WHERE captured_at < $1`, cutoff)
	}

	reqHeadersJSON, err := json.Marshal(sanitized.RequestHeaders)
	if err != nil {
		return err
	}
	respHeadersJSON, err := json.Marshal(sanitized.ResponseHeaders)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO proxy_requests
			(id, captured_at, method, url, request_headers, request_body, response_status, response_headers, response_body, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, sanitized.ID, sanitized.CapturedAt, sanitized.Method, sanitized.URL,
		reqHeadersJSON, sanitized.RequestBody,
		sanitized.ResponseStatus,
		respHeadersJSON, sanitized.ResponseBody, sanitized.Notes)
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

func (p *Postgres) SaveFeedback(ctx context.Context, feedback model.ReportFeedback) error {
	if strings.TrimSpace(feedback.ID) == "" {
		return errors.New("feedback id is required")
	}
	if strings.TrimSpace(feedback.ScanID) == "" {
		return errors.New("feedback scanID is required")
	}
	if strings.TrimSpace(feedback.FindingID) == "" {
		return errors.New("feedback findingID is required")
	}
	if strings.TrimSpace(feedback.Outcome) == "" {
		return errors.New("feedback outcome is required")
	}
	ts := feedback.CreatedAt
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO report_feedback (
			id, scan_id, finding_id, category, title, program_name, outcome, payout_usd, notes, created_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, feedback.ID, feedback.ScanID, feedback.FindingID, feedback.Category, feedback.Title, feedback.ProgramName, feedback.Outcome, feedback.PayoutUSD, feedback.Notes, ts)
	if err != nil {
		return fmt.Errorf("insert report feedback: %w", err)
	}
	return nil
}

func (p *Postgres) ListFeedback(ctx context.Context, limit int) ([]model.ReportFeedback, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, scan_id, finding_id, category, title, program_name, outcome, payout_usd, notes, created_at
		FROM report_feedback
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list report feedback: %w", err)
	}
	defer rows.Close()
	out := make([]model.ReportFeedback, 0)
	for rows.Next() {
		var f model.ReportFeedback
		if err := rows.Scan(&f.ID, &f.ScanID, &f.FindingID, &f.Category, &f.Title, &f.ProgramName, &f.Outcome, &f.PayoutUSD, &f.Notes, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan report feedback row: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (p *Postgres) SaveFindingVerification(ctx context.Context, verification model.FindingVerification) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO finding_verifications (id, scan_id, finding_id, status, notes, verified_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, verification.ID, verification.ScanID, verification.FindingID, verification.Status, verification.Notes, verification.VerifiedBy, verification.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert finding verification: %w", err)
	}
	return nil
}

func (p *Postgres) GetLatestFindingVerifications(ctx context.Context, scanID string) (map[string]model.FindingVerification, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT DISTINCT ON (finding_id) id, scan_id, finding_id, status, notes, verified_by, created_at
		FROM finding_verifications
		WHERE scan_id = $1
		ORDER BY finding_id, created_at DESC
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list finding verifications: %w", err)
	}
	defer rows.Close()
	out := map[string]model.FindingVerification{}
	for rows.Next() {
		var v model.FindingVerification
		if err := rows.Scan(&v.ID, &v.ScanID, &v.FindingID, &v.Status, &v.Notes, &v.VerifiedBy, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan finding verification row: %w", err)
		}
		out[v.FindingID] = v
	}
	return out, rows.Err()
}

func (p *Postgres) SaveSuppressionRule(ctx context.Context, rule model.SuppressionRule) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO suppression_rules (id, target, finding_id, category, title, reason, created_by, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, rule.ID, rule.Target, rule.FindingID, rule.Category, rule.Title, rule.Reason, rule.CreatedBy, rule.CreatedAt, rule.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert suppression rule: %w", err)
	}
	return nil
}

func (p *Postgres) ListActiveSuppressionRules(ctx context.Context, target string, now time.Time) ([]model.SuppressionRule, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, target, finding_id, category, title, reason, created_by, created_at, expires_at
		FROM suppression_rules
		WHERE (target = '' OR target = $1) AND (expires_at IS NULL OR expires_at > $2)
		ORDER BY created_at DESC
	`, target, now)
	if err != nil {
		return nil, fmt.Errorf("list suppression rules: %w", err)
	}
	defer rows.Close()
	out := make([]model.SuppressionRule, 0)
	for rows.Next() {
		var r model.SuppressionRule
		if err := rows.Scan(&r.ID, &r.Target, &r.FindingID, &r.Category, &r.Title, &r.Reason, &r.CreatedBy, &r.CreatedAt, &r.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan suppression rule row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) GetScanState(ctx context.Context, target string) (*model.PersistentScanState, error) {
	row := p.db.QueryRowContext(ctx, `
		SELECT target, last_updated_at, session_instability, known_runtime_endpoints
		FROM scan_states
		WHERE target = $1
	`, target)
	var state model.PersistentScanState
	var endpointsRaw []byte
	if err := row.Scan(&state.Target, &state.LastUpdatedAt, &state.SessionInstability, &endpointsRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get scan state: %w", err)
	}
	if len(endpointsRaw) > 0 {
		_ = json.Unmarshal(endpointsRaw, &state.KnownRuntimeEndpoints)
	}
	return &state, nil
}

func (p *Postgres) UpsertScanState(ctx context.Context, state model.PersistentScanState) error {
	endpointsJSON, err := json.Marshal(state.KnownRuntimeEndpoints)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO scan_states (target, last_updated_at, session_instability, known_runtime_endpoints)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (target) DO UPDATE
		SET last_updated_at = EXCLUDED.last_updated_at,
			session_instability = EXCLUDED.session_instability,
			known_runtime_endpoints = EXCLUDED.known_runtime_endpoints
	`, state.Target, state.LastUpdatedAt, state.SessionInstability, endpointsJSON)
	if err != nil {
		return fmt.Errorf("upsert scan state: %w", err)
	}
	return nil
}

func (p *Postgres) SaveIdempotencyRecord(ctx context.Context, key, target, scanID string, createdAt time.Time) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO scan_idempotency (idempotency_key, target, scan_id, created_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (idempotency_key, target)
		DO UPDATE SET scan_id = EXCLUDED.scan_id, created_at = EXCLUDED.created_at
	`, key, target, scanID, createdAt)
	if err != nil {
		return fmt.Errorf("insert idempotency: %w", err)
	}
	return nil
}

func (p *Postgres) GetRecentJobByIdempotencyKey(ctx context.Context, key, target string, since time.Time) (*model.ScanJob, error) {
	row := p.db.QueryRowContext(ctx, `
		SELECT s.id
		FROM scan_idempotency si
		INNER JOIN scans s ON s.id = si.scan_id
		WHERE si.idempotency_key = $1 AND si.target = $2 AND si.created_at >= $3
		LIMIT 1
	`, key, target, since)
	var id string
	if err := row.Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get idempotency job: %w", err)
	}
	return p.GetJob(ctx, id)
}

func (p *Postgres) UpsertAutomationTicket(ctx context.Context, ticket model.AutomationTicket) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO automation_tickets (
			id, target, fingerprint, title, severity, status, owner, sla_due_at, first_seen_at, last_seen_at, resolved_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (target, fingerprint) DO UPDATE
		SET title = EXCLUDED.title,
			severity = EXCLUDED.severity,
			status = EXCLUDED.status,
			owner = EXCLUDED.owner,
			sla_due_at = EXCLUDED.sla_due_at,
			last_seen_at = EXCLUDED.last_seen_at,
			resolved_at = EXCLUDED.resolved_at
	`, ticket.ID, ticket.Target, ticket.Fingerprint, ticket.Title, string(ticket.Severity), ticket.Status, ticket.Owner, ticket.SLADueAt, ticket.FirstSeenAt, ticket.LastSeenAt, ticket.ResolvedAt)
	if err != nil {
		return fmt.Errorf("upsert automation ticket: %w", err)
	}
	return nil
}

func (p *Postgres) ResolveAutomationTicketsMissingFingerprints(ctx context.Context, target string, fingerprints []string, resolvedAt time.Time) (int64, error) {
	if len(fingerprints) == 0 {
		res, err := p.db.ExecContext(ctx, `
			UPDATE automation_tickets
			SET status = 'resolved',
				resolved_at = $2
			WHERE target = $1
				AND status <> 'resolved'
		`, target, resolvedAt)
		if err != nil {
			return 0, fmt.Errorf("resolve automation tickets: %w", err)
		}
		rows, _ := res.RowsAffected()
		return rows, nil
	}
	res, err := p.db.ExecContext(ctx, `
		UPDATE automation_tickets
		SET status = 'resolved',
			resolved_at = $3
		WHERE target = $1
			AND status <> 'resolved'
			AND fingerprint <> ALL($2::text[])
	`, target, fingerprints, resolvedAt)
	if err != nil {
		return 0, fmt.Errorf("resolve automation tickets: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows, nil
}

func (p *Postgres) ListOpenAutomationTickets(ctx context.Context, target string, limit int) ([]model.AutomationTicket, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		rows *sql.Rows
		err  error
	)
	if strings.TrimSpace(target) == "" {
		rows, err = p.db.QueryContext(ctx, `
			SELECT id, target, fingerprint, title, severity, status, owner, sla_due_at, first_seen_at, last_seen_at, resolved_at
			FROM automation_tickets
			WHERE status <> 'resolved'
			ORDER BY last_seen_at DESC
			LIMIT $1
		`, limit)
	} else {
		rows, err = p.db.QueryContext(ctx, `
			SELECT id, target, fingerprint, title, severity, status, owner, sla_due_at, first_seen_at, last_seen_at, resolved_at
			FROM automation_tickets
			WHERE status <> 'resolved' AND target = $1
			ORDER BY last_seen_at DESC
			LIMIT $2
		`, target, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list open automation tickets: %w", err)
	}
	defer rows.Close()
	out := make([]model.AutomationTicket, 0)
	for rows.Next() {
		var ticket model.AutomationTicket
		var severity string
		if err := rows.Scan(&ticket.ID, &ticket.Target, &ticket.Fingerprint, &ticket.Title, &severity, &ticket.Status, &ticket.Owner, &ticket.SLADueAt, &ticket.FirstSeenAt, &ticket.LastSeenAt, &ticket.ResolvedAt); err != nil {
			return nil, fmt.Errorf("scan automation ticket row: %w", err)
		}
		ticket.Severity = model.Severity(strings.ToLower(strings.TrimSpace(severity)))
		out = append(out, ticket)
	}
	return out, rows.Err()
}

func (p *Postgres) UpsertAutomationCampaign(ctx context.Context, campaign model.AutomationCampaign) error {
	authJSON, err := json.Marshal(campaign.AuthProfile)
	if err != nil {
		return fmt.Errorf("marshal campaign auth profile: %w", err)
	}
	optionsJSON, err := json.Marshal(campaign.Options)
	if err != nil {
		return fmt.Errorf("marshal campaign options: %w", err)
	}
	scopeJSON, err := json.Marshal(campaign.Scope)
	if err != nil {
		return fmt.Errorf("marshal campaign scope: %w", err)
	}
	if campaign.CreatedAt.IsZero() {
		campaign.CreatedAt = time.Now().UTC()
	}
	if campaign.UpdatedAt.IsZero() {
		campaign.UpdatedAt = campaign.CreatedAt
	}
	var nextRunAt any = campaign.NextRunAt
	if campaign.NextRunAt.IsZero() {
		nextRunAt = nil
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO automation_campaigns (
			id, target, workspace_id, requested_by, name, interval_min, next_run_at, last_run_at, active, auth_profile, options, scope, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (id) DO UPDATE
		SET target = EXCLUDED.target,
			workspace_id = EXCLUDED.workspace_id,
			requested_by = EXCLUDED.requested_by,
			name = EXCLUDED.name,
			interval_min = EXCLUDED.interval_min,
			next_run_at = EXCLUDED.next_run_at,
			last_run_at = EXCLUDED.last_run_at,
			active = EXCLUDED.active,
			auth_profile = EXCLUDED.auth_profile,
			options = EXCLUDED.options,
			scope = EXCLUDED.scope,
			updated_at = EXCLUDED.updated_at
	`, campaign.ID, campaign.Target, campaign.WorkspaceID, campaign.RequestedBy, campaign.Name, campaign.IntervalMin, nextRunAt, campaign.LastRunAt, campaign.Active, authJSON, optionsJSON, scopeJSON, campaign.CreatedAt, campaign.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert automation campaign: %w", err)
	}
	return nil
}

func (p *Postgres) ListAutomationCampaigns(ctx context.Context, workspaceID string, activeOnly bool, limit int) ([]model.AutomationCampaign, error) {
	if limit <= 0 {
		limit = 100
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		workspaceID = "default"
	}
	query := `
		SELECT id, target, workspace_id, requested_by, name, interval_min, next_run_at, last_run_at, active, auth_profile, options, scope, created_at, updated_at
		FROM automation_campaigns
		WHERE workspace_id = $1
	`
	args := []any{workspaceID}
	if activeOnly {
		query += ` AND active = TRUE`
	}
	query += ` ORDER BY updated_at DESC LIMIT $2`
	args = append(args, limit)
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list automation campaigns: %w", err)
	}
	defer rows.Close()
	out := make([]model.AutomationCampaign, 0)
	for rows.Next() {
		var item model.AutomationCampaign
		var authRaw, optionsRaw, scopeRaw []byte
		if err := rows.Scan(&item.ID, &item.Target, &item.WorkspaceID, &item.RequestedBy, &item.Name, &item.IntervalMin, &item.NextRunAt, &item.LastRunAt, &item.Active, &authRaw, &optionsRaw, &scopeRaw, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan automation campaign row: %w", err)
		}
		if len(authRaw) > 0 {
			_ = json.Unmarshal(authRaw, &item.AuthProfile)
		}
		if len(optionsRaw) > 0 {
			_ = json.Unmarshal(optionsRaw, &item.Options)
		}
		if len(scopeRaw) > 0 {
			_ = json.Unmarshal(scopeRaw, &item.Scope)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (p *Postgres) ListDueAutomationCampaigns(ctx context.Context, now time.Time, limit int) ([]model.AutomationCampaign, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, target, workspace_id, requested_by, name, interval_min, next_run_at, last_run_at, active, auth_profile, options, scope, created_at, updated_at
		FROM automation_campaigns
		WHERE active = TRUE AND next_run_at IS NOT NULL AND next_run_at <= $1
		ORDER BY next_run_at ASC
		LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list due automation campaigns: %w", err)
	}
	defer rows.Close()
	out := make([]model.AutomationCampaign, 0)
	for rows.Next() {
		var item model.AutomationCampaign
		var authRaw, optionsRaw, scopeRaw []byte
		if err := rows.Scan(&item.ID, &item.Target, &item.WorkspaceID, &item.RequestedBy, &item.Name, &item.IntervalMin, &item.NextRunAt, &item.LastRunAt, &item.Active, &authRaw, &optionsRaw, &scopeRaw, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan due automation campaign row: %w", err)
		}
		if len(authRaw) > 0 {
			_ = json.Unmarshal(authRaw, &item.AuthProfile)
		}
		if len(optionsRaw) > 0 {
			_ = json.Unmarshal(optionsRaw, &item.Options)
		}
		if len(scopeRaw) > 0 {
			_ = json.Unmarshal(scopeRaw, &item.Scope)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateAutomationCampaignRun(ctx context.Context, id string, lastRunAt, nextRunAt time.Time) error {
	_, err := p.db.ExecContext(ctx, `
		UPDATE automation_campaigns
		SET last_run_at = $2,
			next_run_at = $3,
			updated_at = NOW()
		WHERE id = $1
	`, strings.TrimSpace(id), lastRunAt, nextRunAt)
	if err != nil {
		return fmt.Errorf("update automation campaign run: %w", err)
	}
	return nil
}

func (p *Postgres) DeleteAutomationCampaign(ctx context.Context, id, workspaceID string) error {
	_, err := p.db.ExecContext(ctx, `
		DELETE FROM automation_campaigns
		WHERE id = $1 AND workspace_id = $2
	`, strings.TrimSpace(id), strings.TrimSpace(workspaceID))
	if err != nil {
		return fmt.Errorf("delete automation campaign: %w", err)
	}
	return nil
}

func (p *Postgres) CreateAPIKey(ctx context.Context, workspaceID, name string, role model.APIKeyRole) (*model.APIKeyRecord, string, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		workspaceID = "default"
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unnamed"
	}
	role = model.APIKeyRole(strings.ToLower(strings.TrimSpace(string(role))))
	if role == "" {
		role = model.APIKeyRoleViewer
	}
	raw, err := generateRawAPIKey()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	rec := &model.APIKeyRecord{
		ID:          uuid.NewString(),
		WorkspaceID: workspaceID,
		Name:        name,
		Role:        role,
		KeyPrefix:   apiKeyPrefix(raw),
		CreatedAt:   now,
		Active:      true,
	}
	hashed, err := hashAPIKey(raw)
	if err != nil {
		return nil, "", err
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, workspace_id, name, role, key_hash, key_prefix, active, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7)
	`, rec.ID, rec.WorkspaceID, rec.Name, string(rec.Role), hashed, rec.KeyPrefix, rec.CreatedAt)
	if err != nil {
		return nil, "", fmt.Errorf("insert api key: %w", err)
	}
	return rec, raw, nil
}

func (p *Postgres) ListAPIKeys(ctx context.Context, workspaceID string) ([]model.APIKeyRecord, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, workspace_id, name, role, key_prefix, created_at, rotated_at, revoked_at, active
		FROM api_keys
		WHERE workspace_id = $1
		ORDER BY created_at DESC
	`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()
	out := make([]model.APIKeyRecord, 0)
	for rows.Next() {
		var rec model.APIKeyRecord
		var role string
		if err := rows.Scan(&rec.ID, &rec.WorkspaceID, &rec.Name, &role, &rec.KeyPrefix, &rec.CreatedAt, &rec.RotatedAt, &rec.RevokedAt, &rec.Active); err != nil {
			return nil, fmt.Errorf("scan api key row: %w", err)
		}
		rec.Role = model.APIKeyRole(strings.ToLower(strings.TrimSpace(role)))
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (p *Postgres) RotateAPIKey(ctx context.Context, id string) (*model.APIKeyRecord, string, error) {
	raw, err := generateRawAPIKey()
	if err != nil {
		return nil, "", err
	}
	hashed, err := hashAPIKey(raw)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	res, err := p.db.ExecContext(ctx, `
		UPDATE api_keys
		SET key_hash = $2, key_prefix = $3, rotated_at = $4, revoked_at = NULL, active = TRUE
		WHERE id = $1
	`, strings.TrimSpace(id), hashed, apiKeyPrefix(raw), now)
	if err != nil {
		return nil, "", fmt.Errorf("rotate api key: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return nil, "", sql.ErrNoRows
	}
	rec, err := p.getAPIKeyByID(ctx, id)
	if err != nil {
		return nil, "", err
	}
	return rec, raw, nil
}

func (p *Postgres) RevokeAPIKey(ctx context.Context, id string) error {
	res, err := p.db.ExecContext(ctx, `
		UPDATE api_keys
		SET active = FALSE, revoked_at = NOW()
		WHERE id = $1
	`, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (p *Postgres) AuthenticateAPIKey(ctx context.Context, rawKey string) (*model.APIKeyRecord, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, workspace_id, name, role, key_prefix, created_at, rotated_at, revoked_at, active, key_hash
		FROM api_keys
		WHERE active = TRUE
	`)
	if err != nil {
		return nil, fmt.Errorf("authenticate api key: %w", err)
	}
	defer rows.Close()
	candidate := strings.TrimSpace(rawKey)
	for rows.Next() {
		var rec model.APIKeyRecord
		var role, hashed string
		if err := rows.Scan(&rec.ID, &rec.WorkspaceID, &rec.Name, &role, &rec.KeyPrefix, &rec.CreatedAt, &rec.RotatedAt, &rec.RevokedAt, &rec.Active, &hashed); err != nil {
			return nil, fmt.Errorf("authenticate api key row: %w", err)
		}
		if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(candidate)) == nil {
			rec.Role = model.APIKeyRole(strings.ToLower(strings.TrimSpace(role)))
			return &rec, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (p *Postgres) getAPIKeyByID(ctx context.Context, id string) (*model.APIKeyRecord, error) {
	row := p.db.QueryRowContext(ctx, `
		SELECT id, workspace_id, name, role, key_prefix, created_at, rotated_at, revoked_at, active
		FROM api_keys WHERE id = $1
	`, strings.TrimSpace(id))
	var rec model.APIKeyRecord
	var role string
	if err := row.Scan(&rec.ID, &rec.WorkspaceID, &rec.Name, &role, &rec.KeyPrefix, &rec.CreatedAt, &rec.RotatedAt, &rec.RevokedAt, &rec.Active); err != nil {
		return nil, err
	}
	rec.Role = model.APIKeyRole(strings.ToLower(strings.TrimSpace(role)))
	return &rec, nil
}

func generateRawAPIKey() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "abh_" + hex.EncodeToString(buf), nil
}

func hashAPIKey(raw string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(strings.TrimSpace(raw)), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func apiKeyPrefix(raw string) string {
	if len(raw) <= 12 {
		return raw
	}
	return raw[:12]
}

func redactHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		lower := strings.ToLower(strings.TrimSpace(k))
		if lower == "authorization" || lower == "cookie" || lower == "set-cookie" || strings.Contains(lower, "token") || strings.Contains(lower, "secret") {
			out[k] = "[redacted]"
			continue
		}
		out[k] = redactText(v)
	}
	return out
}

var sensitiveKV = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*([^\s&;]+)`)

func redactText(value string) string {
	value = sensitiveKV.ReplaceAllString(value, "$1=[redacted]")
	return strings.ReplaceAll(value, "Bearer ", "Bearer [redacted]")
}
