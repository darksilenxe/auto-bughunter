package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
		decodeScanJSONColumn(job.ID, "findings", findingsRaw, &job.Findings)
	}
	if len(summaryRaw) > 0 && string(summaryRaw) != "null" {
		var summary model.ScanAuthProfileSummary
		if err := json.Unmarshal(summaryRaw, &summary); err == nil {
			job.AuthProfileSummary = &summary
		} else {
			logScanColumnUnmarshalError(job.ID, "auth_profile_summary", err)
		}
	}
	if len(optionsRaw) > 0 {
		decodeScanJSONColumn(job.ID, "options", optionsRaw, &job.Options)
	}
	if len(scopeRaw) > 0 {
		decodeScanJSONColumn(job.ID, "scope", scopeRaw, &job.Scope)
	}
	if len(agentRunsRaw) > 0 {
		decodeScanJSONColumn(job.ID, "agent_runs", agentRunsRaw, &job.AgentRuns)
	}
	if len(assetLinksRaw) > 0 {
		decodeScanJSONColumn(job.ID, "asset_links", assetLinksRaw, &job.AssetLinks)
	}
	if len(dashboardRaw) > 0 && string(dashboardRaw) != "null" {
		var dashboard model.DecisionDashboard
		if err := json.Unmarshal(dashboardRaw, &dashboard); err == nil {
			job.Dashboard = &dashboard
		} else {
			logScanColumnUnmarshalError(job.ID, "dashboard", err)
		}
	}
	if len(nextActionsRaw) > 0 {
		decodeScanJSONColumn(job.ID, "next_actions", nextActionsRaw, &job.NextActions)
	}
	if len(modelRecommendationsRaw) > 0 && string(modelRecommendationsRaw) != "null" {
		var modelRecommendations model.ModelRecommendations
		if err := json.Unmarshal(modelRecommendationsRaw, &modelRecommendations); err == nil {
			job.ModelRecommendations = &modelRecommendations
		} else {
			logScanColumnUnmarshalError(job.ID, "model_recommendations", err)
		}
	}
	if len(disallowedTestsRaw) > 0 {
		decodeScanJSONColumn(job.ID, "disallowed_tests", disallowedTestsRaw, &job.DisallowedTestTypes)
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
	// Additive migration: add owner column for finding lifecycle ownership
	// transitions. Older deployments may not have this column.
	_, err = p.db.ExecContext(ctx, `
		ALTER TABLE finding_verifications ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT ''
	`)
	if err != nil {
		return fmt.Errorf("migrate finding_verifications.owner column: %w", err)
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
			known_runtime_endpoints JSONB NOT NULL DEFAULT '[]'::jsonb,
			autonomy_memory JSONB NOT NULL DEFAULT '{}'::jsonb
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate scan_states table: %w", err)
	}
	// Backward-compatible migration for deployments where scan_states already
	// exists from older versions without autonomy_memory.
	_, err = p.db.ExecContext(ctx, `
		ALTER TABLE scan_states
		ADD COLUMN IF NOT EXISTS autonomy_memory JSONB NOT NULL DEFAULT '{}'::jsonb
	`)
	if err != nil {
		return fmt.Errorf("migrate scan_states.autonomy_memory column: %w", err)
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
	// Index used by AuthenticateAPIKey to look up the candidate row by
	// prefix instead of scanning every active key with bcrypt.
	if _, err := p.db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS api_keys_active_prefix_idx
		ON api_keys (key_prefix)
		WHERE active = TRUE
	`); err != nil {
		return fmt.Errorf("migrate api_keys index: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS automation_campaigns (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			workspace_id TEXT NOT NULL DEFAULT 'default',
			requested_by TEXT NOT NULL DEFAULT '',
			policy_pack TEXT NOT NULL DEFAULT 'internal',
			policy_version INTEGER NOT NULL DEFAULT 1,
			name TEXT NOT NULL DEFAULT '',
			program_name TEXT NOT NULL DEFAULT '',
			interval_min INTEGER NOT NULL,
			schedule_type TEXT NOT NULL DEFAULT 'interval',
			schedule_value TEXT NOT NULL DEFAULT '',
			run_window TEXT NOT NULL DEFAULT '',
			blackout_windows JSONB NOT NULL DEFAULT '[]'::jsonb,
			next_run_at TIMESTAMPTZ NULL,
			last_run_at TIMESTAMPTZ NULL,
			retry_count INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 3,
			next_retry_at TIMESTAMPTZ NULL,
			last_error TEXT NOT NULL DEFAULT '',
			dead_letter BOOLEAN NOT NULL DEFAULT FALSE,
			queue_state TEXT NOT NULL DEFAULT 'queued',
			lease_until TIMESTAMPTZ NULL,
			heartbeat_at TIMESTAMPTZ NULL,
			run_idempotency_key TEXT NOT NULL DEFAULT '',
			authorization_approval JSONB NOT NULL DEFAULT '{}'::jsonb,
			authorization_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
			authorization_digest TEXT NOT NULL DEFAULT '',
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
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS schedule_type TEXT NOT NULL DEFAULT 'interval'`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.schedule_type column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS schedule_value TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.schedule_value column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS run_window TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.run_window column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS blackout_windows JSONB NOT NULL DEFAULT '[]'::jsonb`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.blackout_windows column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.retry_count column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 3`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.max_attempts column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ NULL`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.next_retry_at column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.last_error column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS dead_letter BOOLEAN NOT NULL DEFAULT FALSE`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.dead_letter column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ NULL`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.lease_until column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS program_name TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.program_name column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS policy_pack TEXT NOT NULL DEFAULT 'internal'`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.policy_pack column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS policy_version INTEGER NOT NULL DEFAULT 1`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.policy_version column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS queue_state TEXT NOT NULL DEFAULT 'queued'`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.queue_state column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ NULL`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.heartbeat_at column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS run_idempotency_key TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.run_idempotency_key column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS authorization_approval JSONB NOT NULL DEFAULT '{}'::jsonb`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.authorization_approval column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS authorization_evidence JSONB NOT NULL DEFAULT '[]'::jsonb`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.authorization_evidence column: %w", err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE automation_campaigns ADD COLUMN IF NOT EXISTS authorization_digest TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("migrate automation_campaigns.authorization_digest column: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS automation_program_roi_overrides (
			workspace_id TEXT NOT NULL,
			program_name TEXT NOT NULL,
			min_expected_roi_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (workspace_id, program_name)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate automation_program_roi_overrides table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS automation_policy_packs (
			workspace_id TEXT NOT NULL,
			name TEXT NOT NULL,
			strategy_version INTEGER NOT NULL DEFAULT 1,
			canary_percent INTEGER NOT NULL DEFAULT 0,
			automation_mode TEXT NOT NULL DEFAULT 'autonomous',
			min_expected_roi_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
			max_automation_concurrency INTEGER NOT NULL DEFAULT 0,
			max_per_target_concurrency INTEGER NOT NULL DEFAULT 0,
			max_exploit_attempts INTEGER NOT NULL DEFAULT 0,
			daily_scan_limit INTEGER NOT NULL DEFAULT 0,
			daily_runtime_limit_minutes INTEGER NOT NULL DEFAULT 0,
			daily_probe_limit INTEGER NOT NULL DEFAULT 0,
			escalate_on_new_high BOOLEAN NOT NULL DEFAULT TRUE,
			escalate_on_changed_high BOOLEAN NOT NULL DEFAULT TRUE,
			governance_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (workspace_id, name)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate automation_policy_packs table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `ALTER TABLE automation_policy_packs ADD COLUMN IF NOT EXISTS governance_profile JSONB NOT NULL DEFAULT '{}'::jsonb`)
	if err != nil {
		return fmt.Errorf("migrate automation_policy_packs.governance_profile column: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS automation_policy_audit (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL,
			policy_pack TEXT NOT NULL,
			strategy_version INTEGER NOT NULL DEFAULT 1,
			action TEXT NOT NULL,
			changed_by TEXT NOT NULL DEFAULT '',
			changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			before_json TEXT NOT NULL DEFAULT '',
			after_json TEXT NOT NULL DEFAULT ''
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate automation_policy_audit table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS scan_annotations (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL,
			workspace_id TEXT NOT NULL DEFAULT '',
			author TEXT NOT NULL DEFAULT '',
			text TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate scan_annotations table: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_scan_annotations_scan_id ON scan_annotations(scan_id)
	`)
	if err != nil {
		return fmt.Errorf("migrate scan_annotations index: %w", err)
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
		decodeScanJSONColumn(job.ID, "findings", findingsRaw, &job.Findings)
	}
	if len(summaryRaw) > 0 && string(summaryRaw) != "null" {
		var summary model.ScanAuthProfileSummary
		if err := json.Unmarshal(summaryRaw, &summary); err == nil {
			job.AuthProfileSummary = &summary
		} else {
			logScanColumnUnmarshalError(job.ID, "auth_profile_summary", err)
		}
	}
	if len(optionsRaw) > 0 {
		decodeScanJSONColumn(job.ID, "options", optionsRaw, &job.Options)
	}
	if len(scopeRaw) > 0 {
		decodeScanJSONColumn(job.ID, "scope", scopeRaw, &job.Scope)
	}
	if len(agentRunsRaw) > 0 {
		decodeScanJSONColumn(job.ID, "agent_runs", agentRunsRaw, &job.AgentRuns)
	}
	if len(assetLinksRaw) > 0 {
		decodeScanJSONColumn(job.ID, "asset_links", assetLinksRaw, &job.AssetLinks)
	}
	if len(dashboardRaw) > 0 && string(dashboardRaw) != "null" {
		var dashboard model.DecisionDashboard
		if err := json.Unmarshal(dashboardRaw, &dashboard); err == nil {
			job.Dashboard = &dashboard
		} else {
			logScanColumnUnmarshalError(job.ID, "dashboard", err)
		}
	}
	if len(nextActionsRaw) > 0 {
		decodeScanJSONColumn(job.ID, "next_actions", nextActionsRaw, &job.NextActions)
	}
	if len(modelRecommendationsRaw) > 0 && string(modelRecommendationsRaw) != "null" {
		var modelRecommendations model.ModelRecommendations
		if err := json.Unmarshal(modelRecommendationsRaw, &modelRecommendations); err == nil {
			job.ModelRecommendations = &modelRecommendations
		} else {
			logScanColumnUnmarshalError(job.ID, "model_recommendations", err)
		}
	}
	if len(disallowedTestsRaw) > 0 {
		decodeScanJSONColumn(job.ID, "disallowed_tests", disallowedTestsRaw, &job.DisallowedTestTypes)
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
		INSERT INTO finding_verifications (id, scan_id, finding_id, status, notes, verified_by, owner, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, verification.ID, verification.ScanID, verification.FindingID, verification.Status, verification.Notes, verification.VerifiedBy, verification.Owner, verification.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert finding verification: %w", err)
	}
	return nil
}

func (p *Postgres) GetLatestFindingVerifications(ctx context.Context, scanID string) (map[string]model.FindingVerification, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT DISTINCT ON (finding_id) id, scan_id, finding_id, status, notes, verified_by, owner, created_at
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
		if err := rows.Scan(&v.ID, &v.ScanID, &v.FindingID, &v.Status, &v.Notes, &v.VerifiedBy, &v.Owner, &v.CreatedAt); err != nil {
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
		SELECT target, last_updated_at, session_instability, known_runtime_endpoints, autonomy_memory
		FROM scan_states
		WHERE target = $1
	`, target)
	var state model.PersistentScanState
	var endpointsRaw []byte
	var autonomyRaw []byte
	if err := row.Scan(&state.Target, &state.LastUpdatedAt, &state.SessionInstability, &endpointsRaw, &autonomyRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get scan state: %w", err)
	}
	if len(endpointsRaw) > 0 {
		_ = json.Unmarshal(endpointsRaw, &state.KnownRuntimeEndpoints)
	}
	if len(autonomyRaw) > 0 {
		_ = json.Unmarshal(autonomyRaw, &state.AutonomyMemory)
	}
	return &state, nil
}

func (p *Postgres) UpsertScanState(ctx context.Context, state model.PersistentScanState) error {
	endpointsJSON, err := json.Marshal(state.KnownRuntimeEndpoints)
	if err != nil {
		return err
	}
	autonomyJSON, err := json.Marshal(state.AutonomyMemory)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO scan_states (target, last_updated_at, session_instability, known_runtime_endpoints, autonomy_memory)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (target) DO UPDATE
		SET last_updated_at = EXCLUDED.last_updated_at,
			session_instability = EXCLUDED.session_instability,
			known_runtime_endpoints = EXCLUDED.known_runtime_endpoints,
			autonomy_memory = EXCLUDED.autonomy_memory
	`, state.Target, state.LastUpdatedAt, state.SessionInstability, endpointsJSON, autonomyJSON)
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
	approvalJSON, err := json.Marshal(campaign.AuthorizationApproval)
	if err != nil {
		return fmt.Errorf("marshal campaign authorization approval: %w", err)
	}
	evidenceJSON, err := json.Marshal(campaign.AuthorizationEvidence)
	if err != nil {
		return fmt.Errorf("marshal campaign authorization evidence: %w", err)
	}
	optionsJSON, err := json.Marshal(campaign.Options)
	if err != nil {
		return fmt.Errorf("marshal campaign options: %w", err)
	}
	scopeJSON, err := json.Marshal(campaign.Scope)
	if err != nil {
		return fmt.Errorf("marshal campaign scope: %w", err)
	}
	blackoutJSON, err := json.Marshal(campaign.BlackoutWindows)
	if err != nil {
		return fmt.Errorf("marshal campaign blackout windows: %w", err)
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
	var nextRetryAt any = campaign.NextRetryAt
	if campaign.NextRetryAt == nil || campaign.NextRetryAt.IsZero() {
		nextRetryAt = nil
	}
	var leaseUntil any = campaign.LeaseUntil
	if campaign.LeaseUntil == nil || campaign.LeaseUntil.IsZero() {
		leaseUntil = nil
	}
	var heartbeatAt any = campaign.HeartbeatAt
	if campaign.HeartbeatAt == nil || campaign.HeartbeatAt.IsZero() {
		heartbeatAt = nil
	}
	queueState := strings.TrimSpace(campaign.QueueState)
	if queueState == "" {
		queueState = "queued"
	}
	policyPack := strings.TrimSpace(campaign.PolicyPack)
	if policyPack == "" {
		policyPack = "internal"
	}
	policyVersion := campaign.PolicyVersion
	if policyVersion <= 0 {
		policyVersion = 1
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO automation_campaigns (
			id, target, workspace_id, requested_by, policy_pack, policy_version, authorization_approval, authorization_evidence, authorization_digest, name, program_name, interval_min, schedule_type, schedule_value, run_window, blackout_windows, next_run_at, last_run_at, retry_count, max_attempts, next_retry_at, last_error, dead_letter, queue_state, lease_until, heartbeat_at, run_idempotency_key, active, auth_profile, options, scope, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)
		ON CONFLICT (id) DO UPDATE
		SET target = EXCLUDED.target,
			workspace_id = EXCLUDED.workspace_id,
			requested_by = EXCLUDED.requested_by,
			policy_pack = EXCLUDED.policy_pack,
			policy_version = EXCLUDED.policy_version,
			authorization_approval = EXCLUDED.authorization_approval,
			authorization_evidence = EXCLUDED.authorization_evidence,
			authorization_digest = EXCLUDED.authorization_digest,
			name = EXCLUDED.name,
			program_name = EXCLUDED.program_name,
			interval_min = EXCLUDED.interval_min,
			schedule_type = EXCLUDED.schedule_type,
			schedule_value = EXCLUDED.schedule_value,
			run_window = EXCLUDED.run_window,
			blackout_windows = EXCLUDED.blackout_windows,
			next_run_at = EXCLUDED.next_run_at,
			last_run_at = EXCLUDED.last_run_at,
			retry_count = EXCLUDED.retry_count,
			max_attempts = EXCLUDED.max_attempts,
			next_retry_at = EXCLUDED.next_retry_at,
			last_error = EXCLUDED.last_error,
			dead_letter = EXCLUDED.dead_letter,
			queue_state = EXCLUDED.queue_state,
			lease_until = EXCLUDED.lease_until,
			heartbeat_at = EXCLUDED.heartbeat_at,
			run_idempotency_key = EXCLUDED.run_idempotency_key,
			active = EXCLUDED.active,
			auth_profile = EXCLUDED.auth_profile,
			options = EXCLUDED.options,
			scope = EXCLUDED.scope,
			updated_at = EXCLUDED.updated_at
	`, campaign.ID, campaign.Target, campaign.WorkspaceID, campaign.RequestedBy, policyPack, policyVersion, approvalJSON, evidenceJSON, strings.TrimSpace(campaign.AuthorizationDigest), campaign.Name, campaign.ProgramName, campaign.IntervalMin, campaign.ScheduleType, campaign.ScheduleValue, campaign.RunWindow, blackoutJSON, nextRunAt, campaign.LastRunAt, campaign.RetryCount, campaign.MaxAttempts, nextRetryAt, campaign.LastError, campaign.DeadLetter, queueState, leaseUntil, heartbeatAt, strings.TrimSpace(campaign.RunIdempotency), campaign.Active, authJSON, optionsJSON, scopeJSON, campaign.CreatedAt, campaign.UpdatedAt)
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
		SELECT id, target, workspace_id, requested_by, policy_pack, policy_version, authorization_approval, authorization_evidence, authorization_digest, name, program_name, interval_min, schedule_type, schedule_value, run_window, blackout_windows, next_run_at, last_run_at, retry_count, max_attempts, next_retry_at, last_error, dead_letter, queue_state, lease_until, heartbeat_at, run_idempotency_key, active, auth_profile, options, scope, created_at, updated_at
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
		var authRaw, approvalRaw, evidenceRaw, optionsRaw, scopeRaw, blackoutRaw []byte
		if err := rows.Scan(&item.ID, &item.Target, &item.WorkspaceID, &item.RequestedBy, &item.PolicyPack, &item.PolicyVersion, &approvalRaw, &evidenceRaw, &item.AuthorizationDigest, &item.Name, &item.ProgramName, &item.IntervalMin, &item.ScheduleType, &item.ScheduleValue, &item.RunWindow, &blackoutRaw, &item.NextRunAt, &item.LastRunAt, &item.RetryCount, &item.MaxAttempts, &item.NextRetryAt, &item.LastError, &item.DeadLetter, &item.QueueState, &item.LeaseUntil, &item.HeartbeatAt, &item.RunIdempotency, &item.Active, &authRaw, &optionsRaw, &scopeRaw, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan automation campaign row: %w", err)
		}
		if len(approvalRaw) > 0 {
			if err := json.Unmarshal(approvalRaw, &item.AuthorizationApproval); err != nil {
				return nil, fmt.Errorf("unmarshal automation campaign authorization approval: %w", err)
			}
		}
		if len(evidenceRaw) > 0 {
			if err := json.Unmarshal(evidenceRaw, &item.AuthorizationEvidence); err != nil {
				return nil, fmt.Errorf("unmarshal automation campaign authorization evidence: %w", err)
			}
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
		if len(blackoutRaw) > 0 {
			_ = json.Unmarshal(blackoutRaw, &item.BlackoutWindows)
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
		SELECT id, target, workspace_id, requested_by, policy_pack, policy_version, authorization_approval, authorization_evidence, authorization_digest, name, program_name, interval_min, schedule_type, schedule_value, run_window, blackout_windows, next_run_at, last_run_at, retry_count, max_attempts, next_retry_at, last_error, dead_letter, queue_state, lease_until, heartbeat_at, run_idempotency_key, active, auth_profile, options, scope, created_at, updated_at
		FROM automation_campaigns
		WHERE active = TRUE
			AND dead_letter = FALSE
			AND queue_state <> 'running'
			AND COALESCE(next_retry_at, next_run_at) IS NOT NULL
			AND COALESCE(next_retry_at, next_run_at) <= $1
			AND (lease_until IS NULL OR lease_until < $1)
		ORDER BY COALESCE(next_retry_at, next_run_at) ASC
		LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list due automation campaigns: %w", err)
	}
	defer rows.Close()
	out := make([]model.AutomationCampaign, 0)
	for rows.Next() {
		var item model.AutomationCampaign
		var authRaw, approvalRaw, evidenceRaw, optionsRaw, scopeRaw, blackoutRaw []byte
		if err := rows.Scan(&item.ID, &item.Target, &item.WorkspaceID, &item.RequestedBy, &item.PolicyPack, &item.PolicyVersion, &approvalRaw, &evidenceRaw, &item.AuthorizationDigest, &item.Name, &item.ProgramName, &item.IntervalMin, &item.ScheduleType, &item.ScheduleValue, &item.RunWindow, &blackoutRaw, &item.NextRunAt, &item.LastRunAt, &item.RetryCount, &item.MaxAttempts, &item.NextRetryAt, &item.LastError, &item.DeadLetter, &item.QueueState, &item.LeaseUntil, &item.HeartbeatAt, &item.RunIdempotency, &item.Active, &authRaw, &optionsRaw, &scopeRaw, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan due automation campaign row: %w", err)
		}
		if len(approvalRaw) > 0 {
			if err := json.Unmarshal(approvalRaw, &item.AuthorizationApproval); err != nil {
				return nil, fmt.Errorf("unmarshal due automation campaign authorization approval: %w", err)
			}
		}
		if len(evidenceRaw) > 0 {
			if err := json.Unmarshal(evidenceRaw, &item.AuthorizationEvidence); err != nil {
				return nil, fmt.Errorf("unmarshal due automation campaign authorization evidence: %w", err)
			}
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
		if len(blackoutRaw) > 0 {
			_ = json.Unmarshal(blackoutRaw, &item.BlackoutWindows)
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
			next_retry_at = NULL,
			retry_count = 0,
			last_error = '',
			queue_state = 'queued',
			lease_until = NULL,
			heartbeat_at = NULL,
			run_idempotency_key = '',
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

func (p *Postgres) TryLeaseAutomationCampaign(ctx context.Context, id string, leaseUntil time.Time) (bool, error) {
	res, err := p.db.ExecContext(ctx, `
		UPDATE automation_campaigns
		SET lease_until = $2,
			queue_state = 'running',
			heartbeat_at = NOW(),
			updated_at = NOW()
		WHERE id = $1
			AND dead_letter = FALSE
			AND (lease_until IS NULL OR lease_until < NOW())
	`, strings.TrimSpace(id), leaseUntil)
	if err != nil {
		return false, fmt.Errorf("lease automation campaign: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

func (p *Postgres) MarkAutomationCampaignDispatchFailure(ctx context.Context, id, lastError string, now time.Time, backoff time.Duration) error {
	nextRetry := now.Add(backoff)
	_, err := p.db.ExecContext(ctx, `
		UPDATE automation_campaigns
		SET retry_count = retry_count + 1,
			next_retry_at = $2,
			last_error = $3,
			queue_state = CASE WHEN (retry_count + 1) >= max_attempts THEN 'dead-letter' ELSE 'queued' END,
			lease_until = NULL,
			heartbeat_at = NULL,
			dead_letter = (retry_count + 1) >= max_attempts,
			updated_at = NOW()
		WHERE id = $1
	`, strings.TrimSpace(id), nextRetry, strings.TrimSpace(lastError))
	if err != nil {
		return fmt.Errorf("mark automation campaign dispatch failure: %w", err)
	}
	return nil
}

func (p *Postgres) HeartbeatAutomationCampaignLease(ctx context.Context, id string, heartbeatAt, leaseUntil time.Time) (bool, error) {
	res, err := p.db.ExecContext(ctx, `
		UPDATE automation_campaigns
		SET heartbeat_at = $2,
			lease_until = $3,
			updated_at = NOW()
		WHERE id = $1
			AND dead_letter = FALSE
			AND queue_state = 'running'
			AND lease_until IS NOT NULL
			AND lease_until >= NOW()
	`, strings.TrimSpace(id), heartbeatAt, leaseUntil)
	if err != nil {
		return false, fmt.Errorf("heartbeat automation campaign lease: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

func (p *Postgres) ReclaimStaleAutomationCampaignLeases(ctx context.Context, staleBefore time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 100
	}
	res, err := p.db.ExecContext(ctx, `
		WITH stale AS (
			SELECT id
			FROM automation_campaigns
			WHERE dead_letter = FALSE
				AND queue_state = 'running'
				AND (heartbeat_at IS NULL OR heartbeat_at < $1)
			ORDER BY updated_at ASC
			LIMIT $2
		)
		UPDATE automation_campaigns c
		SET queue_state = 'queued',
			lease_until = NULL,
			heartbeat_at = NULL,
			last_error = CASE
				WHEN trim(c.last_error) = '' THEN 'stale lease reclaimed for replay'
				ELSE c.last_error
			END,
			updated_at = NOW()
		FROM stale
		WHERE c.id = stale.id
	`, staleBefore, limit)
	if err != nil {
		return 0, fmt.Errorf("reclaim stale automation campaign leases: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows, nil
}

func (p *Postgres) UpdateAutomationCampaignQueueState(ctx context.Context, id, queueState, runIdempotencyKey string, heartbeatAt *time.Time) error {
	queueState = strings.ToLower(strings.TrimSpace(queueState))
	if queueState == "" {
		queueState = "queued"
	}
	var hb any
	if heartbeatAt != nil && !heartbeatAt.IsZero() {
		hb = *heartbeatAt
	}
	_, err := p.db.ExecContext(ctx, `
		UPDATE automation_campaigns
		SET queue_state = $2,
			run_idempotency_key = $3,
			heartbeat_at = $4,
			updated_at = NOW()
		WHERE id = $1
	`, strings.TrimSpace(id), queueState, strings.TrimSpace(runIdempotencyKey), hb)
	if err != nil {
		return fmt.Errorf("update automation campaign queue state: %w", err)
	}
	return nil
}

func (p *Postgres) GetProgramROIOverride(ctx context.Context, workspaceID, programName string) (*model.ProgramROIOverride, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		workspaceID = "default"
	}
	programName = strings.TrimSpace(programName)
	if programName == "" {
		return nil, nil
	}
	row := p.db.QueryRowContext(ctx, `
		SELECT workspace_id, program_name, min_expected_roi_usd, updated_at
		FROM automation_program_roi_overrides
		WHERE workspace_id = $1 AND lower(program_name) = lower($2)
	`, workspaceID, programName)
	var item model.ProgramROIOverride
	if err := row.Scan(&item.WorkspaceID, &item.ProgramName, &item.MinExpectedROIUSD, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get program roi override: %w", err)
	}
	return &item, nil
}

func (p *Postgres) UpsertProgramROIOverride(ctx context.Context, item model.ProgramROIOverride) error {
	item.WorkspaceID = strings.TrimSpace(item.WorkspaceID)
	if item.WorkspaceID == "" {
		item.WorkspaceID = "default"
	}
	item.ProgramName = strings.TrimSpace(item.ProgramName)
	if item.ProgramName == "" {
		return fmt.Errorf("program name is required")
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = time.Now().UTC()
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO automation_program_roi_overrides (workspace_id, program_name, min_expected_roi_usd, updated_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (workspace_id, program_name) DO UPDATE
		SET min_expected_roi_usd = EXCLUDED.min_expected_roi_usd,
			updated_at = EXCLUDED.updated_at
	`, item.WorkspaceID, item.ProgramName, item.MinExpectedROIUSD, item.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert program roi override: %w", err)
	}
	return nil
}

func (p *Postgres) ListProgramROIOverrides(ctx context.Context, workspaceID string, limit int) ([]model.ProgramROIOverride, error) {
	if limit <= 0 {
		limit = 100
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		workspaceID = "default"
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT workspace_id, program_name, min_expected_roi_usd, updated_at
		FROM automation_program_roi_overrides
		WHERE workspace_id = $1
		ORDER BY updated_at DESC
		LIMIT $2
	`, workspaceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list program roi overrides: %w", err)
	}
	defer rows.Close()
	out := make([]model.ProgramROIOverride, 0)
	for rows.Next() {
		var item model.ProgramROIOverride
		if err := rows.Scan(&item.WorkspaceID, &item.ProgramName, &item.MinExpectedROIUSD, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan program roi override row: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (p *Postgres) GetAutomationPolicyPack(ctx context.Context, workspaceID, name string) (*model.AutomationPolicyPack, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		workspaceID = "default"
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	row := p.db.QueryRowContext(ctx, `
		SELECT workspace_id, name, strategy_version, canary_percent, automation_mode, min_expected_roi_usd,
			max_automation_concurrency, max_per_target_concurrency, max_exploit_attempts,
			daily_scan_limit, daily_runtime_limit_minutes, daily_probe_limit,
			escalate_on_new_high, escalate_on_changed_high, governance_profile, updated_by, updated_at
		FROM automation_policy_packs
		WHERE workspace_id = $1 AND lower(name) = lower($2)
	`, workspaceID, name)
	var item model.AutomationPolicyPack
	var governanceRaw []byte
	if err := row.Scan(
		&item.WorkspaceID,
		&item.Name,
		&item.StrategyVersion,
		&item.CanaryPercent,
		&item.AutomationMode,
		&item.MinExpectedROIUSD,
		&item.MaxAutomationConcurrency,
		&item.MaxPerTargetConcurrency,
		&item.MaxExploitAttempts,
		&item.DailyScanLimit,
		&item.DailyRuntimeLimitMinutes,
		&item.DailyProbeLimit,
		&item.EscalateOnNewHigh,
		&item.EscalateOnChangedHigh,
		&governanceRaw,
		&item.UpdatedBy,
		&item.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get automation policy pack: %w", err)
	}
	if len(governanceRaw) > 0 {
		_ = json.Unmarshal(governanceRaw, &item.GovernanceProfile)
	}
	return &item, nil
}

func (p *Postgres) UpsertAutomationPolicyPack(ctx context.Context, item model.AutomationPolicyPack) error {
	item.WorkspaceID = strings.TrimSpace(item.WorkspaceID)
	if item.WorkspaceID == "" {
		item.WorkspaceID = "default"
	}
	item.Name = strings.TrimSpace(item.Name)
	if item.Name == "" {
		return fmt.Errorf("policy pack name is required")
	}
	if item.StrategyVersion <= 0 {
		item.StrategyVersion = 1
	}
	if item.CanaryPercent < 0 {
		item.CanaryPercent = 0
	}
	if item.CanaryPercent > 100 {
		item.CanaryPercent = 100
	}
	if item.MinExpectedROIUSD < 0 {
		item.MinExpectedROIUSD = 0
	}
	if item.MaxAutomationConcurrency < 0 {
		item.MaxAutomationConcurrency = 0
	}
	if item.MaxPerTargetConcurrency < 0 {
		item.MaxPerTargetConcurrency = 0
	}
	if item.MaxExploitAttempts < 0 {
		item.MaxExploitAttempts = 0
	}
	if item.DailyScanLimit < 0 {
		item.DailyScanLimit = 0
	}
	if item.DailyRuntimeLimitMinutes < 0 {
		item.DailyRuntimeLimitMinutes = 0
	}
	if item.DailyProbeLimit < 0 {
		item.DailyProbeLimit = 0
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = time.Now().UTC()
	}
	governanceJSON, err := json.Marshal(item.GovernanceProfile)
	if err != nil {
		return fmt.Errorf("marshal governance profile: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO automation_policy_packs (
			workspace_id, name, strategy_version, canary_percent, automation_mode, min_expected_roi_usd,
			max_automation_concurrency, max_per_target_concurrency, max_exploit_attempts,
			daily_scan_limit, daily_runtime_limit_minutes, daily_probe_limit,
			escalate_on_new_high, escalate_on_changed_high, governance_profile, updated_by, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (workspace_id, name) DO UPDATE
		SET strategy_version = EXCLUDED.strategy_version,
			canary_percent = EXCLUDED.canary_percent,
			automation_mode = EXCLUDED.automation_mode,
			min_expected_roi_usd = EXCLUDED.min_expected_roi_usd,
			max_automation_concurrency = EXCLUDED.max_automation_concurrency,
			max_per_target_concurrency = EXCLUDED.max_per_target_concurrency,
			max_exploit_attempts = EXCLUDED.max_exploit_attempts,
			daily_scan_limit = EXCLUDED.daily_scan_limit,
			daily_runtime_limit_minutes = EXCLUDED.daily_runtime_limit_minutes,
			daily_probe_limit = EXCLUDED.daily_probe_limit,
			escalate_on_new_high = EXCLUDED.escalate_on_new_high,
			escalate_on_changed_high = EXCLUDED.escalate_on_changed_high,
			governance_profile = EXCLUDED.governance_profile,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
	`, item.WorkspaceID, item.Name, item.StrategyVersion, item.CanaryPercent, strings.TrimSpace(item.AutomationMode), item.MinExpectedROIUSD, item.MaxAutomationConcurrency, item.MaxPerTargetConcurrency, item.MaxExploitAttempts, item.DailyScanLimit, item.DailyRuntimeLimitMinutes, item.DailyProbeLimit, item.EscalateOnNewHigh, item.EscalateOnChangedHigh, governanceJSON, strings.TrimSpace(item.UpdatedBy), item.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert automation policy pack: %w", err)
	}
	return nil
}

func (p *Postgres) ListAutomationPolicyPacks(ctx context.Context, workspaceID string, limit int) ([]model.AutomationPolicyPack, error) {
	if limit <= 0 {
		limit = 100
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		workspaceID = "default"
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT workspace_id, name, strategy_version, canary_percent, automation_mode, min_expected_roi_usd,
			max_automation_concurrency, max_per_target_concurrency, max_exploit_attempts,
			daily_scan_limit, daily_runtime_limit_minutes, daily_probe_limit,
			escalate_on_new_high, escalate_on_changed_high, governance_profile, updated_by, updated_at
		FROM automation_policy_packs
		WHERE workspace_id = $1
		ORDER BY updated_at DESC
		LIMIT $2
	`, workspaceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list automation policy packs: %w", err)
	}
	defer rows.Close()
	out := make([]model.AutomationPolicyPack, 0)
	for rows.Next() {
		var item model.AutomationPolicyPack
		var governanceRaw []byte
		if err := rows.Scan(
			&item.WorkspaceID,
			&item.Name,
			&item.StrategyVersion,
			&item.CanaryPercent,
			&item.AutomationMode,
			&item.MinExpectedROIUSD,
			&item.MaxAutomationConcurrency,
			&item.MaxPerTargetConcurrency,
			&item.MaxExploitAttempts,
			&item.DailyScanLimit,
			&item.DailyRuntimeLimitMinutes,
			&item.DailyProbeLimit,
			&item.EscalateOnNewHigh,
			&item.EscalateOnChangedHigh,
			&governanceRaw,
			&item.UpdatedBy,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan automation policy pack row: %w", err)
		}
		if len(governanceRaw) > 0 {
			_ = json.Unmarshal(governanceRaw, &item.GovernanceProfile)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (p *Postgres) AppendAutomationPolicyAudit(ctx context.Context, event model.AutomationPolicyAuditEvent) error {
	event.ID = strings.TrimSpace(event.ID)
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	event.WorkspaceID = strings.TrimSpace(event.WorkspaceID)
	if event.WorkspaceID == "" {
		event.WorkspaceID = "default"
	}
	event.PolicyPack = strings.TrimSpace(event.PolicyPack)
	if event.ChangedAt.IsZero() {
		event.ChangedAt = time.Now().UTC()
	}
	strategyVersion := event.StrategyVersion
	if strategyVersion <= 0 {
		strategyVersion = 1
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO automation_policy_audit (
			id, workspace_id, policy_pack, strategy_version, action, changed_by, changed_at, before_json, after_json
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, event.ID, event.WorkspaceID, event.PolicyPack, strategyVersion, strings.TrimSpace(event.Action), strings.TrimSpace(event.ChangedBy), event.ChangedAt, strings.TrimSpace(event.BeforeJSON), strings.TrimSpace(event.AfterJSON))
	if err != nil {
		return fmt.Errorf("append automation policy audit: %w", err)
	}
	return nil
}

func (p *Postgres) ListAutomationPolicyAudit(ctx context.Context, workspaceID, policyPack string, limit int) ([]model.AutomationPolicyAuditEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		workspaceID = "default"
	}
	policyPack = strings.TrimSpace(policyPack)
	query := `
		SELECT id, workspace_id, policy_pack, strategy_version, action, changed_by, changed_at, before_json, after_json
		FROM automation_policy_audit
		WHERE workspace_id = $1
	`
	args := []any{workspaceID}
	if policyPack != "" {
		query += ` AND lower(policy_pack) = lower($2)`
		args = append(args, policyPack)
	}
	query += ` ORDER BY changed_at DESC`
	if policyPack == "" {
		query += ` LIMIT $2`
		args = append(args, limit)
	} else {
		query += ` LIMIT $3`
		args = append(args, limit)
	}
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list automation policy audit: %w", err)
	}
	defer rows.Close()
	out := make([]model.AutomationPolicyAuditEvent, 0)
	for rows.Next() {
		var item model.AutomationPolicyAuditEvent
		if err := rows.Scan(&item.ID, &item.WorkspaceID, &item.PolicyPack, &item.StrategyVersion, &item.Action, &item.ChangedBy, &item.ChangedAt, &item.BeforeJSON, &item.AfterJSON); err != nil {
			return nil, fmt.Errorf("scan automation policy audit row: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (p *Postgres) GetWorkspaceDailyUsage(ctx context.Context, workspaceID string, day time.Time) (model.WorkspaceDailyUsage, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		workspaceID = "default"
	}
	start := day.UTC().Truncate(24 * time.Hour)
	end := start.Add(24 * time.Hour)
	var usage model.WorkspaceDailyUsage
	usage.WorkspaceID = workspaceID
	usage.Day = start
	err := p.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) AS scan_count,
			COALESCE(ROUND(SUM(
				CASE
					WHEN completed_at IS NOT NULL THEN GREATEST(EXTRACT(EPOCH FROM (completed_at - started_at)) / 60.0, 0)
					ELSE 0
				END
			)), 0)::INTEGER AS runtime_minutes,
			COALESCE(SUM(jsonb_array_length(findings)), 0) AS probe_volume
		FROM scans
		WHERE workspace_id = $1
			AND started_at >= $2
			AND started_at < $3
	`, workspaceID, start, end).Scan(&usage.ScanCount, &usage.RuntimeMinutes, &usage.ProbeVolume)
	if err != nil {
		return usage, fmt.Errorf("get workspace daily usage: %w", err)
	}
	return usage, nil
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
	// nosemgrep -- static SQL with parameterized $N placeholders; no string concatenation of user input.
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
	// nosemgrep -- static SQL with parameterized $N placeholders; no string concatenation of user input.
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
	candidate := strings.TrimSpace(rawKey)
	// Issued keys all share the deterministic prefix produced by
	// apiKeyPrefix(); using it as an indexed lookup means we perform exactly
	// one bcrypt comparison per request instead of O(n) over every active
	// key in the workspace. This closes a per-request DoS / timing-leak
	// vector against the unauthenticated /api/* surface.
	prefix := apiKeyPrefix(candidate)
	if prefix == "" {
		return nil, sql.ErrNoRows
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, workspace_id, name, role, key_prefix, created_at, rotated_at, revoked_at, active, key_hash
		FROM api_keys
		WHERE active = TRUE AND key_prefix = $1
	`, prefix)
	if err != nil {
		return nil, fmt.Errorf("authenticate api key: %w", err)
	}
	defer rows.Close()
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

// decodeScanJSONColumn unmarshals a JSON-encoded scan column into dst, logging
// (but not failing) on malformed payloads. Persisted scan columns occasionally
// outlive a schema change; surfacing the error gives operators a chance to
// notice silent data loss instead of seeing zero-valued fields appear in the
// UI.
func decodeScanJSONColumn(scanID, column string, raw []byte, dst any) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		logScanColumnUnmarshalError(scanID, column, err)
	}
}

func logScanColumnUnmarshalError(scanID, column string, err error) {
	if err == nil {
		return
	}
	log.Printf("storage: scan %s column %q: json unmarshal failed: %v", scanID, column, err)
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

// SaveScanAnnotation persists a single operator scan annotation.
func (p *Postgres) SaveScanAnnotation(ctx context.Context, annotation model.ScanAnnotation) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO scan_annotations (id, scan_id, workspace_id, author, text, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (id) DO NOTHING`,
		annotation.ID,
		annotation.ScanID,
		annotation.WorkspaceID,
		annotation.Author,
		annotation.Text,
		annotation.CreatedAt,
	)
	return err
}

// ListScanAnnotations returns all annotations for the given scan ID, ordered
// oldest first.
func (p *Postgres) ListScanAnnotations(ctx context.Context, scanID string) ([]model.ScanAnnotation, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, scan_id, workspace_id, author, text, created_at
		 FROM scan_annotations
		 WHERE scan_id = $1
		 ORDER BY created_at ASC`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.ScanAnnotation
	for rows.Next() {
		var a model.ScanAnnotation
		if err := rows.Scan(&a.ID, &a.ScanID, &a.WorkspaceID, &a.Author, &a.Text, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

var sensitiveKV = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*([^\s&;]+)`)

func redactText(value string) string {
	value = sensitiveKV.ReplaceAllString(value, "$1=[redacted]")
	return strings.ReplaceAll(value, "Bearer ", "Bearer [redacted]")
}
