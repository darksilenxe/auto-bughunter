package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

	_, err = p.db.ExecContext(ctx, `
		INSERT INTO scans (
			id, target, status, started_at, completed_at, findings, ai_summary, error, auth_profile_summary, options
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, job.ID, job.Target, job.Status, job.StartedAt, job.CompletedAt, findingsJSON, job.AISummary, job.Error, summaryJSON, optionsJSON)
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

	res, err := p.db.ExecContext(ctx, `
		UPDATE scans
		SET status = $2,
			completed_at = $3,
			findings = $4,
			ai_summary = $5,
			error = $6,
			auth_profile_summary = $7,
			options = $8
		WHERE id = $1
	`, job.ID, job.Status, job.CompletedAt, findingsJSON, job.AISummary, job.Error, summaryJSON, optionsJSON)
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
		SELECT id, target, status, started_at, completed_at, findings, ai_summary, error, auth_profile_summary, options
		FROM scans
		WHERE id = $1
	`, id)

	var job model.ScanJob
	var findingsRaw []byte
	var summaryRaw []byte
	var optionsRaw []byte
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
			options JSONB NOT NULL DEFAULT '{}'::jsonb
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate scans table: %w", err)
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
