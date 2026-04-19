package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

type Config struct {
	ExternalURL string
	AuthToken   string
	Timeout     time.Duration
}

type Client struct {
	externalURL string
	authToken   string
	httpClient  *http.Client
}

func NewClient(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.ExternalURL), "/")
	if base == "" {
		return nil
	}
	return &Client{
		externalURL: base,
		authToken:   strings.TrimSpace(cfg.AuthToken),
		httpClient:  &http.Client{Timeout: timeout},
	}
}

type retrieveRequest struct {
	Query       string         `json:"query"`
	Stage       string         `json:"stage"`
	Findings    []findingInput `json:"findings,omitempty"`
	AttackPaths []string       `json:"attackPaths,omitempty"`
	Limit       int            `json:"limit"`
}

type findingInput struct {
	Category       string         `json:"category,omitempty"`
	Severity       model.Severity `json:"severity,omitempty"`
	Title          string         `json:"title,omitempty"`
	Description    string         `json:"description,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
}

type retrieveResponse struct {
	Query            string                     `json:"query"`
	Stage            string                     `json:"stage"`
	CurationMode     string                     `json:"curationMode"`
	LicenseNotice    string                     `json:"licenseNotice"`
	SuggestedActions []string                   `json:"suggestedActions"`
	References       []model.KnowledgeReference `json:"references"`
}

func (c *Client) RetrieveForJob(ctx context.Context, stage string, job *model.ScanJob, limit int) *model.SecurityKnowledgeContext {
	if c == nil || job == nil || len(job.Findings) == 0 {
		return nil
	}
	if limit <= 0 {
		limit = 5
	}
	reqBody := retrieveRequest{
		Query:       buildQuery(job),
		Stage:       strings.TrimSpace(stage),
		Findings:    make([]findingInput, 0, len(job.Findings)),
		AttackPaths: nil,
		Limit:       limit,
	}
	for _, f := range job.Findings {
		reqBody.Findings = append(reqBody.Findings, findingInput{
			Category:       f.Category,
			Severity:       f.Severity,
			Title:          f.Title,
			Description:    f.Description,
			Recommendation: f.Recommendation,
		})
	}
	if job.Dashboard != nil {
		reqBody.AttackPaths = append(reqBody.AttackPaths, job.Dashboard.TopAttackPaths...)
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.externalURL+"/v1/retrieve", bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil
	}
	var out retrieveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil
	}
	if len(out.References) == 0 {
		return nil
	}
	return &model.SecurityKnowledgeContext{
		Query:            out.Query,
		Stage:            out.Stage,
		CurationMode:     out.CurationMode,
		LicenseNotice:    out.LicenseNotice,
		SuggestedActions: dedupeActions(out.SuggestedActions),
		References:       out.References,
	}
}

func buildQuery(job *model.ScanJob) string {
	if job == nil {
		return ""
	}
	categories := map[string]struct{}{}
	titles := make([]string, 0, 3)
	for _, f := range job.Findings {
		category := strings.TrimSpace(strings.ToLower(f.Category))
		if category != "" {
			categories[category] = struct{}{}
		}
		if len(titles) < 3 {
			titles = append(titles, strings.TrimSpace(f.Title))
		}
	}
	cats := make([]string, 0, len(categories))
	for category := range categories {
		cats = append(cats, category)
	}
	return fmt.Sprintf(
		"target=%s categories=%s priorities=%s",
		job.Target,
		strings.Join(cats, ", "),
		strings.Join(titles, " | "),
	)
}

func dedupeActions(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, action := range in {
		action = strings.TrimSpace(action)
		if action == "" {
			continue
		}
		key := strings.ToLower(action)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, action)
	}
	return out
}
