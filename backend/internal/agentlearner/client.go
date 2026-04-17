package agentlearner

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

// Client communicates with the autonomous agents service (agents container).
// All methods are nil-safe: a nil Client is a no-op.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Client pointing at the agents service.
// baseURL should be e.g. "http://agents:8091".
func NewClient(baseURL string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// SpawnRequest is sent to the agents service to request spawn recommendations.
type SpawnRequest struct {
	SourceAgent string           `json:"sourceAgent"`
	Findings    []findingPayload `json:"findings"`
	TopK        int              `json:"topK"`
	Threshold   float64          `json:"threshold"`
}

// SpawnResponse is the agents service spawn recommendation response.
type SpawnResponse struct {
	Recommended  []string `json:"recommended"`
	ContextFlags int      `json:"contextFlags"`
}

// LearnRequest is sent to the agents service after a scan completes.
type LearnRequest struct {
	ScanID        string           `json:"scanId"`
	AgentSequence []string         `json:"agentSequence"`
	Findings      []findingPayload `json:"findings"`
	HighCount     int              `json:"highCount"`
	MediumCount   int              `json:"mediumCount"`
	LowCount      int              `json:"lowCount"`
	DurationMs    int64            `json:"durationMs"`
}

type findingPayload struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
}

// Recommend calls the agents service to get spawn recommendations for the given source agent.
// Returns nil if the client is nil, the service is unreachable, or an error occurs.
func (c *Client) Recommend(ctx context.Context, sourceAgent string, findings []model.Finding, topK int, threshold float64) []string {
	if c == nil {
		return nil
	}
	req := SpawnRequest{
		SourceAgent: sourceAgent,
		Findings:    toPayload(findings),
		TopK:        topK,
		Threshold:   threshold,
	}
	var resp SpawnResponse
	if err := c.post(ctx, "/v1/spawn", req, &resp); err != nil {
		return nil
	}
	return resp.Recommended
}

// Learn calls the agents service to update Q-values from a completed scan.
func (c *Client) Learn(ctx context.Context, scanID string, agentSequence []string, findings []model.Finding, durationMs int64) {
	if c == nil {
		return
	}
	high, medium, low := countBySeverity(findings)
	req := LearnRequest{
		ScanID:        scanID,
		AgentSequence: agentSequence,
		Findings:      toPayload(findings),
		HighCount:     high,
		MediumCount:   medium,
		LowCount:      low,
		DurationMs:    durationMs,
	}
	// Fire-and-forget: learning is non-critical and should not block the scan.
	go func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = c.post(ctx2, "/v1/learn", req, nil)
	}()
}

// Weights fetches the current Q-table weights summary from the agents service.
func (c *Client) Weights(ctx context.Context) (map[string]any, error) {
	if c == nil {
		return nil, fmt.Errorf("agent learner client not configured")
	}
	url := c.baseURL + "/v1/weights"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func toPayload(findings []model.Finding) []findingPayload {
	out := make([]findingPayload, 0, len(findings))
	for _, f := range findings {
		out = append(out, findingPayload{
			Category: f.Category,
			Severity: string(f.Severity),
			Title:    f.Title,
			Evidence: f.Evidence,
		})
	}
	return out
}

func countBySeverity(findings []model.Finding) (high, medium, low int) {
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityHigh:
			high++
		case model.SeverityMedium:
			medium++
		case model.SeverityLow:
			low++
		}
	}
	return
}
