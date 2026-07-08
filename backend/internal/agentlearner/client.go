package agentlearner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/sidecartls"
)

// Client communicates with the autonomous agents service (agents container).
// All methods are nil-safe: a nil Client is a no-op.
type Client struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewClient creates a new Client pointing at the agents service.
// baseURL should be e.g. "http://agents:8091".
func NewClient(baseURL string) *Client {
	return NewClientWithToken(baseURL, "")
}

// NewClientWithToken creates a new Client and, if authToken is non-empty,
// sends it in the Authorization header on every outgoing request. The
// matching token must be configured on the sidecar (SIDECAR_AUTH_TOKEN).
func NewClientWithToken(baseURL, authToken string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}
	sidecartls.ConfigureClient(httpClient)
	return &Client{
		baseURL:    baseURL,
		authToken:  strings.TrimSpace(authToken),
		httpClient: httpClient,
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

// GenerateCommandRequest is sent to the agents sidecar to request bounded,
// target-scoped tool command proposals.
type GenerateCommandRequest struct {
	AgentName   string           `json:"agentName"`
	Target      string           `json:"target"`
	Findings    []findingPayload `json:"findings"`
	MaxCommands int              `json:"maxCommands"`
}

// GeneratedCommand is one proposed command returned by the agents sidecar.
// The backend still validates and enforces command safety before execution.
type GeneratedCommand struct {
	Binary         string   `json:"binary"`
	Args           []string `json:"args"`
	Rationale      string   `json:"rationale"`
	GeneratedBy    string   `json:"generatedBy"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
}

// GenerateCommandResponse is the sidecar response envelope.
type GenerateCommandResponse struct {
	Commands []GeneratedCommand `json:"commands"`
}

// LearnRequest is sent to the agents service after a scan completes.
type LearnRequest struct {
	ScanID               string           `json:"scanId"`
	AgentSequence        []string         `json:"agentSequence"`
	Findings             []findingPayload `json:"findings"`
	HighCount            int              `json:"highCount"`
	MediumCount          int              `json:"mediumCount"`
	LowCount             int              `json:"lowCount"`
	DurationMs           int64            `json:"durationMs"`
	DecisionQualityScore float64          `json:"decisionQualityScore,omitempty"`
	FalsePositiveProxy   float64          `json:"falsePositiveProxy,omitempty"`
	TimeToSignalMs       int64            `json:"timeToSignalMs,omitempty"`
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

// GenerateCommands asks the agents service to propose bounded tool commands
// for the supplied findings context. Returns nil on nil client or errors.
func (c *Client) GenerateCommands(ctx context.Context, agentName, target string, findings []model.Finding, maxCommands int) []GeneratedCommand {
	if c == nil {
		return nil
	}
	if maxCommands <= 0 {
		maxCommands = 5
	}
	req := GenerateCommandRequest{
		AgentName:   strings.TrimSpace(agentName),
		Target:      strings.TrimSpace(target),
		Findings:    toPayload(findings),
		MaxCommands: maxCommands,
	}
	var resp GenerateCommandResponse
	if err := c.post(ctx, "/v1/generate-command", req, &resp); err != nil {
		return nil
	}
	return resp.Commands
}

// Learn calls the agents service to update Q-values from a completed scan.
func (c *Client) Learn(ctx context.Context, scanID string, agentSequence []string, findings []model.Finding, durationMs int64, runs []model.AgentRunTelemetry) {
	if c == nil {
		return
	}
	high, medium, low := countBySeverity(findings)
	decisionScore, falsePositiveProxy, timeToSignalMs := summarizeAutonomyRunQuality(findings, runs, durationMs)
	req := LearnRequest{
		ScanID:               scanID,
		AgentSequence:        agentSequence,
		Findings:             toPayload(findings),
		HighCount:            high,
		MediumCount:          medium,
		LowCount:             low,
		DurationMs:           durationMs,
		DecisionQualityScore: decisionScore,
		FalsePositiveProxy:   falsePositiveProxy,
		TimeToSignalMs:       timeToSignalMs,
	}
	// Fire-and-forget: learning is non-critical and should not block the scan.
	go func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = c.post(ctx2, "/v1/learn", req, nil)
	}()
}

func summarizeAutonomyRunQuality(findings []model.Finding, runs []model.AgentRunTelemetry, durationMs int64) (decisionQuality float64, falsePositiveProxy float64, timeToSignalMs int64) {
	scoreSum := 0.0
	scoreCount := 0
	lowConf := 0
	withConf := 0
	elapsed := int64(0)
	timeToSignalMs = durationMs
	for _, run := range runs {
		elapsed += run.DurationMs
		if run.Metadata != nil {
			if raw := strings.TrimSpace(run.Metadata["decision_quality_score"]); raw != "" {
				if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
					scoreSum += clamp(parsed, 0, 1)
					scoreCount++
				}
			}
		}
		if timeToSignalMs == durationMs {
			if raw := strings.TrimSpace(run.Metadata["findings"]); raw != "" && raw != "0" {
				timeToSignalMs = elapsed
			}
		}
	}
	for _, f := range findings {
		if f.Confidence <= 0 {
			continue
		}
		withConf++
		if f.Confidence < 0.4 {
			lowConf++
		}
	}
	if scoreCount > 0 {
		decisionQuality = scoreSum / float64(scoreCount)
	}
	if withConf > 0 {
		falsePositiveProxy = float64(lowConf) / float64(withConf)
	}
	return clamp(decisionQuality, 0, 1), clamp(falsePositiveProxy, 0, 1), maxInt64(0, timeToSignalMs)
}

func clamp(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
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
	c.applyAuth(httpReq)
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
	c.applyAuth(req)
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

func (c *Client) applyAuth(req *http.Request) {
	if c == nil || c.authToken == "" || req == nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)
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
