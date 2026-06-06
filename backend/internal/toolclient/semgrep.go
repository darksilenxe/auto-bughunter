package toolclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"auto-bughunter/backend/internal/sidecartls"
)

// SemgrepClient communicates with the Semgrep SAST HTTP wrapper service.
type SemgrepClient struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewSemgrepClient creates a new HTTP client for the semgrep service.
func NewSemgrepClient() *SemgrepClient {
	baseURL := os.Getenv("SEMGREP_SERVICE_URL")
	if baseURL == "" {
		baseURL = "https://semgrep-service:8095"
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Minute,
	}
	sidecartls.ConfigureClient(httpClient)
	return &SemgrepClient{
		baseURL:   baseURL,
		authToken: os.Getenv("SIDECAR_AUTH_TOKEN"),
		httpClient: httpClient,
	}
}

// SemgrepScanRequest is the body sent to POST /v1/scan.
type SemgrepScanRequest struct {
	// Snippet is the source-code fragment to analyse.
	Snippet string `json:"snippet"`
	// Language hints semgrep at the grammar to use (e.g. "js", "python", "go").
	Language string `json:"language"`
	// Timeout is the maximum execution time in seconds (default 60).
	Timeout int `json:"timeout"`
}

// SemgrepFinding is one semgrep result mapped to a structured finding.
type SemgrepFinding struct {
	RuleID   string `json:"ruleId"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Line     int    `json:"line"`
	Language string `json:"language"`
}

// SemgrepScanResponse is the body returned by POST /v1/scan.
type SemgrepScanResponse struct {
	Findings []SemgrepFinding `json:"findings"`
	TimedOut bool             `json:"timedOut"`
	Error    string           `json:"error,omitempty"`
}

// Scan sends a code snippet to the semgrep service for static analysis.
func (c *SemgrepClient) Scan(ctx context.Context, snippet, language string, timeoutSecs int) (*SemgrepScanResponse, error) {
	if timeoutSecs <= 0 {
		timeoutSecs = 60
	}
	reqBody := SemgrepScanRequest{
		Snippet:  snippet,
		Language: language,
		Timeout:  timeoutSecs,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/scan", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("service returned status %d: %s", resp.StatusCode, string(body))
	}

	var result SemgrepScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &result, nil
}

// IsAvailable checks if the semgrep service is reachable.
func (c *SemgrepClient) IsAvailable(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
