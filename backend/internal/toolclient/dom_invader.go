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

// DOMInvaderClient communicates with the DOM Invader (plugin) sidecar, a
// Playwright-driven client-side DOM XSS taint tracker in the spirit of Burp
// Suite's "DOM Invader" extension.
type DOMInvaderClient struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewDOMInvaderClient creates a new HTTP client for the dom-invader-service sidecar.
func NewDOMInvaderClient() *DOMInvaderClient {
	baseURL := os.Getenv("DOM_INVADER_SERVICE_URL")
	if baseURL == "" {
		baseURL = "https://dom-invader-service:8097"
	}

	httpClient := &http.Client{
		Timeout: 2 * time.Minute,
	}
	sidecartls.ConfigureClient(httpClient)
	return &DOMInvaderClient{
		baseURL:    baseURL,
		authToken:  os.Getenv("SIDECAR_AUTH_TOKEN"),
		httpClient: httpClient,
	}
}

// DOMInvaderAnalyzeRequest is the body sent to POST /v1/analyze.
type DOMInvaderAnalyzeRequest struct {
	Target  string            `json:"target"`
	Sources []string          `json:"sources,omitempty"`
	Sinks   []string          `json:"sinks,omitempty"`
	Cookies string            `json:"cookies,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Timeout int               `json:"timeout,omitempty"`
}

// DOMInvaderFinding is one observed source→sink taint flow.
type DOMInvaderFinding struct {
	Source   string `json:"source"`
	Sink     string `json:"sink"`
	Snippet  string `json:"snippet"`
	FrameURL string `json:"frame_url"`
}

// DOMInvaderAnalyzeResponse is the body returned by POST /v1/analyze.
type DOMInvaderAnalyzeResponse struct {
	Target        string              `json:"target"`
	Findings      []DOMInvaderFinding `json:"findings"`
	SourcesTested []string            `json:"sources_tested"`
	SinksTested   []string            `json:"sinks_tested"`
	TimedOut      bool                `json:"timed_out"`
	Error         string              `json:"error,omitempty"`
}

// Analyze runs DOM taint analysis against req.Target using the sidecar.
func (c *DOMInvaderClient) Analyze(ctx context.Context, req DOMInvaderAnalyzeRequest) (*DOMInvaderAnalyzeResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("dom-invader: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/analyze", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("dom-invader: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("dom-invader: execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("dom-invader: service returned status %d: %s", resp.StatusCode, string(body))
	}

	var result DOMInvaderAnalyzeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("dom-invader: decode response: %w", err)
	}
	return &result, nil
}

// IsAvailable reports whether the dom-invader-service sidecar is reachable.
func (c *DOMInvaderClient) IsAvailable(ctx context.Context) bool {
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
