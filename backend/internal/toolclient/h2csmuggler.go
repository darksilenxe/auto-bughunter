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

// H2CSmugglerClient communicates with the h2csmuggler-service sidecar, which
// probes HTTP targets for HTTP/2 cleartext (h2c) upgrade acceptance and
// request-smuggling opportunities.
type H2CSmugglerClient struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewH2CSmugglerClient creates a new HTTP client for the h2csmuggler-service sidecar.
func NewH2CSmugglerClient() *H2CSmugglerClient {
	baseURL := os.Getenv("H2CSMUGGLER_SERVICE_URL")
	if baseURL == "" {
		baseURL = "https://h2csmuggler-service:8098"
	}

	httpClient := &http.Client{
		Timeout: 90 * time.Second,
	}
	sidecartls.ConfigureClient(httpClient)
	return &H2CSmugglerClient{
		baseURL:   baseURL,
		authToken: os.Getenv("SIDECAR_AUTH_TOKEN"),
		httpClient: httpClient,
	}
}

// H2CScanRequest is the body sent to POST /v1/scan.
type H2CScanRequest struct {
	URL           string   `json:"url"`
	SmugglePaths  []string `json:"smuggle_paths,omitempty"`
	Timeout       int      `json:"timeout,omitempty"`
}

// H2CFinding is a single vulnerability observation returned by the sidecar.
type H2CFinding struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
}

// H2CScanResponse is the body returned by POST /v1/scan.
type H2CScanResponse struct {
	URL                string       `json:"url"`
	H2CUpgradeAccepted bool         `json:"h2c_upgrade_accepted"`
	SmuggleAttempted   bool         `json:"smuggle_attempted"`
	Findings           []H2CFinding `json:"findings"`
	Error              string       `json:"error,omitempty"`
}

// Scan probes url for h2c upgrade acceptance and smuggling anomalies.
func (c *H2CSmugglerClient) Scan(ctx context.Context, req H2CScanRequest) (*H2CScanResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("h2csmuggler: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/scan", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("h2csmuggler: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("h2csmuggler: execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("h2csmuggler: service returned status %d: %s", resp.StatusCode, string(body))
	}

	var result H2CScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("h2csmuggler: decode response: %w", err)
	}
	return &result, nil
}

// IsAvailable reports whether the h2csmuggler-service sidecar is reachable.
func (c *H2CSmugglerClient) IsAvailable(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
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
