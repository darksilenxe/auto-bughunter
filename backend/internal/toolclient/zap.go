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
)

// ZapClient communicates with the ZAP baseline HTTP wrapper service.
type ZapClient struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewZapClient creates a new HTTP client for the ZAP baseline service.
func NewZapClient() *ZapClient {
	baseURL := os.Getenv("ZAP_SERVICE_URL")
	if baseURL == "" {
		baseURL = "http://zap-service:8094"
	}

	return &ZapClient{
		baseURL:   baseURL,
		authToken: os.Getenv("SIDECAR_AUTH_TOKEN"),
		httpClient: &http.Client{
			Timeout: 15 * time.Minute, // Longer timeout for ZAP scans
		},
	}
}

// Execute runs zap-baseline.py with the provided arguments via HTTP.
func (c *ZapClient) Execute(ctx context.Context, args []string, timeout int) (*ExecuteResponse, error) {
	reqBody := ExecuteRequest{
		Args:    args,
		Timeout: timeout,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/execute", bytes.NewReader(jsonData))
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

	var result ExecuteResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// IsAvailable checks if the ZAP baseline service is reachable.
func (c *ZapClient) IsAvailable(ctx context.Context) bool {
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
