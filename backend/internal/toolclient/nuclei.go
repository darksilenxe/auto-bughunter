// Package toolclient provides HTTP clients for communicating with tool wrapper services.
// This eliminates the need for Docker socket access by using HTTP instead of
// `docker compose exec` commands.
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

// NucleiClient communicates with the nuclei HTTP wrapper service.
type NucleiClient struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewNucleiClient creates a new HTTP client for the nuclei service.
func NewNucleiClient() *NucleiClient {
	baseURL := os.Getenv("NUCLEI_SERVICE_URL")
	if baseURL == "" {
		baseURL = "https://nuclei-service:8093"
	}

	httpClient := &http.Client{
		Timeout: 15 * time.Minute, // Longer timeout for nuclei scans
	}
	sidecartls.ConfigureClient(httpClient)
	return &NucleiClient{
		baseURL:    baseURL,
		authToken:  os.Getenv("SIDECAR_AUTH_TOKEN"),
		httpClient: httpClient,
	}
}

// ExecuteRequest represents a request to execute nuclei.
type ExecuteRequest struct {
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"`
}

// ExecuteResponse represents the response from nuclei execution.
type ExecuteResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	TimedOut bool   `json:"timed_out"`
	Error    string `json:"error,omitempty"`
}

// Execute runs nuclei with the provided arguments via HTTP.
func (c *NucleiClient) Execute(ctx context.Context, args []string, timeout int) (*ExecuteResponse, error) {
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

// IsAvailable checks if the nuclei service is reachable.
func (c *NucleiClient) IsAvailable(ctx context.Context) bool {
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
