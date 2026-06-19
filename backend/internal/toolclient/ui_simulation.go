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

// UISimulationClient communicates with the UI-simulation HTTP wrapper service.
type UISimulationClient struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewUISimulationClient creates a new HTTP client for the ui-simulation service.
func NewUISimulationClient() *UISimulationClient {
	baseURL := os.Getenv("UI_SIMULATION_SERVICE_URL")
	if baseURL == "" {
		baseURL = "https://ui-simulation-service:8096"
	}

	httpClient := &http.Client{
		Timeout: 6 * time.Minute,
	}
	sidecartls.ConfigureClient(httpClient)
	return &UISimulationClient{
		baseURL:    baseURL,
		authToken:  os.Getenv("SIDECAR_AUTH_TOKEN"),
		httpClient: httpClient,
	}
}

// LoginStep mirrors the frontend LoginStep shape used in scan auth profiles.
type LoginStep struct {
	Action   string `json:"action"`
	Selector string `json:"selector,omitempty"`
	Value    string `json:"value,omitempty"`
	URL      string `json:"url,omitempty"`
}

// UISimulationRequest is the body sent to POST /v1/simulate.
type UISimulationRequest struct {
	Target     string            `json:"target"`
	LoginSteps []LoginStep       `json:"login_steps,omitempty"`
	Cookies    string            `json:"cookies,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	MaxPages   int               `json:"max_pages,omitempty"`
	MaxDepth   int               `json:"max_depth,omitempty"`
	Timeout    int               `json:"timeout,omitempty"`
}

// UISimulationEndpoint represents a single network endpoint captured during simulation.
type UISimulationEndpoint struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

// UISimulationResponse is the body returned by POST /v1/simulate.
type UISimulationResponse struct {
	Target              string                 `json:"target"`
	PagesVisited        int                    `json:"pages_visited"`
	ClicksPerformed     int                    `json:"clicks_performed"`
	FormsFilled         int                    `json:"forms_filled"`
	DiscoveredEndpoints []UISimulationEndpoint `json:"discovered_endpoints"`
	ActionsLog          []string               `json:"actions_log"`
	TimedOut            bool                   `json:"timed_out"`
	Error               string                 `json:"error,omitempty"`
}

// Simulate runs a human-simulation session against target using the sidecar.
func (c *UISimulationClient) Simulate(ctx context.Context, req UISimulationRequest) (*UISimulationResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("ui-simulation: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/simulate", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("ui-simulation: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ui-simulation: execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ui-simulation: service returned status %d: %s", resp.StatusCode, string(body))
	}

	var result UISimulationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ui-simulation: decode response: %w", err)
	}
	return &result, nil
}

// IsAvailable reports whether the ui-simulation service is reachable.
func (c *UISimulationClient) IsAvailable(ctx context.Context) bool {
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
