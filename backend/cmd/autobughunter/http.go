package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type clientConfig struct {
	baseURL     string
	apiKey      string
	workspaceID string
	bearerToken string
	timeout     time.Duration
}

type httpClient struct {
	baseURL     string
	apiKey      string
	workspaceID string
	bearerToken string
	client      *http.Client
}

type httpError struct {
	StatusCode int
	Message    string
	Body       []byte
}

func (e *httpError) Error() string {
	if e == nil {
		return ""
	}
	if e.StatusCode <= 0 {
		return e.Message
	}
	if strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("request failed with HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("request failed with HTTP %d", e.StatusCode)
}

func newHTTPClient(cfg clientConfig) *httpClient {
	timeout := cfg.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &httpClient{
		baseURL:     strings.TrimRight(strings.TrimSpace(cfg.baseURL), "/"),
		apiKey:      strings.TrimSpace(cfg.apiKey),
		workspaceID: strings.TrimSpace(cfg.workspaceID),
		bearerToken: strings.TrimSpace(cfg.bearerToken),
		client:      &http.Client{Timeout: timeout},
	}
}

func (c *httpClient) get(ctx context.Context, path string, query map[string]string) ([]byte, error) {
	u, err := c.buildURL(path, query)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *httpClient) postJSON(ctx context.Context, path string, body []byte) ([]byte, error) {
	u, err := c.buildURL(path, nil)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *httpClient) buildURL(path string, query map[string]string) (string, error) {
	if c.baseURL == "" {
		return "", fmt.Errorf("base URL is required")
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL %q: %w", c.baseURL, err)
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("invalid path %q: %w", path, err)
	}
	finalURL := base.ResolveReference(rel)
	values := finalURL.Query()
	for key, value := range query {
		values.Set(key, value)
	}
	finalURL.RawQuery = values.Encode()
	return finalURL.String(), nil
}

func (c *httpClient) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.workspaceID != "" {
		req.Header.Set("X-Workspace-ID", c.workspaceID)
	}
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, &httpError{
			StatusCode: resp.StatusCode,
			Message:    responseMessage(body),
			Body:       body,
		}
	}
	return body, nil
}

func responseMessage(body []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"error", "detail", "message"} {
			if value := strings.TrimSpace(fmt.Sprint(payload[key])); value != "" && value != "<nil>" {
				return value
			}
		}
	}
	return strings.TrimSpace(string(body))
}
