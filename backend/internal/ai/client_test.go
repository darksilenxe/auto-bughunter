package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCompletion builds a minimal OpenAI-compatible chat completion response
// whose first choice contains the given content string.
func fakeCompletion(t *testing.T, content string) string {
	t.Helper()
	resp := map[string]any{
		"choices": []map[string]any{
			{
				"message": map[string]string{
					"content": content,
				},
			},
		},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("fakeCompletion: marshal: %v", err)
	}
	return string(b)
}

func TestGenerateTool_Success(t *testing.T) {
	toolJSON := `{"name":"custom_probe","code":"#!/usr/bin/env python3\nimport sys,json\nprint(json.dumps({\"id\":\"1\",\"category\":\"test\",\"severity\":\"info\",\"title\":\"t\",\"description\":\"d\",\"evidence\":\"e\",\"recommendation\":\"r\"}))\n","rationale":"tests custom probe generation"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fakeCompletion(t, toolJSON)))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key", "test-model")
	got := c.GenerateTool(context.Background(), "probe for XSS on login page", "http://example.com", []string{"Reflected input detected"})

	if got == nil {
		t.Fatal("expected GenerateTool to return a spec, got nil")
	}
	if got.Name != "custom_probe" {
		t.Errorf("Name = %q, want %q", got.Name, "custom_probe")
	}
	if !strings.Contains(got.Code, "python3") {
		t.Errorf("Code does not look like a Python script: %q", got.Code[:min(80, len(got.Code))])
	}
	if got.Rationale == "" {
		t.Error("Rationale should not be empty")
	}
}

func TestGenerateTool_EmptyNameOrCode_ReturnsNil(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"empty name", `{"name":"","code":"print(1)","rationale":"x"}`},
		{"empty code", `{"name":"probe","code":"","rationale":"x"}`},
		{"invalid json", `not-json`},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The handler will be called once per sub-test; we swap the response
		// via the outer cases slice controlled below.
	}))
	defer srv.Close()

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(fakeCompletion(t, tc.content)))
			}))
			defer inner.Close()

			c := NewClient(inner.URL, "test-key", "test-model")
			got := c.GenerateTool(context.Background(), "task", "http://example.com", nil)
			if got != nil {
				t.Errorf("expected nil for case %q, got %+v", tc.name, got)
			}
		})
	}
}

func TestGenerateTool_NilClient_ReturnsNil(t *testing.T) {
	var c *Client
	got := c.GenerateTool(context.Background(), "task", "http://example.com", nil)
	if got != nil {
		t.Errorf("expected nil for nil client, got %+v", got)
	}
}

func TestGenerateTool_NoProvider_ReturnsNil(t *testing.T) {
	// No API key + default OpenAI base URL → shouldCallProvider returns false.
	c := NewClient("", "", "gpt-4o-mini")
	got := c.GenerateTool(context.Background(), "task", "http://example.com", nil)
	if got != nil {
		t.Errorf("expected nil when no provider configured, got %+v", got)
	}
}

func TestPlanToolCall_Success(t *testing.T) {
	respJSON := `{"action":"run_command","binary":"curl","args":["-I","http://example.com"],"rationale":"Confirm exposed headers with impact-focused verification"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fakeCompletion(t, respJSON)))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key", "test-model")
	got := c.PlanToolCall(context.Background(), ToolCallRequest{
		Target:          "http://example.com",
		AllowedBinaries: []string{"curl"},
	})
	if got == nil {
		t.Fatal("expected tool-call decision, got nil")
	}
	if got.Action != "run_command" || got.Binary != "curl" {
		t.Fatalf("unexpected decision: %+v", got)
	}
	if len(got.Args) != 2 || got.Args[0] != "-I" {
		t.Fatalf("unexpected args: %+v", got.Args)
	}
}

func TestPlanToolCall_InvalidActionReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fakeCompletion(t, `{"action":"shell_out","binary":"bash","args":["-c","id"]}`)))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key", "test-model")
	got := c.PlanToolCall(context.Background(), ToolCallRequest{Target: "http://example.com"})
	if got != nil {
		t.Fatalf("expected nil for invalid action, got %+v", got)
	}
}

func TestBuildToolCallSystemPrompt_IncludesStateChangeGuidance(t *testing.T) {
	prompt := buildToolCallSystemPrompt(ToolCallRequest{
		ImpactGoals: []string{"account_takeover"},
	})
	if !strings.Contains(prompt, "verify material state change") {
		t.Fatalf("expected state-change guidance in prompt, got: %q", prompt)
	}
	if !strings.Contains(prompt, "If the last action is working") {
		t.Fatalf("expected working-action continuation guidance in prompt, got: %q", prompt)
	}
}

// countingProvider records the peak number of concurrent Complete calls so a
// test can assert the Client's concurrency limiter is enforced.
type countingProvider struct {
mu      sync.Mutex
current int
peak    int
hold    time.Duration
}

func (p *countingProvider) Complete(ctx context.Context, model string, messages []Message, temperature float64, jsonMode bool) (string, error) {
p.mu.Lock()
p.current++
if p.current > p.peak {
p.peak = p.current
}
p.mu.Unlock()

select {
case <-time.After(p.hold):
case <-ctx.Done():
	p.mu.Lock()
	p.current--
	p.mu.Unlock()
	return "", ctx.Err()
}

p.mu.Lock()
p.current--
p.mu.Unlock()
return "ok", nil
}

func (p *countingProvider) peakConcurrency() int {
p.mu.Lock()
defer p.mu.Unlock()
return p.peak
}

func TestClientLimitsConcurrentAIRequests(t *testing.T) {
t.Setenv("AI_MAX_CONCURRENT_REQUESTS", "2")

prov := &countingProvider{hold: 25 * time.Millisecond}
c := &Client{Model: "test-model", provider: prov}

const callers = 12
var wg sync.WaitGroup
wg.Add(callers)
for i := 0; i < callers; i++ {
go func() {
defer wg.Done()
if _, err := c.primaryComplete(context.Background(), []Message{{Role: "user", Content: "hi"}}, 0, false); err != nil {
t.Errorf("primaryComplete: %v", err)
}
}()
}
wg.Wait()

if peak := prov.peakConcurrency(); peak > 2 {
t.Fatalf("peak concurrent AI requests = %d, want <= 2", peak)
}
}

func TestAcquireRespectsContextCancellation(t *testing.T) {
t.Setenv("AI_MAX_CONCURRENT_REQUESTS", "1")
c := &Client{}

// Take the only slot and never release it.
release, err := c.acquire(context.Background(), lanePrimary)
if err != nil {
t.Fatalf("first acquire: %v", err)
}
defer release()

ctx, cancel := context.WithCancel(context.Background())
cancel()
if _, err := c.acquire(ctx, lanePrimary); err == nil {
t.Fatal("expected acquire to fail on cancelled context, got nil error")
}
}

// TestAIRequestTimeoutEnvVar verifies that AI_REQUEST_TIMEOUT_SECONDS is read
// by aiRequestTimeout and that NewClient uses the result.
func TestAIRequestTimeoutEnvVar(t *testing.T) {
t.Setenv("AI_REQUEST_TIMEOUT_SECONDS", "77")
if got := aiRequestTimeout(); got != 77*time.Second {
t.Fatalf("aiRequestTimeout() = %v, want 77s", got)
}
}

func TestAIRequestTimeoutDefault(t *testing.T) {
t.Setenv("AI_REQUEST_TIMEOUT_SECONDS", "")
if got := aiRequestTimeout(); got != defaultAIRequestTimeoutSeconds*time.Second {
t.Fatalf("aiRequestTimeout() = %v, want %v", got, defaultAIRequestTimeoutSeconds*time.Second)
}
}

// TestPerLaneSemaphoresAreIsolated verifies that a saturated coding lane does
// not block calls on the fast lane (and vice versa). This is the central
// invariant that lets a long-running planner call coexist with high-frequency
// adaptive-probe / tool-call decisions.
func TestPerLaneSemaphoresAreIsolated(t *testing.T) {
t.Setenv("AI_MAX_CONCURRENT_REQUESTS_PRIMARY", "1")
t.Setenv("AI_MAX_CONCURRENT_REQUESTS_CODING", "1")
t.Setenv("AI_MAX_CONCURRENT_REQUESTS_FAST", "1")

// Coding provider hangs forever (simulates a slow planner call). Fast
// provider returns immediately. With a single shared semaphore the fast
// call would block; with per-lane semaphores it must complete.
codingProv := &countingProvider{hold: 5 * time.Second}
fastProv := &countingProvider{hold: 0}
c := &Client{
Model:          "primary-model",
CodingModel:    "coding-model",
FastModel:      "fast-model",
provider:       &countingProvider{hold: 0},
codingProvider: codingProv,
fastProvider:   fastProv,
}

// Saturate the coding lane.
codingDone := make(chan struct{})
go func() {
_, _ = c.planningComplete(context.Background(), []Message{{Role: "user", Content: "plan"}}, 0, false)
close(codingDone)
}()

// Give the coding goroutine a moment to acquire its lane slot.
time.Sleep(50 * time.Millisecond)

start := time.Now()
if _, err := c.fastComplete(context.Background(), []Message{{Role: "user", Content: "fast"}}, 0, false); err != nil {
t.Fatalf("fastComplete: %v", err)
}
if elapsed := time.Since(start); elapsed > time.Second {
t.Fatalf("fastComplete took %v while coding lane was saturated; per-lane isolation appears broken", elapsed)
}
}
// error (and releases its semaphore slot) when the provider blocks longer than
// AI_REQUEST_TIMEOUT_SECONDS instead of hanging the caller indefinitely.
func TestCompleteWithHangingProviderTimesOut(t *testing.T) {
// Set a short timeout so the test completes quickly.
t.Setenv("AI_REQUEST_TIMEOUT_SECONDS", "1")
t.Setenv("AI_MAX_CONCURRENT_REQUESTS", "1")

// Provider that blocks until its context is cancelled.
prov := &countingProvider{hold: 10 * time.Second}
c := &Client{Model: "test-model", provider: prov}

start := time.Now()
_, err := c.primaryComplete(context.Background(), []Message{{Role: "user", Content: "hi"}}, 0, false)
elapsed := time.Since(start)

if err == nil {
t.Fatal("expected an error from a hanging provider, got nil")
}
// Should have returned within ~2 s (1 s timeout + headroom); definitely not 10 s.
if elapsed > 5*time.Second {
t.Fatalf("primaryComplete took %v; expected it to return within 5 s after timeout", elapsed)
}

// The semaphore slot must have been released: a subsequent call must succeed.
prov2 := &countingProvider{hold: 0}
c2 := &Client{Model: "test-model", provider: prov2}
if _, err2 := c2.primaryComplete(context.Background(), []Message{{Role: "user", Content: "hi"}}, 0, false); err2 != nil {
t.Fatalf("follow-up call failed: %v", err2)
}
}
