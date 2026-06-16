package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunAIDOSProbe_DetectsSlowResponse(t *testing.T) {
	// Server that artificially sleeps beyond the DoS threshold for bomb prompts.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q != "" && len(q) > 50 {
			// Simulate slow LLM processing.
			time.Sleep(aiDOSSlowThreshold + 100*time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"response":"done"}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	findings := svc.runAIDOSProbe(ctx, input, "")
	hasLatencyFinding := false
	for _, f := range findings {
		if f.ID == "active-ai-dos" {
			hasLatencyFinding = true
		}
	}
	if !hasLatencyFinding {
		t.Fatal("expected latency-based DoS finding")
	}
}

func TestRunAIDOSProbe_DetectsNoRateLimit(t *testing.T) {
	// Server with no rate-limit headers.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"response":"hello"}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runAIDOSProbe(context.Background(), input, "")
	hasRateLimitFinding := false
	for _, f := range findings {
		if f.ID == "ai-dos-no-rate-limit" {
			hasRateLimitFinding = true
		}
	}
	if !hasRateLimitFinding {
		t.Fatal("expected missing rate-limit finding")
	}
}

func TestRunAIDOSProbe_PassiveOnlySkips(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.Options.PassiveOnly = true
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runAIDOSProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("PassiveOnly must disable probe, got %d findings", len(findings))
	}
}

func TestRunAIDOSProbe_NoAIAgentSkips(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	findings := svc.runAIDOSProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("probe without ai-agent tech must skip, got %d findings", len(findings))
	}
}

func TestRunAIDOSProbe_RateLimitHeaderSuppressesWarning(t *testing.T) {
	// Server that advertises rate-limit headers should not produce the
	// missing-rate-limit finding.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("X-RateLimit-Remaining", "99")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"response":"ok"}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runAIDOSProbe(context.Background(), input, "")
	for _, f := range findings {
		if f.ID == "ai-dos-no-rate-limit" {
			t.Fatal("rate-limit headers present: no missing-rate-limit finding expected")
		}
	}
}
