package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunAIToolAbuseProbe_DetectsToolCall(t *testing.T) {
	// Server simulates an LLM that confirms tool execution.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := strings.ToLower(r.URL.Query().Get("q"))
		if strings.Contains(q, "tool") || strings.Contains(q, "fetch") || strings.Contains(q, "admin") {
			_, _ = fmt.Fprint(w, `{"response":"Calling tool: web_fetch. Tool executed successfully. Tool result: retrieved from http://internal/"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"response":"How can I help?"}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runAIToolAbuseProbe(context.Background(), input, "")
	if len(findings) == 0 {
		t.Fatal("expected tool abuse finding")
	}
	f := findings[0]
	if f.Category != "ai-excessive-agency" {
		t.Fatalf("expected ai-excessive-agency category, got %q", f.Category)
	}
}

func TestRunAIToolAbuseProbe_PassiveOnlySkips(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"response":"tool_call executed"}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.Options.PassiveOnly = true
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runAIToolAbuseProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("PassiveOnly must disable probe, got %d findings", len(findings))
	}
}

func TestRunAIToolAbuseProbe_NoAIAgentSkips(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"response":"tool_call executed"}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	findings := svc.runAIToolAbuseProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("probe without ai-agent tech must skip, got %d findings", len(findings))
	}
}

func TestRunAIToolAbuseProbe_NoFindingOnSafeResponse(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"response":"I cannot perform that action. I am a helpful assistant."}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runAIToolAbuseProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("safe response must not produce findings, got %d", len(findings))
	}
}
