package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// unsafeOutputLLMServer returns a test server that echoes the LLM prompt
// output back verbatim — simulating an application that renders LLM responses
// without sanitization.
func unsafeOutputLLMServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		if q == "" {
			q = r.URL.Query().Get("input")
		}
		// Simulate the LLM "following" the prompt and echoing the injected content.
		_, _ = fmt.Fprintf(w, "<div>%s</div>", q)
	}))
}

func TestRunAIOutputHandlingProbe_XSS(t *testing.T) {
	target := unsafeOutputLLMServer()
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runAIOutputHandlingProbe(context.Background(), input, "")
	if len(findings) == 0 {
		t.Fatal("expected insecure output handling finding (XSS)")
	}
	f := findings[0]
	if f.Category != "ai-insecure-output" {
		t.Fatalf("expected ai-insecure-output category, got %q", f.Category)
	}
	if !strings.Contains(strings.ToLower(f.Title), "xss") && !strings.Contains(strings.ToLower(f.Title), "output") {
		t.Fatalf("unexpected title: %q", f.Title)
	}
}

func TestRunAIOutputHandlingProbe_PassiveOnlySkips(t *testing.T) {
	target := unsafeOutputLLMServer()
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.Options.PassiveOnly = true
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runAIOutputHandlingProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("PassiveOnly must disable probe, got %d findings", len(findings))
	}
}

func TestRunAIOutputHandlingProbe_NoAIAgentSkips(t *testing.T) {
	target := unsafeOutputLLMServer()
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	// No ai-agent in DetectedTech.
	findings := svc.runAIOutputHandlingProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("probe without ai-agent tech must skip, got %d findings", len(findings))
	}
}

func TestRunAIOutputHandlingProbe_SafeResponseNoFinding(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"response":"I am a safe AI assistant. How can I help?"}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runAIOutputHandlingProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("safe response must not produce findings, got %d", len(findings))
	}
}
