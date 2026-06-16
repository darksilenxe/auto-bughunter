package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// echoLLMServer returns a test HTTP server that "executes" the trigger if it
// appears anywhere in the query parameter "q", simulating a vulnerable LLM
// endpoint that echoes injected instructions.
func echoLLMServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query().Get("q")
		if strings.Contains(q, promptInjectionTrigger) {
			// Simulate the model "executing" the instruction and echoing the trigger.
			_, _ = fmt.Fprintf(w, `{"response": "%s"}`, promptInjectionTrigger)
			return
		}
		_, _ = fmt.Fprint(w, `{"response": "Hello! How can I help you?"}`)
	}))
}

func TestRunActivePromptInjectionProbe_DirectInjection(t *testing.T) {
	target := echoLLMServer()
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runActivePromptInjectionProbe(context.Background(), input, "")
	if len(findings) == 0 {
		t.Fatal("expected prompt injection finding")
	}
	f := findings[0]
	if f.Category != "prompt-injection" {
		t.Fatalf("expected category prompt-injection, got %q", f.Category)
	}
	if !strings.Contains(f.Title, "direct") {
		t.Fatalf("expected direct injection type in title, got %q", f.Title)
	}
}

func TestRunActivePromptInjectionProbe_PassiveOnlySkips(t *testing.T) {
	target := echoLLMServer()
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.Options.PassiveOnly = true
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runActivePromptInjectionProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("PassiveOnly must disable probe, got %d findings", len(findings))
	}
}

func TestRunActivePromptInjectionProbe_NoAIAgentSkips(t *testing.T) {
	target := echoLLMServer()
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	// DetectedTech does NOT include "ai-agent" → probe should skip.
	findings := svc.runActivePromptInjectionProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("probe without ai-agent tech must skip, got %d findings", len(findings))
	}
}

func TestRunActivePromptInjectionProbe_NoFindingOnCleanResponse(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always returns a neutral response with no trigger.
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"response": "Hi there! I can assist you."}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.DetectedTech = TechStack{techs: map[string]struct{}{"ai-agent": {}}}

	findings := svc.runActivePromptInjectionProbe(context.Background(), input, "")
	if len(findings) != 0 {
		t.Fatalf("clean response must not produce findings, got %d", len(findings))
	}
}

func TestAppendQueryParam(t *testing.T) {
	cases := []struct {
		url      string
		key      string
		val      string
		wantSep  string
	}{
		{"http://example.com/api", "q", "hello", "?"},
		{"http://example.com/api?x=1", "q", "hello", "&"},
	}
	for _, tc := range cases {
		got := appendQueryParamSimple(tc.url, tc.key, tc.val)
		if !strings.Contains(got, tc.wantSep+tc.key+"=") {
			t.Errorf("appendQueryParamSimple(%q, %q, %q) = %q; want sep %q and key %q", tc.url, tc.key, tc.val, got, tc.wantSep, tc.key)
		}
	}
}
