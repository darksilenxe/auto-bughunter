package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetectAIAgent_JSKeyword(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body><script>var client = require('openai');</script></body></html>`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	signals, detected := svc.DetectAIAgent(context.Background(), input, `<script>var client = require('openai');</script>`)
	if !detected {
		t.Fatalf("expected AI agent detected via JS keyword, got signals=%v", signals)
	}
	found := false
	for _, sig := range signals {
		if sig.Source == "js-keyword" && strings.Contains(sig.Detail, "openai") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected js-keyword signal for 'openai', got %v", signals)
	}
}

func TestDetectAIAgent_NoSignal(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for everything except root, so endpoint probes don't fire.
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body><h1>Welcome</h1></body></html>`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	_, detected := svc.DetectAIAgent(context.Background(), input, `<html><body><h1>Welcome</h1></body></html>`)
	if detected {
		t.Fatal("expected no AI agent detection on plain page")
	}
}

func TestDetectAIAgent_ResponseHeader(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-openai-model", "gpt-4")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{}`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	signals, detected := svc.DetectAIAgent(context.Background(), input, "")
	if !detected {
		t.Fatalf("expected AI agent detected via response header, got signals=%v", signals)
	}
	found := false
	for _, sig := range signals {
		if sig.Source == "header" && strings.Contains(sig.Detail, "x-openai-model") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected header signal for x-openai-model, got %v", signals)
	}
}

func TestDetectAIAgent_ChatEndpoint(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/chat" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	signals, detected := svc.DetectAIAgent(context.Background(), input, "")
	if !detected {
		t.Fatalf("expected AI agent detected via /api/chat endpoint, got signals=%v", signals)
	}
	found := false
	for _, sig := range signals {
		if sig.Source == "endpoint" && strings.Contains(sig.Detail, "/api/chat") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected endpoint signal for /api/chat, got %v", signals)
	}
}

func TestRunAIAgentDetectProbe_PassiveOnly(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body>powered by openai</body></html>`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	input.Options.PassiveOnly = true
	findings := svc.runAIAgentDetectProbe(context.Background(), input, `<html><body>powered by openai</body></html>`)
	// Should produce a passive informational finding
	if len(findings) == 0 {
		t.Fatal("expected passive AI agent finding")
	}
	if findings[0].Category != "ai-agent" {
		t.Fatalf("expected ai-agent category, got %q", findings[0].Category)
	}
}

func TestRunAIAgentDetectProbe_NoFindingWhenNoSignal(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, `<html><body><h1>Store</h1></body></html>`)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	findings := svc.runAIAgentDetectProbe(context.Background(), input, `<html><body><h1>Store</h1></body></html>`)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestRunAIAgentDetectProbe_StreamingBody(t *testing.T) {
	// A response body containing SSE streaming markers is a strong AI signal.
	body := `data: {"choices":[{"delta":{"content":"Hello"}}],"object":"chat.completion.chunk"}`
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, body)
	}))
	defer target.Close()

	svc := NewService(Config{})
	input := RunInput{Target: target.URL}
	findings := svc.runAIAgentDetectProbe(context.Background(), input, body)
	if len(findings) == 0 {
		t.Fatal("expected AI agent finding from streaming body markers")
	}
}
