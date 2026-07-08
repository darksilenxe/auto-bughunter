package agentlearner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestClientSendsBearerTokenWhenConfigured(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"recommended":["a"],"contextFlags":0}`))
	}))
	defer srv.Close()

	c := NewClientWithToken(srv.URL, "secret-token")
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	_ = c.Recommend(context.Background(), "src", []model.Finding{}, 1, 0.5)

	if want := "Bearer secret-token"; gotAuth != want {
		t.Fatalf("Authorization header = %q, want %q", gotAuth, want)
	}
}

func TestClientOmitsAuthHeaderWhenTokenEmpty(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"recommended":[],"contextFlags":0}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	_ = c.Recommend(context.Background(), "src", []model.Finding{}, 1, 0.5)

	if gotAuth != "" {
		t.Fatalf("Authorization header should be empty, got %q", gotAuth)
	}
}

func TestNewClientWithTokenEmptyBaseURLReturnsNil(t *testing.T) {
	if c := NewClientWithToken("", "tok"); c != nil {
		t.Fatalf("expected nil client for empty base URL, got %#v", c)
	}
}

func TestGenerateCommandsUsesEndpointAndDefaultsMaxCommands(t *testing.T) {
	var gotPath string
	var gotReq GenerateCommandRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_, _ = w.Write([]byte(`{"commands":[{"binary":"wafw00f","args":["https://example.com"],"rationale":"fallback","generatedBy":"dynamic_commands","timeoutSeconds":30}]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	commands := c.GenerateCommands(context.Background(), "dynamic_commands", "https://example.com", []model.Finding{
		{Category: "reconnaissance", Severity: model.SeverityInfo, Title: "seed", Evidence: "target=https://example.com"},
	}, 0)

	if gotPath != "/v1/generate-command" {
		t.Fatalf("request path = %q, want %q", gotPath, "/v1/generate-command")
	}
	if gotReq.MaxCommands != 5 {
		t.Fatalf("maxCommands = %d, want %d", gotReq.MaxCommands, 5)
	}
	if len(commands) != 1 || commands[0].Binary != "wafw00f" {
		t.Fatalf("unexpected commands: %#v", commands)
	}
}
