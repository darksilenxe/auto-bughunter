package agentlearner

import (
	"context"
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
