package ml

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// postJSON is the only HTTP path on Service today; verify it sends the
// configured Authorization header so the sidecar middleware can authenticate
// the call.
func TestPostJSONSendsBearerTokenWhenConfigured(t *testing.T) {
	var gotAuth, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "1"})
	}))
	defer srv.Close()

	s := NewService(Config{ExternalURL: srv.URL, AuthToken: "secret-token"})
	var out map[string]string
	if ok := s.postJSON(context.Background(), "/v1/whatever", map[string]string{"x": "y"}, &out); !ok {
		t.Fatal("postJSON returned false")
	}
	if want := "Bearer secret-token"; gotAuth != want {
		t.Fatalf("Authorization = %q, want %q", gotAuth, want)
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotCT)
	}
}

func TestPostJSONOmitsAuthHeaderWhenTokenEmpty(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	s := NewService(Config{ExternalURL: srv.URL})
	var out map[string]string
	if ok := s.postJSON(context.Background(), "/v1/whatever", map[string]string{"x": "y"}, &out); !ok {
		t.Fatal("postJSON returned false")
	}
	if gotAuth != "" {
		t.Fatalf("Authorization header should be empty, got %q", gotAuth)
	}
}

func TestPostJSONReturnsFalseWhenExternalURLEmpty(t *testing.T) {
	s := NewService(Config{})
	var out map[string]string
	if ok := s.postJSON(context.Background(), "/v1/whatever", map[string]string{}, &out); ok {
		t.Fatal("postJSON should return false when no external URL is configured")
	}
}
