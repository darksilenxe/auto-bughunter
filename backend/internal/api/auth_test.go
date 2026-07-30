package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticatePrincipal_DoesNotAcceptImplicitDevDefault(t *testing.T) {
	t.Setenv("BOOTSTRAP_ADMIN_API_KEY", "")

	s := &Server{}
	_, err := s.authenticatePrincipal(context.Background(), "dev-admin-key")
	if err == nil {
		t.Fatal("expected implicit dev-admin-key to be rejected when BOOTSTRAP_ADMIN_API_KEY is unset")
	}
	if !strings.Contains(err.Error(), "api key store unavailable") {
		t.Fatalf("expected api key store unavailable error, got %v", err)
	}
}

func TestAuthenticatePrincipal_AcceptsConfiguredBootstrapKey(t *testing.T) {
	t.Setenv("BOOTSTRAP_ADMIN_API_KEY", "test-bootstrap-key")

	s := &Server{}
	p, err := s.authenticatePrincipal(context.Background(), "test-bootstrap-key")
	if err != nil {
		t.Fatalf("expected configured bootstrap key to authenticate, got %v", err)
	}
	if !p.SuperAdmin {
		t.Fatal("expected configured bootstrap key to grant super admin principal")
	}
}

func TestProxyBrowseToken_IsOneTimeAndURLScoped(t *testing.T) {
	s := &Server{}
	p := principal{KeyID: "k1", WorkspaceID: "w1", Role: "admin"}
	token, _, err := s.issueProxyBrowseToken(p, "https://example.com/path")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/proxy/browse?url=https%3A%2F%2Fexample.com%2Fpath&browse_token="+token, nil)
	got, browseURL, ok := s.consumeProxyBrowseToken(req)
	if !ok {
		t.Fatal("expected token to be accepted")
	}
	if got.KeyID != p.KeyID {
		t.Fatalf("expected principal %q, got %q", p.KeyID, got.KeyID)
	}
	if browseURL != "https://example.com/path" {
		t.Fatalf("expected browse URL match, got %q", browseURL)
	}
	reqReuse := httptest.NewRequest(http.MethodGet, "/api/proxy/browse?url=https%3A%2F%2Fexample.com%2Fpath&browse_token="+token, nil)
	if _, _, ok := s.consumeProxyBrowseToken(reqReuse); ok {
		t.Fatal("expected token to be one-time use")
	}
}

func TestProxyBrowseToken_RejectsMismatchedURL(t *testing.T) {
	s := &Server{}
	p := principal{KeyID: "k2", WorkspaceID: "w2", Role: "admin"}
	token, _, err := s.issueProxyBrowseToken(p, "https://example.com/path")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/proxy/browse?url=https%3A%2F%2Fevil.example%2Fpath&browse_token="+token, nil)
	if _, _, ok := s.consumeProxyBrowseToken(req); ok {
		t.Fatal("expected token to reject mismatched URL")
	}
}
