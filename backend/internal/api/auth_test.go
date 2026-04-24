package api

import (
	"context"
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
