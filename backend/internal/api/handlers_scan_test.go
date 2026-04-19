package api

import (
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestValidateAuthProfileAllowsUnauthenticatedScan(t *testing.T) {
	if err := validateAuthProfile(model.ScanAuthProfile{}); err != nil {
		t.Fatalf("expected empty auth profile to be allowed, got %v", err)
	}
}

func TestValidateAuthProfileRequiresUsernameAndPasswordTogether(t *testing.T) {
	err := validateAuthProfile(model.ScanAuthProfile{Username: "alice"})
	if err == nil {
		t.Fatal("expected error for incomplete standard auth credentials")
	}
	if !strings.Contains(err.Error(), "username and password") {
		t.Fatalf("unexpected error: %v", err)
	}
}
