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

func TestValidateAuthProfileRejectsInvalidLoginStep(t *testing.T) {
	err := validateAuthProfile(model.ScanAuthProfile{
		Username: "alice",
		Password: "secret",
		LoginSteps: []model.ScanAuthLoginStep{
			{Action: "fill", Selector: "#email"},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid login step")
	}
	if !strings.Contains(err.Error(), "requires value") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAuthProfileAllowsCustomLoginSteps(t *testing.T) {
	err := validateAuthProfile(model.ScanAuthProfile{
		Username: "alice",
		Password: "secret",
		LoginSteps: []model.ScanAuthLoginStep{
			{Action: "fill", Selector: "#email", Value: "{{username}}"},
			{Action: "fill", Selector: "#password", Value: "{{password}}"},
			{Action: "click", Selector: "button[type=submit]"},
			{Action: "wait", WaitMillis: 1200},
		},
	})
	if err != nil {
		t.Fatalf("expected login steps to be valid, got %v", err)
	}
}
