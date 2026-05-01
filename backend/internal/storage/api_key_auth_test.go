package storage

import (
	"context"
	"errors"
	"database/sql"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestAuthenticateAPIKey_PrefixLookupHappyPath(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	rec, raw, err := store.CreateAPIKey(ctx, "ws1", "test", model.APIKeyRoleAdmin)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.AuthenticateAPIKey(ctx, raw)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ID != rec.ID {
		t.Fatalf("expected key id %q, got %q", rec.ID, got.ID)
	}
}

func TestAuthenticateAPIKey_RejectsUnknownPrefix(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if _, _, err := store.CreateAPIKey(ctx, "ws1", "test", model.APIKeyRoleAdmin); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.AuthenticateAPIKey(ctx, "abh_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows for unknown prefix, got %v", err)
	}
}

func TestAuthenticateAPIKey_RejectsRevoked(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	rec, raw, err := store.CreateAPIKey(ctx, "ws1", "test", model.APIKeyRoleAdmin)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.RevokeAPIKey(ctx, rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := store.AuthenticateAPIKey(ctx, raw); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows after revoke, got %v", err)
	}
}

func TestAuthenticateAPIKey_RejectsEmpty(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if _, err := store.AuthenticateAPIKey(ctx, ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows for empty key, got %v", err)
	}
	if _, err := store.AuthenticateAPIKey(ctx, "   "); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows for whitespace key, got %v", err)
	}
}
