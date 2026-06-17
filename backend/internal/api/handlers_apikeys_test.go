package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/storage"
)

func TestHandleAPIKeyByIDRejectsCrossWorkspaceMutation(t *testing.T) {
	store := storage.NewMemoryStore()
	_, _, err := store.CreateAPIKey(context.Background(), "workspace-a", "admin-a", model.APIKeyRoleAdmin)
	if err != nil {
		t.Fatalf("create admin key: %v", err)
	}
	other, _, err := store.CreateAPIKey(context.Background(), "workspace-b", "other", model.APIKeyRoleViewer)
	if err != nil {
		t.Fatalf("create other key: %v", err)
	}
	originalPrefix := other.KeyPrefix
	s := &Server{repo: store}
	principal := principal{WorkspaceID: "workspace-a", Role: model.APIKeyRoleAdmin}

	for _, action := range []string{"rotate", "revoke"} {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/apikeys/"+other.ID+"/"+action, nil)
		req = req.WithContext(context.WithValue(req.Context(), principalContextKey, principal))
		rec := httptest.NewRecorder()

		s.handleAPIKeyByID(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: expected 403, got %d", action, rec.Code)
		}
		got, err := store.GetAPIKey(context.Background(), other.ID)
		if err != nil {
			t.Fatalf("%s: reload api key: %v", action, err)
		}
		if !got.Active {
			t.Fatalf("%s: cross-workspace request revoked key", action)
		}
		if got.KeyPrefix != originalPrefix {
			t.Fatalf("%s: cross-workspace request rotated key prefix from %q to %q", action, originalPrefix, got.KeyPrefix)
		}
	}
}
