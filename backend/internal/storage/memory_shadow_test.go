package storage

import (
	"context"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestMemoryStoreShadowDecisionsRoundTrip(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now().UTC()
	older := model.ShadowDecision{ID: "1", ScanID: "scan-1", FindingID: "f-1", Category: "xss", Aligned: false, CreatedAt: now.Add(-2 * time.Hour)}
	newer := model.ShadowDecision{ID: "2", ScanID: "scan-1", FindingID: "f-2", Category: "xss", Aligned: true, CreatedAt: now}

	if err := store.SaveShadowDecision(context.Background(), older); err != nil {
		t.Fatalf("save older decision: %v", err)
	}
	if err := store.SaveShadowDecision(context.Background(), newer); err != nil {
		t.Fatalf("save newer decision: %v", err)
	}

	items, err := store.ListShadowDecisions(context.Background(), now.Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatalf("list shadow decisions: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].ID != "2" || items[1].ID != "1" {
		t.Fatalf("expected reverse-chronological order, got %+v", items)
	}
}

