package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

// activityRepo is a minimal fake Repository that only implements the methods
// exercised by handleGetScanActivity. All other methods panic.
type activityRepo struct {
	reportTestRepo
	events map[string][]model.ScanEvent
	err    error
}

func (r *activityRepo) ListAgentEvents(_ context.Context, scanID string) ([]model.ScanEvent, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.events[scanID], nil
}

func TestHandleGetScanActivityRejectsNonGet(t *testing.T) {
	s := &Server{repo: &activityRepo{}}
	req := authRequest("POST", "/api/scan/abc123/activity", nil)
	rec := httptest.NewRecorder()
	s.handleGetScanActivity(rec, req)

	if rec.Code != 405 {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHandleGetScanActivityReturnsEmptyArrayWhenNoEvents(t *testing.T) {
	s := &Server{repo: &activityRepo{events: map[string][]model.ScanEvent{}}}
	req := authRequest("GET", "/api/scan/nosuchid/activity", nil)
	rec := httptest.NewRecorder()
	s.handleGetScanActivity(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []model.ScanEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %d events", len(got))
	}
}

func TestHandleGetScanActivityReturnsStoredEvents(t *testing.T) {
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	stored := []model.ScanEvent{
		{Type: model.ScanEventAgentStart, AgentName: "recon", Message: "started", Timestamp: ts},
		{Type: model.ScanEventAgentComplete, AgentName: "recon", Message: "done", Timestamp: ts},
		{Type: model.ScanEventFinding, AgentName: "xss-agent", FindingTitle: "Reflected XSS", Severity: "high", Timestamp: ts},
	}
	s := &Server{repo: &activityRepo{events: map[string][]model.ScanEvent{"scan-1": stored}}}
	req := authRequest("GET", "/api/scan/scan-1/activity", nil)
	rec := httptest.NewRecorder()
	s.handleGetScanActivity(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []model.ScanEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != len(stored) {
		t.Fatalf("expected %d events, got %d", len(stored), len(got))
	}
	if got[0].AgentName != "recon" {
		t.Fatalf("event[0].AgentName = %q, want %q", got[0].AgentName, "recon")
	}
	if got[2].FindingTitle != "Reflected XSS" {
		t.Fatalf("event[2].FindingTitle = %q, want %q", got[2].FindingTitle, "Reflected XSS")
	}
}

func TestHandleGetScanActivityReturns500OnRepoError(t *testing.T) {
	s := &Server{repo: &activityRepo{err: fmt.Errorf("db is down")}}
	req := authRequest("GET", "/api/scan/scan-1/activity", nil)
	rec := httptest.NewRecorder()
	s.handleGetScanActivity(rec, req)

	if rec.Code != 500 {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestHandleGetScanActivityIsolatesScanIDs(t *testing.T) {
	ts := time.Now().UTC()
	s := &Server{repo: &activityRepo{events: map[string][]model.ScanEvent{
		"scan-A": {{Type: model.ScanEventInfo, Message: "for A", Timestamp: ts}},
		"scan-B": {{Type: model.ScanEventInfo, Message: "for B", Timestamp: ts}},
	}}}

	for _, tc := range []struct{ id, want string }{
		{"scan-A", "for A"},
		{"scan-B", "for B"},
	} {
		req := authRequest("GET", "/api/scan/"+tc.id+"/activity", nil)
		rec := httptest.NewRecorder()
		s.handleGetScanActivity(rec, req)

		if rec.Code != 200 {
			t.Fatalf("[%s] status = %d, want 200", tc.id, rec.Code)
		}
		var got []model.ScanEvent
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("[%s] unmarshal: %v", tc.id, err)
		}
		if len(got) != 1 || got[0].Message != tc.want {
			t.Fatalf("[%s] got %v, want message %q", tc.id, got, tc.want)
		}
	}
}
