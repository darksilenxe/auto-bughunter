package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

type probeRepo struct {
	reportTestRepo
	records map[string][]model.ProbeRecord
}

func (r *probeRepo) ListProbeRecords(_ context.Context, scanID string) ([]model.ProbeRecord, error) {
	return r.records[scanID], nil
}

func TestHandleListScanProbesReturnsRecords(t *testing.T) {
	s := &Server{repo: &probeRepo{
		reportTestRepo: reportTestRepo{
			jobs: map[string]*model.ScanJob{
				"scan-1": {ID: "scan-1", WorkspaceID: "default"},
			},
		},
		records: map[string][]model.ProbeRecord{
			"scan-1": {
				{ID: "p-1", ScanID: "scan-1", Category: "xss", FindingID: "f-1"},
				{ID: "p-2", ScanID: "scan-1", Category: "sqli", FindingID: "f-2"},
			},
		},
	}}

	req := authRequest("GET", "/api/scan/scan-1/probes", nil)
	rec := httptest.NewRecorder()
	s.handleScanOrEvents(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []model.ProbeRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].ID != "p-1" || got[1].ID != "p-2" {
		t.Fatalf("unexpected records: %#v", got)
	}
}

func TestHandleListScanProbesFiltersByFindingID(t *testing.T) {
	s := &Server{repo: &probeRepo{
		reportTestRepo: reportTestRepo{
			jobs: map[string]*model.ScanJob{
				"scan-1": {ID: "scan-1", WorkspaceID: "default"},
			},
		},
		records: map[string][]model.ProbeRecord{
			"scan-1": {
				{ID: "p-1", ScanID: "scan-1", Category: "xss", FindingID: "f-1"},
				{ID: "p-2", ScanID: "scan-1", Category: "sqli", FindingID: "f-2"},
				{ID: "p-3", ScanID: "scan-1", Category: "xss", FindingID: "f-1"},
			},
		},
	}}

	req := authRequest("GET", "/api/scan/scan-1/probes?findingId=f-1", nil)
	rec := httptest.NewRecorder()
	s.handleListScanProbes(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []model.ProbeRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for _, record := range got {
		if record.FindingID != "f-1" {
			t.Fatalf("record findingId = %q, want f-1", record.FindingID)
		}
	}
}

func TestHandleListScanProbesReturnsEmptyArrayWhenNoRecords(t *testing.T) {
	s := &Server{repo: &probeRepo{
		reportTestRepo: reportTestRepo{
			jobs: map[string]*model.ScanJob{
				"scan-1": {ID: "scan-1", WorkspaceID: "default"},
			},
		},
		records: map[string][]model.ProbeRecord{},
	}}

	req := authRequest("GET", "/api/scan/scan-1/probes", nil)
	rec := httptest.NewRecorder()
	s.handleListScanProbes(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []model.ProbeRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}
