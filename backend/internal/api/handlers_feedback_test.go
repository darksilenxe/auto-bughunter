package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestHandleBountyOutcomeWebhook_NormalizesNAOutcome(t *testing.T) {
	repo := &reportTestRepo{jobs: map[string]*model.ScanJob{
		"scan-1": {
			ID:          "scan-1",
			WorkspaceID: "default",
			ProgramName: "acme",
		},
	}}
	srv := &Server{repo: repo}
	body, _ := json.Marshal(model.ReportFeedback{
		ScanID:    "scan-1",
		FindingID: "f-1",
		Outcome:   "N/A",
		Notes:     "triager marked not applicable",
	})
	req := authRequest(http.MethodPost, "/api/bounty-outcomes/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.handleBountyOutcomeWebhook(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(repo.feedback) != 1 {
		t.Fatalf("expected 1 feedback record, got %d", len(repo.feedback))
	}
	if repo.feedback[0].Outcome != "na" {
		t.Fatalf("expected normalized outcome 'na', got %q", repo.feedback[0].Outcome)
	}
}

func TestHandleBountyOutcomeWebhook_RejectsInvalidSecret(t *testing.T) {
	t.Setenv("ABH_BOUNTY_OUTCOME_WEBHOOK_SECRET", "expected-secret")
	repo := &reportTestRepo{jobs: map[string]*model.ScanJob{
		"scan-1": {ID: "scan-1", WorkspaceID: "default"},
	}}
	srv := &Server{repo: repo}
	body, _ := json.Marshal(model.ReportFeedback{
		ScanID:    "scan-1",
		FindingID: "f-1",
		Outcome:   "accepted",
	})
	req := authRequest(http.MethodPost, "/api/bounty-outcomes/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bounty-Webhook-Secret", "wrong")
	rec := httptest.NewRecorder()

	srv.handleBountyOutcomeWebhook(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleFeedback_NormalizesNAOutcome(t *testing.T) {
	repo := &reportTestRepo{jobs: map[string]*model.ScanJob{
		"scan-1": {ID: "scan-1", WorkspaceID: "default"},
	}}
	srv := &Server{repo: repo}
	body, _ := json.Marshal(model.ReportFeedback{
		ScanID:    "scan-1",
		FindingID: "f-1",
		Outcome:   "not applicable",
	})
	req := authRequest(http.MethodPost, "/api/feedback", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.handleFeedback(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(repo.feedback) != 1 || repo.feedback[0].Outcome != "na" {
		t.Fatalf("expected normalized na feedback, got %+v", repo.feedback)
	}
}

func TestHandleScanReport_SubmitFindingBlockedOnDuplicatePrecheck(t *testing.T) {
	completed := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	ready := &model.ScanJob{
		ID:          "scan-ready",
		Target:      "https://example.com",
		WorkspaceID: "default",
		Status:      "completed",
		StartedAt:   completed.Add(-time.Hour),
		CompletedAt: &completed,
		Findings: []model.Finding{{
			ID:                "f-ready",
			Title:             "SQL Injection in login",
			Description:       "SQL injection via username parameter.",
			Category:          "sqli",
			Severity:          model.SeverityHigh,
			AffectedURL:       "https://example.com/login",
			AffectedParameter: "username",
			ReproductionSteps: []string{"POST /login with payload"},
			Evidence:          "response contains SQL error",
			CWE:               "CWE-89",
			CVSSScore:         9.1,
			Impact:            "database read access",
			Recommendation:    "use prepared statements",
			ProofArtifacts:    []model.ProofArtifact{{Type: "curl", Label: "reproducer", Value: "curl ..."}},
			Confidence:        0.95,
		}},
	}
	prior := &model.ScanJob{
		ID:          "scan-old",
		Target:      "https://example.com",
		WorkspaceID: "default",
		Status:      "completed",
		StartedAt:   completed.Add(-2 * time.Hour),
		CompletedAt: &completed,
		Findings: []model.Finding{{
			ID:                "f-old",
			Title:             "SQL Injection in login",
			Category:          "sqli",
			Severity:          model.SeverityHigh,
			AffectedURL:       "https://example.com/login?x=1",
			AffectedParameter: "username",
			CWE:               "CWE-89",
		}},
	}
	srv := newReportServer(t, map[string]*model.ScanJob{
		"scan-ready": ready,
		"scan-old":   prior,
	})
	req := authRequest(http.MethodPost, "/api/report/scan-ready/finding/f-ready/submit?platform=hackerone", nil)
	rec := httptest.NewRecorder()

	srv.handleScanReport(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("duplicate pre-check")) {
		t.Fatalf("expected duplicate pre-check message, got %s", rec.Body.String())
	}
}
