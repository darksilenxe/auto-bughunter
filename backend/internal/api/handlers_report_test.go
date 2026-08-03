package api

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func authRequest(method, target string, body *bytes.Reader) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, body)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	ctx := context.WithValue(req.Context(), principalContextKey, principal{
		KeyID:       "test-key",
		WorkspaceID: "default",
		Role:        model.APIKeyRoleAdmin,
		Name:        "test-admin",
		SuperAdmin:  true,
	})
	return req.WithContext(ctx)
}

// reportTestRepo is a hand-rolled fake implementation of the Repository
// interface that returns a single in-memory ScanJob keyed by ID. It only
// implements the methods invoked by the report handlers; all other methods
// panic so accidental use in tests is loud.
type reportTestRepo struct {
	jobs map[string]*model.ScanJob
}

type healthStatsRepo struct {
	reportTestRepo
	stats sql.DBStats
}

func (r *healthStatsRepo) ConnectionStats() sql.DBStats { return r.stats }

func (r *reportTestRepo) GetJob(_ context.Context, id string) (*model.ScanJob, error) {
	job, ok := r.jobs[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return job, nil
}

// The remaining Repository methods are stubbed so the type satisfies the
// interface. Tests that invoke them will fail loudly.
func (r *reportTestRepo) CreateJob(context.Context, *model.ScanJob) error { panic("not used") }
func (r *reportTestRepo) UpdateJob(context.Context, *model.ScanJob) error { panic("not used") }
func (r *reportTestRepo) GetLatestCompletedJobByTarget(context.Context, string, string) (*model.ScanJob, error) {
	// Returns nil so handler tests that exercise the report context don't
	// require a previous scan to be present.
	return nil, nil
}
func (r *reportTestRepo) SaveAssets(context.Context, string, []model.ScanAsset) error {
	panic("not used")
}
func (r *reportTestRepo) GetAssetsByScanID(context.Context, string) ([]model.ScanAsset, error) {
	panic("not used")
}
func (r *reportTestRepo) AppendAuditEvent(context.Context, string, model.ScanAuditEvent) error {
	panic("not used")
}
func (r *reportTestRepo) ListAuditEvents(context.Context, string) ([]model.ScanAuditEvent, error) {
	panic("not used")
}
func (r *reportTestRepo) ListCompletedJobs(context.Context, int) ([]*model.ScanJob, error) {
	panic("not used")
}
func (r *reportTestRepo) SaveFeedback(context.Context, model.ReportFeedback) error { panic("not used") }
func (r *reportTestRepo) ListFeedback(context.Context, int) ([]model.ReportFeedback, error) {
	panic("not used")
}
func (r *reportTestRepo) SaveFindingVerification(context.Context, model.FindingVerification) error {
	panic("not used")
}
func (r *reportTestRepo) GetLatestFindingVerifications(context.Context, string) (map[string]model.FindingVerification, error) {
	panic("not used")
}
func (r *reportTestRepo) SaveSuppressionRule(context.Context, model.SuppressionRule) error {
	panic("not used")
}
func (r *reportTestRepo) ListActiveSuppressionRules(context.Context, string, time.Time) ([]model.SuppressionRule, error) {
	panic("not used")
}
func (r *reportTestRepo) GetScanState(context.Context, string) (*model.PersistentScanState, error) {
	panic("not used")
}
func (r *reportTestRepo) UpsertScanState(context.Context, model.PersistentScanState) error {
	panic("not used")
}
func (r *reportTestRepo) GetRecentJobByIdempotencyKey(context.Context, string, string, time.Time) (*model.ScanJob, error) {
	panic("not used")
}
func (r *reportTestRepo) SaveIdempotencyRecord(context.Context, string, string, string, time.Time) error {
	panic("not used")
}
func (r *reportTestRepo) UpsertAutomationTicket(context.Context, model.AutomationTicket) error {
	panic("not used")
}
func (r *reportTestRepo) ResolveAutomationTicketsMissingFingerprints(context.Context, string, []string, time.Time) (int64, error) {
	panic("not used")
}
func (r *reportTestRepo) ListOpenAutomationTickets(context.Context, string, int) ([]model.AutomationTicket, error) {
	panic("not used")
}
func (r *reportTestRepo) UpsertAutomationCampaign(context.Context, model.AutomationCampaign) error {
	panic("not used")
}
func (r *reportTestRepo) ListAutomationCampaigns(context.Context, string, bool, int) ([]model.AutomationCampaign, error) {
	panic("not used")
}
func (r *reportTestRepo) ListDueAutomationCampaigns(context.Context, time.Time, int) ([]model.AutomationCampaign, error) {
	panic("not used")
}
func (r *reportTestRepo) UpdateAutomationCampaignRun(context.Context, string, time.Time, time.Time) error {
	panic("not used")
}
func (r *reportTestRepo) DeleteAutomationCampaign(context.Context, string, string) error {
	panic("not used")
}
func (r *reportTestRepo) TryLeaseAutomationCampaign(context.Context, string, time.Time) (bool, error) {
	panic("not used")
}
func (r *reportTestRepo) MarkAutomationCampaignDispatchFailure(context.Context, string, string, time.Time, time.Duration) error {
	panic("not used")
}
func (r *reportTestRepo) HeartbeatAutomationCampaignLease(context.Context, string, time.Time, time.Time) (bool, error) {
	panic("not used")
}
func (r *reportTestRepo) ReclaimStaleAutomationCampaignLeases(context.Context, time.Time, int) (int64, error) {
	panic("not used")
}
func (r *reportTestRepo) UpdateAutomationCampaignQueueState(context.Context, string, string, string, *time.Time) error {
	panic("not used")
}
func (r *reportTestRepo) GetProgramROIOverride(context.Context, string, string) (*model.ProgramROIOverride, error) {
	panic("not used")
}
func (r *reportTestRepo) UpsertProgramROIOverride(context.Context, model.ProgramROIOverride) error {
	panic("not used")
}
func (r *reportTestRepo) ListProgramROIOverrides(context.Context, string, int) ([]model.ProgramROIOverride, error) {
	panic("not used")
}
func (r *reportTestRepo) GetWorkspaceDailyUsage(context.Context, string, time.Time) (model.WorkspaceDailyUsage, error) {
	panic("not used")
}
func (r *reportTestRepo) GetAutomationPolicyPack(context.Context, string, string) (*model.AutomationPolicyPack, error) {
	panic("not used")
}
func (r *reportTestRepo) UpsertAutomationPolicyPack(context.Context, model.AutomationPolicyPack) error {
	panic("not used")
}
func (r *reportTestRepo) ListAutomationPolicyPacks(context.Context, string, int) ([]model.AutomationPolicyPack, error) {
	panic("not used")
}
func (r *reportTestRepo) AppendAutomationPolicyAudit(context.Context, model.AutomationPolicyAuditEvent) error {
	panic("not used")
}
func (r *reportTestRepo) ListAutomationPolicyAudit(context.Context, string, string, int) ([]model.AutomationPolicyAuditEvent, error) {
	panic("not used")
}
func (r *reportTestRepo) SaveScanAnnotation(context.Context, model.ScanAnnotation) error {
	return nil
}
func (r *reportTestRepo) ListScanAnnotations(_ context.Context, _ string) ([]model.ScanAnnotation, error) {
	return nil, nil
}
func (r *reportTestRepo) SaveProbeRecord(context.Context, string, model.ProbeResult) error {
	panic("not used")
}
func (r *reportTestRepo) ListProbeRecords(context.Context, string) ([]model.ProbeRecord, error) {
	panic("not used")
}
func (r *reportTestRepo) ListProbeRecordsByOutcome(context.Context, model.ProbeOutcome, time.Time, int) ([]model.ProbeRecord, error) {
	panic("not used")
}
func (r *reportTestRepo) ListProbeRecordsByCategory(context.Context, string, time.Time, int) ([]model.ProbeRecord, error) {
	panic("not used")
}
func (r *reportTestRepo) GetRejectedFindingsByTarget(context.Context, string) ([]model.FindingVerification, error) {
	return nil, nil
}

func TestHandleHealthIncludesDatabaseStatsWhenAvailable(t *testing.T) {
	s := &Server{
		repo: &healthStatsRepo{
			reportTestRepo: reportTestRepo{jobs: map[string]*model.ScanJob{}},
			stats: sql.DBStats{
				MaxOpenConnections: 32,
				OpenConnections:    5,
				InUse:              2,
				Idle:               3,
				WaitCount:          7,
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()

	s.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected ok status, got %#v", body["status"])
	}
	database, ok := body["database"].(map[string]any)
	if !ok {
		t.Fatalf("expected database stats in response, got %#v", body["database"])
	}
	if got := int(database["maxOpenConnections"].(float64)); got != 32 {
		t.Fatalf("expected maxOpenConnections=32, got %d", got)
	}
	if got := int(database["waitCount"].(float64)); got != 7 {
		t.Fatalf("expected waitCount=7, got %d", got)
	}
}

func newReportServer(t *testing.T, jobs map[string]*model.ScanJob) *Server {
	t.Helper()
	return &Server{
		repo: &reportTestRepo{jobs: jobs},
	}
}

func sampleReportJob() *model.ScanJob {
	completed := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	return &model.ScanJob{
		ID:          "scan-1",
		Target:      "https://example.com",
		Status:      "completed",
		StartedAt:   time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC),
		CompletedAt: &completed,
		Findings: []model.Finding{
			{
				ID:                "sqlmap-error-based",
				Category:          "injection",
				Severity:          model.SeverityHigh,
				Title:             "SQL injection",
				AffectedParameter: "id",
			},
		},
	}
}

func TestHandleScanReport_DefaultsToPDF(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	req := authRequest(http.MethodGet, "/api/report/scan-1", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/pdf" {
		t.Errorf("expected application/pdf content type, got %q", got)
	}
	if !bytes.HasPrefix(rec.Body.Bytes(), []byte("%PDF-")) {
		t.Errorf("response body is not a PDF")
	}
}

func TestHandleScanReport_FormatNegotiation(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	cases := []struct {
		format         string
		expectedPrefix string
		expectedType   string
	}{
		{"md", "# Penetration", "text/markdown"},
		{"html", "<!DOCTYPE html>", "text/html"},
		{"json", "{", "application/json"},
	}
	for _, c := range cases {
		t.Run(c.format, func(t *testing.T) {
			req := authRequest(http.MethodGet, "/api/report/scan-1?format="+c.format, nil)
			rec := httptest.NewRecorder()
			srv.handleScanReport(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
			}
			if !strings.HasPrefix(rec.Header().Get("Content-Type"), c.expectedType) {
				t.Errorf("expected content-type prefix %q, got %q", c.expectedType, rec.Header().Get("Content-Type"))
			}
			if !strings.HasPrefix(rec.Body.String(), c.expectedPrefix) {
				t.Errorf("expected body prefix %q, got %q", c.expectedPrefix, rec.Body.String()[:min(60, len(rec.Body.String()))])
			}
		})
	}
}

func TestHandleScanReport_ExecutiveType(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	req := authRequest(http.MethodGet, "/api/report/scan-1?type=executive&format=md", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Executive Security Summary") {
		t.Errorf("expected executive summary content, got: %s", rec.Body.String()[:200])
	}
}

func TestHandleScanReport_NotFound(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{})
	req := authRequest(http.MethodGet, "/api/report/missing", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleScanReport_SingleFindingMarkdown(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	req := authRequest(http.MethodGet, "/api/report/scan-1/finding/sqlmap-error-based?strict=false", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "## Steps to Reproduce") {
		t.Errorf("expected bug-bounty markdown structure, got: %s", rec.Body.String()[:200])
	}
}

func TestHandleScanReport_SingleFindingNotFound(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	req := authRequest(http.MethodGet, "/api/report/scan-1/finding/missing", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestHandleScanReport_BugBountyZip(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	req := authRequest(http.MethodGet, "/api/report/scan-1/bugbounty.zip?strict=false", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/zip" {
		t.Errorf("expected application/zip content type, got %q", got)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("response is not a valid zip: %v", err)
	}
	hasIndex := false
	for _, f := range zr.File {
		if f.Name == "INDEX.md" {
			hasIndex = true
		}
	}
	if !hasIndex {
		t.Errorf("INDEX.md missing from zip")
	}
}

func TestHandleScanReport_PostWithTemplateOptions(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	body, _ := json.Marshal(model.ReportTemplateOptions{
		CompanyName:    "Posted Co.",
		Classification: "Internal",
	})
	req := authRequest(http.MethodPost, "/api/report/scan-1?format=md", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Posted Co.") {
		t.Errorf("expected company name from POST body to appear, got: %s", rec.Body.String()[:300])
	}
	if !strings.Contains(rec.Body.String(), "Internal") {
		t.Errorf("expected classification from POST body to appear")
	}
}

func TestHandleScanReport_UnsupportedFormat(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	req := authRequest(http.MethodGet, "/api/report/scan-1?format=docx", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleScanReport_MissingScanID(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{})
	req := authRequest(http.MethodGet, "/api/report/", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestApplyStrictReportingFilterSuppressesUnverifiedHighSeverity(t *testing.T) {
	job := sampleReportJob()
	job.Options.StrictReporting = true
	job.Options.MinReportConfidence = 0.7
	job.Findings = []model.Finding{{
		ID:         "f1",
		Category:   "authentication",
		Severity:   model.SeverityHigh,
		Confidence: 0.95,
		Title:      "OAuth token replay",
		EvidenceFields: map[string]string{
			"evidenceQuality": "valid",
		},
	}}
	out, suppressed, _, strict := applyStrictReportingFilter(job, nil, false)
	if !strict {
		t.Fatal("expected strict filter to apply")
	}
	if suppressed != 1 || len(out.Findings) != 0 {
		t.Fatalf("expected strict filter to suppress unverified high-severity finding, suppressed=%d findings=%d", suppressed, len(out.Findings))
	}
}

func TestApplyStrictReportingFilterKeepsVerifiedHighSeverity(t *testing.T) {
	job := sampleReportJob()
	job.Options.StrictReporting = true
	job.Options.MinReportConfidence = 0.7
	job.Findings = []model.Finding{{
		ID:         "f1",
		Category:   "authentication",
		Severity:   model.SeverityHigh,
		Confidence: 0.95,
		Title:      "OAuth token replay",
		Sources:    []string{"scanner", "burp"},
		EvidenceFields: map[string]string{
			"evidenceQuality":         "valid",
			"preReport.verified":      "true",
			"preReport.verifiedBy":    "oauth_session_probe@v1",
			"preReport.pocTranscript": "POST /oauth/token -> 200",
		},
	}}
	out, suppressed, _, _ := applyStrictReportingFilter(job, nil, false)
	if suppressed != 0 || len(out.Findings) != 1 {
		t.Fatalf("expected verified finding to survive strict filter, suppressed=%d findings=%d", suppressed, len(out.Findings))
	}
}

func TestApplyStrictReportingFilterSuppressesProofGapsForAuthFlowFindings(t *testing.T) {
	job := sampleReportJob()
	job.Options.StrictReporting = true
	job.Options.MinReportConfidence = 0.7
	job.Findings = []model.Finding{{
		ID:         "f1",
		Category:   "authentication",
		Severity:   model.SeverityMedium,
		Confidence: 0.91,
		Title:      "OIDC nonce omission",
		EvidenceFields: map[string]string{
			"evidenceQuality":      "valid",
			"preReport.verified":   "true",
			"preReport.verifiedBy": "oauth_session_probe@v1",
			"proofPolicyMissing":   "nonce",
		},
	}}
	out, suppressed, _, _ := applyStrictReportingFilter(job, nil, false)
	if suppressed != 1 || len(out.Findings) != 0 {
		t.Fatalf("expected proof-gap auth-flow finding to be suppressed, suppressed=%d findings=%d", suppressed, len(out.Findings))
	}
}

func TestApplyStrictReportingFilterSuppressesUncorroboratedHighSeverity(t *testing.T) {
	job := sampleReportJob()
	job.Options.StrictReporting = true
	job.Options.MinReportConfidence = 0.7
	job.Findings = []model.Finding{{
		ID:         "f1",
		Category:   "authentication",
		Severity:   model.SeverityHigh,
		Confidence: 0.95,
		Title:      "OAuth token replay",
		EvidenceFields: map[string]string{
			"evidenceQuality":         "valid",
			"preReport.verified":      "true",
			"preReport.verifiedBy":    "oauth_session_probe@v1",
			"preReport.pocTranscript": "POST /oauth/token -> 200",
		},
	}}
	out, suppressed, _, _ := applyStrictReportingFilter(job, nil, false)
	if suppressed != 1 || len(out.Findings) != 0 {
		t.Fatalf("expected uncorroborated high-severity finding to be suppressed, suppressed=%d findings=%d", suppressed, len(out.Findings))
	}
}

func TestApplyStrictReportingFilterSuppressesHighSeverityWithoutReplayableProof(t *testing.T) {
	job := sampleReportJob()
	job.Options.StrictReporting = true
	job.Options.MinReportConfidence = 0.7
	job.Findings = []model.Finding{{
		ID:         "f1",
		Category:   "authentication",
		Severity:   model.SeverityHigh,
		Confidence: 0.95,
		Title:      "OAuth token replay",
		Sources:    []string{"scanner", "burp"},
		EvidenceFields: map[string]string{
			"evidenceQuality":      "valid",
			"preReport.verified":   "true",
			"preReport.verifiedBy": "oauth_session_probe@v1",
		},
	}}
	out, suppressed, _, _ := applyStrictReportingFilter(job, nil, false)
	if suppressed != 1 || len(out.Findings) != 0 {
		t.Fatalf("expected high-severity finding without replayable proof to be suppressed, suppressed=%d findings=%d", suppressed, len(out.Findings))
	}
}

func TestHandleScanReport_SingleFindingSuppressedByDefaultStrictMode(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	req := authRequest(http.MethodGet, "/api/report/scan-1/finding/sqlmap-error-based", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "strict reporting") {
		t.Fatalf("expected strict-reporting suppression message, got %s", rec.Body.String())
	}
}

func TestHandleScanReport_DefaultPDFAppliesStrictReportingByDefault(t *testing.T) {
	srv := newReportServer(t, map[string]*model.ScanJob{"scan-1": sampleReportJob()})
	req := authRequest(http.MethodGet, "/api/report/scan-1", nil)
	rec := httptest.NewRecorder()
	srv.handleScanReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Strict-Reporting"); got != "true" {
		t.Fatalf("expected strict-reporting header, got %q", got)
	}
	if got := rec.Header().Get("X-Strict-Reporting-Suppressed"); got != "1" {
		t.Fatalf("expected 1 suppressed finding, got %q", got)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *reportTestRepo) SaveAgentEvent(ctx context.Context, scanID string, event model.ScanEvent) error {
	return nil
}
func (r *reportTestRepo) ListAgentEvents(ctx context.Context, scanID string) ([]model.ScanEvent, error) {
	return nil, nil
}
