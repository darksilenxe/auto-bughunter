package api

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/report"
)

// applyStrictReportingFilter filters job.Findings down to those whose
// Confidence meets the configured floor when StrictReporting is enabled.
// The mutation is local — callers receive a copy of the job with the
// filtered findings and a "strictMode.suppressed" annotation in
// AdditionalContext so report renderers can surface the reduction in noise.
// Query-string overrides (?strict=true&minConfidence=0.85) take precedence
// over the values stored on job.Options so operators can experiment without
// mutating persisted scan options.
func applyStrictReportingFilter(job *model.ScanJob, r *http.Request) (*model.ScanJob, int, float64, bool) {
	if job == nil {
		return job, 0, 0, false
	}
	strict := job.Options.StrictReporting
	threshold := job.Options.MinReportConfidence
	if r != nil {
		q := r.URL.Query()
		if raw := strings.TrimSpace(q.Get("strict")); raw != "" {
			switch strings.ToLower(raw) {
			case "1", "true", "yes", "on":
				strict = true
			case "0", "false", "no", "off":
				strict = false
			}
		}
		if raw := strings.TrimSpace(q.Get("minConfidence")); raw != "" {
			if v, err := strconv.ParseFloat(raw, 64); err == nil {
				threshold = v
			}
		}
	}
	if !strict {
		return job, 0, threshold, false
	}
	if threshold <= 0 {
		threshold = 0.75
	}
	if threshold > 1 {
		threshold = 1
	}
	clone := *job
	filtered := make([]model.Finding, 0, len(job.Findings))
	suppressed := 0
	for _, f := range job.Findings {
		// Always retain governance/operations sentinels and high-severity
		// findings that have already been verified, even if their nominal
		// confidence is low — strict mode is meant to suppress noisy
		// uncorroborated low-confidence chatter, not authoritative signal.
		if isStrictReportingExempt(f) {
			filtered = append(filtered, f)
			continue
		}
		if reason := strictReportingSuppressionReason(f, threshold); reason != "" {
			suppressed++
			continue
		}
		filtered = append(filtered, f)
	}
	clone.Findings = filtered
	return &clone, suppressed, threshold, true
}

func isStrictReportingExempt(f model.Finding) bool {
	switch strings.ToLower(strings.TrimSpace(f.Category)) {
	case "governance", "operations":
		return true
	}
	return false
}

func strictReportingSuppressionReason(f model.Finding, threshold float64) string {
	if f.Confidence < threshold {
		return "confidence_below_threshold"
	}
	if f.EvidenceFields != nil && f.EvidenceFields["evidenceQuality"] == "incomplete" {
		return "evidence_incomplete"
	}
	verified := strings.EqualFold(strings.TrimSpace(f.EvidenceFields["preReport.verified"]), "true")
	stamp := strictVerifierStamp(f)
	hasProofGap := strings.TrimSpace(f.EvidenceFields["proofPolicyMissing"]) != ""
	sev := strings.ToLower(strings.TrimSpace(string(f.Severity)))
	highImpact := sev == "high" || sev == "critical"
	if strictCategoryNeedsVerifier(f.Category) && stamp == "" {
		return "missing_verifier_stamp"
	}
	if highImpact && !verified {
		return "high_severity_not_verified"
	}
	if (highImpact || strictCategoryNeedsProof(f.Category)) && hasProofGap {
		return "missing_required_proof"
	}
	return ""
}

func strictVerifierStamp(f model.Finding) string {
	if f.EvidenceFields == nil {
		return ""
	}
	if stamp := strings.TrimSpace(f.EvidenceFields["preReport.verifiedBy"]); stamp != "" {
		return stamp
	}
	return strings.TrimSpace(f.EvidenceFields["verifiedBy"])
}

func strictCategoryNeedsVerifier(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "authentication", "xss", "dom_xss", "dom-xss", "open_redirect", "open-redirect",
		"csrf", "cors", "clickjacking", "xxe", "ssti", "sqli", "nosqli", "path_traversal",
		"path-traversal", "prototype_pollution", "prototype-pollution":
		return true
	}
	return false
}

func strictCategoryNeedsProof(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "authentication", "xss", "dom_xss", "dom-xss", "open_redirect", "open-redirect",
		"csrf", "cors", "clickjacking":
		return true
	}
	return false
}

// handleScanReport multiplexes all `/api/report/...` requests onto the
// appropriate concrete handler based on the URL suffix.
//
// Supported routes:
//
//	GET  /api/report/{scanId}                     -- main report (format/type via query)
//	POST /api/report/{scanId}                     -- main report with template options in body
//	GET  /api/report/{scanId}/finding/{findingId} -- single bug-bounty submission
//	GET  /api/report/{scanId}/bugbounty.zip       -- bundle of one Markdown file per finding
func (s *Server) handleScanReport(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/report/")
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}

	parts := strings.Split(rest, "/")
	scanID := parts[0]
	if scanID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}

	switch {
	case len(parts) == 2 && parts[1] == "bugbounty.zip":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.serveBugBountyZip(w, r, scanID)
	case len(parts) == 3 && parts[1] == "finding":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.serveSingleFindingReport(w, r, scanID, parts[2])
	case len(parts) == 1:
		s.serveMainReport(w, r, scanID)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown report route"})
	}
}

// serveMainReport handles GET (with query-string options) and POST (with JSON
// body options) and returns the requested report in PDF / Markdown / HTML / JSON.
func (s *Server) serveMainReport(w http.ResponseWriter, r *http.Request, scanID string) {
	job, ok := s.loadJobOrRespond(w, r, scanID)
	if !ok {
		return
	}

	opts, format, reportType, err := parseReportRequest(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	job, suppressed, threshold, strictApplied := applyStrictReportingFilter(job, r)
	if strictApplied {
		w.Header().Set("X-Strict-Reporting", "true")
		w.Header().Set("X-Strict-Reporting-Min-Confidence", fmt.Sprintf("%.2f", threshold))
		w.Header().Set("X-Strict-Reporting-Suppressed", fmt.Sprintf("%d", suppressed))
	}

	ctx := s.buildReportContext(r, job)

	switch reportType {
	case "executive":
		s.writeExecutiveReport(w, job, opts, format, scanID, ctx)
	case "compliance":
		s.writeComplianceReport(w, job, opts, format, scanID, ctx)
	default: // pentest (also default)
		s.writePentestReport(w, job, opts, format, scanID, ctx)
	}
}

// buildReportContext gathers optional inputs (previous job for delta, harvested
// screenshots from the event bus) for the requested scan. Failures are
// silently downgraded — these are nice-to-have inputs and the report is still
// usable without them.
func (s *Server) buildReportContext(r *http.Request, job *model.ScanJob) report.ReportContext {
	ctx := report.ReportContext{}
	if job == nil {
		return ctx
	}
	if s.repo != nil {
		if prev, err := s.repo.GetLatestCompletedJobByTarget(r.Context(), job.Target, job.ID); err == nil {
			ctx.PreviousJob = prev
		}
	}
	if s.eventBus != nil {
		ctx.Screenshots = harvestScreenshots(s.eventBus.History(job.ID))
	}
	return ctx
}

// harvestScreenshots converts SSE screenshot events into report.Screenshot
// values, decoding the base64 payload. Invalid entries are skipped.
func harvestScreenshots(events []model.ScanEvent) []report.Screenshot {
	out := make([]report.Screenshot, 0, len(events))
	for _, ev := range events {
		if ev.Type != model.ScanEventScreenshot || ev.Screenshot == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(ev.Screenshot)
		if err != nil || len(raw) == 0 {
			continue
		}
		caption := ev.Message
		if caption == "" {
			caption = "Screenshot"
		}
		ts := ev.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
		out = append(out, report.Screenshot{
			Caption:   caption,
			AgentName: ev.AgentName,
			Timestamp: ts,
			Data:      raw,
		})
		if len(out) >= report.MaxInlineScreenshots {
			break
		}
	}
	return out
}

func (s *Server) writePentestReport(w http.ResponseWriter, job *model.ScanJob, opts model.ReportTemplateOptions, format, scanID string, ctx report.ReportContext) {
	switch format {
	case "md", "markdown":
		md := report.RenderPentestMarkdown(job, opts, ctx)
		writeBytes(w, "text/markdown; charset=utf-8", fmt.Sprintf("scan-report-%s.md", scanID), []byte(md), false)
	case "html":
		htmlOut := report.RenderPentestHTML(job, opts, ctx)
		writeBytes(w, "text/html; charset=utf-8", fmt.Sprintf("scan-report-%s.html", scanID), []byte(htmlOut), false)
	case "json":
		data := report.BuildPentestReportData(job, opts, ctx)
		writeJSON(w, http.StatusOK, data)
	case "sarif":
		sarifBytes, err := report.RenderSARIF(job, opts, ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate SARIF"})
			return
		}
		writeBytes(w, "application/sarif+json", fmt.Sprintf("scan-report-%s.sarif", scanID), sarifBytes, false)
	case "csv":
		csvBytes := report.RenderFindingsCSV(job, opts, ctx)
		writeBytes(w, "text/csv; charset=utf-8", fmt.Sprintf("scan-report-%s.csv", scanID), csvBytes, true)
	case "", "pdf":
		// Default to PDF for backward compatibility with the original
		// /api/report/{scanId} endpoint.
		pdfBytes, err := report.RenderPentestPDF(job, opts, ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate PDF"})
			return
		}
		writeBytes(w, "application/pdf", fmt.Sprintf("scan-report-%s.pdf", scanID), pdfBytes, true)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported format: " + format})
	}
}

func (s *Server) writeExecutiveReport(w http.ResponseWriter, job *model.ScanJob, opts model.ReportTemplateOptions, format, scanID string, ctx report.ReportContext) {
	opts.ReportType = "executive"
	switch format {
	case "json":
		data := report.BuildPentestReportData(job, opts, ctx)
		writeJSON(w, http.StatusOK, data)
	case "html":
		htmlOut := report.RenderPentestHTML(job, opts, ctx)
		writeBytes(w, "text/html; charset=utf-8", fmt.Sprintf("executive-summary-%s.html", scanID), []byte(htmlOut), false)
	case "pdf":
		pdfBytes, err := report.RenderPentestPDF(job, opts, ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate PDF"})
			return
		}
		writeBytes(w, "application/pdf", fmt.Sprintf("executive-summary-%s.pdf", scanID), pdfBytes, true)
	case "", "md", "markdown":
		md := report.RenderExecutiveMarkdown(job, opts, ctx)
		writeBytes(w, "text/markdown; charset=utf-8", fmt.Sprintf("executive-summary-%s.md", scanID), []byte(md), false)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported format: " + format})
	}
}

// writeComplianceReport renders the focused PCI/HIPAA/SOC2 crosswalk variant.
func (s *Server) writeComplianceReport(w http.ResponseWriter, job *model.ScanJob, opts model.ReportTemplateOptions, format, scanID string, ctx report.ReportContext) {
	opts.ReportType = "compliance"
	switch format {
	case "json":
		data := report.BuildPentestReportData(job, opts, ctx)
		writeJSON(w, http.StatusOK, data)
	case "html":
		htmlOut := report.RenderComplianceHTML(job, opts, ctx)
		writeBytes(w, "text/html; charset=utf-8", fmt.Sprintf("compliance-%s.html", scanID), []byte(htmlOut), false)
	case "pdf":
		// PDF re-uses the pentest renderer with the compliance crosswalk
		// appendix (which is always emitted when ComplianceMatrix is non-empty).
		pdfBytes, err := report.RenderPentestPDF(job, opts, ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate PDF"})
			return
		}
		writeBytes(w, "application/pdf", fmt.Sprintf("compliance-%s.pdf", scanID), pdfBytes, true)
	case "", "md", "markdown":
		md := report.RenderComplianceMarkdown(job, opts, ctx)
		writeBytes(w, "text/markdown; charset=utf-8", fmt.Sprintf("compliance-%s.md", scanID), []byte(md), false)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported format: " + format})
	}
}

func (s *Server) serveSingleFindingReport(w http.ResponseWriter, r *http.Request, scanID, findingID string) {
	job, ok := s.loadJobOrRespond(w, r, scanID)
	if !ok {
		return
	}
	finding, found := report.FindingByID(job.Findings, findingID)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "finding not found"})
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	platform := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("platform")))
	switch format {
	case "json":
		writeJSON(w, http.StatusOK, report.FindingToBugBountySubmission(finding, job.Target))
	case "pdf":
		// For a single finding we render a one-finding PDF by passing a job
		// that contains only that finding.
		single := *job
		single.Findings = []model.Finding{finding}
		opts := model.ReportTemplateOptions{ReportType: "bugbounty"}
		pdfBytes, err := report.RenderPentestPDF(&single, opts)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate PDF"})
			return
		}
		writeBytes(w, "application/pdf", fmt.Sprintf("bugbounty-%s-%s.pdf", scanID, safeIDForFilename(findingID)), pdfBytes, true)
	case "", "md", "markdown":
		md := report.RenderBugBountyMarkdownForPlatform(finding, job.Target, platform)
		writeBytes(w, "text/markdown; charset=utf-8", fmt.Sprintf("bugbounty-%s-%s.md", scanID, safeIDForFilename(findingID)), []byte(md), false)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported format: " + format})
	}
}

func (s *Server) serveBugBountyZip(w http.ResponseWriter, r *http.Request, scanID string) {
	job, ok := s.loadJobOrRespond(w, r, scanID)
	if !ok {
		return
	}
	job, suppressed, threshold, strictApplied := applyStrictReportingFilter(job, r)
	if strictApplied {
		w.Header().Set("X-Strict-Reporting", "true")
		w.Header().Set("X-Strict-Reporting-Min-Confidence", fmt.Sprintf("%.2f", threshold))
		w.Header().Set("X-Strict-Reporting-Suppressed", fmt.Sprintf("%d", suppressed))
	}
	platform := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("platform")))
	zipBytes, err := report.RenderBugBountyZipForPlatform(job, platform)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate zip"})
		return
	}
	writeBytes(w, "application/zip", fmt.Sprintf("bugbounty-%s.zip", scanID), zipBytes, true)
}

// loadJobOrRespond fetches the scan job and writes a 404/500 response itself
// on failure. It returns (job, true) on success or (nil, false) otherwise.
func (s *Server) loadJobOrRespond(w http.ResponseWriter, r *http.Request, scanID string) (*model.ScanJob, bool) {
	job, err := s.repo.GetJob(r.Context(), scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
			return nil, false
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load scan"})
		return nil, false
	}
	if job == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return nil, false
	}
	if !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return nil, false
	}
	return job, true
}

// parseReportRequest pulls ReportTemplateOptions, format, and report type from
// either the query string (GET) or the JSON body (POST). Query-string
// parameters take precedence for format/type.
func parseReportRequest(w http.ResponseWriter, r *http.Request) (model.ReportTemplateOptions, string, string, error) {
	q := r.URL.Query()
	opts := model.ReportTemplateOptions{
		CompanyName:    strings.TrimSpace(q.Get("companyName")),
		Classification: strings.TrimSpace(q.Get("classification")),
		Contact:        strings.TrimSpace(q.Get("contact")),
		ProgramHandle:  strings.TrimSpace(q.Get("programHandle")),
		LogoPath:       strings.TrimSpace(q.Get("logoPath")),
		ReportType:     strings.TrimSpace(q.Get("type")),
	}

	if r.Method == http.MethodPost {
		var body model.ReportTemplateOptions
		if err := decodeJSONBody(w, r, &body); err != nil && !errors.Is(err, io.EOF) {
			return opts, "", "", fmt.Errorf("invalid JSON body: %w", err)
		}
		// JSON body fills in any unset values.
		if opts.CompanyName == "" {
			opts.CompanyName = body.CompanyName
		}
		if opts.Classification == "" {
			opts.Classification = body.Classification
		}
		if opts.Contact == "" {
			opts.Contact = body.Contact
		}
		if opts.ProgramHandle == "" {
			opts.ProgramHandle = body.ProgramHandle
		}
		if opts.LogoPath == "" {
			opts.LogoPath = body.LogoPath
		}
		if opts.ReportType == "" {
			opts.ReportType = body.ReportType
		}
	}

	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	reportType := strings.ToLower(strings.TrimSpace(opts.ReportType))
	return opts, format, reportType, nil
}

func writeBytes(w http.ResponseWriter, contentType, filename string, body []byte, attachment bool) {
	w.Header().Set("Content-Type", contentType)
	if attachment {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	} else {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename=%q`, filename))
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// safeIDForFilename returns a filename-safe version of an arbitrary scan or
// finding id. It mirrors the behavior used by the report package.
func safeIDForFilename(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-_.")
	if out == "" {
		out = "report"
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}
