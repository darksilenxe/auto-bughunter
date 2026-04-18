package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/report"
)

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

	opts, format, reportType, err := parseReportRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	switch reportType {
	case "executive":
		s.writeExecutiveReport(w, job, opts, format, scanID)
	default: // pentest (also default)
		s.writePentestReport(w, job, opts, format, scanID)
	}
}

func (s *Server) writePentestReport(w http.ResponseWriter, job *model.ScanJob, opts model.ReportTemplateOptions, format, scanID string) {
	switch format {
	case "md", "markdown":
		md := report.RenderPentestMarkdown(job, opts)
		writeBytes(w, "text/markdown; charset=utf-8", fmt.Sprintf("scan-report-%s.md", scanID), []byte(md), false)
	case "html":
		html := report.RenderPentestHTML(job, opts)
		writeBytes(w, "text/html; charset=utf-8", fmt.Sprintf("scan-report-%s.html", scanID), []byte(html), false)
	case "json":
		data := report.BuildPentestReportData(job, opts)
		writeJSON(w, http.StatusOK, data)
	case "", "pdf":
		// Default to PDF for backward compatibility with the original
		// /api/report/{scanId} endpoint.
		pdfBytes, err := report.RenderPentestPDF(job, opts)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate PDF"})
			return
		}
		writeBytes(w, "application/pdf", fmt.Sprintf("scan-report-%s.pdf", scanID), pdfBytes, true)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported format: " + format})
	}
}

func (s *Server) writeExecutiveReport(w http.ResponseWriter, job *model.ScanJob, opts model.ReportTemplateOptions, format, scanID string) {
	opts.ReportType = "executive"
	switch format {
	case "json":
		data := report.BuildPentestReportData(job, opts)
		writeJSON(w, http.StatusOK, data)
	case "html":
		html := report.RenderPentestHTML(job, opts)
		writeBytes(w, "text/html; charset=utf-8", fmt.Sprintf("executive-summary-%s.html", scanID), []byte(html), false)
	case "pdf":
		pdfBytes, err := report.RenderPentestPDF(job, opts)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate PDF"})
			return
		}
		writeBytes(w, "application/pdf", fmt.Sprintf("executive-summary-%s.pdf", scanID), pdfBytes, true)
	case "", "md", "markdown":
		md := report.RenderExecutiveMarkdown(job, opts)
		writeBytes(w, "text/markdown; charset=utf-8", fmt.Sprintf("executive-summary-%s.md", scanID), []byte(md), false)
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
		md := report.RenderBugBountyMarkdown(finding, job.Target)
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
	zipBytes, err := report.RenderBugBountyZip(job)
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
	return job, true
}

// parseReportRequest pulls ReportTemplateOptions, format, and report type from
// either the query string (GET) or the JSON body (POST). Query-string
// parameters take precedence for format/type.
func parseReportRequest(r *http.Request) (model.ReportTemplateOptions, string, string, error) {
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
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
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
