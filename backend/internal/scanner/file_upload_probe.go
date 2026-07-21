package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// fileUploadBodyLimit caps response body reads during upload probing.
const fileUploadBodyLimit = 128 * 1024

// fileUploadMaxEndpoints caps how many upload endpoints are probed per scan.
const fileUploadMaxEndpoints = 6

// uploadEndpointPatterns are URL path patterns that suggest a file upload
// endpoint. These are matched case-insensitively against candidate paths.
var uploadEndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/(upload|uploads|file|files|media|assets|attach|attachment|import|ingest|image|images|document|documents)`),
	regexp.MustCompile(`(?i)\.(upload|file|attach)`),
}

// uploadProbes are the extension-bypass payloads sent to discovered upload
// endpoints. Each represents a different bypass technique.
var uploadProbes = []struct {
	label       string
	filename    string
	contentType string
	body        string
}{
	{
		label:       "double-extension",
		filename:    "test.php.jpg",
		contentType: "image/jpeg",
		body:        "<?php echo 'abh_upload_rce_test'; ?>",
	},
	{
		label:       "null-byte-bypass",
		filename:    "test.php\x00.jpg",
		contentType: "image/jpeg",
		body:        "<?php echo 'abh_upload_rce_test'; ?>",
	},
	{
		label:       "mime-type-bypass",
		filename:    "test.php",
		contentType: "image/jpeg",
		body:        "<?php echo 'abh_upload_rce_test'; ?>",
	},
	{
		label:       "path-traversal-filename",
		filename:    "../test.php",
		contentType: "application/octet-stream",
		body:        "<?php echo 'abh_upload_rce_test'; ?>",
	},
	{
		label:       "svg-xss",
		filename:    "test.svg",
		contentType: "image/svg+xml",
		body:        `<svg xmlns="http://www.w3.org/2000/svg" onload="abh_upload_xss_test()"><script>abh_upload_xss_test()</script></svg>`,
	},
}

// uploadSuccessSignals are response body substrings that suggest the file was
// stored or processed (i.e. the upload was accepted, not rejected).
var uploadSuccessSignals = []string{
	"abh_upload_rce_test",
	"abh_upload_xss_test",
	"uploaded",
	"upload successful",
	"file saved",
	"file stored",
	"created",
}

// uploadExecutionSignals are response body substrings that confirm server-side
// execution of the uploaded payload — the highest-confidence outcome.
var uploadExecutionSignals = []string{
	"abh_upload_rce_test",
}

// runFileUploadProbe is an active probe covering WSTG-BUSL-08/09. It:
//  1. Discovers upload-path candidate endpoints from runtime hints and known patterns.
//  2. Attempts multipart form file uploads with bypass payloads (double extension,
//     null byte, MIME-type mismatch, path traversal in filename, SVG XSS).
//  3. Flags when the server accepts a payload it should reject, or when server-side
//     execution signals appear in the response.
func (s *Service) runFileUploadProbe(ctx context.Context, input RunInput, bodyText string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := discoverUploadEndpoints(input.Target, bodyText, input.Scope, input.Options.SeedRuntimeEndpoints)
	if len(candidates) == 0 {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("file-upload %s", input.Target),
			Message: fmt.Sprintf("Probing %d potential upload endpoints for extension/MIME bypass", len(candidates)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range candidates {
		if err := safety.ValidateOutboundURL(ep); err != nil {
			continue
		}
		if !scope.IsURLInScope(ep, input.Scope) {
			continue
		}

		// Phase 2 reference wiring: merge miner-discovered upload-field
		// names in front of the built-in "file" field name (see
		// PHASE2_AUDIT.md). Duplicates are dropped.
		fieldNames := phase2ProbeParams(phase2DynamicParams(input.Session), []string{"file"})

		for _, probe := range uploadProbes {
			for _, fieldName := range fieldNames {
				fid := "file-upload-" + probe.label + "-" + fieldName + "-" + hhSlug(ep)
				if emitted[fid] {
					continue
				}

				resp, respBody, err := s.executeUploadAttemptField(ctx, ep, fieldName, probe.filename, probe.contentType, probe.body, input)
				// Phase 2 coverage accounting: record this probe key so the
				// surface-gap detector subtracts it from the inventory.
				RecordProbedKey(http.MethodPost, ep, fieldName)
				if err != nil || resp == nil {
					continue
				}
				respStr := string(respBody)
				assessment := assessUploadResponse(resp.StatusCode, respStr)
				if !assessment.Accepted {
					continue
				}

				blockedControl := blockedUploadControlFilename(probe.label)
				controlBaselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
					cresp, cbody, err := s.executeUploadAttemptField(bctx, ep, fieldName, blockedControl, probe.contentType, probe.body, input)
					if err != nil || cresp == nil {
						return BaselineSample{}, err
					}
					return BaselineSample{Status: cresp.StatusCode, Header: cresp.Header, Body: string(cbody)}, nil
				})
				if berr == nil {
					if assessUploadResponse(controlBaselines.First.Status, controlBaselines.First.Body).Accepted ||
						assessUploadResponse(controlBaselines.Second.Status, controlBaselines.Second.Body).Accepted {
						continue
					}
				}

				diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
					ProbeName:       "file-upload-probe",
					OriginalPayload: probe.filename,
					SafePayload:     blockedControl,
					Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
						return s.executeUploadAttemptField(dctx, ep, fieldName, altPayload, probe.contentType, probe.body, input)
					},
					Oracle: func(_ context.Context, _ string, dresp *http.Response, dbody []byte) (bool, error) {
						if dresp == nil {
							return false, nil
						}
						return assessUploadResponse(dresp.StatusCode, string(dbody)).Accepted, nil
					},
				})
				if diffOutcome.Ran && !diffOutcome.Confirmed {
					continue
				}

				emitted[fid] = true
				severity := model.SeverityHigh
				title := fmt.Sprintf("File upload bypass accepted — %s technique", probe.label)
				desc := fmt.Sprintf(
					"The upload endpoint %s accepted a file submission using the %s bypass technique "+
						"(filename: %q, Content-Type: %q). If the server processes or serves the uploaded file "+
						"without proper validation, an attacker could achieve stored XSS, path traversal, "+
						"or remote code execution depending on how the file is handled.",
					ep, probe.label, probe.filename, probe.contentType,
				)
				if assessment.Executed != "" {
					severity = model.SeverityCritical
					title = fmt.Sprintf("File upload — server-side execution confirmed (%s)", probe.label)
					desc = fmt.Sprintf(
						"The upload endpoint %s not only accepted the %s bypass payload but the response contained "+
							"the execution marker %q, confirming that the server executed the uploaded server-side script. "+
							"This represents a critical remote code execution (RCE) vulnerability.",
						ep, probe.label, assessment.Executed,
					)
				}

				finding := model.Finding{
					ID:          fid,
					Category:    "file-upload",
					Severity:    severity,
					Title:       title,
					Description: desc,
					Evidence: fmt.Sprintf(
						"POST %s (field=%q, filename=%q, Content-Type=%q) → HTTP %d; accepted=%v; executed=%q",
						ep, fieldName, probe.filename, probe.contentType, resp.StatusCode, assessment.Accepted, assessment.Executed,
					),
					Recommendation: "Validate uploaded files by content (magic bytes), not only filename extension or " +
						"MIME type. Store uploaded files in a non-web-accessible location or use a separate origin/CDN. " +
						"Never execute uploaded content server-side. Strip executable extensions and normalize filenames " +
						"before storage. Use a robust allowlist (e.g. JPEG magic bytes for image uploads).",
					Confidence:    0.80,
					AffectedURL:   ep,
					CWE:           "CWE-434",
					OWASPCategory: "A05:2021 - Security Misconfiguration",
					Sources:       []string{"active-scanner", "file-upload"},
					ReproductionSteps: []string{
						fmt.Sprintf("POST %s with a multipart body:", ep),
						fmt.Sprintf("  field=%q, filename=%q, Content-Type=%q", fieldName, probe.filename, probe.contentType),
						fmt.Sprintf("  body: %s", probe.body[:min(len(probe.body), 80)]),
						fmt.Sprintf("Observe HTTP %d — server accepted the upload.", resp.StatusCode),
					},
					EvidenceFields: map[string]string{
						"validationType": "active-probe",
						"method":         http.MethodPost,
						"url":            ep,
						"param":          fieldName,
						"payloadClass":   "upload-bypass",
						"probeLabel":     probe.label,
						"fieldName":      fieldName,
						"filename":       probe.filename,
						"mimetype":       probe.contentType,
						"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
						"executed":       assessment.Executed,
						"responseShape":  ClassifyResponseShape(resp.Header).String(),
						"oracleName":     "file_upload_probe",
						"oracleVersion":  "v1",
					},
				}
				AttachDifferentialEvidence(&finding, diffOutcome)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// discoverUploadEndpoints collects candidate file upload endpoints from seeded
// endpoints, body hints, and well-known upload path patterns derived from the
// target origin.
func discoverUploadEndpoints(target, body string, scanScope model.ScanScope, seeded []string) []string {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	candidates := extractRuntimeEndpoints(target, body, scanScope, 20)
	candidates = append(candidates, seeded...)

	wellKnown := []string{
		"/upload", "/uploads", "/file/upload", "/files/upload",
		"/api/upload", "/api/files", "/api/media", "/api/attachments",
		"/media/upload", "/assets/upload", "/image/upload", "/document/upload",
		"/import", "/ingest",
	}
	for _, wk := range wellKnown {
		ref, err := url.Parse(wk)
		if err != nil {
			continue
		}
		candidates = append(candidates, base.ResolveReference(ref).String())
	}

	var out []string
	seen := map[string]struct{}{}
	for _, raw := range candidates {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		if !scope.IsURLInScope(raw, scanScope) {
			continue
		}
		// Only include paths that look like upload endpoints.
		matchesPattern := false
		for _, pat := range uploadEndpointPatterns {
			parsed, err := url.Parse(raw)
			if err == nil && pat.MatchString(parsed.Path) {
				matchesPattern = true
				break
			}
		}
		if !matchesPattern {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
		if len(out) >= fileUploadMaxEndpoints {
			break
		}
	}
	return out
}

// buildMultipartUpload constructs a multipart/form-data body with a single
// file field named "file". Returns the body buffer, the full Content-Type
// header (including boundary), and any error.
func buildMultipartUpload(filename, mimeType, content string) (*bytes.Buffer, string, error) {
	return buildMultipartUploadField("file", filename, mimeType, content)
}

// buildMultipartUploadField constructs a multipart/form-data body with a
// single file field using the given field name. Phase 2 reference wiring:
// callers can pass miner-discovered upload-field names (see
// PHASE2_AUDIT.md) instead of the built-in "file" default.
func buildMultipartUploadField(fieldName, filename, mimeType, content string) (*bytes.Buffer, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	part, err := w.CreateFormFile(fieldName, filename)
	if err != nil {
		return nil, "", err
	}
	if _, err = part.Write([]byte(content)); err != nil {
		return nil, "", err
	}
	if err = w.Close(); err != nil {
		return nil, "", err
	}

	ct := w.FormDataContentType()
	return &buf, ct, nil
}

// min returns the smaller of a and b (used for excerpt lengths).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type uploadAssessment struct {
	Accepted bool
	Executed string
}

// detectUploadExecution checks response body for execution or acceptance signals.
// Returns "rce" for confirmed execution, "accepted" for acceptance-only, "" for none.
func detectUploadExecution(body string) string {
	lower := strings.ToLower(body)
	for _, sig := range uploadExecutionSignals {
		if strings.Contains(lower, strings.ToLower(sig)) {
			return "rce"
		}
	}
	for _, sig := range uploadSuccessSignals {
		if strings.Contains(lower, strings.ToLower(sig)) {
			return "accepted"
		}
	}
	return ""
}

func assessUploadResponse(status int, body string) uploadAssessment {
	assessment := uploadAssessment{}
	signal := detectUploadExecution(body)
	if signal == "rce" {
		assessment.Accepted = true
		assessment.Executed = matchAnyLower(body, uploadExecutionSignals)
		return assessment
	}
	assessment.Accepted = signal == "accepted" || status < http.StatusBadRequest
	return assessment
}

func blockedUploadControlFilename(label string) string {
	if label == "path-traversal-filename" {
		return "../abh_control_blocked.php"
	}
	return "abh_control_blocked.php"
}

// executeUploadAttemptField is the Phase 2 field-aware variant that lets the
// caller choose the multipart field name so miner-discovered upload-field
// names can be exercised alongside the built-in "file" default.
func (s *Service) executeUploadAttemptField(ctx context.Context, ep, fieldName, filename, mimeType, content string, input RunInput) (*http.Response, []byte, error) {
	body, contentType, err := buildMultipartUploadField(fieldName, filename, mimeType, content)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	ApplyAuthProfile(req, input.AuthProfile)
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return nil, nil, err
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, fileUploadBodyLimit))
	_ = resp.Body.Close()
	resp.Body = http.NoBody
	return resp, respBody, nil
}
