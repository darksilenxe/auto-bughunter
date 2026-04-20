package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// FileUploadAgent tests file upload endpoints for security weaknesses such as
// unrestricted file type acceptance, content-type bypass, double-extension
// bypasses, path traversal in filenames, and zip-slip vulnerabilities.
type FileUploadAgent struct {
	enabled bool
}

func NewFileUploadAgent(enabled bool) *FileUploadAgent {
	return &FileUploadAgent{enabled: enabled}
}

func (a *FileUploadAgent) Name() string  { return "file_upload" }
func (a *FileUploadAgent) Enabled() bool { return a.enabled }

func (a *FileUploadAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	client := &http.Client{Timeout: 12 * time.Second}

	uploadEndpoints := discoverUploadEndpoints(ctx, client, input.Target, input.AuthProfile)

	output.Findings = append(output.Findings, testUnrestrictedFileUpload(ctx, client, input.Target, input.AuthProfile, uploadEndpoints)...)
	output.Findings = append(output.Findings, testContentTypeBypass(ctx, client, input.Target, input.AuthProfile, uploadEndpoints)...)
	output.Findings = append(output.Findings, testDoubleExtensionBypass(ctx, client, input.Target, input.AuthProfile, uploadEndpoints)...)
	output.Findings = append(output.Findings, testPathTraversalInFilename(ctx, client, input.Target, input.AuthProfile, uploadEndpoints)...)

	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.Metadata["upload_endpoints_found"] = fmt.Sprintf("%d", len(uploadEndpoints))
	output.DebugNotes = fmt.Sprintf("File upload security testing completed. %d upload endpoint(s) probed.", len(uploadEndpoints))
	return output, nil
}

// commonUploadPaths lists frequently used upload endpoint paths.
var commonUploadPaths = []string{
	"/upload", "/uploads", "/api/upload", "/api/uploads",
	"/api/v1/upload", "/api/v1/file", "/api/files",
	"/file/upload", "/files/upload", "/media/upload",
	"/avatar/upload", "/profile/avatar", "/profile/photo",
	"/image/upload", "/images/upload", "/document/upload",
	"/attachment/upload", "/import", "/api/import",
}

// discoverUploadEndpoints probes common paths for upload endpoints and returns
// those that respond with anything other than 404.
func discoverUploadEndpoints(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []string {
	found := make([]string, 0)
	base := strings.TrimRight(target, "/")

	for _, path := range commonUploadPaths {
		u := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			found = append(found, u)
		}
	}

	return found
}

// buildMultipartBody creates a multipart/form-data body with a single file field.
func buildMultipartBody(fieldName, filename, contentType, content string) (body *bytes.Buffer, formContentType string) {
	body = &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		_ = writer.Close()
		return body, writer.FormDataContentType()
	}
	_, _ = io.WriteString(part, content)
	_ = writer.Close()
	return body, writer.FormDataContentType()
}

// isUploadAccepted returns true when the server accepted the upload (2xx or
// the response body contains a storage URL / confirmation phrase).
func isUploadAccepted(statusCode int, body []byte) bool {
	if statusCode >= 200 && statusCode < 300 {
		return true
	}
	lower := strings.ToLower(string(body))
	for _, kw := range []string{"uploaded", "success", "url", "path", "filename", "file_id", "fileId"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// uploadFieldNames lists common multipart field names for file uploads.
var uploadFieldNames = []string{"file", "upload", "image", "photo", "avatar", "document", "attachment", "data"}

func tryUpload(ctx context.Context, client *http.Client, endpoint string, profile model.ScanAuthProfile, fieldName, filename, contentType, content string) (int, []byte, error) {
	body, formCT := buildMultipartBody(fieldName, filename, contentType, content)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", formCT)
	scanner.ApplyAuthProfile(req, profile)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, respBody, nil
}

func testUnrestrictedFileUpload(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile, endpoints []string) []model.Finding {
	findings := make([]model.Finding, 0)

	// Server-side executable payloads (safe, inert content that just identifies itself)
	dangerousFiles := []struct {
		filename    string
		contentType string
		content     string
		label       string
	}{
		{"shell.php", "application/x-php", "<?php echo 'upload-test-php'; ?>", "PHP web shell"},
		{"shell.php5", "application/x-php", "<?php echo 'upload-test-php5'; ?>", "PHP5 web shell"},
		{"shell.phtml", "application/x-php", "<? echo 'upload-test-phtml'; ?>", "phtml web shell"},
		{"shell.jsp", "text/plain", "<% out.print(\"upload-test-jsp\"); %>", "JSP web shell"},
		{"shell.aspx", "text/plain", "<%@ Page Language=\"C#\" %><% Response.Write(\"upload-test-aspx\"); %>", "ASPX web shell"},
		{"shell.svg", "image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"><script>alert('xss')</script></svg>`, "SVG XSS payload"},
		{"shell.html", "text/html", `<script>alert('upload-xss')</script>`, "HTML XSS payload"},
	}

	base := strings.TrimRight(target, "/")
	testEndpoints := append([]string{}, endpoints...)
	if len(testEndpoints) == 0 {
		// No discovered endpoints — still probe the most likely path
		testEndpoints = append(testEndpoints, base+"/upload", base+"/api/upload")
	}

	for _, endpoint := range testEndpoints {
		for _, df := range dangerousFiles {
			for _, field := range uploadFieldNames {
				status, body, err := tryUpload(ctx, client, endpoint, profile, field, df.filename, df.contentType, df.content)
				if err != nil {
					continue
				}
				if isUploadAccepted(status, body) {
					findings = append(findings, model.Finding{
						ID:             "unrestricted-file-upload-" + filepath.Ext(df.filename),
						Category:       "file_upload",
						Severity:       model.SeverityHigh,
						Title:          fmt.Sprintf("Unrestricted file upload accepted: %s (%s)", df.filename, df.label),
						Description:    "The upload endpoint accepted a server-side executable file without restriction. An attacker can upload a web shell and achieve Remote Code Execution on the server.",
						Evidence:       fmt.Sprintf("endpoint=%s field=%s filename=%s content_type=%s status=%d", endpoint, field, df.filename, df.contentType, status),
						Recommendation: "Validate the file extension and MIME type server-side against an allowlist. Store uploaded files outside the web root. Rename files to random UUIDs. Serve files via a dedicated storage service (S3, GCS).",
						AffectedURL:    endpoint,
						OWASPCategory:  "OWASP A03:2021 - Injection",
						CWE:            "CWE-434",
						ReproductionSteps: []string{
							fmt.Sprintf("POST %s with multipart field '%s' containing file '%s'", endpoint, field, df.filename),
							"Server returns HTTP 2xx indicating the file was stored",
							"Access the uploaded file at its returned URL to confirm execution",
						},
					})
					return findings
				}
			}
		}
	}

	return findings
}

func testContentTypeBypass(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile, endpoints []string) []model.Finding {
	findings := make([]model.Finding, 0)

	// Upload a PHP file disguised as an image (MIME type spoofing)
	bypassCases := []struct {
		filename    string
		contentType string // legitimate-looking
		content     string
		label       string
	}{
		{"image.jpg", "image/jpeg", "<?php echo 'content-type-bypass'; ?>", "PHP disguised as JPEG"},
		{"photo.png", "image/png", "<?php echo 'content-type-bypass'; ?>", "PHP disguised as PNG"},
		{"document.pdf", "application/pdf", "<?php echo 'content-type-bypass'; ?>", "PHP disguised as PDF"},
		{"avatar.gif", "image/gif", "<?php echo 'content-type-bypass'; ?>", "PHP disguised as GIF"},
	}

	base := strings.TrimRight(target, "/")
	testEndpoints := append([]string{}, endpoints...)
	if len(testEndpoints) == 0 {
		testEndpoints = append(testEndpoints, base+"/upload", base+"/api/upload")
	}

	for _, endpoint := range testEndpoints {
		for _, bc := range bypassCases {
			for _, field := range uploadFieldNames {
				status, body, err := tryUpload(ctx, client, endpoint, profile, field, bc.filename, bc.contentType, bc.content)
				if err != nil {
					continue
				}
				if isUploadAccepted(status, body) {
					findings = append(findings, model.Finding{
						ID:             "file-upload-content-type-bypass",
						Category:       "file_upload",
						Severity:       model.SeverityHigh,
						Title:          "File upload content-type validation bypass: " + bc.label,
						Description:    "The server accepted an executable file whose Content-Type header was spoofed to appear as a benign file type. Attackers can bypass client-side or header-only validation to upload malicious scripts.",
						Evidence:       fmt.Sprintf("endpoint=%s field=%s filename=%s spoofed_type=%s status=%d", endpoint, field, bc.filename, bc.contentType, status),
						Recommendation: "Validate file contents (magic bytes / file signature) in addition to the Content-Type header and extension. Use a library such as libmagic or a cloud virus scanning API.",
						AffectedURL:    endpoint,
						OWASPCategory:  "OWASP A03:2021 - Injection",
						CWE:            "CWE-434",
					})
					return findings
				}
			}
		}
	}

	return findings
}

func testDoubleExtensionBypass(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile, endpoints []string) []model.Finding {
	findings := make([]model.Finding, 0)

	// Double/null-byte extensions to confuse server-side extension blocklists
	doubleExtCases := []struct {
		filename string
		label    string
	}{
		{"shell.php.jpg", "PHP + JPG double extension"},
		{"shell.php.png", "PHP + PNG double extension"},
		{"shell.php%00.jpg", "PHP + null-byte + JPG"},
		{"shell.pHp", "PHP mixed case"},
		{"shell.PHP", "PHP upper case"},
		{"shell.php.", "PHP trailing dot"},
		{"shell.php ", "PHP trailing space"},
	}

	base := strings.TrimRight(target, "/")
	testEndpoints := append([]string{}, endpoints...)
	if len(testEndpoints) == 0 {
		testEndpoints = append(testEndpoints, base+"/upload", base+"/api/upload")
	}

	for _, endpoint := range testEndpoints {
		for _, dc := range doubleExtCases {
			for _, field := range uploadFieldNames {
				status, body, err := tryUpload(ctx, client, endpoint, profile, field, dc.filename, "image/jpeg", "<?php echo 'double-ext-bypass'; ?>")
				if err != nil {
					continue
				}
				if isUploadAccepted(status, body) {
					findings = append(findings, model.Finding{
						ID:             "file-upload-double-extension-bypass",
						Category:       "file_upload",
						Severity:       model.SeverityHigh,
						Title:          "File upload extension filter bypass: " + dc.label,
						Description:    "The server accepted a file whose name uses a double extension, case variation, or null-byte trick to evade blocklist-based extension validation. If served by a web server configured to execute the dangerous extension, this leads to Remote Code Execution.",
						Evidence:       fmt.Sprintf("endpoint=%s field=%s filename=%q status=%d", endpoint, field, dc.filename, status),
						Recommendation: "Use an allowlist of safe extensions rather than a blocklist. Normalise filenames (lowercase, strip special characters) before validation. Rename uploaded files to random UUIDs without preserving the original extension.",
						AffectedURL:    endpoint,
						OWASPCategory:  "OWASP A03:2021 - Injection",
						CWE:            "CWE-434",
					})
					return findings
				}
			}
		}
	}

	return findings
}

func testPathTraversalInFilename(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile, endpoints []string) []model.Finding {
	findings := make([]model.Finding, 0)

	// Attempt to write outside the intended upload directory via the filename.
	// Success signals Zip Slip-style or path traversal in upload handling.
	traversalFilenames := []struct {
		filename string
		label    string
	}{
		{"../../../tmp/pwned.txt", "Unix path traversal (../../../)"},
		{"..\\..\\..\\windows\\win.ini", "Windows path traversal"},
		{"....//....//....//tmp/pwned.txt", "Dot-slash variant"},
		{"%2e%2e%2f%2e%2e%2ftmp/pwned.txt", "URL-encoded traversal"},
		{"../../../../var/www/html/pwned.php", "Web root traversal"},
	}

	base := strings.TrimRight(target, "/")
	testEndpoints := append([]string{}, endpoints...)
	if len(testEndpoints) == 0 {
		testEndpoints = append(testEndpoints, base+"/upload", base+"/api/upload")
	}

	for _, endpoint := range testEndpoints {
		for _, tf := range traversalFilenames {
			for _, field := range uploadFieldNames {
				status, body, err := tryUpload(ctx, client, endpoint, profile, field, tf.filename, "text/plain", "traversal-test")
				if err != nil {
					continue
				}
				if isUploadAccepted(status, body) {
					// Additional check: see if the traversal file is accessible
					traversedURL := base + "/tmp/pwned.txt"
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, traversedURL, nil)
					traversalConfirmed := false
					if err == nil {
						resp2, err2 := client.Do(req)
						if err2 == nil {
							b2, _ := io.ReadAll(io.LimitReader(resp2.Body, 256))
							resp2.Body.Close()
							traversalConfirmed = strings.Contains(string(b2), "traversal-test")
						}
					}

					sev := model.SeverityMedium
					if traversalConfirmed {
						sev = model.SeverityHigh
					}

					findings = append(findings, model.Finding{
						ID:             "file-upload-path-traversal",
						Category:       "file_upload",
						Severity:       sev,
						Title:          "Path traversal via upload filename: " + tf.label,
						Description:    "The server accepted an upload with a filename containing directory traversal sequences. This may allow writing files to arbitrary locations on the filesystem (Zip Slip / path traversal in upload).",
						Evidence:       fmt.Sprintf("endpoint=%s field=%s filename=%q status=%d confirmed=%v", endpoint, field, tf.filename, status, traversalConfirmed),
						Recommendation: "Strip directory components from uploaded filenames (use filepath.Base or equivalent). Validate the resolved storage path is within the intended upload directory. Consider renaming uploads to random UUIDs.",
						AffectedURL:    endpoint,
						OWASPCategory:  "OWASP A01:2021 - Broken Access Control",
						CWE:            "CWE-22",
						ReproductionSteps: []string{
							fmt.Sprintf("POST %s with filename %q", endpoint, tf.filename),
							"Server returns 2xx indicating the file was written",
							"GET " + traversedURL + " to confirm the file was written outside the upload directory",
						},
					})
					return findings
				}
			}
		}
	}

	return findings
}
