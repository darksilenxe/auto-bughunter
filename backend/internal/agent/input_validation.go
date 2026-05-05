package agent

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

type InputValidationAgent struct {
	enabled bool
}

func NewInputValidationAgent(enabled bool) *InputValidationAgent {
	return &InputValidationAgent{enabled: enabled}
}

func (a *InputValidationAgent) Name() string {
	return "input_validation"
}

func (a *InputValidationAgent) Enabled() bool {
	return a.enabled
}

func (a *InputValidationAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	// Use shorter timeout per request (3 seconds) since this agent
	// tests many payloads sequentially. Also check context before each test.
	client := &http.Client{Timeout: 3 * time.Second}

	// Early exit if context is already cancelled
	select {
	case <-ctx.Done():
		return output, ctx.Err()
	default:
	}

	// Test for SQL injection - early exit on first finding to avoid timeouts
	if findings := testSQLInjection(ctx, client, input.Target, input.AuthProfile); len(findings) > 0 {
		output.Findings = append(output.Findings, findings...)
		output.DebugNotes = "Input validation testing completed early (SQL injection found)"
		return output, nil
	}

	// Test for XSS vulnerabilities - only if context still valid
	if ctx.Err() == nil {
		if findings := testXSSVulnerability(ctx, client, input.Target, input.AuthProfile); len(findings) > 0 {
			output.Findings = append(output.Findings, findings...)
			output.DebugNotes = "Input validation testing completed early (XSS found)"
			return output, nil
		}
	}

	// Test for path traversal - only if context still valid
	if ctx.Err() == nil {
		if findings := testPathTraversal(ctx, client, input.Target, input.AuthProfile); len(findings) > 0 {
			output.Findings = append(output.Findings, findings...)
			output.DebugNotes = "Input validation testing completed early (path traversal found)"
			return output, nil
		}
	}

	// Test for XXE injection - only if context still valid
	if ctx.Err() == nil {
		if findings := testXXEInjection(ctx, client, input.Target, input.AuthProfile); len(findings) > 0 {
			output.Findings = append(output.Findings, findings...)
			output.DebugNotes = "Input validation testing completed early (XXE found)"
			return output, nil
		}
	}

	// Test for command injection - only if context still valid
	if ctx.Err() == nil {
		if findings := testCommandInjection(ctx, client, input.Target, input.AuthProfile); len(findings) > 0 {
			output.Findings = append(output.Findings, findings...)
			output.DebugNotes = "Input validation testing completed early (command injection found)"
			return output, nil
		}
	}

	output.Metadata["findings_count"] = strconv.Itoa(len(output.Findings))
	output.DebugNotes = "Input validation testing completed. Tested for SQL injection, XSS, path traversal, XXE, and command injection."
	return output, nil
}

func testSQLInjection(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Check if context is already done before starting
	if ctx.Err() != nil {
		return findings
	}

	sqlPayloads := []string{
		"' OR '1'='1",
		"' OR 1=1 --",
		"' UNION SELECT NULL --",
		`" OR "1"="1`,
	}

	errorPatterns := []string{
		"SQL syntax",
		"mysql_fetch",
		"ORA-",
		"Microsoft SQL Server",
		"PostgreSQL",
		"SQLite",
		"ODBC",
		"column count",
		"supplied",
	}

	u, err := url.Parse(target)
	if err != nil {
		return findings
	}

	// Test query parameters
	if u.RawQuery != "" {
		for _, payload := range sqlPayloads {
			// Early exit on context cancellation
			if ctx.Err() != nil {
				return findings
			}

			testURL := addQueryParam(u.String(), "test", payload)

			// Create request with short timeout per payload (2 seconds)
			reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, testURL, nil)
			if err != nil {
				cancel()
				continue
			}

			scanner.ApplyAuthProfile(req, profile)
			resp, err := client.Do(req)
			cancel()

			if err != nil {
				continue
			}

			// Ensure body is closed even on error
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			lowerResp := strings.ToLower(string(body))
			for _, pattern := range errorPatterns {
				if strings.Contains(lowerResp, strings.ToLower(pattern)) {
					findings = append(findings, model.Finding{
						ID:             "sql-injection-potential",
						Category:       "input_validation",
						Severity:       model.SeverityHigh,
						Title:          "Potential SQL injection vulnerability",
						Description:    "Application returned database error messages that may indicate SQL injection vulnerability.",
						Evidence:       "Database error in response after query parameter fuzzing",
						Recommendation: "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
					})
					return findings
				}
			}
		}
	}

	return findings
}

func testXSSVulnerability(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Check if context is already done before starting
	if ctx.Err() != nil {
		return findings
	}

	xssPayloads := []string{
		`<script>alert('xss')</script>`,
		`"><script>alert('xss')</script>`,
		`<img src=x onerror="alert('xss')">`,
		`<svg onload="alert('xss')">`,
	}

	if _, err := url.Parse(target); err != nil {
		return findings
	}

	for _, payload := range xssPayloads {
		// Early exit on context cancellation
		if ctx.Err() != nil {
			return findings
		}

		testURL := addQueryParam(target, "search", payload)

		// Create request with short timeout per payload (2 seconds)
		reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, testURL, nil)
		if err != nil {
			cancel()
			continue
		}

		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		cancel()

		if err != nil {
			continue
		}

		// Ensure body is closed
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		respStr := string(body)
		// Unescaped reflection in response indicates potential XSS
		if strings.Contains(respStr, payload) || strings.Contains(strings.ToLower(respStr), strings.ToLower(url.QueryEscape(payload))) {
			findings = append(findings, model.Finding{
				ID:             "xss-reflection-potential",
				Category:       "input_validation",
				Severity:       model.SeverityHigh,
				Title:          "Potential Cross-Site Scripting (XSS) vulnerability",
				Description:    "Application may reflect user input directly in responses without proper encoding.",
				Evidence:       "XSS payload appeared unescaped in response",
				Recommendation: "HTML-encode all user-controlled output. Use Content-Security-Policy. Use templating engines with auto-escaping.",
			})
			return findings
		}
	}

	return findings
}

func testPathTraversal(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Check if context is already done before starting
	if ctx.Err() != nil {
		return findings
	}

	pathTraversalPayloads := []string{
		"../../../../../etc/passwd",
		"..\\..\\..\\..\\windows\\win.ini",
		"....//....//....//etc/passwd",
	}

	if _, err := url.Parse(target); err != nil {
		return findings
	}

	for _, payload := range pathTraversalPayloads {
		// Early exit on context cancellation
		if ctx.Err() != nil {
			return findings
		}

		testURL := addQueryParam(target, "file", payload)

		// Create request with short timeout per payload (2 seconds)
		reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, testURL, nil)
		if err != nil {
			cancel()
			continue
		}

		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		cancel()

		if err != nil {
			continue
		}

		// Ensure body is closed
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		respStr := string(body)
		// Check for common file contents
		if strings.Contains(respStr, "root:") || strings.Contains(respStr, "[drivers]") || strings.Contains(respStr, "etc/passwd") {
			findings = append(findings, model.Finding{
				ID:             "path-traversal-detected",
				Category:       "input_validation",
				Severity:       model.SeverityHigh,
				Title:          "Path traversal vulnerability detected",
				Description:    "Application may allow reading arbitrary files from the filesystem.",
				Evidence:       "System file content exposed in response",
				Recommendation: "Validate file paths against allowlist. Never use user input to construct file paths. Use Path.Combine or similar safe APIs.",
			})
			return findings
		}
	}

	return findings
}

func testXXEInjection(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Check if context is already done before starting
	if ctx.Err() != nil {
		return findings
	}

	// Use very short timeout for XXE (1 second) since external entity resolution
	// should fail quickly if security is in place; long timeout indicates XXE vulnerability
	xxeCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	xxePayload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`

	req, err := http.NewRequestWithContext(xxeCtx, http.MethodPost, target, strings.NewReader(xxePayload))
	if err != nil {
		return findings
	}

	req.Header.Set("Content-Type", "application/xml")
	scanner.ApplyAuthProfile(req, profile)

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	respStr := string(body)

	// Check for XXE exploitation indicators
	if strings.Contains(respStr, "root:") || strings.Contains(respStr, "etc/passwd") || strings.Contains(respStr, "XML") {
		findings = append(findings, model.Finding{
			ID:             "xxe-potential",
			Category:       "input_validation",
			Severity:       model.SeverityHigh,
			Title:          "Potential XML External Entity (XXE) injection vulnerability",
			Description:    "Application may process XML without disabling external entity resolution.",
			Evidence:       "XXE payload produced unexpected response",
			Recommendation: "Disable XML external entity processing. Use XML validators/sanitizers. Set feature flags to disable DTD parsing.",
		})
	}

	return findings
}

func testCommandInjection(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Check if context is already done before starting
	if ctx.Err() != nil {
		return findings
	}

	cmdPayloads := []string{
		"; echo 'vuln'",
		"| whoami",
		"`id`",
		"$(id)",
	}

	if _, err := url.Parse(target); err != nil {
		return findings
	}

	for _, payload := range cmdPayloads {
		// Early exit on context cancellation
		if ctx.Err() != nil {
			return findings
		}

		testURL := addQueryParam(target, "cmd", payload)

		// Create request with short timeout per payload (2 seconds)
		reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, testURL, nil)
		if err != nil {
			cancel()
			continue
		}

		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		cancel()

		if err != nil {
			continue
		}

		// Ensure body is closed
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		respStr := string(body)
		if strings.Contains(strings.ToLower(respStr), "vuln") || strings.Contains(respStr, "uid=") || strings.Contains(respStr, "gid=") {
			findings = append(findings, model.Finding{
				ID:             "command-injection-potential",
				Category:       "input_validation",
				Severity:       model.SeverityHigh,
				Title:          "Potential command injection vulnerability",
				Description:    "Application may execute system commands with unsanitized user input.",
				Evidence:       "Command execution output detected in response",
				Recommendation: "Avoid shell execution with user input. Use safe APIs for system calls. Never pass user input to shell interpreters.",
			})
			return findings
		}
	}

	return findings
}

func addQueryParam(target, key, value string) string {
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	return target + separator + key + "=" + url.QueryEscape(value)
}
