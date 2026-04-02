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

	client := &http.Client{Timeout: 10 * time.Second}

	// Test for SQL injection
	output.Findings = append(output.Findings, testSQLInjection(ctx, client, input.Target, input.AuthProfile)...)

	// Test for XSS vulnerabilities
	output.Findings = append(output.Findings, testXSSVulnerability(ctx, client, input.Target, input.AuthProfile)...)

	// Test for path traversal
	output.Findings = append(output.Findings, testPathTraversal(ctx, client, input.Target, input.AuthProfile)...)

	// Test for XXE injection
	output.Findings = append(output.Findings, testXXEInjection(ctx, client, input.Target, input.AuthProfile)...)

	// Test for command injection
	output.Findings = append(output.Findings, testCommandInjection(ctx, client, input.Target, input.AuthProfile)...)

	output.Metadata["findings_count"] = strconv.Itoa(len(output.Findings))
	output.DebugNotes = "Input validation testing completed. Tested for SQL injection, XSS, path traversal, XXE, and command injection."
	return output, nil
}

func testSQLInjection(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	sqlPayloads := []string{
		"' OR '1'='1",
		"' OR 1=1 --",
		"' UNION SELECT NULL --",
		`" OR "1"="1`,
		"1' AND SLEEP(5) --",
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
			testURL := addQueryParam(u.String(), "test", payload)

			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
			scanner.ApplyAuthProfile(req, profile)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}

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

	xssPayloads := []string{
		`<script>alert('xss')</script>`,
		`"><script>alert('xss')</script>`,
		`<img src=x onerror="alert('xss')">`,
		`<svg onload="alert('xss')">`,
		`javascript:alert('xss')`,
	}

	if _, err := url.Parse(target); err != nil {
		return findings
	}

	detectedXSS := false
	for _, payload := range xssPayloads {
		testURL := addQueryParam(target, "search", payload)

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		respStr := string(body)
		// Unescaped reflection in response indicates potential XSS
		if strings.Contains(respStr, payload) || strings.Contains(strings.ToLower(respStr), strings.ToLower(url.QueryEscape(payload))) {
			detectedXSS = true
			break
		}
	}

	if detectedXSS {
		findings = append(findings, model.Finding{
			ID:             "xss-reflection-potential",
			Category:       "input_validation",
			Severity:       model.SeverityHigh,
			Title:          "Potential Cross-Site Scripting (XSS) vulnerability",
			Description:    "Application may reflect user input directly in responses without proper encoding.",
			Evidence:       "XSS payload appeared unescaped in response",
			Recommendation: "HTML-encode all user-controlled output. Use Content-Security-Policy. Use templating engines with auto-escaping.",
		})
	}

	return findings
}

func testPathTraversal(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	pathTraversalPayloads := []string{
		"../../../../../etc/passwd",
		"..\\..\\..\\..\\windows\\win.ini",
		"....//....//....//etc/passwd",
		"..%252F..%252F..%252Fetc%252Fpasswd",
	}

	if _, err := url.Parse(target); err != nil {
		return findings
	}

	for _, payload := range pathTraversalPayloads {
		testURL := addQueryParam(target, "file", payload)

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

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

	xxePayload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(xxePayload))
	req.Header.Set("Content-Type", "application/xml")
	scanner.ApplyAuthProfile(req, profile)

	xxeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req = req.WithContext(xxeCtx)
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

	cmdPayloads := []string{
		"; echo 'vuln'",
		"| whoami",
		"`id`",
		"$(id)",
		"& dir &",
	}

	if _, err := url.Parse(target); err != nil {
		return findings
	}

	for _, payload := range cmdPayloads {
		testURL := addQueryParam(target, "cmd", payload)

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

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
