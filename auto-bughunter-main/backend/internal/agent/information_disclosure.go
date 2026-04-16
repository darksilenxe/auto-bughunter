package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

type InformationDisclosureAgent struct {
	enabled bool
}

func NewInformationDisclosureAgent(enabled bool) *InformationDisclosureAgent {
	return &InformationDisclosureAgent{enabled: enabled}
}

func (a *InformationDisclosureAgent) Name() string {
	return "information_disclosure"
}

func (a *InformationDisclosureAgent) Enabled() bool {
	return a.enabled
}

func (a *InformationDisclosureAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Test for sensitive headers
	output.Findings = append(output.Findings, testSensitiveHeaders(ctx, client, input.Target, input.AuthProfile)...)

	// Test for stack traces and debug information
	output.Findings = append(output.Findings, testDebugInformation(ctx, client, input.Target, input.AuthProfile)...)

	// Test for sensitive files and paths
	output.Findings = append(output.Findings, testSensitiveFiles(ctx, client, input.Target, input.AuthProfile)...)

	// Test for API key/token leakage
	output.Findings = append(output.Findings, testAPIKeyExposure(ctx, client, input.Target, input.AuthProfile)...)

	// Test for internal IP exposure
	output.Findings = append(output.Findings, testInternalIPExposure(ctx, client, input.Target, input.AuthProfile)...)

	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.DebugNotes = "Information disclosure testing completed."
	return output, nil
}

func testSensitiveHeaders(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	scanner.ApplyAuthProfile(req, profile)
	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	sensitiveHeaders := map[string]string{
		"Server":            "Reveals server software version information",
		"X-Powered-By":      "Reveals technology stack (PHP, ASP.NET, etc.)",
		"X-AspNet-Version":  "Discloses ASP.NET version",
		"X-Runtime-Version": "Discloses runtime version",
		"Via":               "May reveal proxy software versions",
		"X-DEBUG-TOKEN":     "Debug mode enabled",
		"X-DEBUG":           "Debug mode enabled",
		"X-DEV-SERVER":      "Development server exposed",
	}

	for header, risk := range sensitiveHeaders {
		if value := resp.Header.Get(header); value != "" {
			severity := model.SeverityMedium
			if strings.Contains(header, "DEBUG") || strings.Contains(header, "DEV") {
				severity = model.SeverityHigh
			}

			findings = append(findings, model.Finding{
				ID:             "info-disclose-header-" + strings.ToLower(strings.ReplaceAll(header, "-", "_")),
				Category:       "information_disclosure",
				Severity:       severity,
				Title:          "Sensitive information in response header: " + header,
				Description:    risk,
				Evidence:       header + ": " + value,
				Recommendation: "Remove or anonymize version-revealing headers. Set X-E-VENDOR-HIDE or custom values.",
			})
		}
	}

	return findings
}

func testDebugInformation(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	scanner.ApplyAuthProfile(req, profile)
	resp, err := client.Do(req)
	if err != nil {
		return findings
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	respStr := string(body)

	debugPatterns := map[string]string{
		`(at|File|line)\s+\d+`:      "Stack trace detected",
		`Exception|Error|Traceback`: "Exception details exposed",
		`<pre>.*?</pre>`:            "HTML pre-formatted debug output",
		`DEBUG\s*=\s*(True|true|1)`: "Debug mode enabled",
		`__pycache__|\.pyc|\.pyo`:   "Python debug artifacts",
		`npm debug|node debug`:      "Node.js debug information",
	}

	for pattern, desc := range debugPatterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(respStr) {
			findings = append(findings, model.Finding{
				ID:             "debug-info-" + strings.ReplaceAll(strings.ToLower(desc), " ", "_"),
				Category:       "information_disclosure",
				Severity:       model.SeverityMedium,
				Title:          "Debug information exposed: " + desc,
				Description:    "Application reveals debug/stack trace information in responses.",
				Evidence:       "Pattern: " + pattern,
				Recommendation: "Disable debug mode in production. Handle exceptions gracefully. Return generic error messages.",
			})
		}
	}

	return findings
}

func testSensitiveFiles(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	sensitiveFiles := []string{
		".env", ".env.local", ".env.*.local",
		".git", ".gitconfig", ".gitlab-ci.yml",
		"composer.json", "package.json", "Gemfile", "requirements.txt",
		"web.config", ".htaccess", ".htpasswd",
		"config.php", "config.rb", "settings.py",
		".aws/credentials", ".ssh/id_rsa", ".ssh/id_rsa.pub",
		"backup.sql", "backup.zip", "dump.sql",
		"debug.log", "error.log", "access.log",
		".well-known/openid-configuration",
		"/admin", "/admin.php", "/administrator",
		"/api/docs", "/api/v1/docs", "/swagger.json", "/openapi.json",
	}

	for _, file := range sensitiveFiles {
		testURLStr := target
		if !strings.HasSuffix(testURLStr, "/") && !strings.HasPrefix(file, ".") {
			testURLStr += "/"
		}
		testURLStr += file

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURLStr, nil)
		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			respStr := string(body)
			if len(respStr) > 50 { // Likely actual file, not 404 page
				findings = append(findings, model.Finding{
					ID:             "sensitive-file-" + strings.ReplaceAll(strings.ToLower(file), "/", "_"),
					Category:       "information_disclosure",
					Severity:       model.SeverityHigh,
					Title:          "Sensitive file accessible: " + file,
					Description:    "A sensitive file was found accessible on the web server.",
					Evidence:       "HTTP 200: " + testURLStr,
					Recommendation: "Restrict access to sensitive files. Use web server configuration to block download.",
				})
			}
		} else {
			resp.Body.Close()
		}
	}

	return findings
}

func testAPIKeyExposure(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	scanner.ApplyAuthProfile(req, profile)
	resp, err := client.Do(req)
	if err != nil {
		return findings
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	respStr := string(body)

	// Patterns for API keys, tokens, secrets
	secretPatterns := map[string]string{
		`[Aa]pi[_-]?[Kk]ey\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}`: "API key exposure",
		`[Pp]assword\s*[:=]\s*['\"]?[^'\"]{6,}`:             "Password exposure",
		`[Tt]oken\s*[:=]\s*['\"]?[a-zA-Z0-9._\-]{20,}`:      "Auth token exposure",
		`[Ss]ecret\s*[:=]\s*['\"]?[^'\"]{10,}`:              "Secret key exposure",
		`sk_live_[a-zA-Z0-9]{20,}`:                          "Stripe API key",
		`aws_access_key_id\s*[:=]`:                          "AWS credentials",
	}

	for pattern, desc := range secretPatterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(respStr) {
			findings = append(findings, model.Finding{
				ID:             "secret-exposure-" + strings.ReplaceAll(strings.ToLower(desc), " ", "_"),
				Category:       "information_disclosure",
				Severity:       model.SeverityHigh,
				Title:          "Potential secret/credential exposure: " + desc,
				Description:    "Application may be exposing sensitive credentials or API keys in responses.",
				Evidence:       "Pattern matched: " + pattern,
				Recommendation: "Never commit secrets to code. Use environment variables or secret management systems. Scan code for secrets.",
			})
		}
	}

	return findings
}

func testInternalIPExposure(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	scanner.ApplyAuthProfile(req, profile)
	resp, err := client.Do(req)
	if err != nil {
		return findings
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	respStr := string(body)

	// Internal IP patterns
	internalIPPatterns := map[string]string{
		`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`:  "Internal IPv4 (10.0.0.0/8)",
		`\b192\.168\.\d{1,3}\.\d{1,3}\b`:     "Internal IPv4 (192.168.0.0/16)",
		`\b172\.1[6-9]\.\d{1,3}\.\d{1,3}\b`:  "Internal IPv4 (172.16.0.0/12)",
		`\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`: "Localhost reference",
		`\bfd[0-9a-f]{2}:[\da-f:]+\b`:        "Internal IPv6",
	}

	for pattern, desc := range internalIPPatterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(respStr) {
			findings = append(findings, model.Finding{
				ID:             "internal-ip-" + strings.ReplaceAll(strings.ToLower(desc), " ", "_"),
				Category:       "information_disclosure",
				Severity:       model.SeverityMedium,
				Title:          "Internal IP address disclosed: " + desc,
				Description:    "Application inadvertently reveals internal IP addresses in responses.",
				Evidence:       "Pattern: " + pattern,
				Recommendation: "Sanitize all user-facing output. Remove internal IPs from error messages and logs visible to users.",
			})
		}
	}

	return findings
}
