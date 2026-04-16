package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

type CORSRedirectAgent struct {
	enabled bool
}

func NewCORSRedirectAgent(enabled bool) *CORSRedirectAgent {
	return &CORSRedirectAgent{enabled: enabled}
}

func (a *CORSRedirectAgent) Name() string {
	return "cors_redirect"
}

func (a *CORSRedirectAgent) Enabled() bool {
	return a.enabled
}

func (a *CORSRedirectAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow following redirects for testing
			if len(via) < 5 {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	// Test for open redirects
	output.Findings = append(output.Findings, testOpenRedirects(ctx, client, input.Target, input.AuthProfile)...)

	// Test for CORS misconfigurations
	output.Findings = append(output.Findings, testCORSMisconfigurations(ctx, client, input.Target)...)

	// Test for unvalidated redirects
	output.Findings = append(output.Findings, testUnvalidatedRedirects(ctx, client, input.Target, input.AuthProfile)...)

	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.DebugNotes = "CORS and redirect testing completed."
	return output, nil
}

func testOpenRedirects(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	redirectParams := []string{
		"?redirect=",
		"?return=",
		"?url=",
		"?redirect_uri=",
		"?next=",
		"?goto=",
		"?continue=",
		"?back=",
		"?target=",
		"?link=",
	}

	redirectDestinations := []string{
		"http://attacker.com",
		"//attacker.com",
		"attacker.com",
		"https://evil.com",
	}

	for _, param := range redirectParams {
		for _, dest := range redirectDestinations {
			testURL := target + param + url.QueryEscape(dest)

			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			location := resp.Header.Get("Location")
			if location != "" {
				// Check if redirect points to external domain
				if strings.Contains(location, "attacker.com") || strings.Contains(location, "evil.com") {
					findings = append(findings, model.Finding{
						ID:             "open-redirect",
						Category:       "cors_redirect",
						Severity:       model.SeverityMedium,
						Title:          "Open redirect vulnerability detected",
						Description:    "Application redirects to user-controlled URLs without validation.",
						Evidence:       fmt.Sprintf("Redirect parameter: %s → Location: %s", param, location),
						Recommendation: "Never redirect to user-provided URLs. Validate against allowlist of safe destinations.",
					})
					resp.Body.Close()
					return findings
				}
			}
			resp.Body.Close()
		}
	}

	return findings
}

func testCORSMisconfigurations(ctx context.Context, client *http.Client, target string) []model.Finding {
	findings := make([]model.Finding, 0)

	testOrigins := []string{
		"http://attacker.com",
		"http://localhost:8000",
		"http://127.0.0.1:3000",
		"null",
	}

	for _, origin := range testOrigins {
		req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
		allowMethods := resp.Header.Get("Access-Control-Allow-Methods")

		// Wildcard origin
		if allowOrigin == "*" {
			findings = append(findings, model.Finding{
				ID:             "cors-wildcard",
				Category:       "cors_redirect",
				Severity:       model.SeverityMedium,
				Title:          "CORS allows any origin (*)",
				Description:    "The application allows requests from any origin.",
				Evidence:       "Access-Control-Allow-Origin: *",
				Recommendation: "Specify explicit allowed origins. Use allowlist approach.",
			})
		}

		// Credentials with permissive CORS
		if allowCreds == "true" && (allowOrigin == "*" || allowOrigin == "null" || strings.HasPrefix(origin, "http://")) {
			findings = append(findings, model.Finding{
				ID:             "cors-credentials",
				Category:       "cors_redirect",
				Severity:       model.SeverityHigh,
				Title:          "CORS allows credentials with permissive origin",
				Description:    "CORS configuration allows credentials to be sent to potentially untrusted origins.",
				Evidence:       fmt.Sprintf("Access-Control-Allow-Origin: %s with Credentials: true", allowOrigin),
				Recommendation: "Never allow credentials with non-secure CORS configurations.",
			})
		}

		// Wildcard in methods with credentials
		if allowMethods == "*" && allowCreds == "true" {
			findings = append(findings, model.Finding{
				ID:             "cors-wildcard-methods",
				Category:       "cors_redirect",
				Severity:       model.SeverityMedium,
				Title:          "CORS allows all HTTP methods with credentials",
				Description:    "Application allows any HTTP method with credential support.",
				Evidence:       "Access-Control-Allow-Methods: * with Credentials: true",
				Recommendation: "Explicitly list allowed methods. Restrict dangerous methods (DELETE, PUT).",
			})
		}

		resp.Body.Close()
	}

	return findings
}

func testUnvalidatedRedirects(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Test relative redirect bypass
	relativeRedirects := []string{
		"?next=/admin",
		"?redirect=/admin/panel",
		"?url=/../admin",
		"?goto=//internal-site.local",
	}

	for _, redirect := range relativeRedirects {
		testURL := target + redirect

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		req.Header.Set("User-Agent", "SecurityScanner")
		scanner.ApplyAuthProfile(req, profile)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		location := resp.Header.Get("Location")

		// Check if redirect is to admin/restricted paths
		if location != "" && (strings.Contains(location, "admin") || strings.Contains(location, "..")) {
			findings = append(findings, model.Finding{
				ID:             "unvalidated-redirect",
				Category:       "cors_redirect",
				Severity:       model.SeverityMedium,
				Title:          "Unvalidated redirect to restricted path",
				Description:    "Application may redirect to paths it shouldn't without validation.",
				Evidence:       fmt.Sprintf("Parameter: %s → Location: %s", redirect, location),
				Recommendation: "Validate redirect destinations. Use relative paths where possible. Never redirect based on raw user input.",
			})
		}

		resp.Body.Close()
	}

	return findings
}
