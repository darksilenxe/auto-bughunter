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

type AccessControlAgent struct {
	enabled bool
}

func NewAccessControlAgent(enabled bool) *AccessControlAgent {
	return &AccessControlAgent{enabled: enabled}
}

func (a *AccessControlAgent) Name() string {
	return "access_control"
}

func (a *AccessControlAgent) Enabled() bool {
	return a.enabled
}

// accessControlChecks is the canonical ordered list of checks this agent
// performs. An AI advisor may reorder or skip entries based on scan context.
var accessControlChecks = []string{
	"idor",
	"weak_auth",
	"default_creds",
	"admin_panel",
	"priv_escalation",
}

func (a *AccessControlAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// If an AgentAdvisor pre-run hook wrote advice to the blackboard, use it
	// to reorder or skip checks. When no advice is present the default order
	// (idor → weak_auth → default_creds → admin_panel → priv_escalation) is
	// preserved exactly.
	advice := ParseAdviceNote(input.SharedScanContext.GetNote(a.Name()))
	ordered := OrderChecks(advice, accessControlChecks)

	type checkFn func() []model.Finding
	checkMap := map[string]checkFn{
		"idor":           func() []model.Finding { return testIDOR(ctx, client, input.Target, input.AuthProfile) },
		"weak_auth":      func() []model.Finding { return testWeakAuthentication(ctx, client, input.Target) },
		"default_creds":  func() []model.Finding { return testDefaultCredentials(ctx, client, input.Target) },
		"admin_panel":    func() []model.Finding { return testAdminPanelExposure(ctx, client, input.Target) },
		"priv_escalation": func() []model.Finding {
			return testPrivilegeEscalation(ctx, client, input.Target, input.AuthProfile)
		},
	}

	for _, check := range ordered {
		if ctx.Err() != nil {
			break
		}
		if fn, ok := checkMap[check]; ok {
			output.Findings = append(output.Findings, fn()...)
		}
	}

	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.DebugNotes = "Access control testing completed. Checked: " + strings.Join(ordered, ", ") + "."
	return output, nil
}

func testIDOR(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Test common IDOR patterns
	idorPatterns := []string{
		"?id=1",
		"?user_id=1",
		"?profile_id=1",
		"?order_id=1",
		"?account_id=1",
		"?resource_id=1",
		"/user/1",
		"/profile/1",
		"/order/1",
		"/account/1",
	}

	baseURLs := []string{
		target,
		target + "/api",
		target + "/api/v1",
	}

	for _, baseURL := range baseURLs {
		for _, pattern := range idorPatterns {
			testURL := baseURL
			if !strings.HasSuffix(testURL, "/") && strings.HasPrefix(pattern, "/") {
				testURL += pattern
			} else if strings.HasSuffix(testURL, "/") && strings.HasPrefix(pattern, "/") {
				testURL += pattern[1:]
			} else if !strings.HasSuffix(testURL, "/") && !strings.HasPrefix(pattern, "/") && !strings.HasPrefix(pattern, "?") {
				testURL += "/" + pattern
			} else {
				testURL += pattern
			}

			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
			scanner.ApplyAuthProfile(req, profile)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				respStr := string(body)
				if len(respStr) > 200 { // Likely real data, not 404 page

					// Check for ID parameter tampering possibility
					if strings.Contains(testURL, "=") {
						// Try changing the ID
						newURL := testURL
						idParam := regexp.MustCompile(`(=)(\d+)`)
						newURL = idParam.ReplaceAllString(newURL, "${1}999")

						req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, newURL, nil)
						scanner.ApplyAuthProfile(req2, profile)
						resp2, err := client.Do(req2)
						if err == nil {
							if resp2.StatusCode == http.StatusOK {
								body2, _ := io.ReadAll(resp2.Body)
								resp2.Body.Close()
								if len(body2) > 100 {
									findings = append(findings, model.Finding{
										ID:             "idor-potential",
										Category:       "access_control",
										Severity:       model.SeverityHigh,
										Title:          "Insecure Direct Object Reference (IDOR) vulnerability",
										Description:    "Application may allow accessing other users' resources by tampering with ID parameters.",
										Evidence:       fmt.Sprintf("Different IDs return data without validation: %s vs %s", testURL, newURL),
										Recommendation: "Verify authorization on all resource access. Don't rely on client-provided IDs. Use UUIDs instead of sequential IDs.",
									})
									return findings
								}
							} else {
								// Close the body for non-OK responses so we
								// don't leak the connection.
								_, _ = io.Copy(io.Discard, resp2.Body)
								resp2.Body.Close()
							}
						}
					}
				}
			}
			resp.Body.Close()
		}
	}

	return findings
}

func testWeakAuthentication(ctx context.Context, client *http.Client, target string) []model.Finding {
	findings := make([]model.Finding, 0)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(req)
	if err != nil {
		return findings
	}

	// Check for Basic Auth endpoints
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth != "" && strings.Contains(strings.ToLower(wwwAuth), "basic") {
		findings = append(findings, model.Finding{
			ID:             "weak-auth-basic",
			Category:       "access_control",
			Severity:       model.SeverityMedium,
			Title:          "Basic authentication detected",
			Description:    "Application uses HTTP Basic Authentication which transmits credentials in Base64 (easily reversible).",
			Evidence:       "WWW-Authenticate: " + wwwAuth,
			Recommendation: "Use HTTP Bearer tokens or OAuth 2.0. Basic auth should only be used over HTTPS with strong credentials.",
		})
	}

	// Check for missing auth headers in response
	if resp.Header.Get("Authorization") != "" || resp.Header.Get("Set-Cookie") != "" {
		// Application sends auth info - check if it's secure
		setCookie := resp.Header.Get("Set-Cookie")
		if setCookie != "" && !strings.Contains(setCookie, "Secure") {
			findings = append(findings, model.Finding{
				ID:             "weak-auth-cookie",
				Category:       "access_control",
				Severity:       model.SeverityHigh,
				Title:          "Weak session cookie security",
				Description:    "Session cookies are not properly secured (missing Secure, HttpOnly, or SameSite flags).",
				Evidence:       "Set-Cookie: " + setCookie,
				Recommendation: "Always set Secure, HttpOnly, and SameSite=Strict on session cookies.",
			})
		}
	}

	resp.Body.Close()
	return findings
}

func testDefaultCredentials(ctx context.Context, client *http.Client, target string) []model.Finding {
	findings := make([]model.Finding, 0)

	defaultCreds := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "12345"},
		{"admin", "123456"},
		{"root", "root"},
		{"root", "password"},
		{"test", "test"},
		{"user", "user"},
		{"guest", "guest"},
	}

	loginPaths := []string{
		"/admin/login",
		"/login",
		"/authenticate",
		"/api/login",
		"/api/auth/login",
	}

	for _, path := range loginPaths {
		testURL := target
		if !strings.HasSuffix(testURL, "/") {
			testURL += "/"
		}
		testURL += strings.TrimPrefix(path, "/")

		for _, cred := range defaultCreds {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
			req.SetBasicAuth(cred.username, cred.password)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusOK {
				findings = append(findings, model.Finding{
					ID:             "default-credentials",
					Category:       "access_control",
					Severity:       model.SeverityHigh,
					Title:          "Default credentials accepted",
					Description:    fmt.Sprintf("Application accepted default credentials %s:%s", cred.username, cred.password),
					Evidence:       fmt.Sprintf("HTTP 200 at %s with basic auth", testURL),
					Recommendation: "Change all default credentials immediately. Enforce strong password policies.",
				})
				resp.Body.Close()
				return findings
			}
			resp.Body.Close()
		}
	}

	return findings
}

func testAdminPanelExposure(ctx context.Context, client *http.Client, target string) []model.Finding {
	findings := make([]model.Finding, 0)

	adminPaths := []string{
		"/admin",
		"/admin/",
		"/administration",
		"/administrator",
		"/admin-panel",
		"/adminpanel",
		"/console",
		"/management",
		"/manager",
		"/backend",
		"/dashboard",
		"/cpanel",
		"/control",
		"/master",
		"/system",
		"/tools",
	}

	for _, path := range adminPaths {
		testURL := target
		if !strings.HasSuffix(testURL, "/") {
			testURL += "/"
		}
		testURL += strings.TrimPrefix(path, "/")

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		severity := model.SeverityMedium
		if resp.StatusCode == http.StatusOK {
			severity = model.SeverityHigh
		}

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusTemporaryRedirect {
			findings = append(findings, model.Finding{
				ID:             "admin-panel-exposed-" + strings.ReplaceAll(strings.ToLower(path), "/", "_"),
				Category:       "access_control",
				Severity:       severity,
				Title:          "Admin panel potentially accessible: " + path,
				Description:    "An admin/management panel path returned a non-404 response.",
				Evidence:       fmt.Sprintf("HTTP %d at %s", resp.StatusCode, testURL),
				Recommendation: "Restrict admin panels to authorized IPs/networks. Use strong authentication. Don't use predictable paths.",
			})
		}
		resp.Body.Close()
	}

	return findings
}

func testPrivilegeEscalation(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	escalationTests := []string{
		"?role=admin",
		"?admin=true",
		"?user_type=superadmin",
		"?is_admin=1",
	}

	for _, test := range escalationTests {
		testURL := target + test

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			respStr := string(body)
			// Check if response contains admin-level content
			if strings.Contains(strings.ToLower(respStr), "admin") || strings.Contains(strings.ToLower(respStr), "manage") {
				findings = append(findings, model.Finding{
					ID:             "privilege-escalation-potential",
					Category:       "access_control",
					Severity:       model.SeverityHigh,
					Title:          "Potential privilege escalation via parameter injection",
					Description:    "Application may allow role/privilege escalation through URL/form parameters.",
					Evidence:       fmt.Sprintf("Parameter %s produced privilege escalation response", test),
					Recommendation: "Never trust client-provided role/privilege information. Verify authorization server-side with session/token.",
				})
				return findings
			}
		} else {
			resp.Body.Close()
		}
	}

	return findings
}
