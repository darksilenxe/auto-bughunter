package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

type APISecurityAgent struct {
	enabled bool
}

func NewAPISecurityAgent(enabled bool) *APISecurityAgent {
	return &APISecurityAgent{enabled: enabled}
}

func (a *APISecurityAgent) Name() string {
	return "api_security"
}

func (a *APISecurityAgent) Enabled() bool {
	return a.enabled
}

func (a *APISecurityAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Test for GraphQL introspection
	output.Findings = append(output.Findings, testGraphQLIntrospection(ctx, client, input.Target, input.AuthProfile)...)

	// Test for API rate limiting
	output.Findings = append(output.Findings, testRateLimitingAbsence(ctx, client, input.Target)...)

	// Test for CORS misconfigurations
	output.Findings = append(output.Findings, testCORSMisconfiguration(ctx, client, input.Target)...)

	// Test for API versioning issues
	output.Findings = append(output.Findings, testAPIVersioning(ctx, client, input.Target, input.AuthProfile)...)

	// Test for resource exposure
	output.Findings = append(output.Findings, testResourceExposure(ctx, client, input.Target, input.AuthProfile)...)

	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.DebugNotes = "API security testing completed."
	return output, nil
}

func testGraphQLIntrospection(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Common GraphQL endpoints
	graphqlEndpoints := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/v2/graphql",
		"/graphql/",
	}

	introspectionQuery := `{"query":"{ __schema { types { name } } }"}`

	for _, endpoint := range graphqlEndpoints {
		testURL := target
		if !strings.HasSuffix(testURL, "/") {
			testURL += "/"
		}
		testURL += strings.TrimPrefix(endpoint, "/")

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, testURL, strings.NewReader(introspectionQuery))
		req.Header.Set("Content-Type", "application/json")
		scanner.ApplyAuthProfile(req, profile)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			respStr := string(body)
			if strings.Contains(respStr, "__schema") || strings.Contains(respStr, "types") {
				findings = append(findings, model.Finding{
					ID:             "graphql-introspection-enabled",
					Category:       "api_security",
					Severity:       model.SeverityMedium,
					Title:          "GraphQL introspection enabled",
					Description:    "GraphQL endpoint allows introspection queries, exposing API schema and available queries/mutations.",
					Evidence:       "Introspection query successful at " + testURL,
					Recommendation: "Disable GraphQL introspection in production. Restrict introspection queries with middleware or AuthN.",
				})
				return findings
			}
		}
		resp.Body.Close()
	}

	return findings
}

func testRateLimitingAbsence(ctx context.Context, client *http.Client, target string) []model.Finding {
	findings := make([]model.Finding, 0)

	// Send rapid requests to test rate limiting
	requestCount := 50
	var successCount int

	for i := 0; i < requestCount; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, err := client.Do(req)
		if err != nil {
			break
		}

		// 429 = Too Many Requests (rate limited)
		// 503 = Service Unavailable (rate limited)
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
			successCount++
		}
		resp.Body.Close()
	}

	// If more than 80% of requests succeeded, likely no rate limiting
	if float64(successCount)/float64(requestCount) > 0.8 {
		findings = append(findings, model.Finding{
			ID:             "rate-limiting-absent",
			Category:       "api_security",
			Severity:       model.SeverityMedium,
			Title:          "Rate limiting not enforced",
			Description:    "Application does not appear to implement rate limiting on requests.",
			Evidence:       fmt.Sprintf("%d/%d requests succeeded", successCount, requestCount),
			Recommendation: "Implement rate limiting using tokens, sliding windows, or throttling. Common: 100 req/min per IP.",
		})
	}

	return findings
}

func testCORSMisconfiguration(ctx context.Context, client *http.Client, target string) []model.Finding {
	findings := make([]model.Finding, 0)

	req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
	req.Header.Set("Origin", "http://attacker.com")

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")

	// Check for permissive CORS
	if allowOrigin == "*" {
		findings = append(findings, model.Finding{
			ID:             "cors-wildcard-origin",
			Category:       "api_security",
			Severity:       model.SeverityMedium,
			Title:          "CORS allows all origins (*)",
			Description:    "Access-Control-Allow-Origin header is set to *, allowing any domain to make cross-origin requests.",
			Evidence:       "Access-Control-Allow-Origin: *",
			Recommendation: "Specify explicit allowed origins. Never use * with credentials.",
		})
	}

	if allowOrigin != "" && allowCreds == "true" && (allowOrigin == "*" || !isValidOrigin(allowOrigin)) {
		findings = append(findings, model.Finding{
			ID:             "cors-credential-leak",
			Category:       "api_security",
			Severity:       model.SeverityHigh,
			Title:          "CORS misconfiguration may allow credential theft",
			Description:    "Application allows credentials with permissive CORS settings.",
			Evidence:       "Access-Control-Allow-Credentials: true with permissive origin policy",
			Recommendation: "Never set Allow-Credentials with wildcard origins or overly permissive rules.",
		})
	}

	return findings
}

func testAPIVersioning(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	apiVersions := []string{"/api/v0", "/api/v1", "/api/v2", "/v1/", "/v2/", "/v3/"}

	foundVersions := make([]string, 0)
	for _, version := range apiVersions {
		testURL := target
		if strings.HasSuffix(testURL, "/") {
			testURL += strings.TrimPrefix(version, "/")
		} else {
			testURL += version
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode < 400 {
			foundVersions = append(foundVersions, version)
		}
		resp.Body.Close()
	}

	if len(foundVersions) > 1 {
		findings = append(findings, model.Finding{
			ID:             "multiple-api-versions",
			Category:       "api_security",
			Severity:       model.SeverityLow,
			Title:          "Multiple API versions accessible",
			Description:    "Multiple versions of the API are accessible, potentially allowing version downgrade attacks.",
			Evidence:       fmt.Sprintf("Versions found: %v", foundVersions),
			Recommendation: "Maintain only supported API versions. Deprecate old versions with clear timelines.",
		})
	}

	return findings
}

func testResourceExposure(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Common API resource patterns that may expose sensitive data
	resources := []string{
		"/api/users",
		"/api/v1/users",
		"/api/employees",
		"/api/products",
		"/api/customers",
		"/api/settings",
		"/api/config",
		"/api/admin",
	}

	for _, resource := range resources {
		testURL := target
		if !strings.HasSuffix(testURL, "/") {
			testURL += "/"
		}
		testURL += strings.TrimPrefix(resource, "/")

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		scanner.ApplyAuthProfile(req, profile)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var jsonData interface{}
			if err := json.Unmarshal(body, &jsonData); err == nil {
				// Successfully parsed as JSON - likely a real API endpoint
				bodyStr := string(body)
				if len(bodyStr) > 100 {
					findings = append(findings, model.Finding{
						ID:             "resource-exposure-" + strings.ReplaceAll(strings.ToLower(resource), "/", "_"),
						Category:       "api_security",
						Severity:       model.SeverityMedium,
						Title:          "Unauthenticated resource exposure: " + resource,
						Description:    "API endpoint returns data without apparent authentication checks.",
						Evidence:       "HTTP 200 with JSON response at " + testURL,
						Recommendation: "Implement proper authentication/authorization. Return 401/403 for unauthorized access.",
					})
				}
			}
		} else {
			resp.Body.Close()
		}
	}

	return findings
}

func isValidOrigin(origin string) bool {
	// Check if origin looks legitimate (not wildcard, not attacker domain)
	if origin == "*" || strings.Contains(origin, "attacker") {
		return false
	}
	return strings.HasPrefix(origin, "http://") || strings.HasPrefix(origin, "https://")
}
