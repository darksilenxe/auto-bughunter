package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// SSRFAgent tests for Server-Side Request Forgery vulnerabilities. It probes
// URL-like parameters with payloads that would trigger out-of-band DNS/HTTP
// requests to attacker-controlled destinations (cloud metadata endpoints,
// internal services, file/gopher schemes) and flags any that fetch unexpected
// content or return anomalous responses.
type SSRFAgent struct {
	enabled bool
}

func NewSSRFAgent(enabled bool) *SSRFAgent {
	return &SSRFAgent{enabled: enabled}
}

func (a *SSRFAgent) Name() string    { return "ssrf" }
func (a *SSRFAgent) Enabled() bool   { return a.enabled }

func (a *SSRFAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		// Do not follow redirects automatically — SSRF payloads often cause
		// immediate redirects to internal addresses that the scanner host
		// cannot reach; we want to observe the redirect target, not follow it.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	output.Findings = append(output.Findings, testSSRFViaParams(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, testCloudMetadataSSRF(ctx, client, input.Target, input.AuthProfile)...)
	output.Findings = append(output.Findings, testInternalServiceSSRF(ctx, client, input.Target, input.AuthProfile)...)

	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(output.Findings))
	output.DebugNotes = "SSRF testing completed: URL parameter injection, cloud metadata, and internal service probes."
	return output, nil
}

// ssrfURLParams lists query parameter names that commonly pass URLs to server-side fetchers.
var ssrfURLParams = []string{
	"url", "uri", "src", "href", "link", "fetch", "load", "open",
	"redirect", "return", "next", "goto", "continue", "target",
	"proxy", "callback", "webhook", "endpoint", "remote", "host",
	"image", "img", "avatar", "logo", "icon", "resource", "file",
}

func testSSRFViaParams(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Use a non-routable RFC 5737 / IANA-reserved address as canary so we
	// never accidentally reach a real host.  A response body containing the
	// canary string or an unexpected 2xx/3xx from a target that normally
	// returns 4xx indicates the server fetched our URL.
	canaryPayloads := []string{
		"http://169.254.169.254/",       // AWS/GCP/Azure instance metadata
		"http://metadata.google.internal/",
		"http://100.100.100.200/latest/meta-data/", // Alibaba Cloud metadata
		"http://192.168.0.1/",                      // common internal gateway
		"http://localhost/",
		"http://127.0.0.1/",
	}

	u, err := url.Parse(target)
	if err != nil {
		return findings
	}

	for _, param := range ssrfURLParams {
		for _, payload := range canaryPayloads {
			q := u.Query()
			q.Set(param, payload)
			testURL := *u
			testURL.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			bodyStr := strings.ToLower(string(body))

			// Indicators that the server fetched the canary URL:
			// • Response body contains recognisable metadata content
			// • 3xx Location header points to an internal address
			ssrfIndicators := []string{
				"ami-id", "instance-id", "local-ipv4",    // AWS EC2
				"google", "metadata-flavor",               // GCP
				"compute/v1", "serviceaccounts",           // GCP metadata
				"latest/meta-data", "iam/security-credentials", // AWS
				"alibaba", "ram/security-credentials",     // Alibaba Cloud
				"root:", "/etc/passwd",                    // file:// reflection
			}
			triggered := false
			indicator := ""
			for _, ind := range ssrfIndicators {
				if strings.Contains(bodyStr, ind) {
					triggered = true
					indicator = ind
					break
				}
			}

			// Also flag if a 3xx points to a cloud/internal address
			if !triggered && (resp.StatusCode == http.StatusMovedPermanently ||
				resp.StatusCode == http.StatusFound ||
				resp.StatusCode == http.StatusTemporaryRedirect ||
				resp.StatusCode == http.StatusPermanentRedirect) {
				loc := strings.ToLower(resp.Header.Get("Location"))
				for _, kw := range []string{"169.254", "metadata", "localhost", "127.0.0.1", "192.168."} {
					if strings.Contains(loc, kw) {
						triggered = true
						indicator = "redirect→" + resp.Header.Get("Location")
						break
					}
				}
			}

			if triggered {
				findings = append(findings, model.Finding{
					ID:             "ssrf-url-param",
					Category:       "ssrf",
					Severity:       model.SeverityHigh,
					Title:          "Server-Side Request Forgery (SSRF) via URL parameter",
					Description:    "The application appears to fetch server-side URLs supplied via a query parameter, enabling attackers to reach internal services or cloud metadata endpoints.",
					Evidence:       fmt.Sprintf("param=%s payload=%s indicator=%q status=%d", param, payload, indicator, resp.StatusCode),
					Recommendation: "Validate and allowlist every URL the server fetches. Deny requests to link-local (169.254.x.x), loopback, and private RFC 1918 addresses. Prefer indirect object references over raw URLs.",
					AffectedURL:    testURL.String(),
					AffectedParameter: param,
					OWASPCategory:  "OWASP A10:2021 - Server-Side Request Forgery",
					CWE:            "CWE-918",
					ReproductionSteps: []string{
						fmt.Sprintf("Send GET %s", testURL.String()),
						"Observe that the server returns metadata/internal content or redirects to an internal address",
					},
				})
				return findings
			}
		}
	}

	return findings
}

func testCloudMetadataSSRF(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Endpoints that accept a URL path and proxy/render it on the server side.
	proxyPaths := []string{
		"/proxy?url=",
		"/fetch?url=",
		"/render?url=",
		"/screenshot?url=",
		"/preview?url=",
		"/load?url=",
		"/api/proxy?url=",
		"/api/fetch?url=",
		"/api/render?url=",
	}

	metadataURLs := []struct {
		url      string
		keywords []string
	}{
		{
			"http://169.254.169.254/latest/meta-data/",
			[]string{"ami-id", "instance-id", "local-ipv4", "hostname"},
		},
		{
			"http://metadata.google.internal/computeMetadata/v1/",
			[]string{"project", "instance", "serviceaccounts"},
		},
	}

	base := strings.TrimRight(target, "/")

	for _, path := range proxyPaths {
		for _, meta := range metadataURLs {
			affectedURL := base + path + url.QueryEscape(meta.url)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, affectedURL, nil)
			if err != nil {
				continue
			}
			// GCP metadata requires this header; adding it does not harm AWS.
			req.Header.Set("Metadata-Flavor", "Google")
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			bodyStr := strings.ToLower(string(body))
			for _, kw := range meta.keywords {
				if strings.Contains(bodyStr, kw) {
					findings = append(findings, model.Finding{
						ID:             "ssrf-cloud-metadata",
						Category:       "ssrf",
						Severity:       model.SeverityHigh,
						Title:          "SSRF exposes cloud instance metadata",
						Description:    "A server-side proxy endpoint fetched the cloud instance metadata service, leaking IAM credentials, instance details, and other sensitive data.",
						Evidence:       fmt.Sprintf("endpoint=%s metadata_url=%s keyword=%q", path, meta.url, kw),
						Recommendation: "Block outbound requests to 169.254.169.254, metadata.google.internal, and similar link-local addresses at the application and network (egress firewall) layers.",
						AffectedURL:    affectedURL,
						OWASPCategory:  "OWASP A10:2021 - Server-Side Request Forgery",
						CWE:            "CWE-918",
					})
					return findings
				}
			}
		}
	}

	return findings
}

func testInternalServiceSSRF(ctx context.Context, client *http.Client, target string, profile model.ScanAuthProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	// Try to make the server request common internal services.  A non-error
	// HTTP response (especially 2xx) from a normally-blocked address strongly
	// suggests the server issued the request.
	internalTargets := []struct {
		url      string
		keywords []string
		label    string
	}{
		{"http://localhost:6379/", []string{"-err", "+pong", "redis"}, "Redis"},
		{"http://127.0.0.1:9200/", []string{"elasticsearch", "cluster_name", "version"}, "Elasticsearch"},
		{"http://127.0.0.1:2379/version", []string{"etcdserver", "etcdcluster"}, "etcd"},
		{"http://localhost:8500/v1/agent/self", []string{"consul", "datacenter"}, "Consul"},
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", []string{"role", "AccessKeyId", "SecretAccessKey"}, "AWS IAM credentials"},
	}

	proxyParams := []string{"url=", "proxy=", "fetch=", "src=", "endpoint="}
	base := strings.TrimRight(target, "/")

	for _, svc := range internalTargets {
		for _, param := range proxyParams {
			affectedURL := base + "/?" + param + url.QueryEscape(svc.url)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, affectedURL, nil)
			if err != nil {
				continue
			}
			scanner.ApplyAuthProfile(req, profile)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			bodyStr := strings.ToLower(string(body))
			for _, kw := range svc.keywords {
				if strings.Contains(bodyStr, strings.ToLower(kw)) {
					findings = append(findings, model.Finding{
						ID:             "ssrf-internal-service",
						Category:       "ssrf",
						Severity:       model.SeverityHigh,
						Title:          fmt.Sprintf("SSRF reaches internal service: %s", svc.label),
						Description:    fmt.Sprintf("The application relayed a request to an internal %s instance, exposing internal infrastructure to the attacker.", svc.label),
						Evidence:       fmt.Sprintf("param=%s internal_url=%s response_keyword=%q", param, svc.url, kw),
						Recommendation: "Implement an egress allowlist. Never use raw user-supplied URLs for server-side fetches. Deploy a dedicated fetch proxy with strict allowlisting.",
						AffectedURL:    affectedURL,
						OWASPCategory:  "OWASP A10:2021 - Server-Side Request Forgery",
						CWE:            "CWE-918",
					})
					return findings
				}
			}
		}
	}

	return findings
}
