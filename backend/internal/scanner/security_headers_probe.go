package scanner

import (
	"fmt"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// runSecurityHeadersProbe is a passive probe that inspects the baseline HTTP
// response for missing or misconfigured security-relevant response headers and
// cookie attributes that the existing inline checks in scanner.go do not cover:
//
//   - Strict-Transport-Security (HSTS) — absence or missing preload/includeSubDomains
//   - Permissions-Policy — absence allows full access to browser APIs
//   - SameSite cookie attribute — missing SameSite risks cross-site request forgery
//
// The probe is intentionally passive: it requires zero additional HTTP requests
// and operates solely on the headers and cookies already present in the baseline
// response passed by the caller.
func (s *Service) runSecurityHeadersProbe(input RunInput, respHeader http.Header, resp *http.Response) []model.Finding {
	RecordProbedKey(http.MethodGet, input.Target, "")
	var findings []model.Finding

	// ── HSTS ──────────────────────────────────────────────────────────────────
	hsts := strings.TrimSpace(respHeader.Get("Strict-Transport-Security"))
	if hsts == "" {
		findings = append(findings, model.Finding{
			ID:          "missing-hsts",
			Category:    "headers",
			Severity:    model.SeverityMedium,
			Title:       "Missing Strict-Transport-Security header",
			Description: "The response does not include a Strict-Transport-Security (HSTS) header. Without HSTS, browsers may silently downgrade HTTPS connections to HTTP, enabling network-level interception (SSL stripping) by an active attacker on the same network.",
			Evidence:    "Strict-Transport-Security header absent from response",
			Recommendation: "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to all HTTPS responses. " +
				"Ensure all HTTP traffic is redirected to HTTPS before enabling HSTS.",
			Confidence:    0.90,
			AffectedURL:   input.Target,
			CWE:           "CWE-319",
			OWASPCategory: "A02:2021 - Cryptographic Failures",
			Sources:       []string{"passive-scanner", "security-headers"},
			ReproductionSteps: []string{
				fmt.Sprintf("GET %s", input.Target),
				"Inspect the response headers.",
				"Confirm that Strict-Transport-Security is absent.",
			},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      fmt.Sprintf("GET %s and inspect response headers", input.Target),
			},
		})
	} else {
		lower := strings.ToLower(hsts)
		if !strings.Contains(lower, "includesubdomains") {
			findings = append(findings, model.Finding{
				ID:          "hsts-missing-includesubdomains",
				Category:    "headers",
				Severity:    model.SeverityLow,
				Title:       "HSTS missing includeSubDomains directive",
				Description: "The Strict-Transport-Security header is present but does not include the 'includeSubDomains' directive. Subdomains are not covered by HSTS and remain vulnerable to SSL-stripping attacks.",
				Evidence:    fmt.Sprintf("Strict-Transport-Security: %s", hsts),
				Recommendation: "Add the 'includeSubDomains' directive to the HSTS header: " +
					"'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'.",
				Confidence:    0.85,
				AffectedURL:   input.Target,
				CWE:           "CWE-319",
				OWASPCategory: "A02:2021 - Cryptographic Failures",
				Sources:       []string{"passive-scanner", "security-headers"},
				EvidenceFields: map[string]string{
					"validationType": "safe-observation",
					"headerValue":    hsts,
				},
			})
		}
		if !strings.Contains(lower, "preload") {
			findings = append(findings, model.Finding{
				ID:          "hsts-missing-preload",
				Category:    "headers",
				Severity:    model.SeverityInfo,
				Title:       "HSTS missing preload directive",
				Description: "The Strict-Transport-Security header does not include the 'preload' directive. Without preload, users who visit the site for the first time over HTTP are not protected. Adding 'preload' and submitting to the HSTS preload list ensures browsers enforce HTTPS before the first connection.",
				Evidence:    fmt.Sprintf("Strict-Transport-Security: %s", hsts),
				Recommendation: "Add the 'preload' directive and submit your domain to https://hstspreload.org/. " +
					"Ensure 'includeSubDomains' is also set before requesting preload listing.",
				Confidence:    0.80,
				AffectedURL:   input.Target,
				CWE:           "CWE-319",
				OWASPCategory: "A02:2021 - Cryptographic Failures",
				Sources:       []string{"passive-scanner", "security-headers"},
				EvidenceFields: map[string]string{
					"validationType": "safe-observation",
					"headerValue":    hsts,
				},
			})
		}
	}

	// ── Permissions-Policy ────────────────────────────────────────────────────
	pp := strings.TrimSpace(respHeader.Get("Permissions-Policy"))
	if pp == "" {
		findings = append(findings, model.Finding{
			ID:          "missing-permissions-policy",
			Category:    "headers",
			Severity:    model.SeverityLow,
			Title:       "Missing Permissions-Policy header",
			Description: "The response does not include a Permissions-Policy header (formerly Feature-Policy). Without this header, the page retains full access to powerful browser APIs — including geolocation, camera, microphone, and payment — which embedded third-party scripts can abuse.",
			Evidence:    "Permissions-Policy header absent from response",
			Recommendation: "Define a restrictive Permissions-Policy header, e.g. " +
				"'Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()'. " +
				"Only grant permissions to origins that legitimately require them.",
			Confidence:    0.80,
			AffectedURL:   input.Target,
			CWE:           "CWE-693",
			OWASPCategory: "A05:2021 - Security Misconfiguration",
			Sources:       []string{"passive-scanner", "security-headers"},
			ReproductionSteps: []string{
				fmt.Sprintf("GET %s", input.Target),
				"Inspect the response headers.",
				"Confirm that Permissions-Policy is absent.",
			},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      fmt.Sprintf("GET %s and inspect response headers", input.Target),
			},
		})
	}

	// ── SameSite cookie attribute ─────────────────────────────────────────────
	if resp != nil {
		for _, c := range resp.Cookies() {
			sameSite := cookieSameSite(resp.Header, c.Name)
			if sameSite == "" {
				findings = append(findings, model.Finding{
					ID:          "cookie-samesite-" + c.Name,
					Category:    "cookies",
					Severity:    model.SeverityMedium,
					Title:       fmt.Sprintf("Cookie %q missing SameSite attribute", c.Name),
					Description: fmt.Sprintf("The cookie %q is set without a SameSite attribute. Without SameSite, the browser sends this cookie on cross-site requests, enabling cross-site request forgery (CSRF) attacks against authenticated users.", c.Name),
					Evidence:    fmt.Sprintf("Set-Cookie: %s — SameSite not set", c.Name),
					Recommendation: "Set SameSite=Strict for session cookies or SameSite=Lax as a minimum. " +
						"Avoid SameSite=None unless the cookie genuinely requires cross-site embedding, and only combine it with Secure.",
					Confidence:    0.85,
					AffectedURL:   input.Target,
					CWE:           "CWE-1275",
					OWASPCategory: "A01:2021 - Broken Access Control",
					Sources:       []string{"passive-scanner", "security-headers"},
					EvidenceFields: map[string]string{
						"validationType": "safe-observation",
						"cookieName":     c.Name,
						"reproStep":      fmt.Sprintf("GET %s and inspect Set-Cookie headers", input.Target),
					},
				})
			} else if strings.EqualFold(sameSite, "none") && !c.Secure {
				findings = append(findings, model.Finding{
					ID:          "cookie-samesite-none-insecure-" + c.Name,
					Category:    "cookies",
					Severity:    model.SeverityMedium,
					Title:       fmt.Sprintf("Cookie %q has SameSite=None without Secure flag", c.Name),
					Description: fmt.Sprintf("The cookie %q is set with SameSite=None but without the Secure flag. Modern browsers reject SameSite=None cookies that are not also marked Secure, and the combination removes cross-site request forgery protections on HTTPS endpoints.", c.Name),
					Evidence:    fmt.Sprintf("Set-Cookie: %s; SameSite=None (Secure absent)", c.Name),
					Recommendation: "Either add the Secure flag alongside SameSite=None, or use SameSite=Lax/Strict " +
						"if cross-site access is not required.",
					Confidence:    0.90,
					AffectedURL:   input.Target,
					CWE:           "CWE-1275",
					OWASPCategory: "A01:2021 - Broken Access Control",
					Sources:       []string{"passive-scanner", "security-headers"},
					EvidenceFields: map[string]string{
						"validationType": "safe-observation",
						"cookieName":     c.Name,
						"sameSite":       sameSite,
					},
				})
			}
		}
	}

	return findings
}

// cookieSameSite extracts the SameSite attribute value for the named cookie
// directly from the raw Set-Cookie header lines, because Go's http.Cookie
// struct does not expose SameSite as a string until after parsing.
func cookieSameSite(h http.Header, cookieName string) string {
	for _, raw := range h["Set-Cookie"] {
		if !strings.HasPrefix(raw, cookieName+"=") && !strings.HasPrefix(raw, cookieName+";") {
			// Rough name match — check if the name appears before the first semicolon/equals.
			nameEnd := strings.IndexByte(raw, '=')
			if nameEnd < 0 {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(raw[:nameEnd]), cookieName) {
				continue
			}
		}
		lower := strings.ToLower(raw)
		idx := strings.Index(lower, "samesite=")
		if idx < 0 {
			return ""
		}
		rest := raw[idx+len("samesite="):]
		end := strings.IndexAny(rest, "; \t")
		if end >= 0 {
			return rest[:end]
		}
		return rest
	}
	return ""
}
