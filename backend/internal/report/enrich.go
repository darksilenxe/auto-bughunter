// Package report contains report generation primitives (PDF, Markdown, HTML)
// for pen-test, executive, and bug-bounty deliverables.
//
// The renderers in this package read from model.ScanJob (and individual
// model.Finding values) and never touch HTTP or persistence directly. This
// keeps templates pure and unit-testable.
package report

import (
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// categoryProfile is a deterministic mapping from a finding category to the
// CWE / OWASP Top-10 / impact / references metadata that is required for a
// professional pen-test or bug-bounty report. It is used to fill in fields
// that the underlying scanners do not already provide.
type categoryProfile struct {
	CWE        string
	OWASP      string
	CVSSVector string
	CVSSScore  float64
	Impact     string
	References []string
}

// categoryProfiles is the deterministic enrichment table. Keys are
// lowercase category names that match values produced by scanners across
// the codebase (see the various model.Finding constructions in
// backend/internal/scanner, sqlmap, nikto, wpscan, agent, ml).
var categoryProfiles = map[string]categoryProfile{
	"injection": {
		CWE:        "CWE-89",
		OWASP:      "A03:2021 - Injection",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		Impact:     "An attacker can read, modify, or destroy database contents and may achieve remote code execution depending on the database engine configuration.",
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/89.html",
		},
	},
	"xss": {
		CWE:        "CWE-79",
		OWASP:      "A03:2021 - Injection",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		CVSSScore:  6.1,
		Impact:     "An attacker can execute arbitrary JavaScript in the context of another user's browser session, leading to session hijacking, credential theft, or arbitrary actions performed as the victim.",
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/79.html",
		},
	},
	"access_control": {
		CWE:        "CWE-284",
		OWASP:      "A01:2021 - Broken Access Control",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		CVSSScore:  8.1,
		Impact:     "Authenticated or unauthenticated users can access functionality or data they are not authorized for, allowing privilege escalation or data exfiltration.",
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/284.html",
		},
	},
	"information_disclosure": {
		CWE:        "CWE-200",
		OWASP:      "A01:2021 - Broken Access Control",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		CVSSScore:  5.3,
		Impact:     "Sensitive data is exposed to unauthorized actors, providing reconnaissance value or directly leaking secrets, configuration, or PII.",
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/200.html",
		},
	},
	"misconfiguration": {
		CWE:        "CWE-16",
		OWASP:      "A05:2021 - Security Misconfiguration",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
		CVSSScore:  5.4,
		Impact:     "Insecure defaults or missing hardening expose the application to a broader attack surface than necessary.",
		References: []string{
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
			"https://cwe.mitre.org/data/definitions/16.html",
		},
	},
	"tls": {
		CWE:        "CWE-326",
		OWASP:      "A02:2021 - Cryptographic Failures",
		CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
		CVSSScore:  4.8,
		Impact:     "Weak TLS configuration may allow an active network attacker to downgrade, intercept, or tamper with traffic.",
		References: []string{
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
			"https://cwe.mitre.org/data/definitions/326.html",
		},
	},
	"cors": {
		CWE:        "CWE-942",
		OWASP:      "A05:2021 - Security Misconfiguration",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
		CVSSScore:  5.4,
		Impact:     "Permissive CORS allows malicious origins to read authenticated responses from the application.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing",
			"https://cwe.mitre.org/data/definitions/942.html",
		},
	},
	"redirect": {
		CWE:        "CWE-601",
		OWASP:      "A01:2021 - Broken Access Control",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
		CVSSScore:  4.3,
		Impact:     "An attacker can trick users into visiting a malicious destination via a trusted application URL, enabling phishing.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/601.html",
		},
	},
	"api": {
		CWE:        "CWE-1059",
		OWASP:      "API1:2023 - Broken Object Level Authorization",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
		CVSSScore:  6.5,
		Impact:     "API endpoints expose data or functionality without sufficient authorization checks.",
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
		},
	},
}

// reproductionTemplates returns a deterministic, category-based list of
// reproduction steps when none have been generated by an AI agent.
func reproductionTemplates(category string) []string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "injection":
		return []string{
			"Identify the vulnerable parameter listed in the finding evidence.",
			"Send an HTTP request that injects a SQL meta-character (e.g. `'`) into that parameter.",
			"Observe a database error in the response or a content/timing difference vs. the baseline.",
			"Confirm exploitability by extracting a known value (e.g. `' OR '1'='1`).",
		}
	case "xss":
		return []string{
			"Locate the input field or URL parameter referenced in the evidence.",
			"Submit the payload `<script>alert(1)</script>` (or attribute-context equivalent).",
			"Open the rendered response in a browser and confirm the script executes.",
		}
	case "access_control":
		return []string{
			"Authenticate as a low-privilege user (or no user).",
			"Issue a request to the protected resource referenced in the evidence.",
			"Observe that the response succeeds without the expected authorization check.",
		}
	case "information_disclosure":
		return []string{
			"Issue an unauthenticated GET request to the affected URL.",
			"Inspect the response body and headers for the sensitive data referenced in the evidence.",
		}
	case "tls":
		return []string{
			"Run `openssl s_client -connect <host>:443` against the target.",
			"Inspect the negotiated cipher and protocol version for the weakness referenced in the evidence.",
		}
	case "cors":
		return []string{
			"Send a request including `Origin: https://attacker.example`.",
			"Inspect the `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` response headers.",
		}
	case "redirect":
		return []string{
			"Construct a URL that supplies an attacker-controlled value to the redirect parameter.",
			"Open the URL and confirm the browser navigates to the attacker-controlled destination.",
		}
	case "misconfiguration", "api":
		return []string{
			"Reproduce the request shown in the finding evidence using `curl` or an HTTP client.",
			"Compare the observed behavior against the documented secure configuration.",
		}
	}
	return nil
}

// EnrichFinding fills in CVSS / CWE / OWASP / Impact / References /
// ReproductionSteps fields for a finding when they are not already populated.
// It never overwrites values that are already present, so any data supplied
// by a scanner or AI agent takes precedence.
func EnrichFinding(f model.Finding) model.Finding {
	profile, ok := categoryProfiles[strings.ToLower(strings.TrimSpace(f.Category))]
	if ok {
		if f.CWE == "" {
			f.CWE = profile.CWE
		}
		if f.OWASPCategory == "" {
			f.OWASPCategory = profile.OWASP
		}
		if f.CVSSVector == "" {
			f.CVSSVector = profile.CVSSVector
		}
		if f.CVSSScore == 0 {
			f.CVSSScore = profile.CVSSScore
		}
		if f.Impact == "" {
			f.Impact = profile.Impact
		}
		if len(f.References) == 0 && len(profile.References) > 0 {
			refs := make([]string, len(profile.References))
			copy(refs, profile.References)
			sort.Strings(refs)
			f.References = refs
		}
	}
	if len(f.ReproductionSteps) == 0 {
		f.ReproductionSteps = reproductionTemplates(f.Category)
	}
	return f
}

// EnrichFindings returns a copy of the findings slice with enrichment applied
// to each entry.
func EnrichFindings(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return findings
	}
	out := make([]model.Finding, len(findings))
	for i, f := range findings {
		out[i] = EnrichFinding(f)
	}
	return out
}
