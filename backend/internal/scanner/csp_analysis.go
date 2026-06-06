package scanner

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
)

var cspMetaTagPattern = regexp.MustCompile(`(?is)<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]+content=["']([^"']+)["']`)

func (s *Service) runCSPAnalysisProbe(input RunInput, respHeader http.Header, bodyText string) []model.Finding {
	csp := strings.TrimSpace(respHeader.Get("Content-Security-Policy"))
	if csp == "" {
		if match := cspMetaTagPattern.FindStringSubmatch(bodyText); len(match) > 1 {
			csp = strings.TrimSpace(match[1])
		}
	}
	if csp == "" {
		return nil
	}

	directives := parseCSPDirectives(csp)
	scriptSources, hasScript := directives["script-src"]
	defaultSources, hasDefault := directives["default-src"]
	combined := append([]string{}, scriptSources...)
	combined = append(combined, defaultSources...)

	var findings []model.Finding
	if cspContainsSource(scriptSources, "'unsafe-inline'") || (!hasScript && cspContainsSource(defaultSources, "'unsafe-inline'")) {
		findings = append(findings, cspFinding(input.Target, "csp-bypass-unsafe-inline", model.SeverityHigh, "CSP permits unsafe inline scripts", "The CSP allows 'unsafe-inline' in script execution sources, enabling inline script execution and weakening XSS protections.", csp))
	}
	if cspContainsSource(scriptSources, "'unsafe-eval'") || (!hasScript && cspContainsSource(defaultSources, "'unsafe-eval'")) {
		findings = append(findings, cspFinding(input.Target, "csp-bypass-unsafe-eval", model.SeverityHigh, "CSP permits unsafe script evaluation", "The CSP allows 'unsafe-eval', enabling dynamic code execution primitives such as eval() and Function(), which materially weakens script-execution controls.", csp))
	}
	if cspContainsSource(combined, "*") {
		findings = append(findings, cspFinding(input.Target, "csp-bypass-wildcard", model.SeverityHigh, "CSP allows wildcard script sources", "The CSP includes a wildcard source in script-src or default-src, allowing scripts to load from arbitrary origins and making CSP bypass substantially easier.", csp))
	}
	if !hasDefault && !hasScript {
		findings = append(findings, cspFinding(input.Target, "csp-missing-script-src", model.SeverityMedium, "CSP omits script restrictions", "The CSP is present but does not define default-src or script-src, leaving script execution insufficiently constrained.", csp))
	}
	for _, source := range combined {
		lower := strings.ToLower(source)
		if strings.Contains(lower, "cdn.jsdelivr.net") || strings.Contains(lower, "rawgit.com") || strings.Contains(lower, "cdnjs.cloudflare.com") || strings.Contains(lower, "unpkg.com") {
			findings = append(findings, cspFinding(input.Target, "csp-bypass-cdn", model.SeverityMedium, "CSP trusts user-content CDN domains", "The CSP trusts a CDN domain commonly abused for user-controlled or easily publishable content, which can provide a practical CSP bypass path.", csp))
			break
		}
	}
	return findings
}

func parseCSPDirectives(csp string) map[string][]string {
	directives := make(map[string][]string)
	for _, rawDirective := range strings.Split(csp, ";") {
		fields := strings.Fields(strings.TrimSpace(rawDirective))
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		if len(fields) > 1 {
			directives[key] = append(directives[key], fields[1:]...)
		} else {
			directives[key] = nil
		}
	}
	return directives
}

func cspContainsSource(sources []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, source := range sources {
		if strings.ToLower(strings.TrimSpace(source)) == needle {
			return true
		}
	}
	return false
}

func cspFinding(target, id string, severity model.Severity, title, description, csp string) model.Finding {
	return model.Finding{
		ID:             id,
		Category:       "headers",
		Severity:       severity,
		Title:          title,
		Description:    description,
		Evidence:       fmt.Sprintf("Content-Security-Policy: %s", csp),
		Recommendation: "Restrict script execution with explicit allowlists, remove unsafe-inline/unsafe-eval, avoid wildcard sources, and prefer self-hosted scripts where possible.",
		Confidence:     0.9,
		AffectedURL:    target,
		CWE:            "CWE-693",
		OWASPCategory:  "A05:2021 - Security Misconfiguration",
		Sources:        []string{"header-analysis"},
		EvidenceFields: map[string]string{
			"validationType": "safe-observation",
			"csp":            csp,
		},
	}
}
