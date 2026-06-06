package scanner

import (
	"fmt"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
)

func (s *Service) runClickjackingProbe(input RunInput, respHeader http.Header) []model.Finding {
	if respHeader == nil {
		return nil
	}
	xfo := strings.ToUpper(strings.TrimSpace(respHeader.Get("X-Frame-Options")))
	if xfo == "DENY" || xfo == "SAMEORIGIN" {
		return nil
	}
	if clickjackingProtectedByCSP(respHeader.Get("Content-Security-Policy")) {
		return nil
	}
	poc := fmt.Sprintf(`<html><body><iframe src="%s" width="1200" height="900" style="opacity:0.01;position:absolute;top:0;left:0;border:0"></iframe></body></html>`, input.Target)
	return []model.Finding{{
		ID:             "clickjacking-missing-protection",
		Category:       "clickjacking",
		Severity:       model.SeverityMedium,
		Title:          "Clickjacking protection headers are missing",
		Description:    "The response does not enforce X-Frame-Options or a restrictive CSP frame-ancestors directive, so an attacker can embed the page in a transparent iframe and trick victims into clicking sensitive UI elements.",
		Evidence:       fmt.Sprintf("X-Frame-Options=%q; Content-Security-Policy=%q", respHeader.Get("X-Frame-Options"), respHeader.Get("Content-Security-Policy")),
		Recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN and enforce Content-Security-Policy: frame-ancestors 'none' or 'self' on all sensitive pages.",
		Confidence:     0.94,
		AffectedURL:    input.Target,
		CWE:            "CWE-1021",
		OWASPCategory:  "A05:2021 - Security Misconfiguration",
		Sources:        []string{"header-analysis"},
		ReproductionSteps: []string{
			fmt.Sprintf("Load %s in an attacker-controlled iframe.", input.Target),
			"Verify the browser renders the page instead of blocking framing.",
			"Overlay decoy controls to demonstrate UI redress risk.",
		},
		PoC: poc,
		EvidenceFields: map[string]string{
			"validationType": "safe-observation",
			"xFrameOptions":  respHeader.Get("X-Frame-Options"),
			"csp":            respHeader.Get("Content-Security-Policy"),
		},
	}}
}

func clickjackingProtectedByCSP(csp string) bool {
	if strings.TrimSpace(csp) == "" {
		return false
	}
	directives := parseCSPDirectives(csp)
	for _, source := range directives["frame-ancestors"] {
		normalized := strings.ToLower(strings.TrimSpace(source))
		if normalized == "'none'" || normalized == "'self'" {
			return true
		}
	}
	return false
}
