package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
)

func (s *Service) runClickjackingProbe(input RunInput, respHeader http.Header) []model.Finding {
	if respHeader == nil {
		return nil
	}
	// Phase 2 coverage accounting: record this probe key so the
	// surface-gap detector subtracts it from the inventory. Clickjacking
	// is a header-only observation, so there is no per-parameter key.
	RecordProbedKey(http.MethodGet, input.Target, "")
	// Clickjacking only applies to pages that are rendered as HTML by the
	// browser. JSON/XML API responses used by SPAs cannot be embedded in a
	// meaningful iframe — skip them to avoid false positives on API endpoints
	// that are legitimately missing X-Frame-Options.
	if !IsHTMLShape(respHeader) {
		return nil
	}
	xfo := strings.ToUpper(strings.TrimSpace(respHeader.Get("X-Frame-Options")))
	if xfo == "DENY" || xfo == "SAMEORIGIN" {
		return nil
	}
	if clickjackingProtectedByCSP(respHeader.Get("Content-Security-Policy")) {
		return nil
	}
	baselineSummary := ""
	if s != nil {
		control, summary, err := s.clickjackingFramingControl(context.Background(), input)
		if err == nil {
			baselineSummary = summary
			if !control {
				return nil
			}
		}
	}
	poc := fmt.Sprintf(`<html><body><iframe src="%s" width="1200" height="900" style="opacity:0.01;position:absolute;top:0;left:0;border:0"></iframe></body></html>`, input.Target)
	finding := model.Finding{
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
			"responseShape":  ClassifyResponseShape(respHeader).String(),
		},
	}
	if baselineSummary != "" {
		finding.EvidenceFields["framingControl"] = baselineSummary
	}
	outcome := SubmitVerifiedFinding(context.Background(), VerifyCandidate{
		Finding:               finding,
		Signals:               []EvidenceSignal{EvidenceHeaderDelta, EvidenceSinkObserved},
		AllowNoReplayEmission: true,
		ProbeName:             "clickjacking-probe",
	})
	if outcome.Suppressed {
		return nil
	}
	return []model.Finding{outcome.EmittedFinding}
}

func (s *Service) clickjackingFramingControl(ctx context.Context, input RunInput) (bool, string, error) {
	if strings.TrimSpace(input.Target) == "" {
		return true, "", nil
	}
	unframed, err := s.clickjackingFetchVariant(ctx, input, false)
	if err != nil {
		return false, "", err
	}
	framed, err := s.clickjackingFetchVariant(ctx, input, true)
	if err != nil {
		return false, "", err
	}
	summary := fmt.Sprintf("unframed=%d/%q/%q framed=%d/%q/%q",
		unframed.Status,
		strings.TrimSpace(unframed.Header.Get("X-Frame-Options")),
		strings.TrimSpace(unframed.Header.Get("Content-Security-Policy")),
		framed.Status,
		strings.TrimSpace(framed.Header.Get("X-Frame-Options")),
		strings.TrimSpace(framed.Header.Get("Content-Security-Policy")),
	)
	if unframed.Status != framed.Status {
		return true, summary, nil
	}
	if strings.TrimSpace(unframed.Header.Get("X-Frame-Options")) != strings.TrimSpace(framed.Header.Get("X-Frame-Options")) {
		return true, summary, nil
	}
	if strings.TrimSpace(unframed.Header.Get("Content-Security-Policy")) != strings.TrimSpace(framed.Header.Get("Content-Security-Policy")) {
		return true, summary, nil
	}
	return NormalizeResponseBody(unframed.Body) != NormalizeResponseBody(framed.Body), summary, nil
}

func (s *Service) clickjackingFetchVariant(ctx context.Context, input RunInput, framed bool) (BaselineSample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Target, nil)
	if err != nil {
		return BaselineSample{}, err
	}
	ApplyAuthProfile(req, input.AuthProfile)
	if framed {
		req.Header.Set("Sec-Fetch-Dest", "iframe")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
	} else {
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return BaselineSample{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return BaselineSample{Status: resp.StatusCode, Header: resp.Header, Body: string(body)}, nil
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
