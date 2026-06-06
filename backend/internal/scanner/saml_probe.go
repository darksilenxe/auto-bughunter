package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

var samlPaths = []string{"/saml", "/sso", "/sp", "/idp"}

func (s *Service) runSAMLProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates, detected := samlCandidates(input.Target, body, input.Options.SeedRuntimeEndpoints, input.Scope)
	if !detected || len(candidates) == 0 {
		return nil
	}
	payload := base64.StdEncoding.EncodeToString([]byte(`<samlp:Response><saml:Assertion><saml:NameID>admin<!--</saml:NameID></saml:Assertion></samlp:Response>`))
	for _, raw := range candidates {
		probeURL, err := appendQueryParam(raw, "SAMLResponse", payload)
		if err != nil || !scope.IsURLInScope(probeURL, input.Scope) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		lower := strings.ToLower(string(respBody))
		if resp.StatusCode == http.StatusOK && (strings.Contains(lower, "<saml") || strings.Contains(lower, "assertion") || strings.Contains(lower, "nameid") || strings.Contains(lower, "welcome")) && !strings.Contains(lower, "invalid") && !strings.Contains(lower, "error") {
			return []model.Finding{{
				ID:                "saml-endpoint-detected",
				Category:          "auth_bypass",
				Severity:          model.SeverityHigh,
				Title:             "SAML endpoint accepted tampered SAMLResponse content",
				Description:       "A SAML-related endpoint was identified and responded successfully to a tampered SAMLResponse delivered via GET, suggesting weak signature validation, comment-injection handling, or overly permissive SAML parsing.",
				Evidence:          fmt.Sprintf("GET %s returned HTTP %d with SAML/XML indicators in the response", probeURL, resp.StatusCode),
				Recommendation:    "Require signed SAML assertions, reject unsigned or GET-delivered SAMLResponse values where inappropriate, hard-fail on malformed XML/comments, and validate issuer/audience/recipient conditions strictly.",
				Confidence:        0.74,
				AffectedURL:       raw,
				CWE:               "CWE-347",
				OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
				Sources:           []string{"active-scanner"},
				ReproductionSteps: []string{fmt.Sprintf("Send GET %s", probeURL), "Observe the successful XML/SAML-bearing response and verify malformed SAML is not rejected."},
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"payload":        payload,
				},
			}}
		}
	}
	return []model.Finding{{
		ID:             "saml-endpoint-detected",
		Category:       "auth_bypass",
		Severity:       model.SeverityInfo,
		Title:          "SAML endpoint or artifacts detected",
		Description:    "The application exposes SAML-related endpoints or SAML artifacts. Manual review should verify signature validation, recipient/audience checks, and error handling for malformed assertions.",
		Evidence:       strings.Join(limitStrings(candidates, 6), ", "),
		Recommendation: "Review SAML flows for signature wrapping, weak audience validation, and unsafe bindings. Ensure malformed SAML requests are rejected with consistent errors.",
		Confidence:     0.7,
		AffectedURL:    candidates[0],
		CWE:            "CWE-347",
		OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
		Sources:        []string{"active-scanner"},
		EvidenceFields: map[string]string{"validationType": "safe-observation"},
	}}
}

func samlCandidates(target, body string, seeds []string, scanScope model.ScanScope) ([]string, bool) {
	lowerBody := strings.ToLower(body)
	detected := strings.Contains(lowerBody, "/saml") || strings.Contains(lowerBody, "/sso") || strings.Contains(lowerBody, "/sp") || strings.Contains(lowerBody, "/idp") || strings.Contains(lowerBody, "samlresponse") || strings.Contains(lowerBody, "samlrequest") || strings.Contains(lowerBody, "<saml")
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, detected
	}
	var out []string
	add := func(raw string) {
		resolved := resolveEndpoint(target, raw)
		if resolved != "" && scope.IsURLInScope(resolved, scanScope) {
			out = append(out, resolved)
		}
	}
	for _, seed := range seeds {
		lower := strings.ToLower(seed)
		if strings.Contains(lower, "saml") || strings.Contains(lower, "sso") || strings.Contains(lower, "/sp") || strings.Contains(lower, "/idp") {
			add(seed)
			detected = true
		}
	}
	if strings.Contains(strings.ToLower(base.Path), "saml") || strings.Contains(strings.ToLower(base.Path), "sso") {
		detected = true
	}
	if !detected {
		return nil, false
	}
	for _, path := range samlPaths {
		add(base.ResolveReference(&url.URL{Path: path}).String())
	}
	return dedupeStrings(out), true
}
