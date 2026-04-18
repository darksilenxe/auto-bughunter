package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
)

// CORS misconfiguration probe — passive check that issues a single GET
// with a synthetic, attacker-controlled Origin header and inspects the
// reflected CORS response headers. This is read-only and never follows
// redirects, so it is safe to run against any in-scope target.
//
// Findings raised:
//   - reflected-origin: ACAO mirrors the attacker-supplied Origin (medium)
//   - acao-credentials: ACAO + ACAC=true with reflected origin (high)
//   - wildcard-credentials: ACAO=* combined with ACAC=true (high — spec
//     forbids this combo, but some misconfigured servers still send it)
//
// The probe is intentionally limited to the entry-point URL; deeper API
// paths are picked up by the runtime-endpoint discovery logic + nuclei.

const corsProbeOrigin = "https://abh-cors-probe.invalid"

func runCORSProbe(ctx context.Context, target string, auth model.ScanAuthProfile, options model.ScanOptions, service *Service) []model.Finding {
	if service == nil || service.httpClient == nil {
		return nil
	}
	if err := safety.ValidateOutboundURL(target); err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, auth)
	req.Header.Set("Origin", corsProbeOrigin)
	resp, err := service.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	return classifyCORSResponse(target, resp.Header)
}

// classifyCORSResponse turns the response headers from a single CORS probe
// into zero or one finding. Pulled out as a pure function so it can be
// exhaustively tested without standing up HTTP infrastructure.
func classifyCORSResponse(target string, header http.Header) []model.Finding {
	acao := strings.TrimSpace(header.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(header.Get("Access-Control-Allow-Credentials")), "true")
	if acao == "" {
		return nil
	}
	reproStep := fmt.Sprintf("curl -i -H 'Origin: %s' '%s'", corsProbeOrigin, target)
	switch {
	case acao == "*" && acac:
		return []model.Finding{{
			ID:             "cors-wildcard-with-credentials",
			Category:       "cors",
			Severity:       model.SeverityHigh,
			Title:          "CORS: Access-Control-Allow-Origin: * combined with Allow-Credentials: true",
			Description:    "The server returned ACAO=* together with ACAC=true. The CORS specification forbids this combination because it would allow any origin to make credentialed cross-origin requests; many browsers still honour the response, which can lead to account/data takeover from any malicious site.",
			Evidence:       fmt.Sprintf("ACAO=%q ACAC=true", acao),
			Recommendation: "Either remove the credentials from the response (drop the ACAC header) or replace the wildcard with an explicit, allow-listed origin. Never combine wildcard ACAO with credentials.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      reproStep,
			},
		}}
	case acao == corsProbeOrigin && acac:
		return []model.Finding{{
			ID:             "cors-reflected-origin-with-credentials",
			Category:       "cors",
			Severity:       model.SeverityHigh,
			Title:          "CORS: Access-Control-Allow-Origin reflects arbitrary Origin with credentials",
			Description:    "The server reflected an attacker-supplied Origin header into Access-Control-Allow-Origin while also returning Allow-Credentials: true. This effectively allows any website to issue authenticated cross-origin requests on behalf of the user.",
			Evidence:       fmt.Sprintf("Sent Origin=%s; got ACAO=%s ACAC=true", corsProbeOrigin, acao),
			Recommendation: "Validate the Origin header against an allow-list before reflecting it. Never reflect arbitrary Origins when ACAC is enabled.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      reproStep,
			},
		}}
	case acao == corsProbeOrigin:
		return []model.Finding{{
			ID:             "cors-reflected-origin",
			Category:       "cors",
			Severity:       model.SeverityMedium,
			Title:          "CORS: Access-Control-Allow-Origin reflects arbitrary Origin",
			Description:    "The server reflected an attacker-supplied Origin header into Access-Control-Allow-Origin without validation. While not directly exploitable for authenticated requests (no Allow-Credentials), this still permits cross-origin reads of public content from any origin, which can amplify other vulnerabilities.",
			Evidence:       fmt.Sprintf("Sent Origin=%s; got ACAO=%s", corsProbeOrigin, acao),
			Recommendation: "Validate the Origin header against an allow-list before reflecting it.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      reproStep,
			},
		}}
	}
	return nil
}
