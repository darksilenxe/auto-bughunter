package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

var xpathProbeParams = []string{"username", "user", "uid", "login", "email", "cn", "search", "q", "filter", "name", "id", "node", "item", "xpath", "data"}
var xpathPayloads = []string{"' or '1'='1", "' or 1=1 or ''='", "'] | //user/*[1=1 or '", "x' or name()='username' or 'x'='y"}
var xpathErrorSignatures = []string{"xpathexception", "invalid xpath", "javax.xml.xpath", "libxml2", "xpatherror", "unexpected token", "xpath syntax", "xslt", "/descendant::", "org.w3c.dom"}

const xpathMaxAttempts = 12

func (s *Service) runActiveXPathInjectionProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 10)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	attempts := 0
	for _, raw := range candidates {
		if attempts >= xpathMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range xpathProbeParams {
			if attempts >= xpathMaxAttempts {
				break
			}
			for _, payload := range xpathPayloads {
				if attempts >= xpathMaxAttempts {
					break
				}
				probe := *base
				q := probe.Query()
				q.Set(param, payload)
				probe.RawQuery = q.Encode()
				probeURL := probe.String()
				if !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				attempts++
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
				_ = resp.Body.Close()
				if sig := matchAnyLower(string(respBody), xpathErrorSignatures); sig != "" {
					curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
					return []model.Finding{{
						ID:                "active-xpath-injection",
						Category:          "injection",
						Severity:          model.SeverityHigh,
						Title:             "XPath injection confirmed via active probe",
						Description:       "Supplying XPath metacharacters triggered an XPath parser or XML-processing error, indicating user input is being concatenated into an XPath expression without proper escaping.",
						Evidence:          fmt.Sprintf("Probe %s triggered %q on parameter %q", probeURL, sig, param),
						Recommendation:    "Avoid string-building XPath expressions from user input. Use parameterized XPath APIs or strict allowlists and escape untrusted input before it reaches XPath or XSLT evaluation.",
						Confidence:        0.88,
						AffectedURL:       probeURL,
						AffectedParameter: param,
						CWE:               "CWE-643",
						OWASPCategory:     "A03:2021 - Injection",
						Sources:           []string{"active-scanner"},
						ReproductionSteps: []string{fmt.Sprintf("Send GET %s", probeURL), fmt.Sprintf("Observe the XPath signal %q in the response.", sig)},
						PoC:               curl,
						EvidenceFields: map[string]string{
							"validationType": "active-probe",
							"payload":        payload,
							"signature":      sig,
							"curlReproducer": curl,
						},
					}}
				}
			}
		}
	}
	return nil
}
