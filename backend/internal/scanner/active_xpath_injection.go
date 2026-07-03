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

	// Phase 2 reference wiring: merge miner-discovered parameter names in
	// front of the built-in XPath wordlist (see PHASE2_AUDIT.md).
	probeParams := phase2ProbeParams(phase2DynamicParams(input.Session), xpathProbeParams)

	type hit struct {
		url       string
		param     string
		payload   string
		signature string
		header    http.Header
	}
	var hits []hit
	attempts := 0
	for _, raw := range candidates {
		if attempts >= xpathMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range probeParams {
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
				// Phase 2 coverage accounting: record this probe key so the
				// surface-gap detector subtracts it from the inventory.
				RecordProbedKey(http.MethodGet, probeURL, param)
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
				respHeader := resp.Header
				_ = resp.Body.Close()
				if !IsXMLShape(respHeader) {
					continue
				}
				if sig := matchAnyLower(string(respBody), xpathErrorSignatures); sig != "" {
					hits = append(hits, hit{url: probeURL, param: param, payload: payload, signature: sig, header: respHeader})
					goto doneProbes
				}
			}
		}
	}
doneProbes:
	if len(hits) == 0 {
		return nil
	}
	first := hits[0]
	baselines, berr := s.phase1QueryBaselines(ctx, first.url, first.param, "guest", true, input, 256*1024)
	if berr == nil && phase1BaselineContains(baselines, first.signature) {
		return nil
	}
	diffOutcome := phase1DifferentialQuery(ctx, s, input, "active-xpath-injection", first.url, first.param, first.payload, "guest", 256*1024,
		func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
			return matchAnyLower(string(body), xpathErrorSignatures) != "", nil
		})
	if diffOutcome.Ran && !diffOutcome.Confirmed {
		return nil
	}
	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")
	finding := model.Finding{
		ID:                "active-xpath-injection",
		Category:          "injection",
		Severity:          model.SeverityHigh,
		Title:             "XPath injection confirmed via active probe",
		Description:       "Supplying XPath metacharacters triggered an XPath parser or XML-processing error, indicating user input is being concatenated into an XPath expression without proper escaping.",
		Evidence:          fmt.Sprintf("Probe %s triggered %q on parameter %q", first.url, first.signature, first.param),
		Recommendation:    "Avoid string-building XPath expressions from user input. Use parameterized XPath APIs or strict allowlists and escape untrusted input before it reaches XPath or XSLT evaluation.",
		Confidence:        0.88,
		AffectedURL:       first.url,
		AffectedParameter: first.param,
		CWE:               "CWE-643",
		OWASPCategory:     "A03:2021 - Injection",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: []string{fmt.Sprintf("Send GET %s", first.url), fmt.Sprintf("Observe the XPath signal %q in the response.", first.signature)},
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"payload":        first.payload,
			"signature":      first.signature,
			"curlReproducer": curl,
			"responseShape":  ClassifyResponseShape(first.header).String(),
		},
	}
	AttachDifferentialEvidence(&finding, diffOutcome)
	return []model.Finding{finding}
}
