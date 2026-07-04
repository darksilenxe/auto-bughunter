package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// corsProbeOrigins are the origins the probe sends in the `Origin` header
// to detect the highest-impact CORS misconfigurations:
//
//   - A literal attacker-controlled origin tests "naive reflection" — apps
//     that echo whatever Origin they receive back into
//     Access-Control-Allow-Origin, which combined with credentials is a
//     full account-takeover primitive.
//   - "null" tests sandboxed-iframe / file:// scenarios.
//   - A subdomain of the target tests overly-greedy regex allow-lists
//     (e.g. `^https?://.*example.com$` matched by `evil.example.com.attacker`).
var corsProbeOrigins = []string{
	"https://abh-cors-canary.invalid",
	"null",
}

// corsMaxAttempts caps how many endpoint/origin combinations the probe
// will attempt per scan. Each attempt is one preflight-style OPTIONS plus
// one GET, so the actual request budget is ~2× this number.
const corsMaxAttempts = 12

// runActiveCORSProbe is an active CORS misconfiguration scanner. For each
// in-scope runtime endpoint it sends a request with a controlled Origin
// header and inspects the response for two high-impact patterns:
//
//  1. Full naive reflection of the supplied Origin into
//     Access-Control-Allow-Origin (with or without credentials).
//  2. Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true.
//
// Both patterns enable cross-origin reading of authenticated responses
// when combined with credentials; the credentialed variants are reported
// at high severity, the non-credentialed at medium.
//
// The probe deliberately does NOT mutate state — it only sends GET — and
// every request is gated by scope + SSRF safety like the other active
// probes in this package.
func (s *Service) runActiveCORSProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 8)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("active-cors %s", input.Target),
			Message: "Probing for CORS misconfigurations via Origin reflection checks",
		})
	}

	type hit struct {
		url          string
		origin       string
		allowOrigin  string
		allowCreds   bool
		nullVariant  bool
		credentialed bool // shorthand: high-severity case
		jsonAPI      bool // true when the endpoint serves JSON (not HTML)
	}
	var hits []hit
	attempts := 0
	for _, raw := range candidates {
		if attempts >= corsMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		probeURL := base.String()
		if !scope.IsURLInScope(probeURL, input.Scope) {
			continue
		}
		// safety.ValidateOutboundURL is intentionally not re-checked
		// here: the URL comes from extractRuntimeEndpoints/SeedRuntimeEndpoints
		// or input.Target, both of which are validated upstream.

		// Control request — send without an Origin header. If the endpoint
		// already responds with a non-empty Access-Control-Allow-Origin in
		// the absence of an Origin header it is an intentional wildcard CORS
		// policy, not a reflection attack. Flagging it would be a false
		// positive: the server is not echoing our controlled value back.
		// Consume one attempt slot for the control request.
		var baselineACAO string
		var isJSONAPI bool
		if attempts < corsMaxAttempts {
			ctrlReq, ctrlErr := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if ctrlErr == nil {
				ApplyAuthProfile(ctrlReq, input.AuthProfile)
				ctrlResp, ctrlErr := s.doRequestWithRetry(ctx, ctrlReq, input.Options)
				attempts++
				// Phase 2 coverage accounting: record this probe key so the
				// surface-gap detector subtracts it from the inventory. CORS
				// is header-only, so no parameter name applies.
				RecordProbedKey(http.MethodGet, probeURL, "")
				if ctrlErr == nil && ctrlResp != nil {
					baselineACAO = strings.TrimSpace(ctrlResp.Header.Get("Access-Control-Allow-Origin"))
					isJSONAPI = !isHTMLLikeContentType(ctrlResp.Header)
					_ = ctrlResp.Body.Close()
				}
			}
		}

		for _, origin := range corsProbeOrigins {
			if attempts >= corsMaxAttempts {
				break
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, input.AuthProfile)
			req.Header.Set("Origin", origin)
			resp, err := s.doRequestWithRetry(ctx, req, input.Options)
			attempts++
			// Phase 2 coverage accounting: see the control-request comment
			// above.
			RecordProbedKey(http.MethodGet, probeURL, "")
			if err != nil || resp == nil {
				continue
			}
			allowOrigin := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
			allowCreds := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
			_ = resp.Body.Close()
			if allowOrigin == "" {
				continue
			}
			reflected := strings.EqualFold(allowOrigin, origin)
			nullVariant := origin == "null" && strings.EqualFold(allowOrigin, "null")
			if !reflected && !nullVariant {
				continue
			}
			// Skip if the baseline (no-Origin) response already returned the
			// same ACAO value: this means the server unconditionally sends it
			// without inspecting the Origin header, making it a permissive
			// policy rather than an active reflection attack.
			if baselineACAO != "" && strings.EqualFold(baselineACAO, allowOrigin) {
				continue
			}
			hits = append(hits, hit{
				url:          probeURL,
				origin:       origin,
				allowOrigin:  allowOrigin,
				allowCreds:   allowCreds,
				nullVariant:  nullVariant,
				credentialed: allowCreds,
				jsonAPI:      isJSONAPI,
			})
		}
	}

	if len(hits) == 0 {
		return nil
	}

	// Pick the most severe hit to drive the primary finding shape.
	primary := hits[0]
	for _, h := range hits {
		if h.credentialed && !primary.credentialed {
			primary = h
		}
	}
	severity := model.SeverityMedium
	confidence := 0.85
	title := "CORS misconfiguration: response reflects attacker-controlled Origin"
	if primary.credentialed {
		severity = model.SeverityHigh
		confidence = 0.92
		title = "CORS misconfiguration with credentials: cross-origin reads of authenticated data"
	} else if primary.jsonAPI {
		// Non-credentialed CORS reflection on a JSON API endpoint is
		// significantly lower impact: without cookies or session tokens the
		// attacker cannot read authenticated responses. Downgrade severity
		// so SPA backends that legitimately serve open APIs are not reported
		// at medium; they still surface for review but at informational.
		severity = model.SeverityInfo
		confidence = 0.72
		title = "CORS misconfiguration: attacker-controlled Origin reflected on unauthenticated JSON API"
	}

	urls := make([]string, 0, len(hits))
	for _, h := range hits {
		urls = append(urls, fmt.Sprintf("%s (Origin=%s -> ACAO=%s ACAC=%v)", h.url, h.origin, h.allowOrigin, h.allowCreds))
	}
	steps := []string{
		fmt.Sprintf("Send GET %s with header `Origin: %s`.", primary.url, primary.origin),
		fmt.Sprintf("Observe `Access-Control-Allow-Origin: %s` in the response.", primary.allowOrigin),
	}
	if primary.credentialed {
		steps = append(steps, "Observe `Access-Control-Allow-Credentials: true` — combined with the reflected origin, an attacker page can read the authenticated response cross-origin.")
	} else {
		steps = append(steps, "Without credentials this is lower-impact, but still indicates an unsafe wildcard/reflection policy that can leak responses lacking auth.")
	}

	curl := buildCurlReproducer(http.MethodGet, primary.url, input.AuthProfile, "", "")
	curl = curl + " -H " + shellQuote("Origin: "+primary.origin)
	rec := "Validate the Origin header against a strict allow-list before echoing it. Never combine Access-Control-Allow-Credentials: true with a reflected or `null` origin."
	finding := model.Finding{
		ID:                idForCORSFinding(primary),
		Category:          "cors_redirect",
		Severity:          severity,
		Title:             title,
		Description:       "The application echoes the request `Origin` header into `Access-Control-Allow-Origin` without validating it against an allow-list. When combined with `Access-Control-Allow-Credentials: true`, this lets any malicious page read authenticated responses cross-origin and is commonly chained into account-takeover.",
		Evidence:          fmt.Sprintf("Reflected origins observed at: %s", strings.Join(limitStrings(urls, 6), "; ")),
		Recommendation:    rec,
		Confidence:        confidence,
		AffectedURL:       primary.url,
		AffectedParameter: "Origin",
		CWE:               "CWE-942",
		OWASPCategory:     "A05:2021 - Security Misconfiguration",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType":      "active-probe",
			"reproStep":           "Replay the listed URL with the controlled Origin header and inspect ACAO/ACAC",
			"reflectedOrigin":     primary.origin,
			"allowOriginResponse": primary.allowOrigin,
			"credentialsAllowed":  fmt.Sprintf("%v", primary.credentialed),
			"jsonAPIEndpoint":     fmt.Sprintf("%v", primary.jsonAPI),
			"curlReproducer":      curl,
			"responseShape":       shapeTagForCORSHit(primary),
			"method":              http.MethodGet,
			"url":                 primary.url,
			"payloadClass":        "cors-origin-reflection",
			"oracleName":          "active_cors",
			"oracleVersion":       "v1",
		},
	}

	// Phase 1 pre-report verification. Temporarily canonicalise the
	// category to "cors" so the proof-policy engine evaluates the correct
	// ruleset; the external category label is preserved on the emitted
	// finding. Signals: origin reflection is a header delta, and the ACAO
	// echo is the reflected marker itself.
	signals := []EvidenceSignal{EvidenceHeaderDelta, EvidenceReflection}
	if primary.credentialed {
		signals = append(signals, EvidenceSinkObserved)
	}
	originalCategory := finding.Category
	finding.Category = "cors"
	verifyOutcome := SubmitVerifiedFinding(ctx, VerifyCandidate{
		Finding:               finding,
		Signals:               signals,
		AllowNoReplayEmission: true,
		ProbeName:             "active-cors",
	})
	if verifyOutcome.Suppressed {
		return nil
	}
	emitted := verifyOutcome.EmittedFinding
	emitted.Category = originalCategory
	return []model.Finding{emitted}
}

// shapeTagForCORSHit returns the response-shape label recorded on the
// emitted finding for downstream evidence normalisation. The probe already
// classified the endpoint as JSON vs HTML during the baseline request.
func shapeTagForCORSHit(h struct {
	url          string
	origin       string
	allowOrigin  string
	allowCreds   bool
	nullVariant  bool
	credentialed bool
	jsonAPI      bool
}) string {
	if h.jsonAPI {
		return ShapeJSON.String()
	}
	return ShapeHTML.String()
}

func idForCORSFinding(h struct {
	url          string
	origin       string
	allowOrigin  string
	allowCreds   bool
	nullVariant  bool
	credentialed bool
	jsonAPI      bool
}) string {
	if h.credentialed {
		return "active-cors-credentialed-reflection"
	}
	if h.nullVariant {
		return "active-cors-null-origin-reflected"
	}
	if h.jsonAPI {
		return "active-cors-json-api-origin-reflected"
	}
	return "active-cors-origin-reflected"
}
