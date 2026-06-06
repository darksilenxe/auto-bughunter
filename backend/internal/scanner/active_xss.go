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

// xssProbeParams are common parameter names that tend to be reflected into
// HTML responses (search forms, "you said X" pages, error toasts, redirect
// confirmation banners). Picked to maximise reflection probability without
// touching identifiers/IDs that could mutate state.
var xssProbeParams = []string{"q", "search", "query", "s", "keyword", "term", "text", "name", "title", "msg", "message"}

// techAwareXSSProbeParams returns the XSS parameter probe list reordered so
// parameters most likely to be reflected by the detected technology stack are
// tried first. This reduces probe budget waste when the tech stack implies a
// well-known parameter naming convention (e.g. "search" for CMS platforms,
// "query" / "q" for SPA APIs).
//
// All default parameters are still included; only the ordering changes.
func techAwareXSSProbeParams(tech TechStack) []string {
	// Determine which parameter names to front-load based on detected tech.
	var priority []string
	switch {
	case tech.Has("wordpress") || tech.Has("drupal") || tech.Has("joomla"):
		// CMS search boxes almost universally use "s" (WordPress) or
		// "search" (Drupal/Joomla).
		priority = []string{"s", "search", "q"}
	case tech.Has("django"):
		// Django views typically expose "q" or "query" for search.
		priority = []string{"q", "query", "search"}
	case tech.Has("react") || tech.Has("next.js") || tech.Has("vue.js") || tech.Has("angularjs") || tech.Has("angular"):
		// SPA/API frontends often surface parameters as "query", "q", or
		// "term" via JSON-powered search endpoints.
		priority = []string{"query", "q", "term", "search"}
	case tech.Has("ruby on rails"):
		// Rails conventions favour "q" (Ransack gem) and "search".
		priority = []string{"q", "search", "query"}
	}

	if len(priority) == 0 {
		return xssProbeParams
	}

	seen := make(map[string]struct{}, len(xssProbeParams))
	out := make([]string, 0, len(xssProbeParams))
	for _, p := range priority {
		out = append(out, p)
		seen[p] = struct{}{}
	}
	for _, p := range xssProbeParams {
		if _, ok := seen[p]; !ok {
			out = append(out, p)
		}
	}
	return out
}

// xssMarker is a deliberately distinctive payload chosen to be:
//   - Cheap to send (a few dozen bytes per probe).
//   - Obvious if reflected raw into HTML (contains "<", ">", quotes and a
//     unique random-looking token so we don't false-positive on user content).
//   - Harmless: there is no real script execution attempted; we look only for
//     the literal payload appearing unescaped in the response body.
const xssMarker = `"><svg/onload=abh_xss_7f9e2()><!--abh_xss_7f9e2-->`

// xssConfirmMarker is a structurally different secondary payload used to
// confirm a reflection found by xssMarker. Requiring two distinct payloads to
// reflect without HTML encoding virtually eliminates accidental matches caused
// by debug output, error messages, or coincidental HTML fragments.
const xssConfirmMarker = `'><script>/*abh_xss_c3f81*/</script><!--abh_c3f81-->`

// xssMaxAttempts caps how many request/parameter combinations the active XSS
// probe will attempt per scan to bound scan time. The same budget applies in
// the existing contextual-probe code (12).
const xssMaxAttempts = 12

// runActiveXSSProbe is an active reflected-XSS scanner. For each in-scope
// runtime endpoint it injects a distinctive HTML-context marker into common
// reflective parameter names and inspects the response body for an unescaped
// reflection. Only one finding is emitted per scan; the probe is silent when
// no reflections are observed.
//
// The probe is intentionally non-destructive: it never sends mutating verbs,
// never executes a real payload, and respects scope/SSRF safety on every
// request. It is independent of the AI input_validation agent (which uses a
// different, ad-hoc HTTP client) and benefits from doRequestWithRetry, the
// runtime endpoint discovery already used elsewhere in the scanner, and
// auth/scope plumbing.
func (s *Service) runActiveXSSProbe(ctx context.Context, input RunInput, body string) []model.Finding {
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

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("active-xss %s", input.Target),
			Message: "Probing for reflected XSS via context-aware payload injection",
		})
	}

	type hit struct {
		url   string
		param string
	}
	var hits []hit
	attempts := 0
	for _, raw := range candidates {
		if attempts >= xssMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, p := range techAwareXSSProbeParams(input.DetectedTech) {
			if attempts >= xssMaxAttempts {
				break
			}
			payloads := []string{xssMarker}
			if input.Options.WAFBypass {
				payloads = xssBypassVariants(xssMarker)
			}
			matched := false
			for _, payload := range payloads {
				if attempts >= xssMaxAttempts {
					break
				}
				probe := *base
				q := probe.Query()
				q.Set(p, payload)
				probe.RawQuery = q.Encode()
				probeURL := probe.String()
				if !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				// safety.ValidateOutboundURL is intentionally not re-checked
				// here: the host comes from input.Target (validated by Run)
				// or from extractRuntimeEndpoints (which validates each
				// candidate); modifying only the query string cannot change
				// the host, so the check would be redundant.
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
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				_ = resp.Body.Close()
				if !isHTMLContextReflection(string(respBody), payload) {
					continue
				}
				// Primary reflection confirmed. Issue a second probe with a
				// structurally different marker to rule out accidental matches
				// caused by error messages or debug output containing the
				// same string fragment. Only promote to a finding when both
				// distinct payloads reflect without HTML encoding.
				confirmed := false
				if attempts < xssMaxAttempts {
					confirmProbe := *base
					cq := confirmProbe.Query()
					cq.Set(p, xssConfirmMarker)
					confirmProbe.RawQuery = cq.Encode()
					confirmURL := confirmProbe.String()
					if scope.IsURLInScope(confirmURL, input.Scope) {
						creq, cerr := http.NewRequestWithContext(ctx, http.MethodGet, confirmURL, nil)
						if cerr == nil {
							ApplyAuthProfile(creq, input.AuthProfile)
							cresp, cerr := s.doRequestWithRetry(ctx, creq, input.Options)
							attempts++
							if cerr == nil && cresp != nil {
								cb, _ := io.ReadAll(io.LimitReader(cresp.Body, 512*1024))
								_ = cresp.Body.Close()
								confirmed = isHTMLContextReflection(string(cb), xssConfirmMarker)
							}
						}
					}
				}
				if !confirmed {
					// Single-marker reflection only — not enough evidence.
					// Reduce probability it was a coincidental string match
					// by continuing to check other parameters, but don't
					// emit a finding on the basis of one payload alone.
					break
				}
				hits = append(hits, hit{url: probeURL, param: p})
				matched = true
				break
			}
			if matched {
				// One reflection is enough to surface the issue; keep
				// searching other endpoints to enrich evidence but don't
				// loop indefinitely on the same parameter set.
				break
			}
		}
	}

	if len(hits) == 0 {
		return nil
	}

	urls := make([]string, 0, len(hits))
	params := make([]string, 0, len(hits))
	seenParam := map[string]struct{}{}
	for _, h := range hits {
		urls = append(urls, h.url)
		if _, ok := seenParam[h.param]; !ok {
			params = append(params, h.param)
			seenParam[h.param] = struct{}{}
		}
	}

	first := hits[0]
	steps := []string{
		fmt.Sprintf("Send GET %s", first.url),
		fmt.Sprintf("Inspect the response body and confirm the literal payload %q appears unescaped (no HTML entity encoding) in an HTML context.", xssMarker),
		fmt.Sprintf("Repeat with other reflective parameters (%s) to assess scope.", strings.Join(params, ", ")),
	}
	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")

	return []model.Finding{{
		ID:                "active-xss-reflected",
		Category:          "input-validation",
		Severity:          model.SeverityHigh,
		Title:             "Reflected Cross-Site Scripting (XSS) via unencoded parameter reflection",
		Description:       "An HTML-context payload supplied via a query parameter was reflected into the response body without HTML encoding. An attacker who can craft a link to this endpoint can execute arbitrary script in a victim's browser, leading to session hijacking, credential theft and account takeover.",
		Evidence:          fmt.Sprintf("Dual-marker reflection confirmed: both %q and a secondary marker reflected without HTML encoding at: %s (parameters: %s)", xssMarker, strings.Join(limitStrings(urls, 6), ", "), strings.Join(params, ", ")),
		Recommendation:    "Apply context-aware output encoding (HTML, attribute, JS, URL) at every sink that emits user-controlled data. Prefer a templating engine with auto-escaping, and add a strict Content-Security-Policy as defense-in-depth.",
		Confidence:        0.97,
		AffectedURL:       first.url,
		AffectedParameter: first.param,
		CWE:               "CWE-79",
		OWASPCategory:     "A03:2021 - Injection",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"reproStep":      "Replay the listed URL and confirm the marker appears unescaped in the HTML body",
			"curlReproducer": curl,
		},
	}}
}

// isHTMLContextReflection returns true when the marker appears literally in
// the response body. It is intentionally conservative: HTML-encoded forms of
// the marker (e.g. "&quot;&gt;&lt;svg…") are deliberately ignored because
// those represent the *defended* case.
func isHTMLContextReflection(body, marker string) bool {
	if marker == "" || body == "" {
		return false
	}
	return strings.Contains(body, marker)
}
