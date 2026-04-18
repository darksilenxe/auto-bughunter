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

// openRedirectParams are the parameter names most commonly used to drive a
// post-action redirect. Picked to maximise hit rate on auth/login flows,
// "back" buttons, OAuth callbacks and SSO landing pages.
var openRedirectParams = []string{
	"redirect", "redirect_uri", "redirect_url", "next", "url",
	"return", "returnTo", "return_to", "goto", "continue",
	"back", "target", "rurl", "destination", "forward",
}

// openRedirectMarker is the canary host the probe asks the application to
// redirect to. It is intentionally a reserved/sink-hole-style domain that no
// production app should ever legitimately redirect to. We never actually
// follow the redirect — we only inspect the `Location` header.
const openRedirectMarker = "abh-redirect-canary.invalid"

// openRedirectMaxAttempts caps probe budget per scan. Same rationale as the
// XSS/SQLi probes (12).
const openRedirectMaxAttempts = 12

// runActiveOpenRedirectProbe is an active open-redirect scanner. For each
// in-scope runtime endpoint it injects an attacker-controlled host into the
// most common redirect parameters and inspects the `Location` response
// header for an off-host destination. The HTTP client is configured to NOT
// follow redirects (CheckRedirect returns ErrUseLastResponse) so we never
// actually request the canary host — we only observe whether the target
// would.
//
// Findings are emitted at most once per scan and at medium severity, in
// line with how most bug-bounty programs triage open-redirect issues
// (impactful for phishing/account-takeover chains, but not directly
// exploitable for code execution).
func (s *Service) runActiveOpenRedirectProbe(ctx context.Context, input RunInput, body string) []model.Finding {
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
			Command: fmt.Sprintf("active-open-redirect %s", input.Target),
			Message: "Probing for open redirects via canary destination injection",
		})
	}

	// A non-following client — we MUST inspect the first Location header
	// instead of the resolved end of the redirect chain, otherwise a 200
	// from the canary host (which is unreachable anyway) would mask the
	// finding.
	noFollow := *s.httpClient
	noFollow.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	type hit struct {
		url      string
		param    string
		location string
	}
	var hits []hit
	attempts := 0
	for _, raw := range candidates {
		if attempts >= openRedirectMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		// Two payload shapes: full scheme+host and protocol-relative `//host`.
		// Some apps reject `http://` but happily accept `//attacker`.
		payloads := []string{"https://" + openRedirectMarker, "//" + openRedirectMarker}
		for _, p := range openRedirectParams {
			if attempts >= openRedirectMaxAttempts {
				break
			}
			for _, payload := range payloads {
				if attempts >= openRedirectMaxAttempts {
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
				// here: candidates come from input.Target (validated by
				// Run) or from extractRuntimeEndpoints (which validates
				// each); changing only the query string cannot change
				// the host.
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := noFollow.Do(req)
				attempts++
				if err != nil || resp == nil {
					continue
				}
				location := resp.Header.Get("Location")
				_ = resp.Body.Close()
				if isOpenRedirectLocation(location, openRedirectMarker) {
					hits = append(hits, hit{url: probeURL, param: p, location: location})
					break
				}
			}
		}
	}

	if len(hits) == 0 {
		return nil
	}

	first := hits[0]
	urls := make([]string, 0, len(hits))
	for _, h := range hits {
		urls = append(urls, fmt.Sprintf("%s (param=%s, Location=%s)", h.url, h.param, h.location))
	}
	steps := []string{
		fmt.Sprintf("Send GET %s", first.url),
		fmt.Sprintf("Inspect the response and confirm the Location header points at the attacker-controlled host (observed: %q).", first.location),
		"Replace the canary host with any attacker-controlled URL to confirm impact (e.g. credential-phishing landing page).",
	}
	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")
	return []model.Finding{{
		ID:                "active-open-redirect",
		Category:          "input-validation",
		Severity:          model.SeverityMedium,
		Title:             "Open redirect via unvalidated redirect parameter",
		Description:       "The application accepted an attacker-controlled host in a redirect parameter and emitted a Location header pointing to that host. Open redirects are commonly chained into phishing campaigns and OAuth/SSO account-takeover flows.",
		Evidence:          fmt.Sprintf("Off-host redirect destination observed at: %s", strings.Join(limitStrings(urls, 6), "; ")),
		Recommendation:    "Validate every redirect target against a strict allow-list of internal paths or hostnames. Prefer relative paths; if external redirects are required, require an explicit signed token.",
		Confidence:        0.85,
		AffectedURL:       first.url,
		AffectedParameter: first.param,
		CWE:               "CWE-601",
		OWASPCategory:     "A01:2021 - Broken Access Control",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType":      "active-probe",
			"reproStep":           "Replay the listed URL and inspect the Location response header",
			"redirectDestination": first.location,
			"curlReproducer":      curl,
		},
	}}
}

// isOpenRedirectLocation returns true when `location` resolves to a host
// that contains the canary marker. It accepts:
//   - absolute URLs ("https://canary/...")
//   - protocol-relative URLs ("//canary/...")
//   - schemeless host references that begin with the marker
//
// Anything that resolves to the same origin as the request, or that is
// purely a path/fragment, is rejected — those are not open redirects.
func isOpenRedirectLocation(location, marker string) bool {
	location = strings.TrimSpace(location)
	if location == "" || marker == "" {
		return false
	}
	lower := strings.ToLower(location)
	mlower := strings.ToLower(marker)
	if strings.HasPrefix(lower, "//") {
		return strings.Contains(lower, mlower)
	}
	if u, err := url.Parse(location); err == nil && u.Host != "" {
		return strings.Contains(strings.ToLower(u.Host), mlower)
	}
	// Bare-host references like `Location: canary/path` (rare, but seen on
	// misconfigured nginx) — treat as a redirect when the marker leads.
	return strings.HasPrefix(lower, mlower)
}
