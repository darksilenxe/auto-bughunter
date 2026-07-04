package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
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

	// Phase 2 reference wiring: merge miner-discovered parameter names in
	// front of the built-in redirect-parameter wordlist (see PHASE2_AUDIT.md).
	probeParams := phase2ProbeParams(phase2DynamicParams(input.Session), openRedirectParams)

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
	// Use the session client as base when available so the shared cookie jar
	// is preserved; the shallow copy still shares the same jar pointer.
	baseClient := s.httpClient
	if input.Session != nil {
		baseClient = input.Session.Client()
	}
	noFollow := *baseClient
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
		for _, p := range probeParams {
			if attempts >= openRedirectMaxAttempts {
				break
			}
			for _, payload := range payloads {
				if attempts >= openRedirectMaxAttempts {
					break
				}
				// Rebuild the probe URL from explicit, already-validated
				// fields of `base` (rather than re-stringifying a tainted
				// parsed URL). The host can only ever equal `base.Host`,
				// which extractRuntimeEndpoints / Run already passed
				// through safety.ValidateOutboundURL. This makes the
				// safety property locally obvious and recognisable to
				// static taint trackers.
				q := base.Query()
				q.Set(p, payload)
				safe := url.URL{
					Scheme:   base.Scheme,
					Host:     base.Host,
					Path:     base.Path,
					RawQuery: q.Encode(),
				}
				probeURL := safe.String()
				if !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				// Final defence-in-depth check on the constructed URL.
				if err := safety.ValidateOutboundURL(probeURL); err != nil {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := noFollow.Do(req)
				attempts++
				// Phase 2 coverage accounting: record this probe key so the
				// surface-gap detector subtracts it from the inventory.
				RecordProbedKey(http.MethodGet, probeURL, p)
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

	// Phase 1 control baseline: fetch the same endpoint with the redirect
	// parameter stripped. If the Location header already points off-host
	// in the baseline, the target unconditionally emits a static redirect
	// destination and this is not an attacker-controlled sink.
	baselineFetch := func(bctx context.Context) (BaselineSample, error) {
		bu, perr := url.Parse(first.url)
		if perr != nil {
			return BaselineSample{}, perr
		}
		bq := bu.Query()
		bq.Del(first.param)
		bu.RawQuery = bq.Encode()
		br, berr := http.NewRequestWithContext(bctx, http.MethodGet, bu.String(), nil)
		if berr != nil {
			return BaselineSample{}, berr
		}
		ApplyAuthProfile(br, input.AuthProfile)
		bresp, bcerr := noFollow.Do(br)
		if bcerr != nil || bresp == nil {
			return BaselineSample{}, bcerr
		}
		defer bresp.Body.Close()
		return BaselineSample{
			Status: bresp.StatusCode,
			Header: bresp.Header,
			Body:   bresp.Header.Get("Location"),
		}, nil
	}
	if baselines, berr := CaptureTwoControlBaselines(ctx, baselineFetch); berr == nil {
		if isOpenRedirectLocation(baselines.First.Body, openRedirectMarker) ||
			isOpenRedirectLocation(baselines.Second.Body, openRedirectMarker) {
			// Static off-host redirect present without our payload —
			// suppress to avoid false-positive on shared logout/exit URLs.
			return nil
		}
	}

	// Phase 1 differential re-verify: substitute the canary host with a
	// benign on-host path. If the Location still contains the canary
	// marker the target is echoing baseline noise rather than the payload.
	execDifferential := func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
		du, perr := url.Parse(first.url)
		if perr != nil {
			return nil, nil, perr
		}
		dq := du.Query()
		dq.Set(first.param, altPayload)
		du.RawQuery = dq.Encode()
		dreq, derr := http.NewRequestWithContext(dctx, http.MethodGet, du.String(), nil)
		if derr != nil {
			return nil, nil, derr
		}
		ApplyAuthProfile(dreq, input.AuthProfile)
		dresp, dcerr := noFollow.Do(dreq)
		if dcerr != nil || dresp == nil {
			return nil, nil, dcerr
		}
		defer dresp.Body.Close()
		return dresp, []byte(dresp.Header.Get("Location")), nil
	}
	oracle := func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
		// Signal fires when the canary marker still appears in the
		// Location header for a benign payload — that is the FP case.
		return isOpenRedirectLocation(string(body), openRedirectMarker), nil
	}
	diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
		ProbeName:       "active-open-redirect",
		OriginalPayload: "https://" + openRedirectMarker,
		SafePayload:     "/",
		Exec:            execDifferential,
		Oracle:          oracle,
	})
	if diffOutcome.Ran && !diffOutcome.Confirmed {
		return nil
	}

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
	finding := model.Finding{
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
			"reflectionContext":   ContextURL.String(),
			"method":              http.MethodGet,
			"url":                 first.url,
			"param":               first.param,
			"payloadClass":        "open-redirect",
			"oracleName":          "active_open_redirect",
			"oracleVersion":       "v1",
		},
	}
	AttachDifferentialEvidence(&finding, diffOutcome)

	// Phase 1 pre-report verification. Canonicalise category to
	// "open_redirect" for proof-policy evaluation, restore label on emit.
	signals := []EvidenceSignal{EvidenceHeaderDelta, EvidenceReflection, EvidenceStatusDelta}
	originalCategory := finding.Category
	finding.Category = "open_redirect"
	verifyOutcome := SubmitVerifiedFinding(ctx, VerifyCandidate{
		Finding:               finding,
		Signals:               signals,
		AllowNoReplayEmission: true,
		ProbeName:             "active-open-redirect",
	})
	if verifyOutcome.Suppressed {
		return nil
	}
	emitted := verifyOutcome.EmittedFinding
	emitted.Category = originalCategory
	return []model.Finding{emitted}
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
