package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// oauthWellKnownPaths are the conventional OAuth/OIDC metadata and authorization
// endpoint paths probed on every target.
var oauthWellKnownPaths = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/oauth/authorize",
	"/oauth2/authorize",
	"/auth/authorize",
	"/connect/authorize",
	"/api/oauth/authorize",
	"/oauth/token",
	"/oauth2/token",
	"/auth/token",
	"/connect/token",
}

// oauthRedirectURIPayloads tests common redirect_uri bypass techniques.
// Each has a label and a transform function that mutates a legitimate callback URL.
type redirectURITest struct {
	label     string
	mutate    func(legit string) string
	technique string
}

var redirectURITests = []redirectURITest{
	{
		label:     "open-redirect-external",
		mutate:    func(_ string) string { return "https://attacker.example.com/callback" },
		technique: "Fully external attacker domain — no allowlist enforced",
	},
	{
		label:  "null-byte-bypass",
		mutate: func(legit string) string { return legit + "\x00@attacker.example.com" },
		technique: "Null-byte injection may terminate string comparison at server side, " +
			"allowing an attacker-controlled suffix to pass",
	},
	{
		label:     "path-traversal-bypass",
		mutate:    func(legit string) string { return legit + "/../../attacker.example.com" },
		technique: "Path-traversal appended after a registered callback prefix",
	},
	{
		label:     "wildcard-subdomain",
		mutate:    func(legit string) string { return "https://evil.attacker.example.com/callback" },
		technique: "Wildcard subdomain match if allowlist uses prefix or domain-only comparison",
	},
}

// oauthBodyLimit caps the per-response read during OAuth probing.
const oauthBodyLimit = 64 * 1024

// RunOAuthProbe is an active OAuth/OIDC security probe that tests:
//  1. redirect_uri manipulation — null-byte bypass, path-traversal, external domain.
//  2. state parameter omission — CSRF on the authorization flow.
//  3. PKCE downgrade — initiating a code flow without code_challenge.
//
// The probe is read-only (no tokens are exchanged; it only inspects whether
// the authorization server *accepts* the manipulated initiation request).
// All endpoints are scope-checked and the PassiveOnly gate is respected.
func (s *Service) RunOAuthProbe(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	// Discover OAuth/OIDC endpoints.
	endpoints := oauthDiscoverEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
	if len(endpoints) == 0 {
		return nil
	}
	for _, ep := range endpoints {
		RecordProbedKey(http.MethodGet, ep, "redirect_uri")
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("oauth-probe %s", target),
			Message: fmt.Sprintf("Probing %d OAuth/OIDC endpoints for authorization flow vulnerabilities", len(endpoints)),
		})
	}

	legitimateCallback := base.Scheme + "://" + base.Host + "/oauth/callback"

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range endpoints {
		// Probe 1: redirect_uri manipulation.
		for _, test := range redirectURITests {
			fid := "oauth-redirect-uri-" + test.label
			if emitted[fid] {
				continue
			}
			mutated := test.mutate(legitimateCallback)
			probeURL := buildOAuthAuthorizeURL(ep, mutated, "state_value_abc", "code", "openid", "")
			if !scope.IsURLInScope(probeURL, scanScope) {
				continue
			}
			candidateObs, baselines, suspicious := oauthRedirectBypassesBaseline(ctx, s, ep, mutated, legitimateCallback, auth, options)
			if suspicious {
				observedDelta := float64(absInt(len(NormalizeResponseBody(candidateObs.location+"\n"+candidateObs.body)) - len(baselines.First.Body)))
				finding := oauthFinding(
					fid,
					ep,
					"open_redirect",
					"oauth-redirect-uri-bypass",
					model.SeverityHigh,
					"OAuth redirect_uri bypass — "+test.label,
					fmt.Sprintf(
						"GET %s returned HTTP %d without an error for redirect_uri=%q, and the response differed from two benign redirect_uri control baselines. "+
							"Technique: %s. "+
							"An attacker can craft an authorization link with a poisoned redirect_uri, "+
							"causing the authorization code or access token to be delivered to an "+
							"attacker-controlled server, enabling full account takeover.",
						probeURL, candidateObs.status, mutated, test.technique,
					),
					"CWE-601",
					[]string{
						fmt.Sprintf("Navigate to: %s", probeURL),
						"Complete the OAuth login flow as a victim user.",
						fmt.Sprintf("Observe that the authorization code is delivered to %q instead of the application's registered callback.", mutated),
						"Exchange the code for a token at the /token endpoint using the attacker's client_secret.",
					},
					map[string]string{
						"mutatedRedirectURI":  mutated,
						"technique":           test.label,
						"responseStatus":      fmt.Sprintf("%d", candidateObs.status),
						"controlStatus":       fmt.Sprintf("%d", baselines.First.Status),
						"controlBodyVariance": fmt.Sprintf("%d", baselines.BodyByteVariance),
						"url":                 probeURL,
						"param":               "redirect_uri",
					},
				)
				verify := SubmitVerifiedFinding(ctx, VerifyCandidate{
					Finding:               finding,
					Signals:               []EvidenceSignal{EvidenceStatusDelta, EvidenceHeaderDelta, EvidenceBodyDelta},
					AllowNoReplayEmission: true,
					BaselineVariance:      float64(baselines.BodyByteVariance),
					ObservedDelta:         observedDelta,
					ProbeName:             "oauth_probe",
				})
				if verify.Suppressed {
					continue
				}
				emitted[fid] = true
				findings = append(findings, verify.EmittedFinding)
			}
		}

		// Probe 2: state parameter omission (CSRF on OAuth flow).
		fid := "oauth-csrf-no-state"
		if !emitted[fid] {
			probeURL := buildOAuthAuthorizeURL(ep, legitimateCallback, "", "code", "openid", "")
			if scope.IsURLInScope(probeURL, scanScope) {
				candidateObs, err := oauthFetchAuthorizeObservation(ctx, s, probeURL, auth, options)
				if err == nil {
					controlAcceptedObs, _ := oauthFetchAuthorizeObservation(ctx, s, buildOAuthAuthorizeURL(ep, legitimateCallback, "state_control", "code", "openid", ""), auth, options)
					controlRejectedObs, _ := oauthFetchAuthorizeObservation(ctx, s, buildOAuthAuthorizeURL(ep, legitimateCallback, "state_control", "unsupported_response_type", "openid", ""), auth, options)
					candidateAccepted := oauthAuthorizeLooksSuccessful(candidateObs, legitimateCallback)
					controlAccepted := oauthAuthorizeLooksSuccessful(controlAcceptedObs, legitimateCallback)
					controlRejected := oauthResponseHasError(controlRejectedObs.body) || controlRejectedObs.status >= http.StatusBadRequest
					if candidateAccepted && controlAccepted && controlRejected {
						finding := oauthFinding(
							fid,
							ep,
							"csrf",
							"oauth-state-omission",
							model.SeverityMedium,
							"OAuth CSRF — state parameter accepted as absent",
							fmt.Sprintf(
								"Authorization request to %s without a state parameter advanced the OAuth flow (HTTP %d) in the same way as a valid control request with state, while a malformed control request was rejected. "+
									"The state parameter is the primary CSRF protection for OAuth flows (RFC 6749 §10.12). "+
									"An attacker can initiate an authorization request on behalf of a victim, omit the state, and link the victim's account to the attacker's identity.",
								probeURL, candidateObs.status,
							),
							"CWE-352",
							[]string{
								"Craft an authorization URL without the `state` parameter.",
								"Deliver the link to a victim user and observe that the flow still advances to the callback or consent redirect.",
								"Compare the result with a valid `state` request and confirm the server does not reject the missing-state variant.",
							},
							map[string]string{
								"stateAbsent":           "true",
								"responseStatus":        fmt.Sprintf("%d", candidateObs.status),
								"url":                   probeURL,
								"param":                 "state",
								"controlAcceptedStatus": fmt.Sprintf("%d", controlAcceptedObs.status),
								"controlRejected":       fmt.Sprintf("%v", controlRejected),
								"controlRejectedStatus": fmt.Sprintf("%d", controlRejectedObs.status),
								"tokenCarrierTested":    "state",
							},
						)
						verify := SubmitVerifiedFinding(ctx, VerifyCandidate{
							Finding:               finding,
							Signals:               []EvidenceSignal{EvidenceStatusDelta, EvidenceHeaderDelta, EvidenceErrorSignal},
							AllowNoReplayEmission: true,
							ProbeName:             "oauth_probe",
						})
						if verify.Suppressed {
							continue
						}
						emitted[fid] = true
						findings = append(findings, verify.EmittedFinding)
					}
				}
			}
		}

		// Probe 3: PKCE downgrade — send code flow without code_challenge.
		fid = "oauth-pkce-downgrade"
		if !emitted[fid] {
			probeURL := buildOAuthAuthorizeURL(ep, legitimateCallback, "state_xyz", "code", "openid", "")
			// Note: deliberately no code_challenge parameter.
			if scope.IsURLInScope(probeURL, scanScope) {
				candidateObs, err := oauthFetchAuthorizeObservation(ctx, s, probeURL, auth, options)
				if err == nil {
					validControlURL := buildOAuthAuthorizeURL(ep, legitimateCallback, "state_xyz", "code", "openid", "abh-valid-pkce")
					validControlObs, _ := oauthFetchAuthorizeObservation(ctx, s, validControlURL, auth, options)
					invalidControlURL := buildOAuthAuthorizeURLWithExtras(ep, legitimateCallback, "state_xyz", "code", "openid", "abh-invalid-pkce", map[string]string{
						"code_challenge_method": "plain-invalid",
					})
					invalidControlObs, _ := oauthFetchAuthorizeObservation(ctx, s, invalidControlURL, auth, options)
					candidateAccepted := oauthAuthorizeLooksSuccessful(candidateObs, legitimateCallback)
					validControlAccepted := oauthAuthorizeLooksSuccessful(validControlObs, legitimateCallback)
					invalidControlRejected := oauthResponseHasError(invalidControlObs.body) || invalidControlObs.status >= http.StatusBadRequest
					if candidateAccepted && validControlAccepted && invalidControlRejected {
						finding := oauthFinding(
							fid,
							ep,
							"authentication",
							"oauth-pkce-downgrade",
							model.SeverityMedium,
							"OAuth PKCE not enforced — code_challenge not required",
							fmt.Sprintf(
								"Authorization endpoint %s advanced an authorization request without a code_challenge parameter (HTTP %d) in the same way as a valid PKCE control, while a malformed PKCE control was rejected. "+
									"Without PKCE enforcement, a public client (mobile app, SPA) is vulnerable to authorization code interception because a malicious app can capture and exchange the code without possessing the code_verifier (RFC 7636).",
								probeURL, candidateObs.status,
							),
							"CWE-863",
							[]string{
								"Initiate an authorization flow from a public client without `code_challenge`.",
								"Compare the result with a valid PKCE request and confirm the server advances both flows.",
								"Verify that a malformed PKCE control is rejected while the missing-PKCE flow is not.",
							},
							map[string]string{
								"codeChallengeAbsent":    "true",
								"responseStatus":         fmt.Sprintf("%d", candidateObs.status),
								"url":                    probeURL,
								"param":                  "code_challenge",
								"validControlStatus":     fmt.Sprintf("%d", validControlObs.status),
								"invalidControlRejected": fmt.Sprintf("%v", invalidControlRejected),
								"invalidControlStatus":   fmt.Sprintf("%d", invalidControlObs.status),
							},
						)
						verify := SubmitVerifiedFinding(ctx, VerifyCandidate{
							Finding:               finding,
							Signals:               []EvidenceSignal{EvidenceStatusDelta, EvidenceHeaderDelta, EvidenceErrorSignal},
							AllowNoReplayEmission: true,
							ProbeName:             "oauth_probe",
						})
						if verify.Suppressed {
							continue
						}
						emitted[fid] = true
						findings = append(findings, verify.EmittedFinding)
					}
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// oauthDiscoverEndpoints collects candidate OAuth/OIDC authorization endpoints
// from the well-known paths list and the seeded runtime endpoints.
func oauthDiscoverEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
	out := make([]string, 0)
	seen := map[string]struct{}{}

	for _, path := range oauthWellKnownPaths {
		ref, err := url.Parse(path)
		if err != nil {
			continue
		}
		ep := base.ResolveReference(ref).String()
		if _, ok := seen[ep]; ok {
			continue
		}
		if !scope.IsURLInScope(ep, scanScope) {
			continue
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}

	for _, s := range seeded {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		lower := strings.ToLower(s)
		if !strings.Contains(lower, "oauth") && !strings.Contains(lower, "oidc") &&
			!strings.Contains(lower, "authorize") && !strings.Contains(lower, "connect") &&
			!strings.Contains(lower, "openid") && !strings.Contains(lower, "token") {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		if !scope.IsURLInScope(s, scanScope) {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	return out
}

// buildOAuthAuthorizeURL constructs an authorization initiation URL.
func buildOAuthAuthorizeURL(ep, redirectURI, state, responseType, scope_, codeChallenge string) string {
	return buildOAuthAuthorizeURLWithExtras(ep, redirectURI, state, responseType, scope_, codeChallenge, nil)
}

func buildOAuthAuthorizeURLWithExtras(ep, redirectURI, state, responseType, scope_, codeChallenge string, extras map[string]string) string {
	u, err := url.Parse(ep)
	if err != nil {
		return ep
	}
	q := url.Values{}
	q.Set("client_id", "autobughunter-probe")
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	if state != "" {
		q.Set("state", state)
	}
	if responseType != "" {
		q.Set("response_type", responseType)
	}
	if scope_ != "" {
		q.Set("scope", scope_)
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	for k, v := range extras {
		if strings.TrimSpace(v) == "" {
			q.Del(k)
			continue
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// oauthResponseHasError returns true when the response body contains an OAuth
// error indicator, which means the server correctly rejected the manipulated
// request.
type oauthAuthorizeObservation struct {
	status   int
	location string
	body     string
}

func oauthFetchAuthorizeObservation(ctx context.Context, s *Service, probeURL string, auth model.ScanAuthProfile, options model.ScanOptions) (oauthAuthorizeObservation, error) {
	if strings.TrimSpace(probeURL) == "" {
		return oauthAuthorizeObservation{}, fmt.Errorf("empty probe url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return oauthAuthorizeObservation{}, err
	}
	ApplyAuthProfile(req, auth)
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		if err == nil {
			err = fmt.Errorf("nil response")
		}
		return oauthAuthorizeObservation{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthBodyLimit))
	return oauthAuthorizeObservation{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(body)}, nil
}

func oauthRedirectBypassesBaseline(ctx context.Context, s *Service, authorizeEndpoint, candidateRedirectURI, benignRedirectURI string, auth model.ScanAuthProfile, options model.ScanOptions) (oauthAuthorizeObservation, BaselineControls, bool) {
	candidateURL := buildOAuthAuthorizeURL(authorizeEndpoint, candidateRedirectURI, "state_value_abc", "code", "openid", "")
	if strings.TrimSpace(candidateURL) == "" {
		return oauthAuthorizeObservation{}, BaselineControls{}, false
	}
	fetchBaseline := func(fetchCtx context.Context) (BaselineSample, error) {
		controlURL := buildOAuthAuthorizeURL(authorizeEndpoint, benignRedirectURI, "state_value_abc", "code", "openid", "")
		obs, err := oauthFetchAuthorizeObservation(fetchCtx, s, controlURL, auth, options)
		if err != nil {
			return BaselineSample{}, err
		}
		return BaselineSample{Status: obs.status, Header: http.Header{"Location": []string{obs.location}}, Body: obs.location + "\n" + obs.body}, nil
	}
	baselines, err := CaptureTwoControlBaselines(ctx, fetchBaseline)
	if err != nil {
		return oauthAuthorizeObservation{}, BaselineControls{}, false
	}
	candidateObs, err := oauthFetchAuthorizeObservation(ctx, s, candidateURL, auth, options)
	if err != nil {
		return oauthAuthorizeObservation{}, baselines, false
	}
	if !is2xxOrRedirect(candidateObs.status) || oauthResponseHasError(candidateObs.body) {
		return candidateObs, baselines, false
	}
	candidateBody := NormalizeResponseBody(candidateObs.location + "\n" + candidateObs.body)
	observedDelta := float64(absInt(len(candidateBody) - len(baselines.First.Body)))
	statusDiff := !baselines.StatusStable || candidateObs.status != baselines.First.Status
	locationDiff := candidateObs.location != baselines.First.Header.Get("Location")
	bodyDiff := ExceedsControlVariance(observedDelta, float64(baselines.BodyByteVariance))
	return candidateObs, baselines, statusDiff || locationDiff || bodyDiff
}

func oauthResponseHasError(body string) bool {
	lower := strings.ToLower(body)
	for _, kw := range []string{
		`"error"`, "invalid_request", "invalid_redirect_uri", "redirect_uri_mismatch",
		"access_denied", "unauthorized_client", "unsupported_response_type",
		"invalid_client", "invalid_grant",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func oauthAuthorizeLooksSuccessful(obs oauthAuthorizeObservation, legitimateCallback string) bool {
	if !is2xxOrRedirect(obs.status) || oauthResponseHasError(obs.body) {
		return false
	}
	location := strings.TrimSpace(strings.ToLower(obs.location))
	body := strings.TrimSpace(strings.ToLower(obs.body))
	if legitimateCallback != "" {
		callback := strings.ToLower(strings.TrimSpace(legitimateCallback))
		if strings.Contains(location, strings.ToLower(callback)) {
			return true
		}
	}
	for _, token := range []string{"code=", "access_token=", "id_token=", `"code"`, `"access_token"`, `"id_token"`} {
		if strings.Contains(location, token) || strings.Contains(body, token) {
			return true
		}
	}
	return false
}

func is2xxOrRedirect(code int) bool {
	return (code >= 200 && code < 300) || (code >= 300 && code < 400)
}

// oauthFinding constructs an OAuth/OIDC probe finding.
func oauthFinding(
	id, endpoint string,
	category string,
	payloadClass string,
	severity model.Severity,
	title, evidence, cwe string,
	steps []string,
	extra map[string]string,
) model.Finding {
	ef := map[string]string{
		"validationType": "active-probe",
		"reproStep":      "Replay the manipulated authorization request and observe whether the server rejects it",
		"method":         http.MethodGet,
		"url":            endpoint,
		"payloadClass":   payloadClass,
		"oracleName":     "oauth_probe",
		"oracleVersion":  "v1",
	}
	for k, v := range extra {
		ef[k] = v
	}
	return model.Finding{
		ID:       id,
		Category: category,
		Severity: severity,
		Title:    title,
		Description: "The OAuth/OIDC authorization server accepted a manipulated authorization initiation request. " +
			"This class of vulnerability enables authorization-code theft, account takeover, and CSRF attacks " +
			"against users who interact with the application's OAuth flow.",
		Evidence: evidence,
		Recommendation: "Enforce exact-match redirect_uri allowlisting — never accept wildcard, path-traversal, or unregistered URIs. " +
			"Require the state parameter on every authorization request and validate it on the callback. " +
			"Enforce PKCE (RFC 7636) for all public clients.",
		Confidence:        0.82,
		AffectedURL:       endpoint,
		AffectedParameter: ef["param"],
		CWE:               cwe,
		OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
		Sources:           []string{"active-scanner", "oauth-probe"},
		ReproductionSteps: steps,
		BusinessTags:      []string{"oauth", "oidc", "auth-flow"},
		EvidenceFields:    ef,
	}
}
