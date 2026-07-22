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

// oauthSessionBodyLimit caps per-probe response reads for the OAuth session probe.
const oauthSessionBodyLimit = 64 * 1024

// oauthRevocationPaths are well-known OAuth/OIDC token revocation and logout endpoints.
var oauthRevocationPaths = []string{
	"/oauth2/revoke",
	"/oauth/revoke",
	"/connect/revocation",
	"/connect/endsession",
	"/logout",
	"/api/logout",
	"/auth/logout",
	"/signout",
	"/api/auth/logout",
}

// oauthTokenPaths are well-known token exchange endpoints.
var oauthTokenPaths = []string{
	"/oauth/token",
	"/oauth2/token",
	"/auth/token",
	"/connect/token",
	"/api/oauth/token",
}

// RunOAuthSessionProbe tests OAuth/OIDC session replay and token hijacking
// vulnerabilities beyond the authorization initiation phase:
//
//  1. Authorization code replay — submit a synthetic code twice; correct AS
//     must reject the second attempt with invalid_grant.
//  2. Implicit flow / token-in-URL — send response_type=token; token in
//     Location/body enables history/referrer leakage.
//  3. OIDC nonce omission — initiate code+id_token flow without nonce;
//     acceptance enables cross-session token replay.
//  4. Post-logout token reuse — call revocation/logout, then replay the
//     original ******; 200 means revocation is not enforced.
//  5. Refresh token replay — submit grant_type=refresh_token twice; second
//     call must fail with invalid_grant.
//  6. Token endpoint CORS — OPTIONS preflight with attacker Origin; wildcard
//     or reflected ACAO enables cross-origin token exchange.
//  7. Audience confusion — present a token (or forged JWT) without aud claim
//     to the target resource; acceptance means aud is not validated.
func (s *Service) RunOAuthSessionProbe(
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

	// Discover token endpoints.
	tokenEndpoints := oauthDiscoverTokenEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
	if len(tokenEndpoints) == 0 && !hasOAuthAuthorizeEndpoints(base, options.SeedRuntimeEndpoints, scanScope) {
		return nil
	}
	for _, ep := range tokenEndpoints {
		RecordProbedKey(http.MethodPost, ep, "")
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("oauth-session-probe %s", target),
			Message: "Probing OAuth/OIDC session replay and token hijacking vulnerabilities",
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}
	appendVerified := func(f model.Finding, signals []EvidenceSignal) {
		out := SubmitVerifiedFinding(ctx, VerifyCandidate{
			Finding:               f,
			Signals:               signals,
			AllowNoReplayEmission: true,
			ProbeName:             "oauth_session_probe",
		})
		if !out.Suppressed {
			findings = append(findings, out.EmittedFinding)
		}
	}

	// ── Probe 1: Authorization code replay ─────────────────────────────────
	for _, ep := range tokenEndpoints {
		fid := "oauth-code-replay"
		if emitted[fid] {
			break
		}
		// We can't obtain a real code without user interaction; instead we probe
		// whether the server gives distinct error responses for first vs. second
		// use by submitting a synthetic code twice and comparing responses.
		syntheticCode := "abh-probe-code-replay-test"
		body1 := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {syntheticCode},
			"redirect_uri": {"https://abh-probe.invalid/callback"},
			"client_id":    {"abh-probe"},
		}
		resp1 := oauthPostForm(ctx, s, ep, body1, auth, options)
		resp2 := oauthPostForm(ctx, s, ep, body1, auth, options)

		if resp1 != nil && resp2 != nil {
			// Both returned; if both return the SAME non-error body with no
			// invalid_grant signal the server may not track code use.
			body1Str := strings.ToLower(resp1.body)
			body2Str := strings.ToLower(resp2.body)
			// If neither response contains invalid_grant/code_not_found/used
			// and both look identical in status, flag as candidate.
			noError1 := !oauthTokenResponseHasError(body1Str)
			noError2 := !oauthTokenResponseHasError(body2Str)
			controlCode := RandomMarker()
			controlBody := url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {controlCode},
				"redirect_uri": {"https://abh-probe.invalid/callback"},
				"client_id":    {"abh-probe"},
			}
			controlResp := oauthPostForm(ctx, s, ep, controlBody, auth, options)
			controlAccepted := controlResp != nil && controlResp.status >= 200 && controlResp.status < 300 && !oauthTokenResponseHasError(strings.ToLower(controlResp.body))
			if noError1 && noError2 && resp1.status == resp2.status &&
				resp1.status >= 200 && resp1.status < 300 && !controlAccepted {
				controlStatus := "0"
				if controlResp != nil {
					controlStatus = fmt.Sprintf("%d", controlResp.status)
				}
				emitted[fid] = true
				appendVerified(oauthSessionFinding(
					fid, ep, model.SeverityHigh,
					"OAuth authorization code accepted on replay",
					fmt.Sprintf(
						"The token endpoint %s accepted a synthetic authorization code on two "+
							"successive requests without returning an invalid_grant error on the "+
							"second attempt (HTTP %d both times), while a clearly invalid control code was rejected. A correctly implemented "+
							"authorization server must mark codes as consumed after the first "+
							"exchange, preventing replay attacks.",
						ep, resp2.status,
					),
					"CWE-294",
					[]string{
						"Obtain a legitimate authorization code from the /authorize endpoint.",
						"Exchange the code at " + ep + " for an access token.",
						"Submit the same code a second time — the server should return invalid_grant.",
						"If the second exchange also succeeds, the server does not enforce single-use codes.",
					},
					map[string]string{
						"tokenEndpoint":       ep,
						"syntheticCode":       syntheticCode,
						"firstStatus":         fmt.Sprintf("%d", resp1.status),
						"secondStatus":        fmt.Sprintf("%d", resp2.status),
						"controlCodeRejected": "true",
						"controlStatus":       controlStatus,
					},
				), []EvidenceSignal{EvidenceStatusDelta, EvidenceErrorSignal})
			}
		}
	}

	// ── Probe 2: Implicit flow / token-in-URL ───────────────────────────────
	authorizeEndpoints := oauthDiscoverAuthorizeEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
	for _, ep := range authorizeEndpoints {
		RecordProbedKey(http.MethodGet, ep, "")
	}
	for _, ep := range authorizeEndpoints {
		fid := "oauth-implicit-flow"
		if emitted[fid] {
			break
		}
		legitimateCallback := base.Scheme + "://" + base.Host + "/oauth/callback"
		probeURL := buildOAuthAuthorizeURL(ep, legitimateCallback, "state_abc", "token", "openid", "")
		if !scope.IsURLInScope(probeURL, scanScope) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, auth)
		resp, err := s.doRequestWithRetry(ctx, req, options)
		if err != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthSessionBodyLimit))
		_ = resp.Body.Close()

		bodyStr := string(body)
		locationHdr := resp.Header.Get("Location")
		implicitAccepted := is2xxOrRedirect(resp.StatusCode) && !oauthResponseHasError(bodyStr)
		tokenInResponse := strings.Contains(locationHdr, "access_token=") ||
			strings.Contains(bodyStr, "access_token") ||
			strings.Contains(bodyStr, `"token_type"`)

		if implicitAccepted && tokenInResponse {
			emitted[fid] = true
			appendVerified(oauthSessionFinding(
				fid, ep, model.SeverityMedium,
				"OAuth implicit flow accepted — access token exposed in redirect URL",
				fmt.Sprintf(
					"The authorization endpoint %s accepted response_type=token (implicit grant) "+
						"and returned an access token in the redirect URL or response body "+
						"(HTTP %d). Tokens in URLs are recorded in browser history, "+
						"server access logs, and Referer headers, enabling token theft by "+
						"any party with access to those artifacts.",
					ep, resp.StatusCode,
				),
				"CWE-522",
				[]string{
					"Navigate to: " + probeURL,
					"Observe access_token= in the redirect Location header or response body.",
					"Access the browser history or server access log to confirm the token was recorded.",
				},
				map[string]string{
					"authorizeEndpoint": ep,
					"responseStatus":    fmt.Sprintf("%d", resp.StatusCode),
					"tokenInLocation":   fmt.Sprintf("%v", strings.Contains(locationHdr, "access_token=")),
				},
			), []EvidenceSignal{EvidenceStatusDelta, EvidenceReflection})
		}
	}

	// ── Probe 3: OIDC nonce omission ───────────────────────────────────────
	for _, ep := range authorizeEndpoints {
		fid := "oidc-nonce-omission"
		if emitted[fid] {
			break
		}
		legitimateCallback := base.Scheme + "://" + base.Host + "/oauth/callback"
		// response_type=code id_token triggers nonce requirement per OIDC spec.
		probeURL := buildOAuthAuthorizeURL(ep, legitimateCallback, "state_xyz", "code id_token", "openid", "")
		if !scope.IsURLInScope(probeURL, scanScope) {
			continue
		}
		candidateObs, err := oauthFetchAuthorizeObservation(ctx, s, probeURL, auth, options)
		if err != nil {
			continue
		}
		validControlURL := buildOAuthAuthorizeURLWithExtras(ep, legitimateCallback, "state_xyz", "code id_token", "openid", "", map[string]string{
			"nonce": "abh-valid-nonce",
		})
		validControlObs, _ := oauthFetchAuthorizeObservation(ctx, s, validControlURL, auth, options)
		rejectedControlObs, _ := oauthFetchAuthorizeObservation(ctx, s, buildOAuthAuthorizeURL(ep, legitimateCallback, "state_xyz", "unsupported_response_type", "openid", ""), auth, options)
		if oauthAuthorizeLooksSuccessful(candidateObs, legitimateCallback) &&
			oauthAuthorizeLooksSuccessful(validControlObs, legitimateCallback) &&
			(oauthResponseHasError(rejectedControlObs.body) || rejectedControlObs.status >= http.StatusBadRequest) {
			emitted[fid] = true
			appendVerified(oauthSessionFinding(
				fid, ep, model.SeverityMedium,
				"OIDC hybrid flow accepted without nonce — id_token replay possible",
				fmt.Sprintf(
					"The authorization endpoint %s accepted a hybrid flow request "+
						"(response_type=code id_token) without a nonce parameter (HTTP %d), advanced it like a valid nonce-bearing control, "+
						"and rejected a malformed control request. The nonce binds an "+
						"id_token to a specific browser session; without it an attacker "+
						"who obtains an id_token can replay it across sessions.",
					ep, candidateObs.status,
				),
				"CWE-294",
				[]string{
					"Initiate an OIDC hybrid flow without the nonce parameter.",
					"Compare the result with a valid nonce-bearing hybrid-flow request and confirm both are accepted.",
					"Verify that a malformed control request is rejected while the missing-nonce flow is not.",
					"Present the resulting id_token to a different session or application to demonstrate cross-session replay.",
				},
				map[string]string{
					"authorizeEndpoint":     ep,
					"responseType":          "code id_token",
					"nonceAbsent":           "true",
					"responseStatus":        fmt.Sprintf("%d", candidateObs.status),
					"validControlStatus":    fmt.Sprintf("%d", validControlObs.status),
					"rejectedControlStatus": fmt.Sprintf("%d", rejectedControlObs.status),
				},
			), []EvidenceSignal{EvidenceStatusDelta, EvidenceHeaderDelta, EvidenceErrorSignal})
		}
	}

	// ── Probe 4: Post-logout / revocation non-enforcement ──────────────────
	fid := "oauth-revocation-not-enforced"
	if !emitted[fid] {
		bearerToken := oauthExtractBearerToken(auth)
		if bearerToken != "" {
			revoked := false
			for _, path := range oauthRevocationPaths {
				revEP := base.ResolveReference(&url.URL{Path: path}).String()
				if !scope.IsURLInScope(revEP, scanScope) {
					continue
				}
				rBody := url.Values{"token": {bearerToken}, "token_type_hint": {"access_token"}}
				revokeResp := oauthPostForm(ctx, s, revEP, rBody, auth, options)
				if revokeResp != nil && (revokeResp.status == 200 || revokeResp.status == 204) {
					revoked = true
					break
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, revEP, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, auth)
				resp, err := s.doRequestWithRetry(ctx, req, options)
				if err == nil && resp != nil {
					_ = resp.Body.Close()
					if resp.StatusCode == 200 || resp.StatusCode == 204 || resp.StatusCode == 302 {
						revoked = true
						break
					}
				}
			}
			if revoked {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					goto refreshProbe
				}
				req.Header.Set("Authorization", "Bearer "+bearerToken)
				resp, err := s.doRequestWithRetry(ctx, req, options)
				if err != nil || resp == nil {
					goto refreshProbe
				}
				replayBody, _ := io.ReadAll(io.LimitReader(resp.Body, oauthSessionBodyLimit))
				_ = resp.Body.Close()
				controlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					goto refreshProbe
				}
				controlReq.Header.Set("Authorization", "Bearer "+RandomMarker())
				controlResp, err := s.doRequestWithRetry(ctx, controlReq, options)
				if err != nil || controlResp == nil {
					goto refreshProbe
				}
				controlBody, _ := io.ReadAll(io.LimitReader(controlResp.Body, oauthSessionBodyLimit))
				_ = controlResp.Body.Close()
				controlAccepted := controlResp.StatusCode >= 200 && controlResp.StatusCode < 300 &&
					!strings.Contains(strings.ToLower(string(controlBody)), "unauthorized") &&
					!strings.Contains(strings.ToLower(string(controlBody)), "invalid_token")
				if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
					!strings.Contains(strings.ToLower(string(replayBody)), "unauthorized") &&
					!strings.Contains(strings.ToLower(string(replayBody)), "invalid_token") &&
					!controlAccepted {
					emitted[fid] = true
					appendVerified(oauthSessionFinding(
						fid, target, model.SeverityHigh,
						"OAuth token accepted after revocation — revocation not enforced",
						fmt.Sprintf(
							"An access token was submitted to a revocation/logout endpoint (HTTP 200/204 returned) but was subsequently accepted by the resource at %s (HTTP %d), while a clearly invalid bearer control was rejected. Revoked tokens must be rejected immediately; failure to do so means a stolen token remains valid indefinitely after logout.",
							target, resp.StatusCode,
						),
						"CWE-613",
						[]string{
							"Authenticate and obtain an access token.",
							"Call the revocation/logout endpoint with the token.",
							"Replay the token against a protected resource.",
							"Observe that the resource still returns 200, confirming revocation is not enforced.",
						},
						map[string]string{
							"validationType":       "active-probe",
							"replayStatus":         fmt.Sprintf("%d", resp.StatusCode),
							"controlTokenRejected": "true",
							"controlStatus":        fmt.Sprintf("%d", controlResp.StatusCode),
						},
					), []EvidenceSignal{EvidenceStatusDelta, EvidenceErrorSignal})
				}
			}
		}
	}

refreshProbe:
	// ── Probe 5: Refresh token replay ──────────────────────────────────────
	fid = "oauth-refresh-token-replay"
	if !emitted[fid] {
		refreshToken := oauthExtractRefreshToken(auth)
		if refreshToken != "" {
			for _, ep := range tokenEndpoints {
				body1 := url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {refreshToken},
					"client_id":     {"abh-probe"},
				}
				r1 := oauthPostForm(ctx, s, ep, body1, auth, options)
				r2 := oauthPostForm(ctx, s, ep, body1, auth, options)
				if r1 != nil && r2 != nil {
					// If both succeed (or both give the same non-revoked response)
					// the refresh token is not single-use.
					controlBody := url.Values{
						"grant_type":    {"refresh_token"},
						"refresh_token": {RandomMarker()},
						"client_id":     {"abh-probe"},
					}
					controlResp := oauthPostForm(ctx, s, ep, controlBody, auth, options)
					controlAccepted := controlResp != nil && controlResp.status >= 200 && controlResp.status < 300 && !oauthTokenResponseHasError(strings.ToLower(controlResp.body))
					if r1.status >= 200 && r1.status < 300 &&
						r2.status >= 200 && r2.status < 300 &&
						!oauthTokenResponseHasError(strings.ToLower(r2.body)) && !controlAccepted {
						controlStatus := "0"
						if controlResp != nil {
							controlStatus = fmt.Sprintf("%d", controlResp.status)
						}
						emitted[fid] = true
						appendVerified(oauthSessionFinding(
							fid, ep, model.SeverityHigh,
							"OAuth refresh token accepted on replay — rotation not enforced",
							fmt.Sprintf(
								"The token endpoint %s accepted the same refresh_token value "+
									"twice without returning invalid_grant on the second attempt "+
									"(HTTP %d both times), while a clearly invalid control refresh token was rejected. Refresh token rotation (RFC 6749 §10.4) "+
									"requires that each use of a refresh token issue a new one and "+
									"invalidate the old, preventing replay by a token thief.",
								ep, r2.status,
							),
							"CWE-294",
							[]string{
								"Obtain a refresh token during authentication.",
								"Exchange it at " + ep + " for a new access token.",
								"Submit the same refresh token a second time.",
								"Observe that the server issues a new access token instead of returning invalid_grant.",
							},
							map[string]string{
								"tokenEndpoint":        ep,
								"firstStatus":          fmt.Sprintf("%d", r1.status),
								"secondStatus":         fmt.Sprintf("%d", r2.status),
								"controlTokenRejected": "true",
								"controlStatus":        controlStatus,
							},
						), []EvidenceSignal{EvidenceStatusDelta, EvidenceErrorSignal})
						break
					}
				}
			}
		}
	}

	// ── Probe 6: Token endpoint CORS ───────────────────────────────────────
	fid = "oauth-token-endpoint-cors"
	if !emitted[fid] {
		for _, ep := range tokenEndpoints {
			if !scope.IsURLInScope(ep, scanScope) {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodOptions, ep, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Origin", "https://attacker.example.com")
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", "content-type,authorization")
			ApplyAuthProfile(req, auth)
			resp, err := s.doRequestWithRetry(ctx, req, options)
			if err != nil || resp == nil {
				continue
			}
			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acah := strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers"))
			acam := strings.ToLower(resp.Header.Get("Access-Control-Allow-Methods"))
			_ = resp.Body.Close()
			allowsOrigin := acao == "*" || strings.EqualFold(acao, "https://attacker.example.com")
			allowsMethod := strings.Contains(acam, "post") || strings.Contains(acam, "*")
			allowsHeaders := strings.Contains(acah, "authorization") || strings.Contains(acah, "content-type") || strings.Contains(acah, "*")
			if allowsOrigin && allowsMethod && allowsHeaders {
				emitted[fid] = true
				appendVerified(oauthSessionFinding(
					fid, ep, model.SeverityMedium,
					"OAuth token endpoint allows cross-origin requests from arbitrary origins",
					fmt.Sprintf(
						"The token endpoint %s responded to a CORS preflight from "+
							"https://attacker.example.com with Access-Control-Allow-Origin: %q, Access-Control-Allow-Methods: %q, and Access-Control-Allow-Headers: %q. "+
							"This allows a malicious page to exchange authorization codes for "+
							"access tokens cross-origin using the victim's browser credentials.",
						ep, acao, resp.Header.Get("Access-Control-Allow-Methods"), resp.Header.Get("Access-Control-Allow-Headers"),
					),
					"CWE-942",
					[]string{
						"From a malicious page at https://attacker.example.com, issue a cross-origin POST to " + ep + ".",
						"Observe that the browser permits the response due to the permissive CORS policy.",
						"Use the obtained access token to act as the victim user.",
					},
					map[string]string{
						"tokenEndpoint":             ep,
						"accessControlAllowOrigin":  acao,
						"accessControlAllowMethods": resp.Header.Get("Access-Control-Allow-Methods"),
						"accessControlAllowHeaders": resp.Header.Get("Access-Control-Allow-Headers"),
						"attackerOrigin":            "https://attacker.example.com",
					},
				), []EvidenceSignal{EvidenceHeaderDelta, EvidenceStatusDelta, EvidenceErrorSignal})
				break
			}
		}
	}

	// ── Probe 7: Audience confusion ────────────────────────────────────────
	fid = "oauth-audience-confusion"
	if !emitted[fid] {
		bearerToken := oauthExtractBearerToken(auth)
		if isJWT(bearerToken) {
			_, payload, _, err := parseJWT(bearerToken)
			if err == nil {
				if _, hasAud := payload["aud"]; !hasAud {
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
					if err == nil {
						req.Header.Set("Authorization", "Bearer "+bearerToken)
						resp, err := s.doRequestWithRetry(ctx, req, options)
						if err == nil && resp != nil {
							candidateStatus := resp.StatusCode
							_ = resp.Body.Close()

							controlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
							if err == nil {
								controlReq.Header.Set("Authorization", "Bearer "+RandomMarker())
								controlResp, err := s.doRequestWithRetry(ctx, controlReq, options)
								if err == nil && controlResp != nil {
									controlBody, _ := io.ReadAll(io.LimitReader(controlResp.Body, oauthSessionBodyLimit))
									_ = controlResp.Body.Close()
									controlAccepted := controlResp.StatusCode >= 200 && controlResp.StatusCode < 300 &&
										!strings.Contains(strings.ToLower(string(controlBody)), "unauthorized")
									if candidateStatus >= 200 && candidateStatus < 300 && !controlAccepted {
										emitted[fid] = true
										appendVerified(oauthSessionFinding(
											fid, target, model.SeverityHigh,
											"JWT accepted without audience (aud) claim — audience validation missing",
											fmt.Sprintf(
												"The resource at %s accepted a JWT bearer token that contains no audience (aud) claim (HTTP %d). Without aud validation, a token issued for one service can be replayed at any other service that trusts the same issuer, enabling cross-service impersonation and privilege escalation.",
												target, candidateStatus,
											),
											"CWE-290",
											[]string{
												"Obtain an access token from the authorization server.",
												"Remove the aud claim from the JWT (or obtain a token without one).",
												"Present the token to a different resource server that trusts the same issuer.",
												"Observe that the resource server accepts the token.",
											},
											map[string]string{
												"audClaimPresent":      "false",
												"responseStatus":       fmt.Sprintf("%d", candidateStatus),
												"controlTokenRejected": "true",
												"controlStatus":        fmt.Sprintf("%d", controlResp.StatusCode),
											},
										), []EvidenceSignal{EvidenceStatusDelta, EvidenceErrorSignal})
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return findings
}

// oauthSessionFinding builds a standardized Finding for the OAuth session probe.
func oauthSessionFinding(
	id, endpoint string,
	severity model.Severity,
	title, evidence, cwe string,
	steps []string,
	extra map[string]string,
) model.Finding {
	ef := map[string]string{
		"validationType": "active-probe",
		"reproStep":      "Replay the manipulated OAuth request and observe whether the server rejects it",
		"method":         http.MethodPost,
		"url":            endpoint,
		"oracleName":     "oauth_session_probe",
		"oracleVersion":  "v1",
	}
	for k, v := range extra {
		ef[k] = v
	}
	return model.Finding{
		ID:       id,
		Category: "authentication",
		Severity: severity,
		Title:    title,
		Description: "The OAuth/OIDC authorization server or resource server failed to enforce a token lifecycle control. " +
			"This class of vulnerability enables session replay, token hijacking, and cross-service impersonation.",
		Evidence: evidence,
		Recommendation: "Enforce single-use authorization codes with immediate invalidation after exchange. " +
			"Require and validate the nonce claim in id_tokens for hybrid flows. " +
			"Implement token revocation and verify revoked tokens are rejected by all resource servers. " +
			"Enforce refresh token rotation and require the aud claim on all JWTs.",
		Confidence:        0.80,
		AffectedURL:       endpoint,
		CWE:               cwe,
		OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
		Sources:           []string{"active-scanner", "oauth-session-probe"},
		ReproductionSteps: steps,
		BusinessTags:      []string{"oauth", "oidc", "session-replay", "token-hijacking"},
		EvidenceFields:    ef,
	}
}

// oauthTokenResponseHasError returns true when a token endpoint response body
// contains an OAuth error indicator.
func oauthTokenResponseHasError(lower string) bool {
	for _, kw := range []string{
		`"error"`, "invalid_grant", "invalid_token", "token_expired",
		"invalid_request", "unauthorized_client",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// oauthPostFormResult holds the status code and body of a form POST.
type oauthPostFormResult struct {
	status int
	body   string
}

// oauthPostForm issues a form-encoded POST to ep and returns the result.
func oauthPostForm(ctx context.Context, s *Service, ep string, values url.Values, auth model.ScanAuthProfile, options model.ScanOptions) *oauthPostFormResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(values.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ApplyAuthProfile(req, auth)
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthSessionBodyLimit))
	_ = resp.Body.Close()
	return &oauthPostFormResult{status: resp.StatusCode, body: string(body)}
}

// oauthDiscoverTokenEndpoints returns in-scope token exchange endpoints.
func oauthDiscoverTokenEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, path := range oauthTokenPaths {
		ref, _ := url.Parse(path)
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
		lower := strings.ToLower(s)
		if strings.Contains(lower, "token") {
			if _, ok := seen[s]; !ok && scope.IsURLInScope(s, scanScope) {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}

// oauthDiscoverAuthorizeEndpoints returns in-scope authorization endpoints.
func oauthDiscoverAuthorizeEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, path := range oauthWellKnownPaths {
		if !strings.Contains(path, "authorize") {
			continue
		}
		ref, _ := url.Parse(path)
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
		lower := strings.ToLower(s)
		if strings.Contains(lower, "authorize") || strings.Contains(lower, "auth") {
			if _, ok := seen[s]; !ok && scope.IsURLInScope(s, scanScope) {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}

// hasOAuthAuthorizeEndpoints returns true if any in-scope authorize endpoints exist.
func hasOAuthAuthorizeEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) bool {
	return len(oauthDiscoverAuthorizeEndpoints(base, seeded, scanScope)) > 0
}

// oauthExtractBearerToken returns the ****** from the auth profile if present.
func oauthExtractBearerToken(auth model.ScanAuthProfile) string {
	for _, k := range []string{"Authorization", "authorization"} {
		if v := auth.Headers[k]; strings.HasPrefix(strings.ToLower(v), "bearer ") {
			return v[7:]
		}
	}
	return ""
}

// oauthExtractRefreshToken returns a refresh_token from auth profile cookies if present.
func oauthExtractRefreshToken(auth model.ScanAuthProfile) string {
	for k, v := range auth.Cookies {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "refresh") && v != "" {
			return v
		}
	}
	for k, v := range auth.Headers {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "refresh") && v != "" {
			return v
		}
	}
	return ""
}
