package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// magicLinkBodyLimit caps per-probe response reads for the magic-link probe.
const magicLinkBodyLimit = 64 * 1024

// magicLinkPaths are conventional passwordless / magic-link initiation paths.
var magicLinkPaths = []string{
	"/magic-link",
	"/magic_link",
	"/api/auth/magic",
	"/api/auth/magic-link",
	"/api/magic-link",
	"/api/passwordless",
	"/passwordless",
	"/api/auth/passwordless",
	"/api/auth/email",
	"/api/auth/otp/email",
}

// invitePaths are conventional invitation endpoint paths.
var invitePaths = []string{
	"/api/invite",
	"/api/invitations",
	"/api/user/invite",
	"/api/team/invite",
	"/invite",
	"/invitations",
	"/signup/invite",
}

// accountLinkPaths are conventional account-linking / OAuth-connect paths.
var accountLinkPaths = []string{
	"/account/link",
	"/oauth/link",
	"/connect/provider",
	"/api/account/link",
	"/api/oauth/link",
	"/api/connect",
	"/auth/link",
	"/api/social/link",
}

// magicLinkTokenFieldNames are JSON/query-parameter names for magic-link tokens.
var magicLinkTokenFieldNames = []string{
	"token", "magic_token", "magicToken", "link_token", "linkToken",
	"t", "code", "otp", "verification_token", "verificationToken",
}

// RunMagicLinkProbe tests magic-link, invite-token, and account-linking
// security weaknesses:
//
//  1. Magic link token in response body — token leaked before email delivery.
//  2. Magic link token reuse — same token accepted twice.
//  3. Invite token not bound to invitee — accepted for different email.
//  4. Account-linking CSRF — /connect/provider accepts without CSRF token.
//  5. Invite token enumeration — incrementally modified tokens accepted.
func (s *Service) RunMagicLinkProbe(
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

	magicEPs := magicLinkDiscoverEndpoints(base, magicLinkPaths, options.SeedRuntimeEndpoints, scanScope)
	inviteEPs := magicLinkDiscoverEndpoints(base, invitePaths, options.SeedRuntimeEndpoints, scanScope)
	linkEPs := magicLinkDiscoverEndpoints(base, accountLinkPaths, options.SeedRuntimeEndpoints, scanScope)

	if len(magicEPs) == 0 && len(inviteEPs) == 0 && len(linkEPs) == 0 {
		return nil
	}

	for _, ep := range magicEPs {
		RecordProbedKey(http.MethodPost, ep, "")
	}
	for _, ep := range inviteEPs {
		RecordProbedKey(http.MethodPost, ep, "")
	}
	for _, ep := range linkEPs {
		RecordProbedKey(http.MethodPost, ep, "")
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("magic-link-probe %s", target),
			Message: fmt.Sprintf("Probing %d magic-link, %d invite, and %d account-link endpoints", len(magicEPs), len(inviteEPs), len(linkEPs)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	// ── Probe 1: Magic link token in response body ─────────────────────────
	fid := "magic-link-token-in-response"
	if !emitted[fid] {
		for _, ep := range magicEPs {
			token, status := magicLinkRequestToken(ctx, s, ep, "abh-probe-magic@abh-scanner.invalid", auth, options)
			if token == "" {
				continue
			}
			consumeEPs := magicLinkBuildConsumeURLs(base, ep, token, scanScope)
			consumeStatus := magicLinkConsumeToken(ctx, s, consumeEPs, token, auth, options)
			controlToken := magicLinkInvalidControlToken(token)
			controlStatus := magicLinkConsumeToken(ctx, s, magicLinkBuildConsumeURLs(base, ep, controlToken, scanScope), controlToken, auth, options)
			if consumeStatus == 0 || (controlStatus >= 200 && controlStatus < 400) {
				continue
			}
			// Token appeared in the response body and was accepted while an invalid control was rejected.
			lowEntropy := magicLinkTokenIsLowEntropy(token)
			severity := model.SeverityHigh
			extraNote := ""
			if lowEntropy {
				severity = model.SeverityCritical
				extraNote = " The token also appears to have low entropy, making it brute-forceable."
			}
			emitted[fid] = true
			findings = append(findings, model.Finding{
				ID:             fid,
				Category:       "authentication",
				Severity:       severity,
				Title:          "Magic link token disclosed in API response",
				Description:    "The passwordless authentication endpoint returned a magic-link token directly in the HTTP response body instead of delivering it exclusively via email. The disclosed token was accepted by a consume endpoint while a clearly invalid control token was rejected. Any party who can intercept the API response (logs, proxies, shared caches) can use the token to authenticate as the target user." + extraNote,
				Evidence:       fmt.Sprintf("POST %s → HTTP %d with token %q in response body; consume endpoint accepted disclosed token with HTTP %d and rejected invalid control with HTTP %d", ep, status, truncateString(token, 20), consumeStatus, controlStatus),
				Recommendation: "Never return authentication tokens in API responses. Send them only to the registered email address. Tokens must be single-use, short-lived (≤15 minutes), and cryptographically random (≥128 bits).",
				Confidence:     0.88,
				AffectedURL:    ep,
				CWE:            "CWE-330",
				OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
				Sources:        []string{"active-scanner", "magic-link-probe"},
				BusinessTags:   []string{"magic-link", "passwordless", "token-disclosure"},
				EvidenceFields: map[string]string{
					"validationType":       "active-probe",
					"tokenPrefix":          truncateString(token, 16),
					"lowEntropy":           fmt.Sprintf("%v", lowEntropy),
					"responseStatus":       fmt.Sprintf("%d", status),
					"consumeStatus":        fmt.Sprintf("%d", consumeStatus),
					"controlTokenRejected": "true",
					"controlStatus":        fmt.Sprintf("%d", controlStatus),
					"method":               http.MethodPost,
					"url":                  ep,
					"param":                "token",
					"oracleName":           "magic_link_invite_probe",
					"oracleVersion":        "v1",
				},
			})
			break
		}
	}

	// ── Probe 2: Magic link token reuse ────────────────────────────────────
	fid = "magic-link-token-reuse"
	if !emitted[fid] {
		for _, ep := range magicEPs {
			token, _ := magicLinkRequestToken(ctx, s, ep, "abh-probe-reuse@abh-scanner.invalid", auth, options)
			if token == "" {
				continue
			}
			// Try to use the token twice.
			consumeEPs := magicLinkBuildConsumeURLs(base, ep, token, scanScope)
			status1 := magicLinkConsumeToken(ctx, s, consumeEPs, token, auth, options)
			status2 := magicLinkConsumeToken(ctx, s, consumeEPs, token, auth, options)

			controlToken := magicLinkInvalidControlToken(token)
			controlStatus := magicLinkConsumeToken(ctx, s, magicLinkBuildConsumeURLs(base, ep, controlToken, scanScope), controlToken, auth, options)
			if status1 > 0 && status2 > 0 &&
				status1 >= 200 && status1 < 400 &&
				status2 >= 200 && status2 < 400 &&
				!(controlStatus >= 200 && controlStatus < 400) {
				emitted[fid] = true
				findings = append(findings, model.Finding{
					ID:             fid,
					Category:       "authentication",
					Severity:       model.SeverityHigh,
					Title:          "Magic link token accepted on second use — single-use not enforced",
					Description:    "The same magic-link token was accepted on two consecutive authentication requests without being invalidated after the first use, while a clearly invalid control token was rejected. Tokens must be single-use; reuse allows an attacker who intercepts the link (e.g., from browser history or email forwarding) to establish an additional authenticated session.",
					Evidence:       fmt.Sprintf("Token %q used at consume endpoint — first HTTP %d, second HTTP %d (both accepted); invalid control token → HTTP %d", truncateString(token, 16), status1, status2, controlStatus),
					Recommendation: "Invalidate magic-link tokens immediately after their first successful use. Store a used-token hash and reject any second submission within the validity window.",
					Confidence:     0.82,
					AffectedURL:    ep,
					CWE:            "CWE-294",
					OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
					Sources:        []string{"active-scanner", "magic-link-probe"},
					BusinessTags:   []string{"magic-link", "token-replay"},
					EvidenceFields: map[string]string{
						"validationType":       "active-probe",
						"firstStatus":          fmt.Sprintf("%d", status1),
						"secondStatus":         fmt.Sprintf("%d", status2),
						"controlTokenRejected": "true",
						"controlStatus":        fmt.Sprintf("%d", controlStatus),
						"method":               http.MethodPost,
						"url":                  ep,
						"param":                "token",
						"oracleName":           "magic_link_invite_probe",
						"oracleVersion":        "v1",
					},
				})
				break
			}
		}
	}

	// ── Probe 3: Invite token not bound to invitee ─────────────────────────
	fid = "invite-token-not-bound"
	if !emitted[fid] {
		for _, ep := range inviteEPs {
			token := magicLinkRequestInviteToken(ctx, s, ep, "abh-probe-invited@abh-scanner.invalid", auth, options)
			if token == "" {
				continue
			}
			// Try to accept the invite with a different email.
			differentEmail := "abh-probe-attacker@abh-scanner.invalid"
			accepted, status := magicLinkAcceptInvite(ctx, s, base, token, differentEmail, auth, options)
			controlAccepted, controlStatus := magicLinkAcceptInvite(ctx, s, base, magicLinkInvalidControlToken(token), differentEmail, auth, options)
			if accepted && !controlAccepted {
				emitted[fid] = true
				findings = append(findings, model.Finding{
					ID:             fid,
					Category:       "authentication",
					Severity:       model.SeverityHigh,
					Title:          "Invite token not bound to invitee — token accepted for different email",
					Description:    "An invitation token was accepted with an email address different from the one it was issued for, while a clearly invalid control token was rejected. Invite tokens must be cryptographically bound to the intended recipient; otherwise an attacker who intercepts a token can accept the invite under their own identity.",
					Evidence:       fmt.Sprintf("Invite token for %q accepted for %q at HTTP %d; invalid control token → HTTP %d", "abh-probe-invited@abh-scanner.invalid", differentEmail, status, controlStatus),
					Recommendation: "Bind invite tokens to the target email address at issuance. Validate that the email provided during acceptance matches the one stored with the token. Reject mismatched claims.",
					Confidence:     0.80,
					AffectedURL:    ep,
					CWE:            "CWE-287",
					OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
					Sources:        []string{"active-scanner", "magic-link-probe"},
					BusinessTags:   []string{"invite", "token-binding"},
					EvidenceFields: map[string]string{
						"validationType":       "active-probe",
						"invitedEmail":         "abh-probe-invited@abh-scanner.invalid",
						"attackerEmail":        differentEmail,
						"acceptStatus":         fmt.Sprintf("%d", status),
						"controlTokenRejected": "true",
						"controlStatus":        fmt.Sprintf("%d", controlStatus),
						"method":               http.MethodPost,
						"url":                  ep,
						"param":                "token",
						"oracleName":           "magic_link_invite_probe",
						"oracleVersion":        "v1",
					},
				})
				break
			}
		}
	}

	// ── Probe 4: Account-linking CSRF ──────────────────────────────────────
	fid = "account-link-csrf"
	if !emitted[fid] {
		for _, ep := range linkEPs {
			if f := magicLinkTestLinkCSRF(ctx, s, ep, auth, options); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	// ── Probe 5: Invite token enumeration ─────────────────────────────────
	fid = "invite-token-enumerable"
	if !emitted[fid] {
		for _, ep := range inviteEPs {
			if f := magicLinkTestTokenEnumeration(ctx, s, base, ep, auth, options, scanScope); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	return findings
}

// magicLinkRequestToken posts to a magic-link initiation endpoint and returns
// any token found in the response body.
func magicLinkRequestToken(ctx context.Context, s *Service, ep, email string, auth model.ScanAuthProfile, options model.ScanOptions) (string, int) {
	body := map[string]string{
		"email":    email,
		"username": email,
	}
	bodyJSON, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", 0
	}
	req.Header.Set("Content-Type", "application/json")
	ApplyAuthProfile(req, auth)
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return "", 0
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, magicLinkBodyLimit))
	_ = resp.Body.Close()

	var parsed map[string]interface{}
	if err := json.Unmarshal(rb, &parsed); err != nil {
		// Try URL-encoded or plain response.
		rawBody := string(rb)
		for _, field := range magicLinkTokenFieldNames {
			// Look for field=value pattern in body.
			prefix := field + "="
			if idx := strings.Index(rawBody, prefix); idx >= 0 {
				val := rawBody[idx+len(prefix):]
				if end := strings.IndexAny(val, "&\n\r "); end > 0 {
					val = val[:end]
				}
				if len(val) >= 8 {
					return val, resp.StatusCode
				}
			}
		}
		return "", resp.StatusCode
	}
	for _, field := range magicLinkTokenFieldNames {
		if v, ok := parsed[field]; ok {
			if sv, ok := v.(string); ok && len(sv) >= 8 {
				return sv, resp.StatusCode
			}
		}
	}
	return "", resp.StatusCode
}

// magicLinkBuildConsumeURLs builds candidate consumption URLs for a magic token.
func magicLinkBuildConsumeURLs(base *url.URL, issuerEP, token string, scanScope model.ScanScope) []string {
	candidates := []string{
		issuerEP + "?token=" + url.QueryEscape(token),
		base.Scheme + "://" + base.Host + "/api/auth/verify?token=" + url.QueryEscape(token),
		base.Scheme + "://" + base.Host + "/magic?token=" + url.QueryEscape(token),
		base.Scheme + "://" + base.Host + "/auth/callback?token=" + url.QueryEscape(token),
	}
	var out []string
	for _, c := range candidates {
		if scope.IsURLInScope(c, scanScope) {
			out = append(out, c)
		}
	}
	return out
}

// magicLinkConsumeToken tries to use the token at one of the candidate consume URLs.
func magicLinkConsumeToken(ctx context.Context, s *Service, consumeEPs []string, token string, auth model.ScanAuthProfile, options model.ScanOptions) int {
	for _, ep := range consumeEPs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, auth)
		resp, err := s.doRequestWithRetry(ctx, req, options)
		if err != nil || resp == nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return resp.StatusCode
		}
	}
	return 0
}

func magicLinkInvalidControlToken(token string) string {
	control := strings.ReplaceAll(RandomMarker(), "_", "")
	if len(token) <= 0 {
		return control
	}
	for len(control) < len(token) {
		control += "x"
	}
	if len(control) > len(token) {
		control = control[:len(token)]
	}
	return control
}

// magicLinkRequestInviteToken posts to an invite endpoint and returns any token
// in the response body.
func magicLinkRequestInviteToken(ctx context.Context, s *Service, ep, email string, auth model.ScanAuthProfile, options model.ScanOptions) string {
	body := map[string]string{"email": email, "invitee_email": email}
	bodyJSON, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	ApplyAuthProfile(req, auth)
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return ""
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, magicLinkBodyLimit))
	_ = resp.Body.Close()

	var parsed map[string]interface{}
	if err := json.Unmarshal(rb, &parsed); err != nil {
		return ""
	}
	for _, field := range magicLinkTokenFieldNames {
		if v, ok := parsed[field]; ok {
			if sv, ok := v.(string); ok && sv != "" {
				return sv
			}
		}
	}
	return ""
}

// magicLinkAcceptInvite tries to accept an invite token for an email different
// from the intended invitee.
func magicLinkAcceptInvite(ctx context.Context, s *Service, base *url.URL, token, email string, auth model.ScanAuthProfile, options model.ScanOptions) (bool, int) {
	acceptPaths := []string{
		"/api/invite/accept",
		"/api/invitations/accept",
		"/invite/accept",
		"/signup/invite/accept",
	}
	for _, path := range acceptPaths {
		ep := base.ResolveReference(&url.URL{Path: path}).String()
		body := map[string]string{
			"token": token,
			"email": email,
		}
		bodyJSON, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		ApplyAuthProfile(req, auth)
		resp, err := s.doRequestWithRetry(ctx, req, options)
		if err != nil || resp == nil {
			continue
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, magicLinkBodyLimit))
		_ = resp.Body.Close()
		lower := strings.ToLower(string(rb))
		if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
			!strings.Contains(lower, "invalid") &&
			!strings.Contains(lower, "error") &&
			!strings.Contains(lower, "mismatch") {
			return true, resp.StatusCode
		}
	}
	return false, 0
}

// magicLinkTestLinkCSRF tests account-linking without a CSRF token.
func magicLinkTestLinkCSRF(ctx context.Context, s *Service, ep string, auth model.ScanAuthProfile, options model.ScanOptions) *model.Finding {
	body := map[string]string{"provider": "google", "code": "abh-probe-oauth-code"}
	bodyJSON, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	ApplyAuthProfile(req, auth)
	req.Header.Del("X-CSRF-Token")
	req.Header.Del("X-XSRF-TOKEN")
	req.Header.Del("csrf-token")
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return nil
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, magicLinkBodyLimit))
	_ = resp.Body.Close()

	lower := strings.ToLower(string(rb))
	csrfRejected := resp.StatusCode == http.StatusForbidden ||
		strings.Contains(lower, "csrf") ||
		strings.Contains(lower, "forbidden")

	if !csrfRejected && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &model.Finding{
			ID:             "account-link-csrf",
			Category:       "authentication",
			Severity:       model.SeverityHigh,
			Title:          "Account-linking endpoint missing CSRF protection",
			Description:    "The account-linking endpoint accepted a POST request without a CSRF token. An attacker can craft a malicious page that silently links the victim's account to an attacker-controlled social identity, enabling full account takeover if the attacker can subsequently initiate an OAuth login with that identity.",
			Evidence:       fmt.Sprintf("POST %s without CSRF token → HTTP %d", ep, resp.StatusCode),
			Recommendation: "Require a synchronizer CSRF token on all account-linking endpoints. Validate the OAuth state parameter. Bind linking operations to the authenticated session.",
			Confidence:     0.72,
			AffectedURL:    ep,
			CWE:            "CWE-352",
			OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
			Sources:        []string{"active-scanner", "magic-link-probe"},
			BusinessTags:   []string{"account-linking", "csrf", "oauth"},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"csrfTokenSent":  "false",
				"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
				"method":         http.MethodPost,
				"url":            ep,
				"oracleName":     "magic_link_invite_probe",
				"oracleVersion":  "v1",
			},
		}
	}
	return nil
}

// magicLinkTestTokenEnumeration submits several guessable invite tokens.
func magicLinkTestTokenEnumeration(ctx context.Context, s *Service, base *url.URL, ep string, auth model.ScanAuthProfile, options model.ScanOptions, scanScope model.ScanScope) *model.Finding {
	guessableTokens := []string{
		"000001", "000002", "000003", "100000", "123456", "999999",
	}
	acceptPaths := []string{
		ep + "?token=",
		base.Scheme + "://" + base.Host + "/invite/accept?token=",
	}
	for _, tokenVal := range guessableTokens {
		for _, epBase := range acceptPaths {
			probe := epBase + tokenVal
			if !scope.IsURLInScope(probe, scanScope) {
				continue
			}
			accepted, status := magicLinkTokenProbeAccepted(ctx, s, probe, auth, options)
			if !accepted {
				continue
			}
			controlToken := magicLinkInvalidControlToken(tokenVal)
			controlAccepted, controlStatus := magicLinkTokenProbeAccepted(ctx, s, epBase+controlToken, auth, options)
			if controlAccepted {
				continue
			}
			return &model.Finding{
				ID:             "invite-token-enumerable",
				Category:       "authentication",
				Severity:       model.SeverityMedium,
				Title:          "Invite token appears guessable or enumerable",
				Description:    fmt.Sprintf("A short, sequential invite token value %q was accepted without error at %s, while a clearly invalid control token was rejected. If tokens are not cryptographically random with sufficient entropy, an attacker can enumerate them and accept invitations intended for other users.", tokenVal, probe),
				Evidence:       fmt.Sprintf("GET %s → HTTP %d (accepted); invalid control token → HTTP %d", probe, status, controlStatus),
				Recommendation: "Generate invite tokens using a cryptographically secure random number generator with at least 128 bits of entropy. Avoid sequential or predictable tokens.",
				Confidence:     0.65,
				AffectedURL:    ep,
				CWE:            "CWE-330",
				OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
				Sources:        []string{"active-scanner", "magic-link-probe"},
				BusinessTags:   []string{"invite", "token-enumeration"},
				EvidenceFields: map[string]string{
					"validationType":       "active-probe",
					"guessedToken":         tokenVal,
					"responseStatus":       fmt.Sprintf("%d", status),
					"controlTokenRejected": "true",
					"controlStatus":        fmt.Sprintf("%d", controlStatus),
					"method":               http.MethodGet,
					"url":                  probe,
					"param":                "token",
					"oracleName":           "magic_link_invite_probe",
					"oracleVersion":        "v1",
				},
			}
		}
	}
	return nil
}

func magicLinkTokenProbeAccepted(ctx context.Context, s *Service, probe string, auth model.ScanAuthProfile, options model.ScanOptions) (bool, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
	if err != nil {
		return false, 0
	}
	ApplyAuthProfile(req, auth)
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return false, 0
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, magicLinkBodyLimit))
	_ = resp.Body.Close()
	lower := strings.ToLower(string(rb))
	accepted := (resp.StatusCode >= 200 && resp.StatusCode < 300) &&
		!strings.Contains(lower, "invalid") &&
		!strings.Contains(lower, "expired") &&
		!strings.Contains(lower, "not found") &&
		!strings.Contains(lower, "error")
	return accepted, resp.StatusCode
}

// magicLinkDiscoverEndpoints returns in-scope endpoints from path and seed lists.
func magicLinkDiscoverEndpoints(base *url.URL, paths []string, seeded []string, scanScope model.ScanScope) []string {
	seen := map[string]struct{}{}
	var out []string

	addEP := func(raw string) {
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		var ep string
		if ref.Scheme == "" || ref.Host == "" {
			ep = base.ResolveReference(ref).String()
		} else {
			ep = ref.String()
		}
		if _, ok := seen[ep]; ok {
			return
		}
		if !scope.IsURLInScope(ep, scanScope) {
			return
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}

	for _, p := range paths {
		addEP(p)
	}
	for _, s := range seeded {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "magic") || strings.Contains(lower, "passwordless") ||
			strings.Contains(lower, "invite") || strings.Contains(lower, "link") {
			addEP(s)
		}
	}

	const max = 5
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// magicLinkTokenIsLowEntropy uses a simple bit-diversity heuristic to detect
// tokens that are likely too short or too sequential.
func magicLinkTokenIsLowEntropy(token string) bool {
	if len(token) < 16 {
		return true
	}
	// Count unique bytes as a rough entropy proxy.
	seen := make(map[byte]struct{}, 256)
	for i := 0; i < len(token); i++ {
		seen[token[i]] = struct{}{}
	}
	uniqueBytes := len(seen)
	// Fewer than 8 unique characters in a long token suggests low entropy.
	if uniqueBytes < 8 {
		return true
	}
	// Check if it looks purely numeric (easy to brute-force).
	allDigits := true
	for _, c := range token {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits && len(token) <= 10 {
		return true
	}
	// Count set bits as a rough measure of randomness.
	var setBits int
	for i := 0; i < len(token); i++ {
		setBits += bits.OnesCount8(token[i])
	}
	totalBits := len(token) * 8
	// Highly skewed bit distribution (< 30% or > 70% set) suggests non-random.
	ratio := float64(setBits) / float64(totalBits)
	if ratio < 0.30 || ratio > 0.70 {
		return true
	}
	return false
}
