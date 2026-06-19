package scanner

// session_edge_case_agent.go — sub-agents for session state-change edge cases.
//
// Each sub-agent is an independent function that:
//  1. Captures a pre-transition credential/state.
//  2. Triggers a specific session state change (logout, password-change, etc.).
//  3. Tests one edge case against the resulting state.
//
// The orchestrator RunSessionEdgeCaseAgents spawns all applicable agents
// concurrently (each with its own HTTP client) and collects findings within
// a fixed budget.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// sessionEdgeCaseAgentBudget is the maximum total time for all sub-agents.
const sessionEdgeCaseAgentBudget = 90 * time.Second

// sessionEdgeCaseAgentTimeout is the per-agent timeout.
const sessionEdgeCaseAgentTimeout = 20 * time.Second

// sessionEdgeCaseBodyLimit caps response-body reads in edge-case agents.
const sessionEdgeCaseBodyLimit = 32 * 1024

// sessionEdgeCaseInput is the shared read-only input passed to every sub-agent.
type sessionEdgeCaseInput struct {
	target    string
	base      *url.URL
	auth      model.ScanAuthProfile
	options   model.ScanOptions
	scanScope model.ScanScope
}

// sessionEdgeCaseAgentFn is the signature of a sub-agent function.
// It returns a slice of findings (may be empty) and never panics.
type sessionEdgeCaseAgentFn func(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding

// sessionEdgeCaseAgentDef pairs a name with an agent function.
type sessionEdgeCaseAgentDef struct {
	name    string
	needsCredential bool // skip if no credentials are available
	fn      sessionEdgeCaseAgentFn
}

// sessionEdgeCaseAgentRegistry is the full set of edge-case sub-agents.
var sessionEdgeCaseAgentRegistry = []sessionEdgeCaseAgentDef{
	{"logout-race-window", true, sessionLogoutRaceAgent},
	{"logout-partial-revocation", true, sessionLogoutPartialRevocationAgent},
	{"password-change-refresh-token", true, sessionPasswordChangeRefreshTokenAgent},
	{"password-change-parallel-session", true, sessionPasswordChangeParallelSessionAgent},
	{"session-fixation", true, sessionFixationAgent},
	{"session-token-entropy", true, sessionTokenEntropyAgent},
	{"multi-step-skip", false, sessionMultiStepSkipAgent},
	{"multi-step-replay", false, sessionMultiStepReplayAgent},
	{"privilege-escalation-cache", true, sessionPrivilegeEscalationCacheAgent},
	{"account-lockout-session-survival", true, sessionAccountLockoutSurvivalAgent},
}

// RunSessionEdgeCaseAgents spawns independent sub-agents for session state-change
// edge cases and aggregates their findings.
func (s *Service) RunSessionEdgeCaseAgents(
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

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("session-edge-case-agents %s", target),
			Message: "Spawning session state-change edge-case sub-agents",
		})
	}

	budgetCtx, cancel := context.WithTimeout(ctx, sessionEdgeCaseAgentBudget)
	defer cancel()

	in := sessionEdgeCaseInput{
		target:    target,
		base:      base,
		auth:      auth,
		options:   options,
		scanScope: scanScope,
	}

	hasCredential := hasStandardLoginCredentials(auth) ||
		oauthExtractBearerToken(auth) != "" ||
		sessionExtractSessionCookie(auth) != ""

	type agentResult struct {
		name     string
		findings []model.Finding
	}
	results := make(chan agentResult, len(sessionEdgeCaseAgentRegistry))

	var wg sync.WaitGroup
	for _, def := range sessionEdgeCaseAgentRegistry {
		if def.needsCredential && !hasCredential {
			continue
		}
		wg.Add(1)
		go func(d sessionEdgeCaseAgentDef) {
			defer wg.Done()
			agentCtx, agentCancel := context.WithTimeout(budgetCtx, sessionEdgeCaseAgentTimeout)
			defer agentCancel()
			var found []model.Finding
			func() {
				defer func() {
					if r := recover(); r != nil {
						// sub-agents must never crash the scanner
					}
				}()
				found = d.fn(agentCtx, s, in)
			}()
			if emit != nil && len(found) > 0 {
				emit(model.ScanEvent{
					Type:    model.ScanEventInfo,
					Message: fmt.Sprintf("Session edge-case agent %q found %d issue(s)", d.name, len(found)),
				})
			}
			results <- agentResult{name: d.name, findings: found}
		}(def)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var all []model.Finding
	seen := map[string]bool{}
	for res := range results {
		for _, f := range res.findings {
			if !seen[f.ID] {
				seen[f.ID] = true
				all = append(all, f)
			}
		}
	}
	return all
}

// ─── Sub-agent: logout race window ───────────────────────────────────────────

// sessionLogoutRaceAgent fires a protected-resource request concurrently with
// a logout request to probe whether a narrow race window exists between the
// time the server accepts the logout and the time the session is actually
// destroyed.
func sessionLogoutRaceAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	bearer := oauthExtractBearerToken(in.auth)
	cookie := sessionExtractSessionCookie(in.auth)
	if bearer == "" && cookie == "" {
		return nil
	}

	logoutEPs := sessionDiscoverLogoutEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	protectedEPs := sessionDiscoverProtectedEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	if len(logoutEPs) == 0 || len(protectedEPs) == 0 {
		return nil
	}

	client := sessionFreshClient()
	logoutEP := logoutEPs[0]
	protectedEP := protectedEPs[0]

	type raceResult struct {
		code int
		body string
	}
	ch := make(chan raceResult, 1)

	// Fire the protected request slightly before the logout to hit the window.
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEP, nil)
		if err != nil {
			ch <- raceResult{}
			return
		}
		sessionApplyCredential(req, bearer, cookie)
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			ch <- raceResult{}
			return
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, sessionEdgeCaseBodyLimit))
		_ = resp.Body.Close()
		ch <- raceResult{code: resp.StatusCode, body: string(body)}
	}()

	// Issue logout.
	lReq, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutEP, nil)
	if err != nil {
		return nil
	}
	sessionApplyCredential(lReq, bearer, cookie)
	lResp, err := client.Do(lReq)
	if err != nil || lResp == nil {
		return nil
	}
	_ = lResp.Body.Close()

	res := <-ch

	if res.code >= 200 && res.code < 300 &&
		!strings.Contains(strings.ToLower(res.body), "unauthorized") &&
		!strings.Contains(strings.ToLower(res.body), "login") {
		return []model.Finding{{
			ID:       "session-race-window-on-logout",
			Category: "authentication",
			Severity: model.SeverityMedium,
			Title:    "Session accessible during logout race window",
			Description: "A protected-resource request issued concurrently with the logout request " +
				"received a successful (2xx) response. This indicates a potential race window " +
				"between the server accepting the logout call and invalidating the session, " +
				"which an attacker could exploit to maintain access after the user logs out.",
			Evidence: fmt.Sprintf(
				"Concurrent GET %s (with original token) during POST %s (logout) → HTTP %d",
				protectedEP, logoutEP, res.code,
			),
			Recommendation:  "Invalidate the session synchronously before returning a successful logout response. Use atomic session revocation rather than asynchronous cleanup.",
			Confidence:      0.65,
			AffectedURL:     logoutEP,
			CWE:             "CWE-613",
			OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
			Sources:         []string{"active-scanner", "session-edge-case-agents"},
			BusinessTags:    []string{"session-invalidation", "race-condition"},
			EvidenceFields:  map[string]string{"validationType": "active-probe", "replayStatus": fmt.Sprintf("%d", res.code)},
		}}
	}
	return nil
}

// ─── Sub-agent: logout partial revocation ────────────────────────────────────

// sessionLogoutPartialRevocationAgent tests whether the server only invalidates
// one credential carrier on logout while leaving another valid.  For example,
// a server might revoke the session cookie but keep the ****** active.
func sessionLogoutPartialRevocationAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	bearer := oauthExtractBearerToken(in.auth)
	cookie := sessionExtractSessionCookie(in.auth)
	// Need at least two credential types to test partial revocation.
	if bearer == "" || cookie == "" {
		return nil
	}

	logoutEPs := sessionDiscoverLogoutEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	protectedEPs := sessionDiscoverProtectedEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	if len(logoutEPs) == 0 || len(protectedEPs) == 0 {
		return nil
	}

	client := sessionFreshClient()

	// Logout using the cookie.
	lReq, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutEPs[0], nil)
	if err != nil {
		return nil
	}
	lReq.AddCookie(&http.Cookie{Name: "session", Value: cookie})
	lResp, err := client.Do(lReq)
	if err != nil || lResp == nil {
		return nil
	}
	_ = lResp.Body.Close()
	if lResp.StatusCode < 200 || lResp.StatusCode >= 400 {
		return nil
	}

	// Now replay the bearer token (not the cookie).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEPs[0], nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, sessionEdgeCaseBodyLimit))
	_ = resp.Body.Close()

	lower := strings.ToLower(string(body))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		!strings.Contains(lower, "unauthorized") && !strings.Contains(lower, "login") {
		return []model.Finding{{
			ID:       "session-partial-revocation-on-logout",
			Category: "authentication",
			Severity: model.SeverityHigh,
			Title:    "****** remains valid after cookie-based logout",
			Description: "Logout was performed via a session cookie, but the corresponding ****** " +
				"remained valid and returned a successful response to a protected endpoint. " +
				"An attacker who has captured a ****** can continue to access the account " +
				"even after the user logs out.",
			Evidence: fmt.Sprintf(
				"POST %s (logout with cookie) → GET %s with bearer token → HTTP %d",
				logoutEPs[0], protectedEPs[0], resp.StatusCode,
			),
			Recommendation:  "Invalidate all credential types (cookies, ****** refresh tokens) atomically on logout. Link tokens to the server-side session so revoking one revokes all.",
			Confidence:      0.80,
			AffectedURL:     logoutEPs[0],
			CWE:             "CWE-613",
			OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
			Sources:         []string{"active-scanner", "session-edge-case-agents"},
			BusinessTags:    []string{"session-invalidation", "partial-revocation"},
			EvidenceFields:  map[string]string{"validationType": "active-probe", "replayStatus": fmt.Sprintf("%d", resp.StatusCode)},
		}}
	}
	return nil
}

// ─── Sub-agent: password change + refresh token ───────────────────────────────

// sessionPasswordChangeRefreshTokenAgent tests whether a refresh token obtained
// before a password change can still be used to obtain a new access token after
// the password change.
func sessionPasswordChangeRefreshTokenAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	refreshToken := ""
	for k, v := range in.auth.Headers {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "refresh") {
			refreshToken = v
			break
		}
	}
	if refreshToken == "" {
		// Look for a refresh_token cookie.
		for k, v := range in.auth.Cookies {
			if strings.Contains(strings.ToLower(k), "refresh") {
				refreshToken = v
				break
			}
		}
	}
	if refreshToken == "" || in.auth.Password == "" {
		return nil
	}

	client := sessionFreshClient()
	pwEPs := sessionDiscoverEndpoints(in.base, passwordChangePaths, in.scanScope)
	if len(pwEPs) == 0 {
		return nil
	}

	// Change the password.
	change := map[string]string{
		"currentPassword": in.auth.Password,
		"newPassword":     "ABH-ECA-P@ss1!2#",
		"password":        "ABH-ECA-P@ss1!2#",
	}
	changeJSON, _ := json.Marshal(change)
	cReq, err := http.NewRequestWithContext(ctx, http.MethodPost, pwEPs[0], bytes.NewReader(changeJSON))
	if err != nil {
		return nil
	}
	sessionApplyCredential(cReq, oauthExtractBearerToken(in.auth), sessionExtractSessionCookie(in.auth))
	cReq.Header.Set("Content-Type", "application/json")
	cResp, err := client.Do(cReq)
	if err != nil || cResp == nil {
		return nil
	}
	_ = cResp.Body.Close()
	if cResp.StatusCode < 200 || cResp.StatusCode >= 300 {
		return nil
	}

	// Attempt to use the old refresh token to get a new access token.
	tokenEPs := []string{
		in.base.Scheme + "://" + in.base.Host + "/api/auth/refresh",
		in.base.Scheme + "://" + in.base.Host + "/api/token/refresh",
		in.base.Scheme + "://" + in.base.Host + "/oauth/token",
		in.base.Scheme + "://" + in.base.Host + "/api/v1/auth/refresh",
	}
	for _, ep := range tokenEPs {
		if !scope.IsURLInScope(ep, in.scanScope) {
			continue
		}
		body := map[string]string{"refresh_token": refreshToken, "grant_type": "refresh_token"}
		bodyJSON, _ := json.Marshal(body)
		rReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(bodyJSON))
		if err != nil {
			continue
		}
		rReq.Header.Set("Content-Type", "application/json")
		rResp, err := client.Do(rReq)
		if err != nil || rResp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(rResp.Body, sessionEdgeCaseBodyLimit))
		_ = rResp.Body.Close()

		lower := strings.ToLower(string(respBody))
		if rResp.StatusCode >= 200 && rResp.StatusCode < 300 &&
			(strings.Contains(lower, "access_token") || strings.Contains(lower, "token")) &&
			!strings.Contains(lower, "invalid") && !strings.Contains(lower, "expired") {
			return []model.Finding{{
				ID:       "session-refresh-token-valid-after-password-change",
				Category: "authentication",
				Severity: model.SeverityHigh,
				Title:    "Refresh token remains valid after password change",
				Description: "After changing the account password, the original OAuth refresh token was " +
					"accepted at the token endpoint and returned what appears to be a new access token. " +
					"An attacker who has captured the refresh token can continue to obtain valid access " +
					"tokens even after the victim changes their password.",
				Evidence: fmt.Sprintf(
					"POST %s (password change) → POST %s with old refresh_token → HTTP %d (token in response)",
					pwEPs[0], ep, rResp.StatusCode,
				),
				Recommendation:  "Revoke all refresh tokens when the account password changes. Require re-authentication with the new credentials.",
				Confidence:      0.78,
				AffectedURL:     ep,
				CWE:             "CWE-613",
				OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
				Sources:         []string{"active-scanner", "session-edge-case-agents"},
				BusinessTags:    []string{"session-invalidation", "refresh-token", "password-change"},
				EvidenceFields:  map[string]string{"validationType": "active-probe", "tokenEndpoint": ep, "replayStatus": fmt.Sprintf("%d", rResp.StatusCode)},
			}}
		}
	}
	return nil
}

// ─── Sub-agent: password change + parallel session ───────────────────────────

// sessionPasswordChangeParallelSessionAgent tests whether a *second* session
// obtained before a password change remains valid after the change.  Unlike the
// existing probe (which replays the same token), this agent obtains a fresh
// session via a second login before the password change, then checks it after.
func sessionPasswordChangeParallelSessionAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	if in.auth.Username == "" || in.auth.Password == "" {
		return nil
	}

	loginEPs := sessionDiscoverLoginEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	pwEPs := sessionDiscoverEndpoints(in.base, passwordChangePaths, in.scanScope)
	protectedEPs := sessionDiscoverProtectedEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	if len(loginEPs) == 0 || len(pwEPs) == 0 || len(protectedEPs) == 0 {
		return nil
	}

	client := sessionFreshClient()

	// Obtain a parallel session via login.
	parallelCookie := sessionAttemptLoginAndGetCookie(ctx, s, loginEPs[0], in.auth, in.options)
	if parallelCookie == "" {
		return nil
	}

	// Change the password on the primary auth profile.
	change := map[string]string{
		"currentPassword": in.auth.Password,
		"newPassword":     "ABH-ECA-Parallel-P@ss1!",
		"password":        "ABH-ECA-Parallel-P@ss1!",
	}
	changeJSON, _ := json.Marshal(change)
	cReq, err := http.NewRequestWithContext(ctx, http.MethodPost, pwEPs[0], bytes.NewReader(changeJSON))
	if err != nil {
		return nil
	}
	sessionApplyCredential(cReq, oauthExtractBearerToken(in.auth), sessionExtractSessionCookie(in.auth))
	cReq.Header.Set("Content-Type", "application/json")
	cResp, err := client.Do(cReq)
	if err != nil || cResp == nil {
		return nil
	}
	_ = cResp.Body.Close()
	if cResp.StatusCode < 200 || cResp.StatusCode >= 300 {
		return nil
	}

	// Replay the parallel (pre-change) session.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEPs[0], nil)
	if err != nil {
		return nil
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: parallelCookie})
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, sessionEdgeCaseBodyLimit))
	_ = resp.Body.Close()

	lower := strings.ToLower(string(body))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		!strings.Contains(lower, "unauthorized") && !strings.Contains(lower, "login") {
		return []model.Finding{{
			ID:       "session-parallel-session-survives-password-change",
			Category: "authentication",
			Severity: model.SeverityHigh,
			Title:    "Parallel session survives password change",
			Description: "A second session token obtained before a password change remained valid and " +
				"returned a successful response after the password was changed. Changing a password " +
				"should invalidate all existing sessions across all devices and browsers.",
			Evidence: fmt.Sprintf(
				"Login → parallel session obtained → POST %s (password change) → GET %s with parallel session → HTTP %d",
				pwEPs[0], protectedEPs[0], resp.StatusCode,
			),
			Recommendation:  "On password change, enumerate and invalidate all server-side sessions for the account, not just the current one.",
			Confidence:      0.78,
			AffectedURL:     pwEPs[0],
			CWE:             "CWE-613",
			OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
			Sources:         []string{"active-scanner", "session-edge-case-agents"},
			BusinessTags:    []string{"session-invalidation", "password-change", "parallel-session"},
			EvidenceFields:  map[string]string{"validationType": "active-probe", "replayStatus": fmt.Sprintf("%d", resp.StatusCode)},
		}}
	}
	return nil
}

// ─── Sub-agent: session fixation ─────────────────────────────────────────────

// sessionFixationAgent pre-seeds a crafted session ID cookie, completes a login,
// and then checks whether the pre-seeded ID grants authenticated access.
func sessionFixationAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	if in.auth.Username == "" || in.auth.Password == "" {
		return nil
	}

	loginEPs := sessionDiscoverLoginEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	protectedEPs := sessionDiscoverProtectedEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	if len(loginEPs) == 0 || len(protectedEPs) == 0 {
		return nil
	}

	const fixatedID = "abh-fixated-session-12345"
	client := sessionFreshClient()

	// Pre-set the crafted session ID.
	preReq, err := http.NewRequestWithContext(ctx, http.MethodGet, in.target, nil)
	if err != nil {
		return nil
	}
	preReq.AddCookie(&http.Cookie{Name: "session", Value: fixatedID})
	preResp, err := client.Do(preReq)
	if err != nil || preResp == nil {
		return nil
	}
	_ = preResp.Body.Close()

	// Perform login.
	creds := map[string]string{
		"username": in.auth.Username,
		"email":    in.auth.Username,
		"password": in.auth.Password,
	}
	credsJSON, _ := json.Marshal(creds)
	lReq, err := http.NewRequestWithContext(ctx, http.MethodPost, loginEPs[0], bytes.NewReader(credsJSON))
	if err != nil {
		return nil
	}
	lReq.Header.Set("Content-Type", "application/json")
	lReq.AddCookie(&http.Cookie{Name: "session", Value: fixatedID})
	lResp, err := client.Do(lReq)
	if err != nil || lResp == nil {
		return nil
	}
	_ = lResp.Body.Close()
	if lResp.StatusCode < 200 || lResp.StatusCode >= 400 {
		return nil
	}

	// Check whether the server rotated the ID (it should have).
	rotated := true
	for _, ck := range lResp.Cookies() {
		if sessionIsAuthCookie(ck.Name) && ck.Value == fixatedID {
			rotated = false
			break
		}
	}
	if rotated {
		return nil // server correctly rotated — no fixation
	}

	// Server kept the fixated ID. Now try accessing a protected resource with it.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEPs[0], nil)
	if err != nil {
		return nil
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: fixatedID})
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, sessionEdgeCaseBodyLimit))
	_ = resp.Body.Close()

	lower := strings.ToLower(string(body))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		!strings.Contains(lower, "unauthorized") && !strings.Contains(lower, "login") {
		return []model.Finding{{
			ID:       "session-fixation-confirmed",
			Category: "authentication",
			Severity: model.SeverityHigh,
			Title:    "Session fixation: pre-seeded session ID accepted after login",
			Description: "A crafted session ID was pre-seeded before login and was not rotated by the " +
				"server upon successful authentication. An attacker who plants a known session ID in the " +
				"victim's browser (via XSS, subdomain cookie injection, or a phishing page) can " +
				"hijack the authenticated session without needing to steal any token.",
			Evidence: fmt.Sprintf(
				"Pre-seeded session=%q → login at %s → session ID unchanged → GET %s → HTTP %d",
				fixatedID, loginEPs[0], protectedEPs[0], resp.StatusCode,
			),
			Recommendation:  "Regenerate the session identifier immediately upon successful authentication. Invalidate the pre-login session token before issuing a new one.",
			Confidence:      0.88,
			AffectedURL:     loginEPs[0],
			CWE:             "CWE-384",
			OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
			Sources:         []string{"active-scanner", "session-edge-case-agents"},
			BusinessTags:    []string{"session-fixation", "session-rotation"},
			EvidenceFields:  map[string]string{"validationType": "active-probe", "fixatedID": fixatedID, "loginStatus": fmt.Sprintf("%d", lResp.StatusCode)},
		}}
	}
	return nil
}

// ─── Sub-agent: session token entropy ────────────────────────────────────────

// sessionTokenEntropyAgent collects multiple session tokens and estimates
// whether they are predictable (low Shannon entropy or sequential patterns).
func sessionTokenEntropyAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	if in.auth.Username == "" || in.auth.Password == "" {
		return nil
	}

	loginEPs := sessionDiscoverLoginEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	if len(loginEPs) == 0 {
		return nil
	}

	const sampleSize = 5
	tokens := make([]string, 0, sampleSize)
	for i := 0; i < sampleSize; i++ {
		t := sessionAttemptLoginAndGetCookie(ctx, s, loginEPs[0], in.auth, in.options)
		if t != "" {
			tokens = append(tokens, t)
		}
	}
	if len(tokens) < 3 {
		return nil
	}

	// Check for sequential tokens (identical prefix with incrementing suffix).
	if sessionTokensAreSequential(tokens) {
		return []model.Finding{{
			ID:       "session-token-sequential-pattern",
			Category: "authentication",
			Severity: model.SeverityHigh,
			Title:    "Session tokens show sequential/predictable pattern",
			Description: fmt.Sprintf(
				"Collected %d session tokens across repeated logins. The tokens exhibit a sequential " +
					"or highly similar pattern, suggesting the server uses a predictable ID generation " +
					"algorithm. An attacker can enumerate valid session IDs and hijack active sessions.",
				len(tokens),
			),
			Evidence:        fmt.Sprintf("Sample tokens: %s", strings.Join(sessionTruncateTokens(tokens), ", ")),
			Recommendation:  "Use a cryptographically secure pseudo-random number generator (CSPRNG) with at least 128 bits of entropy for session identifiers. Avoid sequential or timestamp-based generation.",
			Confidence:      0.82,
			AffectedURL:     loginEPs[0],
			CWE:             "CWE-330",
			OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
			Sources:         []string{"active-scanner", "session-edge-case-agents"},
			BusinessTags:    []string{"session-entropy", "predictable-token"},
			EvidenceFields:  map[string]string{"validationType": "active-probe", "sampleCount": fmt.Sprintf("%d", len(tokens))},
		}}
	}

	// Check Shannon entropy of the first token.
	if len(tokens) > 0 {
		entropy := shannonEntropy(tokens[0])
		if entropy < 3.5 {
			return []model.Finding{{
				ID:       "session-token-low-entropy",
				Category: "authentication",
				Severity: model.SeverityMedium,
				Title:    fmt.Sprintf("Session token has low Shannon entropy (%.2f bits/char)", entropy),
				Description: fmt.Sprintf(
					"The session token exhibits low character entropy (%.2f bits per character, " +
						"threshold 3.5). Low entropy tokens are more susceptible to brute-force " +
						"and prediction attacks. A secure session token should have at least 128 bits " +
						"of total entropy.",
					entropy,
				),
				Evidence:        fmt.Sprintf("Token sample: %s; Shannon entropy: %.2f", sessionTruncateTokens(tokens[:1])[0], entropy),
				Recommendation:  "Generate session tokens using a CSPRNG with a minimum of 128 bits of entropy. Prefer opaque random tokens over JWT or structured identifiers.",
				Confidence:      0.70,
				AffectedURL:     loginEPs[0],
				CWE:             "CWE-330",
				OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
				Sources:         []string{"active-scanner", "session-edge-case-agents"},
				BusinessTags:    []string{"session-entropy", "weak-token"},
				EvidenceFields:  map[string]string{"validationType": "active-probe", "entropy": fmt.Sprintf("%.2f", entropy)},
			}}
		}
	}
	return nil
}

// ─── Sub-agent: multi-step flow step-skip ────────────────────────────────────

// sessionMultiStepSkipAgent discovers multi-step flow endpoints (e.g., checkout,
// password-reset, MFA) and tests whether step N can be skipped by jumping
// directly to step N+1.
func sessionMultiStepSkipAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	// Discover step-like endpoints from seeded endpoints.
	stepEndpoints := sessionDiscoverStepEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	if len(stepEndpoints) < 2 {
		return nil
	}

	client := sessionFreshClient()
	bearer := oauthExtractBearerToken(in.auth)
	cookie := sessionExtractSessionCookie(in.auth)

	var findings []model.Finding
	for i := 1; i < len(stepEndpoints); i++ {
		// Skip directly to step i without visiting step i-1.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, stepEndpoints[i], nil)
		if err != nil {
			continue
		}
		sessionApplyCredential(req, bearer, cookie)
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, sessionEdgeCaseBodyLimit))
		_ = resp.Body.Close()

		lower := strings.ToLower(string(body))
		// A successful response that doesn't redirect back to a prior step is suspicious.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
			!strings.Contains(lower, "step") &&
			!strings.Contains(lower, "start") &&
			!strings.Contains(lower, "begin") {
			findings = append(findings, model.Finding{
				ID:       fmt.Sprintf("session-multi-step-skip-%d", i),
				Category: "business-logic",
				Severity: model.SeverityMedium,
				Title:    fmt.Sprintf("Multi-step flow: step %d accessible without completing step %d", i+1, i),
				Description: fmt.Sprintf(
					"Direct access to %s (step %d in a multi-step flow) returned a 2xx response "+
						"without first completing step %d. The server does not enforce sequential "+
						"state transitions, allowing an attacker to skip required steps "+
						"(e.g., payment, MFA verification, identity confirmation).",
					stepEndpoints[i], i+1, i,
				),
				Evidence:        fmt.Sprintf("GET %s (step %d) without step %d → HTTP %d", stepEndpoints[i], i+1, i, resp.StatusCode),
				Recommendation:  "Validate server-side that each step has been completed before allowing progression. Use a stateful session variable (not URL parameters) to track flow position.",
				Confidence:      0.65,
				AffectedURL:     stepEndpoints[i],
				CWE:             "CWE-841",
				OWASPCategory:   "A04:2021 - Insecure Design",
				Sources:         []string{"active-scanner", "session-edge-case-agents"},
				BusinessTags:    []string{"multi-step-flow", "step-skip", "business-logic"},
				EvidenceFields:  map[string]string{"validationType": "active-probe", "stepIndex": fmt.Sprintf("%d", i+1)},
			})
			break // one finding per flow is sufficient
		}
	}
	return findings
}

// ─── Sub-agent: multi-step flow step-replay ──────────────────────────────────

// sessionMultiStepReplayAgent tests whether a completed step can be replayed
// after the flow has advanced, potentially rolling back application state.
func sessionMultiStepReplayAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	stepEndpoints := sessionDiscoverStepEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	if len(stepEndpoints) < 2 {
		return nil
	}

	client := sessionFreshClient()
	bearer := oauthExtractBearerToken(in.auth)
	cookie := sessionExtractSessionCookie(in.auth)

	// Walk forward through steps to advance state.
	for _, ep := range stepEndpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		sessionApplyCredential(req, bearer, cookie)
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	// Replay the first step to see if state rolls back.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stepEndpoints[0], nil)
	if err != nil {
		return nil
	}
	sessionApplyCredential(req, bearer, cookie)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, sessionEdgeCaseBodyLimit))
	_ = resp.Body.Close()

	lower := strings.ToLower(string(body))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		!strings.Contains(lower, "already completed") &&
		!strings.Contains(lower, "invalid state") &&
		!strings.Contains(lower, "forbidden") {
		return []model.Finding{{
			ID:       "session-multi-step-replay",
			Category: "business-logic",
			Severity: model.SeverityMedium,
			Title:    "Multi-step flow: earlier step accepted after flow completion",
			Description: fmt.Sprintf(
				"After advancing through all steps of a multi-step flow, re-submitting step 1 (%s) "+
					"returned a successful (2xx) response without an 'already completed' or 'invalid state' "+
					"indicator. Replaying earlier steps can lead to duplicate processing, double-spending, "+
					"or state corruption depending on the application.",
				stepEndpoints[0],
			),
			Evidence:        fmt.Sprintf("Completed all steps → POST %s (replay step 1) → HTTP %d", stepEndpoints[0], resp.StatusCode),
			Recommendation:  "Track flow state server-side using a nonce or state machine. Mark steps as completed after first execution and reject re-submissions.",
			Confidence:      0.62,
			AffectedURL:     stepEndpoints[0],
			CWE:             "CWE-841",
			OWASPCategory:   "A04:2021 - Insecure Design",
			Sources:         []string{"active-scanner", "session-edge-case-agents"},
			BusinessTags:    []string{"multi-step-flow", "step-replay", "business-logic"},
			EvidenceFields:  map[string]string{"validationType": "active-probe", "replayStatus": fmt.Sprintf("%d", resp.StatusCode)},
		}}
	}
	return nil
}

// ─── Sub-agent: privilege escalation cache ───────────────────────────────────

// sessionPrivilegeEscalationCacheAgent tests whether the server caches role
// information and serves stale elevated-privilege responses after a role change.
func sessionPrivilegeEscalationCacheAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	bearer := oauthExtractBearerToken(in.auth)
	if bearer == "" {
		return nil
	}

	// Look for admin/privilege-level endpoints.
	adminPaths := []string{
		"/api/admin", "/api/admin/users", "/admin", "/api/roles",
		"/api/v1/admin", "/api/settings", "/api/management",
	}
	adminEPs := sessionDiscoverEndpoints(in.base, adminPaths, in.scanScope)
	if len(adminEPs) == 0 {
		return nil
	}

	client := sessionFreshClient()

	// Record baseline access level for each admin endpoint.
	type baseline struct {
		ep   string
		code int
	}
	var baselines []baseline
	for _, ep := range adminEPs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		sessionApplyCredential(req, bearer, "")
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		baselines = append(baselines, baseline{ep: ep, code: resp.StatusCode})
	}

	if len(baselines) == 0 {
		return nil
	}

	// Simulate token refresh (re-present same token with slight delay to trigger cache).
	time.Sleep(500 * time.Millisecond)

	var findings []model.Finding
	for _, b := range baselines {
		if b.code < 200 || b.code >= 300 {
			// Not accessible at baseline — check if it's accessible on retry
			// (would indicate a TOCTOU or stale-cache grant).
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.ep, nil)
			if err != nil {
				continue
			}
			sessionApplyCredential(req, bearer, "")
			resp, err := client.Do(req)
			if err != nil || resp == nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, sessionEdgeCaseBodyLimit))
			_ = resp.Body.Close()

			lower := strings.ToLower(string(body))
			if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
				!strings.Contains(lower, "unauthorized") {
				findings = append(findings, model.Finding{
					ID:       "session-stale-privilege-cache",
					Category: "authorization",
					Severity: model.SeverityHigh,
					Title:    "Stale privilege cache: access granted on retry after initial rejection",
					Description: fmt.Sprintf(
						"An administrative endpoint at %s initially returned HTTP %d, "+
							"but a subsequent identical request returned HTTP %d. "+
							"This may indicate a TOCTOU vulnerability in permission checking or "+
							"that an authorization decision is being cached and incorrectly " +
							"updated between requests.",
						b.ep, b.code, resp.StatusCode,
					),
					Evidence: fmt.Sprintf(
						"GET %s → HTTP %d (first request) → HTTP %d (second request after delay)",
						b.ep, b.code, resp.StatusCode,
					),
					Recommendation:  "Evaluate authorization decisions synchronously on every request. Do not cache role or permission data across requests for security-sensitive endpoints.",
					Confidence:      0.60,
					AffectedURL:     b.ep,
					CWE:             "CWE-285",
					OWASPCategory:   "A01:2021 - Broken Access Control",
					Sources:         []string{"active-scanner", "session-edge-case-agents"},
					BusinessTags:    []string{"authorization", "privilege-escalation", "cache"},
					EvidenceFields:  map[string]string{"validationType": "active-probe", "firstStatus": fmt.Sprintf("%d", b.code), "secondStatus": fmt.Sprintf("%d", resp.StatusCode)},
				})
				break
			}
		}
	}
	return findings
}

// ─── Sub-agent: account lockout session survival ─────────────────────────────

// sessionAccountLockoutSurvivalAgent checks whether an existing valid session
// remains active after the account is locked out via repeated failed logins.
func sessionAccountLockoutSurvivalAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
	if in.auth.Username == "" {
		return nil
	}

	bearer := oauthExtractBearerToken(in.auth)
	cookie := sessionExtractSessionCookie(in.auth)
	if bearer == "" && cookie == "" {
		return nil
	}

	loginEPs := sessionDiscoverLoginEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	protectedEPs := sessionDiscoverProtectedEndpoints(in.base, in.options.SeedRuntimeEndpoints, in.scanScope)
	if len(loginEPs) == 0 || len(protectedEPs) == 0 {
		return nil
	}

	client := sessionFreshClient()

	// Trigger lockout with wrong password (limited attempts to avoid permanent lockout).
	wrongCreds := map[string]string{
		"username": in.auth.Username,
		"email":    in.auth.Username,
		"password": "ABH-WrongP@ss-Lockout-Probe!",
	}
	wrongJSON, _ := json.Marshal(wrongCreds)
	const lockoutAttempts = 5
	lockedOut := false
	for i := 0; i < lockoutAttempts; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginEPs[0], bytes.NewReader(wrongJSON))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			break
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, sessionEdgeCaseBodyLimit))
		_ = resp.Body.Close()
		lower := strings.ToLower(string(body))
		if strings.Contains(lower, "locked") || strings.Contains(lower, "too many") ||
			strings.Contains(lower, "account disabled") || resp.StatusCode == http.StatusTooManyRequests {
			lockedOut = true
			break
		}
	}

	if !lockedOut {
		return nil
	}

	// Now replay the original valid session.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEPs[0], nil)
	if err != nil {
		return nil
	}
	sessionApplyCredential(req, bearer, cookie)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, sessionEdgeCaseBodyLimit))
	_ = resp.Body.Close()

	lower := strings.ToLower(string(body))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		!strings.Contains(lower, "locked") &&
		!strings.Contains(lower, "unauthorized") {
		return []model.Finding{{
			ID:       "session-survives-account-lockout",
			Category: "authentication",
			Severity: model.SeverityHigh,
			Title:    "Active session remains valid after account lockout",
			Description: "Repeatedly submitting wrong credentials triggered an account lockout response, " +
				"but the pre-existing valid session token continued to access protected resources " +
				"with a successful response. Account lockout should terminate all active sessions " +
				"to prevent continued access by an attacker who has compromised a session token.",
			Evidence: fmt.Sprintf(
				"%d failed login attempts at %s (lockout triggered) → GET %s with original token → HTTP %d",
				lockoutAttempts, loginEPs[0], protectedEPs[0], resp.StatusCode,
			),
			Recommendation:  "When an account is locked out, invalidate all active sessions for that account. Treat lockout as a security event requiring full re-authentication.",
			Confidence:      0.80,
			AffectedURL:     loginEPs[0],
			CWE:             "CWE-613",
			OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
			Sources:         []string{"active-scanner", "session-edge-case-agents"},
			BusinessTags:    []string{"account-lockout", "session-invalidation"},
			EvidenceFields:  map[string]string{"validationType": "active-probe", "lockoutAttempts": fmt.Sprintf("%d", lockoutAttempts), "replayStatus": fmt.Sprintf("%d", resp.StatusCode)},
		}}
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// sessionFreshClient returns a new http.Client with no shared cookie state.
func sessionFreshClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: sessionEdgeCaseAgentTimeout,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// sessionApplyCredential attaches a ****** or session cookie to a request.
func sessionApplyCredential(req *http.Request, bearer, cookie string) {
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: cookie})
	}
}

// sessionDiscoverStepEndpoints extracts step-like endpoint paths from seeded
// endpoints (e.g., /checkout/step1, /wizard/2, /reset/verify).
func sessionDiscoverStepEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
	stepKeywords := []string{"step", "wizard", "stage", "phase", "checkout", "reset", "verify", "confirm"}
	var steps []string
	seen := map[string]struct{}{}
	for _, s := range seeded {
		lower := strings.ToLower(s)
		for _, kw := range stepKeywords {
			if strings.Contains(lower, kw) {
				if scope.IsURLInScope(s, scanScope) {
					if _, ok := seen[s]; !ok {
						seen[s] = struct{}{}
						steps = append(steps, s)
					}
				}
				break
			}
		}
	}

	// Also probe conventional step paths.
	conventionalSteps := []string{
		"/checkout/step1", "/checkout/step2", "/checkout/step3",
		"/wizard/step/1", "/wizard/step/2",
		"/password-reset/verify", "/password-reset/confirm",
		"/signup/step/1", "/signup/step/2", "/signup/step/3",
		"/onboarding/step1", "/onboarding/step2",
	}
	for _, p := range conventionalSteps {
		ref, _ := url.Parse(p)
		ep := base.ResolveReference(ref).String()
		if _, ok := seen[ep]; ok {
			continue
		}
		if !scope.IsURLInScope(ep, scanScope) {
			continue
		}
		seen[ep] = struct{}{}
		steps = append(steps, ep)
	}

	sort.Strings(steps)
	const max = 6
	if len(steps) > max {
		steps = steps[:max]
	}
	return steps
}

// sessionTokensAreSequential returns true if the collected tokens share a
// long common prefix with only the last few characters varying incrementally.
func sessionTokensAreSequential(tokens []string) bool {
	if len(tokens) < 3 {
		return false
	}
	// Find longest common prefix.
	prefix := tokens[0]
	for _, t := range tokens[1:] {
		for len(prefix) > 0 && !strings.HasPrefix(t, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	// If >80% of the token is common prefix, it's likely sequential.
	for _, t := range tokens {
		if len(t) == 0 {
			return false
		}
		if float64(len(prefix))/float64(len(t)) > 0.80 {
			return true
		}
	}
	return false
}

// shannonEntropy calculates the Shannon entropy (bits per character) of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]int{}
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	h := 0.0
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// sessionTruncateTokens returns truncated token strings safe for evidence fields.
func sessionTruncateTokens(tokens []string) []string {
	out := make([]string, len(tokens))
	for i, t := range tokens {
		out[i] = truncateString(t, 20)
	}
	return out
}
