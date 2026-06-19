package scanner

// session_edge_case_agent.go — fully-agentic sub-agents for session state-change edge cases.
//
// Architecture
// ────────────
// The orchestrator (RunSessionEdgeCaseAgents) discovers ALL in-scope endpoint
// candidates for each role (login, logout, protected, password-change, step)
// without any per-role cap.  For every agent definition, it spawns a separate
// goroutine for each *anchor endpoint* relevant to that agent type:
//
//   • anchorLogin   → one goroutine per login endpoint
//   • anchorLogout  → one goroutine per logout endpoint
//   • anchorPwChange→ one goroutine per password-change endpoint
//   • anchorOnce    → exactly one goroutine regardless of endpoint count
//
// This means the total concurrency = Σ (agent_count × anchor_endpoint_count),
// ensuring every reachable state-transition boundary is tested by every
// applicable agent without manual tuning.
//
// Each goroutine receives a fresh HTTP client (no shared cookie jar) and a
// per-agent context timeout.  The overall orchestrator budget (sessionEdgeCaseAgentBudget)
// bounds the entire run so the scan cannot stall.

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
// Sized generously because the matrix can spawn many goroutines for large scopes.
const sessionEdgeCaseAgentBudget = 3 * time.Minute

// sessionEdgeCaseAgentTimeout is the per-agent-instance timeout.
const sessionEdgeCaseAgentTimeout = 25 * time.Second

// sessionEdgeCaseBodyLimit caps response-body reads in edge-case agents.
const sessionEdgeCaseBodyLimit = 32 * 1024

// ─── Anchor type ─────────────────────────────────────────────────────────────

// sessionAnchor controls how many goroutines the orchestrator spawns per agent.
type sessionAnchor int

const (
anchorOnce      sessionAnchor = iota // exactly one goroutine
anchorLogin                          // one goroutine per login endpoint
anchorLogout                         // one goroutine per logout endpoint
anchorPwChange                       // one goroutine per password-change endpoint
)

// ─── Input / definition types ────────────────────────────────────────────────

// sessionEdgeCaseInput is the read-only input bundle passed to every sub-agent.
// It carries the scan context and ALL discovered endpoint sets so each agent
// can iterate over the full scope without rediscovery.
type sessionEdgeCaseInput struct {
target      string
base        *url.URL
auth        model.ScanAuthProfile
options     model.ScanOptions
scanScope   model.ScanScope
// anchorEP is the specific endpoint this goroutine is anchored to.
// Semantics depend on the agent: for login-anchored agents it is the
// login URL; for logout-anchored agents it is the logout URL, etc.
anchorEP    string
// Full discovered endpoint sets (no caps).
loginEPs    []string
logoutEPs   []string
protectedEPs []string
pwChangeEPs []string
stepEPs     []string
}

// sessionEdgeCaseAgentFn is the agent function signature.
type sessionEdgeCaseAgentFn func(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding

// sessionEdgeCaseAgentDef pairs metadata with an agent function.
type sessionEdgeCaseAgentDef struct {
name            string
needsCredential bool
anchor          sessionAnchor
fn              sessionEdgeCaseAgentFn
}

// sessionEdgeCaseAgentRegistry is the full set of edge-case sub-agents.
var sessionEdgeCaseAgentRegistry = []sessionEdgeCaseAgentDef{
{"logout-race-window", true, anchorLogout, sessionLogoutRaceAgent},
{"logout-partial-revocation", true, anchorLogout, sessionLogoutPartialRevocationAgent},
{"password-change-refresh-token", true, anchorPwChange, sessionPasswordChangeRefreshTokenAgent},
{"password-change-parallel-session", true, anchorPwChange, sessionPasswordChangeParallelSessionAgent},
{"session-fixation", true, anchorLogin, sessionFixationAgent},
{"session-token-entropy", true, anchorLogin, sessionTokenEntropyAgent},
{"multi-step-skip", false, anchorOnce, sessionMultiStepSkipAgent},
{"multi-step-replay", false, anchorOnce, sessionMultiStepReplayAgent},
{"privilege-escalation-cache", true, anchorOnce, sessionPrivilegeEscalationCacheAgent},
{"account-lockout-session-survival", true, anchorLogin, sessionAccountLockoutSurvivalAgent},
}

// ─── Orchestrator ─────────────────────────────────────────────────────────────

// RunSessionEdgeCaseAgents discovers all in-scope session-related endpoints,
// then spawns one goroutine per (agent × anchor-endpoint) combination so that
// every reachable state-transition boundary is covered concurrently.
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
Message: "Spawning session state-change edge-case sub-agents (one per anchor endpoint)",
})
}

// Discover all endpoint sets with no cap.
loginEPs := sessionAllLoginEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
logoutEPs := sessionAllLogoutEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
protectedEPs := sessionAllProtectedEndpoints(base, options.SeedRuntimeEndpoints, scanScope)
pwChangeEPs := sessionAllEndpoints(base, passwordChangePaths, scanScope)
stepEPs := sessionDiscoverStepEndpoints(base, options.SeedRuntimeEndpoints, scanScope)

hasCredential := hasStandardLoginCredentials(auth) ||
oauthExtractBearerToken(auth) != "" ||
sessionExtractSessionCookie(auth) != ""

budgetCtx, cancel := context.WithTimeout(ctx, sessionEdgeCaseAgentBudget)
defer cancel()

type agentResult struct {
findings []model.Finding
}
resultCh := make(chan agentResult, 256)

var wg sync.WaitGroup

for _, def := range sessionEdgeCaseAgentRegistry {
if def.needsCredential && !hasCredential {
continue
}

// Determine the anchor list for this agent.
var anchors []string
switch def.anchor {
case anchorLogin:
anchors = loginEPs
case anchorLogout:
anchors = logoutEPs
case anchorPwChange:
anchors = pwChangeEPs
case anchorOnce:
anchors = []string{""}
}
if len(anchors) == 0 {
anchors = []string{""}
}

for _, ep := range anchors {
in := sessionEdgeCaseInput{
target:       target,
base:         base,
auth:         auth,
options:      options,
scanScope:    scanScope,
anchorEP:     ep,
loginEPs:     loginEPs,
logoutEPs:    logoutEPs,
protectedEPs: protectedEPs,
pwChangeEPs:  pwChangeEPs,
stepEPs:      stepEPs,
}

wg.Add(1)
go func(d sessionEdgeCaseAgentDef, agentIn sessionEdgeCaseInput) {
defer wg.Done()
agentCtx, agentCancel := context.WithTimeout(budgetCtx, sessionEdgeCaseAgentTimeout)
defer agentCancel()
var found []model.Finding
func() {
defer func() { recover() }() //nolint:errcheck
found = d.fn(agentCtx, s, agentIn)
}()
if emit != nil && len(found) > 0 {
emit(model.ScanEvent{
Type:    model.ScanEventInfo,
Message: fmt.Sprintf("Session edge-case agent %q (anchor=%q) found %d issue(s)", d.name, agentIn.anchorEP, len(found)),
})
}
resultCh <- agentResult{findings: found}
}(def, in)
}
}

go func() {
wg.Wait()
close(resultCh)
}()

var all []model.Finding
seen := map[string]bool{}
for res := range resultCh {
for _, f := range res.findings {
// Deduplicate by ID to avoid N identical findings for N anchor EPs.
if !seen[f.ID] {
seen[f.ID] = true
all = append(all, f)
}
}
}
return all
}

// ─── Sub-agent: logout race window ───────────────────────────────────────────

func sessionLogoutRaceAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
bearer := oauthExtractBearerToken(in.auth)
cookie := sessionExtractSessionCookie(in.auth)
if bearer == "" && cookie == "" {
return nil
}
if in.anchorEP == "" || len(in.protectedEPs) == 0 {
return nil
}

client := sessionFreshClient()
logoutEP := in.anchorEP

for _, protectedEP := range in.protectedEPs {
type raceResult struct {
code int
body string
}
ch := make(chan raceResult, 1)

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

lReq, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutEP, nil)
if err != nil {
<-ch
continue
}
sessionApplyCredential(lReq, bearer, cookie)
lResp, err := client.Do(lReq)
if err != nil || lResp == nil {
<-ch
continue
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
"received a successful (2xx) response, indicating a race window between the server " +
"accepting logout and actually invalidating the session.",
Evidence: fmt.Sprintf(
"Concurrent GET %s (original token) during POST %s (logout) → HTTP %d",
protectedEP, logoutEP, res.code,
),
Recommendation:  "Invalidate the session synchronously before returning a logout 2xx. Use atomic session revocation.",
Confidence:      0.65,
AffectedURL:     logoutEP,
CWE:             "CWE-613",
OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
Sources:         []string{"active-scanner", "session-edge-case-agents"},
BusinessTags:    []string{"session-invalidation", "race-condition"},
EvidenceFields:  map[string]string{"validationType": "active-probe", "replayStatus": fmt.Sprintf("%d", res.code)},
}}
}
}
return nil
}

// ─── Sub-agent: logout partial revocation ────────────────────────────────────

func sessionLogoutPartialRevocationAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
bearer := oauthExtractBearerToken(in.auth)
cookie := sessionExtractSessionCookie(in.auth)
if bearer == "" || cookie == "" {
return nil
}
if in.anchorEP == "" || len(in.protectedEPs) == 0 {
return nil
}

client := sessionFreshClient()
logoutEP := in.anchorEP

lReq, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutEP, nil)
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

for _, protectedEP := range in.protectedEPs {
req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEP, nil)
if err != nil {
continue
}
req.Header.Set("Authorization", "Bearer "+bearer)
resp, err := client.Do(req)
if err != nil || resp == nil {
continue
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
Description: "Logout was performed via a session cookie, but the corresponding bearer token " +
"remained valid and returned a successful response to a protected endpoint.",
Evidence: fmt.Sprintf(
"POST %s (logout with cookie) → GET %s with bearer token → HTTP %d",
logoutEP, protectedEP, resp.StatusCode,
),
Recommendation:  "Invalidate all credential types atomically on logout. Link tokens to the server-side session.",
Confidence:      0.80,
AffectedURL:     logoutEP,
CWE:             "CWE-613",
OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
Sources:         []string{"active-scanner", "session-edge-case-agents"},
BusinessTags:    []string{"session-invalidation", "partial-revocation"},
EvidenceFields:  map[string]string{"validationType": "active-probe", "replayStatus": fmt.Sprintf("%d", resp.StatusCode)},
}}
}
}
return nil
}

// ─── Sub-agent: password change + refresh token ───────────────────────────────

func sessionPasswordChangeRefreshTokenAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
if in.anchorEP == "" {
return nil
}
refreshToken := ""
for k, v := range in.auth.Headers {
if strings.Contains(strings.ToLower(k), "refresh") {
refreshToken = v
break
}
}
if refreshToken == "" {
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
change := map[string]string{
"currentPassword": in.auth.Password,
"newPassword":     "ABH-ECA-P@ss1!2#",
"password":        "ABH-ECA-P@ss1!2#",
}
changeJSON, _ := json.Marshal(change)
cReq, err := http.NewRequestWithContext(ctx, http.MethodPost, in.anchorEP, bytes.NewReader(changeJSON))
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
Description: "After changing the account password, the original OAuth refresh token was accepted " +
"at the token endpoint and returned what appears to be a new access token.",
Evidence: fmt.Sprintf(
"POST %s (password change) → POST %s with old refresh_token → HTTP %d",
in.anchorEP, ep, rResp.StatusCode,
),
Recommendation:  "Revoke all refresh tokens when the account password changes.",
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

func sessionPasswordChangeParallelSessionAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
if in.anchorEP == "" || in.auth.Username == "" || in.auth.Password == "" {
return nil
}
if len(in.loginEPs) == 0 || len(in.protectedEPs) == 0 {
return nil
}

client := sessionFreshClient()

// Obtain a parallel session via the first available login endpoint.
parallelCookie := sessionAttemptLoginAndGetCookie(ctx, s, in.loginEPs[0], in.auth, in.options)
if parallelCookie == "" {
return nil
}

change := map[string]string{
"currentPassword": in.auth.Password,
"newPassword":     "ABH-ECA-Parallel-P@ss1!",
"password":        "ABH-ECA-Parallel-P@ss1!",
}
changeJSON, _ := json.Marshal(change)
cReq, err := http.NewRequestWithContext(ctx, http.MethodPost, in.anchorEP, bytes.NewReader(changeJSON))
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

for _, protectedEP := range in.protectedEPs {
req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEP, nil)
if err != nil {
continue
}
req.AddCookie(&http.Cookie{Name: "session", Value: parallelCookie})
resp, err := client.Do(req)
if err != nil || resp == nil {
continue
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
"returned a successful response after the password was changed.",
Evidence: fmt.Sprintf(
"Login → parallel session → POST %s (password change) → GET %s with parallel session → HTTP %d",
in.anchorEP, protectedEP, resp.StatusCode,
),
Recommendation:  "Invalidate all server-side sessions for the account on password change.",
Confidence:      0.78,
AffectedURL:     in.anchorEP,
CWE:             "CWE-613",
OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
Sources:         []string{"active-scanner", "session-edge-case-agents"},
BusinessTags:    []string{"session-invalidation", "password-change", "parallel-session"},
EvidenceFields:  map[string]string{"validationType": "active-probe", "replayStatus": fmt.Sprintf("%d", resp.StatusCode)},
}}
}
}
return nil
}

// ─── Sub-agent: session fixation ─────────────────────────────────────────────

func sessionFixationAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
if in.anchorEP == "" || in.auth.Username == "" || in.auth.Password == "" {
return nil
}
if len(in.protectedEPs) == 0 {
return nil
}

const fixatedID = "abh-fixated-session-12345"
client := sessionFreshClient()

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

creds := map[string]string{
"username": in.auth.Username,
"email":    in.auth.Username,
"password": in.auth.Password,
}
credsJSON, _ := json.Marshal(creds)
lReq, err := http.NewRequestWithContext(ctx, http.MethodPost, in.anchorEP, bytes.NewReader(credsJSON))
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

// Check if server rotated the session ID.
for _, ck := range lResp.Cookies() {
if sessionIsAuthCookie(ck.Name) && ck.Value == fixatedID {
// Not rotated — test access with the fixated ID.
for _, protectedEP := range in.protectedEPs {
req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEP, nil)
if err != nil {
continue
}
req.AddCookie(&http.Cookie{Name: "session", Value: fixatedID})
resp, err := client.Do(req)
if err != nil || resp == nil {
continue
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
Description: "A crafted session ID was pre-seeded before login and was not rotated " +
"upon successful authentication. An attacker who plants a known session ID can " +
"hijack the session after the victim logs in.",
Evidence: fmt.Sprintf(
"Pre-seeded session=%q → login at %s → ID unchanged → GET %s → HTTP %d",
fixatedID, in.anchorEP, protectedEP, resp.StatusCode,
),
Recommendation:  "Regenerate the session identifier immediately upon successful authentication.",
Confidence:      0.88,
AffectedURL:     in.anchorEP,
CWE:             "CWE-384",
OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
Sources:         []string{"active-scanner", "session-edge-case-agents"},
BusinessTags:    []string{"session-fixation", "session-rotation"},
EvidenceFields:  map[string]string{"validationType": "active-probe", "fixatedID": fixatedID},
}}
}
}
return nil
}
}
return nil // rotated correctly
}

// ─── Sub-agent: session token entropy ────────────────────────────────────────

func sessionTokenEntropyAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
if in.anchorEP == "" || in.auth.Username == "" || in.auth.Password == "" {
return nil
}

const sampleSize = 5
tokens := make([]string, 0, sampleSize)
for i := 0; i < sampleSize; i++ {
t := sessionAttemptLoginAndGetCookie(ctx, s, in.anchorEP, in.auth, in.options)
if t != "" {
tokens = append(tokens, t)
}
}
if len(tokens) < 3 {
return nil
}

if sessionTokensAreSequential(tokens) {
return []model.Finding{{
ID:       "session-token-sequential-pattern",
Category: "authentication",
Severity: model.SeverityHigh,
Title:    "Session tokens show sequential/predictable pattern",
Description: fmt.Sprintf(
"Collected %d session tokens across repeated logins at %s. The tokens exhibit a "+
"sequential or highly similar pattern, suggesting a predictable ID generation algorithm.",
len(tokens), in.anchorEP,
),
Evidence:        fmt.Sprintf("Sample tokens: %s", strings.Join(sessionTruncateTokens(tokens), ", ")),
Recommendation:  "Use a CSPRNG with at least 128 bits of entropy for session identifiers.",
Confidence:      0.82,
AffectedURL:     in.anchorEP,
CWE:             "CWE-330",
OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
Sources:         []string{"active-scanner", "session-edge-case-agents"},
BusinessTags:    []string{"session-entropy", "predictable-token"},
EvidenceFields:  map[string]string{"validationType": "active-probe", "sampleCount": fmt.Sprintf("%d", len(tokens))},
}}
}

if len(tokens) > 0 {
entropy := shannonEntropy(tokens[0])
if entropy < 3.5 {
return []model.Finding{{
ID:       "session-token-low-entropy",
Category: "authentication",
Severity: model.SeverityMedium,
Title:    fmt.Sprintf("Session token has low Shannon entropy (%.2f bits/char) at %s", entropy, in.anchorEP),
Description: fmt.Sprintf(
"The session token from %s has %.2f bits per character (threshold 3.5). "+
"Low entropy tokens are more susceptible to brute-force and prediction attacks.",
in.anchorEP, entropy,
),
Evidence:        fmt.Sprintf("Token: %s; entropy: %.2f", sessionTruncateTokens(tokens[:1])[0], entropy),
Recommendation:  "Generate tokens using a CSPRNG with at least 128 bits of entropy.",
Confidence:      0.70,
AffectedURL:     in.anchorEP,
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

func sessionMultiStepSkipAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
if len(in.stepEPs) < 2 {
return nil
}
client := sessionFreshClient()
bearer := oauthExtractBearerToken(in.auth)
cookie := sessionExtractSessionCookie(in.auth)

var findings []model.Finding
for i := 1; i < len(in.stepEPs); i++ {
req, err := http.NewRequestWithContext(ctx, http.MethodGet, in.stepEPs[i], nil)
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
"Direct access to %s (step %d) returned 2xx without first completing step %d. "+
"The server does not enforce sequential state transitions.",
in.stepEPs[i], i+1, i,
),
Evidence:        fmt.Sprintf("GET %s (step %d, skipped step %d) → HTTP %d", in.stepEPs[i], i+1, i, resp.StatusCode),
Recommendation:  "Validate server-side that each prior step has completed before allowing progression.",
Confidence:      0.65,
AffectedURL:     in.stepEPs[i],
CWE:             "CWE-841",
OWASPCategory:   "A04:2021 - Insecure Design",
Sources:         []string{"active-scanner", "session-edge-case-agents"},
BusinessTags:    []string{"multi-step-flow", "step-skip"},
EvidenceFields:  map[string]string{"validationType": "active-probe", "stepIndex": fmt.Sprintf("%d", i+1)},
})
break
}
}
return findings
}

// ─── Sub-agent: multi-step flow step-replay ──────────────────────────────────

func sessionMultiStepReplayAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
if len(in.stepEPs) < 2 {
return nil
}
client := sessionFreshClient()
bearer := oauthExtractBearerToken(in.auth)
cookie := sessionExtractSessionCookie(in.auth)

for _, ep := range in.stepEPs {
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

req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.stepEPs[0], nil)
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
"After advancing through all %d steps, re-submitting step 1 (%s) returned 2xx "+
"without an 'already completed' or 'invalid state' indicator.",
len(in.stepEPs), in.stepEPs[0],
),
Evidence:        fmt.Sprintf("Completed all steps → POST %s (replay step 1) → HTTP %d", in.stepEPs[0], resp.StatusCode),
Recommendation:  "Track flow state server-side with a nonce or state machine. Reject step re-submissions.",
Confidence:      0.62,
AffectedURL:     in.stepEPs[0],
CWE:             "CWE-841",
OWASPCategory:   "A04:2021 - Insecure Design",
Sources:         []string{"active-scanner", "session-edge-case-agents"},
BusinessTags:    []string{"multi-step-flow", "step-replay"},
EvidenceFields:  map[string]string{"validationType": "active-probe", "replayStatus": fmt.Sprintf("%d", resp.StatusCode)},
}}
}
return nil
}

// ─── Sub-agent: privilege escalation cache ───────────────────────────────────

func sessionPrivilegeEscalationCacheAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
bearer := oauthExtractBearerToken(in.auth)
if bearer == "" {
return nil
}
adminPaths := []string{
"/api/admin", "/api/admin/users", "/admin", "/api/roles",
"/api/v1/admin", "/api/settings", "/api/management",
}
adminEPs := sessionAllEndpoints(in.base, adminPaths, in.scanScope)
if len(adminEPs) == 0 {
return nil
}
client := sessionFreshClient()

type baseline struct{ ep string; code int }
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
baselines = append(baselines, baseline{ep, resp.StatusCode})
}

time.Sleep(500 * time.Millisecond)

var findings []model.Finding
for _, b := range baselines {
if b.code >= 200 && b.code < 300 {
continue // already accessible — not a cache issue
}
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
if resp.StatusCode >= 200 && resp.StatusCode < 300 && !strings.Contains(lower, "unauthorized") {
findings = append(findings, model.Finding{
ID:       "session-stale-privilege-cache",
Category: "authorization",
Severity: model.SeverityHigh,
Title:    "Stale privilege cache: access granted on retry after initial rejection",
Description: fmt.Sprintf(
"Admin endpoint %s initially returned HTTP %d but %d on retry, "+
"suggesting a TOCTOU vulnerability or stale authorization cache.",
b.ep, b.code, resp.StatusCode,
),
Evidence: fmt.Sprintf(
"GET %s → HTTP %d (first) → HTTP %d (second after delay)",
b.ep, b.code, resp.StatusCode,
),
Recommendation:  "Evaluate authorization synchronously on every request. Do not cache roles across requests.",
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
return findings
}

// ─── Sub-agent: account lockout session survival ─────────────────────────────

func sessionAccountLockoutSurvivalAgent(ctx context.Context, s *Service, in sessionEdgeCaseInput) []model.Finding {
if in.anchorEP == "" || in.auth.Username == "" {
return nil
}
bearer := oauthExtractBearerToken(in.auth)
cookie := sessionExtractSessionCookie(in.auth)
if bearer == "" && cookie == "" {
return nil
}
if len(in.protectedEPs) == 0 {
return nil
}

client := sessionFreshClient()
wrongCreds := map[string]string{
"username": in.auth.Username,
"email":    in.auth.Username,
"password": "ABH-WrongP@ss-Lockout!",
}
wrongJSON, _ := json.Marshal(wrongCreds)

const lockoutAttempts = 5
lockedOut := false
for i := 0; i < lockoutAttempts; i++ {
req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.anchorEP, bytes.NewReader(wrongJSON))
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

for _, protectedEP := range in.protectedEPs {
req, err := http.NewRequestWithContext(ctx, http.MethodGet, protectedEP, nil)
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
if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
!strings.Contains(lower, "locked") && !strings.Contains(lower, "unauthorized") {
return []model.Finding{{
ID:       "session-survives-account-lockout",
Category: "authentication",
Severity: model.SeverityHigh,
Title:    "Active session remains valid after account lockout",
Description: fmt.Sprintf(
"%d failed login attempts at %s triggered an account lockout response, "+
"but the pre-existing valid session token continued to access protected resources.",
lockoutAttempts, in.anchorEP,
),
Evidence: fmt.Sprintf(
"%d failed logins at %s → GET %s with original token → HTTP %d",
lockoutAttempts, in.anchorEP, protectedEP, resp.StatusCode,
),
Recommendation:  "When an account is locked out, invalidate all active sessions for that account.",
Confidence:      0.80,
AffectedURL:     in.anchorEP,
CWE:             "CWE-613",
OWASPCategory:   "A07:2021 - Identification and Authentication Failures",
Sources:         []string{"active-scanner", "session-edge-case-agents"},
BusinessTags:    []string{"account-lockout", "session-invalidation"},
EvidenceFields:  map[string]string{"validationType": "active-probe", "lockoutAttempts": fmt.Sprintf("%d", lockoutAttempts), "replayStatus": fmt.Sprintf("%d", resp.StatusCode)},
}}
}
}
return nil
}

// ─── Endpoint discovery helpers (no caps) ────────────────────────────────────

// sessionAllEndpoints resolves paths against base and returns all in-scope ones.
// Unlike sessionDiscoverEndpoints there is no cap on results.
func sessionAllEndpoints(base *url.URL, paths []string, scanScope model.ScanScope) []string {
var out []string
seen := map[string]struct{}{}
for _, p := range paths {
ref, _ := url.Parse(p)
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
return out
}

func sessionAllLoginEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
eps := sessionAllEndpoints(base, loginPaths, scanScope)
seen := map[string]struct{}{}
for _, e := range eps {
seen[e] = struct{}{}
}
for _, s := range seeded {
lower := strings.ToLower(s)
if (strings.Contains(lower, "login") || strings.Contains(lower, "signin")) &&
scope.IsURLInScope(s, scanScope) {
if _, ok := seen[s]; !ok {
seen[s] = struct{}{}
eps = append(eps, s)
}
}
}
return eps
}

func sessionAllLogoutEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
eps := sessionAllEndpoints(base, sessionLogoutPaths, scanScope)
seen := map[string]struct{}{}
for _, e := range eps {
seen[e] = struct{}{}
}
for _, s := range seeded {
lower := strings.ToLower(s)
if (strings.Contains(lower, "logout") || strings.Contains(lower, "signout")) &&
scope.IsURLInScope(s, scanScope) {
if _, ok := seen[s]; !ok {
seen[s] = struct{}{}
eps = append(eps, s)
}
}
}
return eps
}

func sessionAllProtectedEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
eps := sessionAllEndpoints(base, sessionProtectedPaths, scanScope)
seen := map[string]struct{}{}
for _, e := range eps {
seen[e] = struct{}{}
}
for _, s := range seeded {
lower := strings.ToLower(s)
if (strings.Contains(lower, "/me") || strings.Contains(lower, "/profile") ||
strings.Contains(lower, "/user") || strings.Contains(lower, "/account")) &&
scope.IsURLInScope(s, scanScope) {
if _, ok := seen[s]; !ok {
seen[s] = struct{}{}
eps = append(eps, s)
}
}
}
return eps
}

// ─── Step-flow endpoint discovery ────────────────────────────────────────────

func sessionDiscoverStepEndpoints(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
stepKeywords := []string{"step", "wizard", "stage", "phase", "checkout", "reset", "verify", "confirm"}
seen := map[string]struct{}{}
var steps []string

for _, s := range seeded {
lower := strings.ToLower(s)
for _, kw := range stepKeywords {
if strings.Contains(lower, kw) && scope.IsURLInScope(s, scanScope) {
if _, ok := seen[s]; !ok {
seen[s] = struct{}{}
steps = append(steps, s)
}
break
}
}
}

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
const max = 10
if len(steps) > max {
steps = steps[:max]
}
return steps
}

// ─── Shared HTTP/credential helpers ──────────────────────────────────────────

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

// sessionApplyCredential attaches a bearer token or session cookie to a request.
func sessionApplyCredential(req *http.Request, bearer, cookie string) {
if bearer != "" {
req.Header.Set("Authorization", "Bearer "+bearer)
}
if cookie != "" {
req.AddCookie(&http.Cookie{Name: "session", Value: cookie})
}
}

// ─── Token analysis helpers ───────────────────────────────────────────────────

func sessionTokensAreSequential(tokens []string) bool {
if len(tokens) < 3 {
return false
}
prefix := tokens[0]
for _, t := range tokens[1:] {
for len(prefix) > 0 && !strings.HasPrefix(t, prefix) {
prefix = prefix[:len(prefix)-1]
}
}
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

func sessionTruncateTokens(tokens []string) []string {
out := make([]string, len(tokens))
for i, t := range tokens {
out[i] = truncateString(t, 20)
}
return out
}
