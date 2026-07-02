package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// -----------------------------------------------------------------------------
// Baseline tests — lock in the pre-migration behaviour that must remain
// intact after the FN-reduction plan lands. If these tests break, revisit
// the migration; the safe defaults (POST-only fallback, hard-coded path
// list, forged-header carrier, scope enforcement) must survive.
// -----------------------------------------------------------------------------

func TestCollectCSRFCandidates_HardCodedPathsPostOnly(t *testing.T) {
	base, _ := url.Parse("https://example.test")
	scanScope := scope.Normalize(base.String(), model.ScanScope{})
	got := collectCSRFCandidates(base, nil, nil, scanScope)
	if len(got) == 0 {
		t.Fatalf("expected hard-coded state-changing paths, got zero candidates")
	}
	for _, c := range got {
		if c.method != http.MethodPost {
			t.Fatalf("hard-coded fallback list must be POST-only; got %s %s", c.method, c.url)
		}
		if !strings.HasPrefix(c.url, "https://example.test/") {
			t.Fatalf("candidate not scoped to target host: %s", c.url)
		}
	}
}

func TestCollectCSRFCandidates_SeedFilterHeuristicPreserved(t *testing.T) {
	base, _ := url.Parse("https://example.test")
	scanScope := scope.Normalize(base.String(), model.ScanScope{})
	seed := []string{
		"https://example.test/api/orders/list", // idempotent-looking, should not match
		"https://example.test/api/user/update", // matches "/update"
		"https://example.test/api/settings",    // matches "/settings"
	}
	got := collectCSRFCandidates(base, seed, nil, scanScope)
	sawUpdate, sawList := false, false
	for _, c := range got {
		if strings.HasSuffix(c.url, "/api/user/update") {
			sawUpdate = true
		}
		if strings.HasSuffix(c.url, "/api/orders/list") {
			sawList = true
		}
	}
	if !sawUpdate {
		t.Fatalf("expected /api/user/update in candidates: %v", got)
	}
	if sawList {
		t.Fatalf("idempotent-looking /api/orders/list must not be picked up by heuristic")
	}
}

func TestCollectCSRFCandidates_ScopeFiltering(t *testing.T) {
	base, _ := url.Parse("https://example.test")
	scanScope := scope.Normalize(base.String(), model.ScanScope{})
	seed := []string{
		"https://other.invalid/api/user/update", // out of scope
		"https://example.test/api/user/update",  // in scope
	}
	got := collectCSRFCandidates(base, seed, nil, scanScope)
	for _, c := range got {
		if strings.Contains(c.url, "other.invalid") {
			t.Fatalf("out-of-scope URL leaked into candidates: %s", c.url)
		}
	}
}

// -----------------------------------------------------------------------------
// Priority A — SurfaceInventory + method expansion + RecordProbedKey
// -----------------------------------------------------------------------------

func TestCollectCSRFCandidates_ConsumesInventoryStateChangingMethods(t *testing.T) {
	base, _ := url.Parse("https://example.test")
	scanScope := scope.Normalize(base.String(), model.ScanScope{})
	sess := NewScanSession()
	inv := NewSurfaceInventory()
	inv.Add(http.MethodPut, "https://example.test/api/v2/users/me", nil, SurfaceSourceRuntimeXHR)
	inv.Add(http.MethodPatch, "https://example.test/api/v2/accounts/42", nil, SurfaceSourceRuntimeXHR)
	inv.Add(http.MethodDelete, "https://example.test/api/v2/tokens/xyz", nil, SurfaceSourceRuntimeXHR)
	inv.Add(http.MethodGet, "https://example.test/api/v2/list", nil, SurfaceSourceRuntimeXHR) // idempotent, must be skipped
	sess.SetSurfaceInventory(inv)

	got := collectCSRFCandidates(base, nil, sess, scanScope)
	saw := map[string]bool{}
	for _, c := range got {
		saw[c.method+" "+c.url] = true
		if c.method == http.MethodGet {
			t.Fatalf("GET must not appear as a CSRF candidate: %+v", c)
		}
	}
	for _, want := range []string{
		"PUT https://example.test/api/v2/users/me",
		"PATCH https://example.test/api/v2/accounts/42",
		"DELETE https://example.test/api/v2/tokens/xyz",
	} {
		if !saw[want] {
			t.Fatalf("expected inventory candidate %q; got: %v", want, got)
		}
	}
}

func TestRunCSRFProbe_RecordsProbedKey(t *testing.T) {
	ResetSurfaceCoverageMetrics()
	// Vulnerable server: accepts any state-changing method without a
	// CSRF token. We only care that RecordProbedKey was invoked.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	sess := NewScanSession()
	input := RunInput{
		Target:  target.URL,
		Session: sess,
		Scope:   scope.Normalize(target.URL, model.ScanScope{}),
	}
	_ = svc.runCSRFProbe(context.Background(), input)

	m := GetSurfaceCoverageMetrics()
	if m.ProbedTotal == 0 {
		t.Fatalf("expected RecordProbedKey to have been called; ProbedTotal=%d", m.ProbedTotal)
	}
}

// -----------------------------------------------------------------------------
// Priority A/B — method + content-type + token-carrier matrix
// -----------------------------------------------------------------------------

// requestLog is a shared, atomically-updated recorder used by the
// httptest servers below.
type csrfReqLog struct {
	count       atomic.Int64
	sawPUT      atomic.Bool
	sawForm     atomic.Bool
	sawJSON     atomic.Bool
	sawXCSRF    atomic.Bool
	sawXXSRF    atomic.Bool
	sawAttacker atomic.Bool
	sawNull     atomic.Bool
}

func newCSRFVulnerableServer(log *csrfReqLog, accept func(r *http.Request) bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.count.Add(1)
		if r.Method == http.MethodPut {
			log.sawPUT.Store(true)
		}
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			log.sawForm.Store(true)
		}
		if strings.HasPrefix(ct, "application/json") {
			log.sawJSON.Store(true)
		}
		if r.Header.Get("X-CSRF-Token") != "" {
			log.sawXCSRF.Store(true)
		}
		if r.Header.Get("X-XSRF-TOKEN") != "" {
			log.sawXXSRF.Store(true)
		}
		if strings.Contains(r.Header.Get("Origin"), "attacker") {
			log.sawAttacker.Store(true)
		}
		if r.Header.Get("Origin") == "null" {
			log.sawNull.Store(true)
		}
		if accept != nil && accept(r) {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
}

func TestRunCSRFProbe_NonPOSTMethod_DetectedFromInventory(t *testing.T) {
	log := &csrfReqLog{}
	// Accept only PUT that carries the authenticated session cookie —
	// models a PUT-based REST endpoint with no CSRF enforcement.
	target := newCSRFVulnerableServer(log, func(r *http.Request) bool {
		c, _ := r.Cookie("session")
		return r.Method == http.MethodPut && c != nil && c.Value == "authed"
	})
	defer target.Close()

	svc := NewService(Config{})
	sess := NewScanSession()
	sess.SeedCookies(target.URL, map[string]string{"session": "authed"})
	inv := NewSurfaceInventory()
	inv.Add(http.MethodPut, target.URL+"/api/user/profile", nil, SurfaceSourceRuntimeXHR)
	sess.SetSurfaceInventory(inv)

	findings := svc.runCSRFProbe(context.Background(), RunInput{
		Target:  target.URL,
		Session: sess,
		Scope:   scope.Normalize(target.URL, model.ScanScope{}),
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 CSRF finding for PUT-only endpoint; got %d", len(findings))
	}
	f := findings[0]
	if f.EvidenceFields["httpMethod"] != http.MethodPut {
		t.Fatalf("evidence httpMethod should be PUT, got %q", f.EvidenceFields["httpMethod"])
	}
	if !log.sawPUT.Load() {
		t.Fatalf("expected the probe to have issued a PUT request")
	}
}

func TestRunCSRFProbe_FormEncodedOnlyEndpoint_Detected(t *testing.T) {
	log := &csrfReqLog{}
	// Accept POST with form-encoded body only, and only when the
	// session cookie is present — models a legacy form handler that
	// never received JSON hardening but does require auth.
	target := newCSRFVulnerableServer(log, func(r *http.Request) bool {
		if r.Method != http.MethodPost {
			return false
		}
		c, _ := r.Cookie("session")
		if c == nil || c.Value != "authed" {
			return false
		}
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		return strings.HasPrefix(ct, "application/x-www-form-urlencoded")
	})
	defer target.Close()

	svc := NewService(Config{})
	sess := NewScanSession()
	sess.SeedCookies(target.URL, map[string]string{"session": "authed"})
	inv := NewSurfaceInventory()
	inv.Add(http.MethodPost, target.URL+"/legacy/update", nil, SurfaceSourceCrawl)
	sess.SetSurfaceInventory(inv)

	findings := svc.runCSRFProbe(context.Background(), RunInput{
		Target:  target.URL,
		Session: sess,
		Scope:   scope.Normalize(target.URL, model.ScanScope{}),
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 CSRF finding for form-encoded-only endpoint; got %d", len(findings))
	}
	if got := findings[0].EvidenceFields["contentType"]; !strings.HasPrefix(got, "application/x-www-form-urlencoded") {
		t.Fatalf("evidence contentType should be form-encoded, got %q", got)
	}
	if !log.sawForm.Load() {
		t.Fatalf("expected the probe to have issued a form-encoded request")
	}
}

// -----------------------------------------------------------------------------
// Priority C — Origin/Referer defence bypass
// -----------------------------------------------------------------------------

func TestRunCSRFProbe_AttackerOriginBypass_Detected(t *testing.T) {
	log := &csrfReqLog{}
	// Accept only when Origin looks attacker-controlled AND the
	// session cookie is present. This proves that (a) the attacker
	// Origin recipe fires, and (b) the auth cookie is required so
	// the unauth baseline correctly fails.
	target := newCSRFVulnerableServer(log, func(r *http.Request) bool {
		c, _ := r.Cookie("session")
		return strings.Contains(r.Header.Get("Origin"), "attacker.abh-scanner.invalid") &&
			c != nil && c.Value == "authed"
	})
	defer target.Close()

	svc := NewService(Config{})
	sess := NewScanSession()
	sess.SeedCookies(target.URL, map[string]string{"session": "authed"})
	inv := NewSurfaceInventory()
	inv.Add(http.MethodPost, target.URL+"/api/user/profile", nil, SurfaceSourceRuntimeXHR)
	sess.SetSurfaceInventory(inv)

	findings := svc.runCSRFProbe(context.Background(), RunInput{
		Target:  target.URL,
		Session: sess,
		Scope:   scope.Normalize(target.URL, model.ScanScope{}),
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 CSRF finding under attacker-Origin recipe; got %d", len(findings))
	}
	if got := findings[0].EvidenceFields["originHeader"]; got != "attacker" {
		t.Fatalf("evidence originHeader should be \"attacker\", got %q", got)
	}
	if !log.sawAttacker.Load() {
		t.Fatalf("expected the probe to have issued a request with an attacker Origin")
	}
}

// -----------------------------------------------------------------------------
// Priority D — proof gate: unauthenticated baseline downgrade + repeat check
// -----------------------------------------------------------------------------

func TestRunCSRFProbe_PublicEndpoint_Suppressed(t *testing.T) {
	// Server accepts every request (authenticated or not). The
	// endpoint is genuinely public, not CSRF-vulnerable.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	sess := NewScanSession()
	inv := NewSurfaceInventory()
	inv.Add(http.MethodPost, target.URL+"/api/newsletter/subscribe", nil, SurfaceSourceRuntimeXHR)
	sess.SetSurfaceInventory(inv)

	findings := svc.runCSRFProbe(context.Background(), RunInput{
		Target:  target.URL,
		Session: sess,
		Scope:   scope.Normalize(target.URL, model.ScanScope{}),
	})
	if len(findings) != 0 {
		t.Fatalf("public endpoint should not produce a CSRF finding; got %d", len(findings))
	}
}

func TestRunCSRFProbe_FlakyEndpoint_NotReproducible_Suppressed(t *testing.T) {
	// Server accepts the very first mutating request but then fails
	// every subsequent replay. The two-control baseline should reject
	// this as flake.
	var served atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// unauth baseline probe — always deny
			w.WriteHeader(http.StatusForbidden)
			return
		}
		n := served.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer target.Close()

	svc := NewService(Config{})
	sess := NewScanSession()
	inv := NewSurfaceInventory()
	inv.Add(http.MethodPost, target.URL+"/api/user/profile", nil, SurfaceSourceRuntimeXHR)
	sess.SetSurfaceInventory(inv)

	findings := svc.runCSRFProbe(context.Background(), RunInput{
		Target:  target.URL,
		Session: sess,
		Scope:   scope.Normalize(target.URL, model.ScanScope{}),
	})
	if len(findings) != 0 {
		t.Fatalf("flaky endpoint should be suppressed by two-control baseline; got %d findings", len(findings))
	}
}

func TestRunCSRFProbe_AuthenticatedOnly_Reported(t *testing.T) {
	// Server accepts every non-GET request only when the session
	// cookie is present. Unauth baseline (no cookie) must fail so
	// the finding is emitted.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		c, _ := r.Cookie("session")
		if c == nil || c.Value != "authed" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	sess := NewScanSession()
	sess.SeedCookies(target.URL, map[string]string{"session": "authed"})
	inv := NewSurfaceInventory()
	inv.Add(http.MethodPost, target.URL+"/api/user/profile", nil, SurfaceSourceRuntimeXHR)
	sess.SetSurfaceInventory(inv)

	findings := svc.runCSRFProbe(context.Background(), RunInput{
		Target:  target.URL,
		Session: sess,
		Scope:   scope.Normalize(target.URL, model.ScanScope{}),
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 CSRF finding for authenticated-only accepting endpoint; got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "csrf-missing-protection" {
		t.Fatalf("unexpected finding ID %q", f.ID)
	}
	if f.EvidenceFields["httpMethod"] == "" {
		t.Fatalf("evidence httpMethod must be set: %+v", f.EvidenceFields)
	}
	if f.EvidenceFields["contentType"] == "" {
		t.Fatalf("evidence contentType must be set: %+v", f.EvidenceFields)
	}
	if f.EvidenceFields["tokenCarrierTested"] == "" {
		t.Fatalf("evidence tokenCarrierTested must be set: %+v", f.EvidenceFields)
	}
	if f.EvidenceFields["reVerifiedRuns"] != "2" {
		t.Fatalf("evidence reVerifiedRuns should be 2; got %q", f.EvidenceFields["reVerifiedRuns"])
	}
	if _, ok := f.EvidenceFields["preReport.verified"]; !ok {
		t.Fatalf("finding should carry preReport verification metadata: %+v", f.EvidenceFields)
	}
}

// -----------------------------------------------------------------------------
// PassiveOnly + missing-session short-circuit — must remain intact.
// -----------------------------------------------------------------------------

func TestRunCSRFProbe_PassiveOnly_ShortCircuits(t *testing.T) {
	svc := NewService(Config{})
	findings := svc.runCSRFProbe(context.Background(), RunInput{
		Target:  "https://example.test",
		Session: NewScanSession(),
		Options: model.ScanOptions{PassiveOnly: true},
	})
	if len(findings) != 0 {
		t.Fatalf("PassiveOnly mode must suppress CSRF probe; got %d", len(findings))
	}
}

func TestRunCSRFProbe_MissingSession_ShortCircuits(t *testing.T) {
	svc := NewService(Config{})
	findings := svc.runCSRFProbe(context.Background(), RunInput{
		Target: "https://example.test",
	})
	if len(findings) != 0 {
		t.Fatalf("nil session must suppress CSRF probe; got %d", len(findings))
	}
}

// -----------------------------------------------------------------------------
// csrfProbeBody: body-shape matrix has correct MIME semantics.
// -----------------------------------------------------------------------------

func TestCSRFProbeBody_ContentTypeMatrix(t *testing.T) {
	cases := []struct {
		ct       string
		contains string
	}{
		{"application/json", `"email":"csrf-probe@abh-scanner.invalid"`},
		{"application/x-www-form-urlencoded", "email=csrf-probe%40abh-scanner.invalid"},
		{"text/plain", "email=csrf-probe@abh-scanner.invalid"},
		{"multipart/form-data; boundary=abhboundary", "--abhboundary"},
	}
	for _, c := range cases {
		got := string(csrfProbeBody(c.ct))
		if !strings.Contains(got, c.contains) {
			t.Fatalf("csrfProbeBody(%q) = %q; expected substring %q", c.ct, got, c.contains)
		}
	}
}

// -----------------------------------------------------------------------------
// applyCSRFTokenCarrier / applyCSRFOriginVariant: header wiring.
// -----------------------------------------------------------------------------

func TestApplyCSRFTokenCarrier_HeaderIsSetOnlyWhenNamed(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example.test/", nil)
	applyCSRFTokenCarrier(req, "absent")
	if req.Header.Get("X-CSRF-Token") != "" {
		t.Fatalf("absent carrier should not add any header")
	}
	applyCSRFTokenCarrier(req, "X-CSRF-Token")
	if req.Header.Get("X-CSRF-Token") == "" {
		t.Fatalf("named carrier should populate header")
	}
}

func TestApplyCSRFOriginVariant_AttackerAndNull(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example.test/", nil)
	req.Header.Set("Referer", "https://example.test/dashboard")
	applyCSRFOriginVariant(req, "attacker")
	if req.Header.Get("Origin") != csrfAttackerOrigin {
		t.Fatalf("attacker variant should set attacker Origin")
	}
	if req.Header.Get("Referer") != "" {
		t.Fatalf("attacker variant should strip Referer")
	}
	req2, _ := http.NewRequest(http.MethodPost, "https://example.test/", nil)
	applyCSRFOriginVariant(req2, "null")
	if req2.Header.Get("Origin") != "null" {
		t.Fatalf("null variant should set Origin: null")
	}
}

// -----------------------------------------------------------------------------
// CSRF token bypass tests — cover the misconfiguration-detection variants
// added on top of the base Priority-A/B/C matrix. Unit tests exercise the
// applyCSRFBypass mutations; an end-to-end test exercises a server that
// accepts an empty-value token to prove the bypass reaches the wire and
// produces a finding.
// -----------------------------------------------------------------------------

func TestApplyCSRFBypass_EmptyValueOverridesForgedHeader(t *testing.T) {
req, _ := http.NewRequest(http.MethodPost, "https://example.test/", nil)
applyCSRFTokenCarrier(req, "X-CSRF-Token")
if req.Header.Get("X-CSRF-Token") == "" {
t.Fatalf("precondition: carrier should have set a non-empty header")
}
applyCSRFBypass(req, csrfRecipe{tokenCarrier: "X-CSRF-Token", bypass: "empty-value"})
if v, ok := req.Header["X-Csrf-Token"]; !ok || len(v) != 1 || v[0] != "" {
t.Fatalf("empty-value bypass should overwrite header with empty string; got %v", v)
}
}

func TestApplyCSRFBypass_MethodOverrideHeadersSet(t *testing.T) {
req, _ := http.NewRequest(http.MethodPost, "https://example.test/", nil)
applyCSRFBypass(req, csrfRecipe{tokenCarrier: "X-CSRF-Token", bypass: "method-override"})
for _, h := range csrfMethodOverrideAliases {
if got := req.Header.Get(h); got == "" {
t.Fatalf("method-override bypass should set %s header", h)
}
}
// Outer method is POST → override should differ from POST.
if got := req.Header.Get("X-HTTP-Method-Override"); strings.EqualFold(got, http.MethodPost) {
// PUT was the fallback; POST is only used when outer was PUT.
t.Fatalf("method-override should be a different verb when outer is POST; got %q", got)
}
}

func TestApplyCSRFBypass_DuplicateTokenAddsSecondValue(t *testing.T) {
req, _ := http.NewRequest(http.MethodPost, "https://example.test/", nil)
applyCSRFTokenCarrier(req, "X-CSRF-Token")
applyCSRFBypass(req, csrfRecipe{tokenCarrier: "X-CSRF-Token", bypass: "duplicate-token"})
vals := req.Header.Values("X-CSRF-Token")
if len(vals) != 2 {
t.Fatalf("duplicate-token bypass should yield two header values; got %v", vals)
}
if vals[0] == vals[1] {
t.Fatalf("duplicate-token values should differ; got %v", vals)
}
}

func TestApplyCSRFBypass_DefaultTokenIsWellKnownValue(t *testing.T) {
req, _ := http.NewRequest(http.MethodPost, "https://example.test/api/user/profile", nil)
applyCSRFTokenCarrier(req, "X-CSRF-Token")
applyCSRFBypass(req, csrfRecipe{tokenCarrier: "X-CSRF-Token", bypass: "default-token"})
got := req.Header.Get("X-CSRF-Token")
found := false
for _, v := range csrfDefaultTokenValues {
if got == v {
found = true
break
}
}
if !found {
t.Fatalf("default-token bypass should pick a value from csrfDefaultTokenValues; got %q", got)
}
}

func TestApplyCSRFBypass_EmptyBypassIsNoOp(t *testing.T) {
req, _ := http.NewRequest(http.MethodPost, "https://example.test/", nil)
applyCSRFTokenCarrier(req, "X-CSRF-Token")
before := req.Header.Get("X-CSRF-Token")
applyCSRFBypass(req, csrfRecipe{tokenCarrier: "X-CSRF-Token", bypass: ""})
if req.Header.Get("X-CSRF-Token") != before {
t.Fatalf("empty bypass should not mutate the request")
}
if req.Header.Get("X-HTTP-Method-Override") != "" {
t.Fatalf("empty bypass should not set method-override headers")
}
}

// TestRunCSRFProbe_EmptyValueBypass_Detected wires the empty-value bypass
// end-to-end: the server rejects both the absent-token and the forged-token
// requests, but accepts any POST with an empty X-CSRF-Token header. This
// isolates the "presence-only" misconfiguration the bypass targets.
func TestRunCSRFProbe_EmptyValueBypass_Detected(t *testing.T) {
target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.Method == http.MethodGet {
w.WriteHeader(http.StatusForbidden)
return
}
c, _ := r.Cookie("session")
if c == nil || c.Value != "authed" {
w.WriteHeader(http.StatusUnauthorized)
return
}
vals := r.Header.Values("X-CSRF-Token")
// Reject: no token, or any non-empty token value.
if len(vals) == 0 {
w.WriteHeader(http.StatusForbidden)
return
}
for _, v := range vals {
if v != "" {
w.WriteHeader(http.StatusForbidden)
return
}
}
// Empty-value bypass: header is present but every value is "".
w.WriteHeader(http.StatusOK)
}))
defer target.Close()

svc := NewService(Config{})
sess := NewScanSession()
sess.SeedCookies(target.URL, map[string]string{"session": "authed"})
inv := NewSurfaceInventory()
inv.Add(http.MethodPost, target.URL+"/api/user/profile", nil, SurfaceSourceRuntimeXHR)
sess.SetSurfaceInventory(inv)

findings := svc.runCSRFProbe(context.Background(), RunInput{
Target:  target.URL,
Session: sess,
Scope:   scope.Normalize(target.URL, model.ScanScope{}),
})
if len(findings) != 1 {
t.Fatalf("expected 1 CSRF finding for empty-value bypass; got %d", len(findings))
}
if got := findings[0].EvidenceFields["bypassTechnique"]; got != "empty-value" {
t.Fatalf("expected bypassTechnique=empty-value evidence; got %q", got)
}
}

// Guard against accidental removal of a bypass recipe: the matrix must
// carry at least one recipe per bypass variant so the misconfiguration
// classes remain covered end-to-end.
func TestCSRFRecipes_BypassMatrixCoverage(t *testing.T) {
seen := map[string]bool{}
for _, r := range csrfRecipes {
seen[r.bypass] = true
}
for _, want := range []string{"", "empty-value", "method-override", "duplicate-token", "default-token"} {
if !seen[want] {
t.Fatalf("csrfRecipes missing coverage for bypass %q", want)
}
}
// Sanity: total attempts still fits under csrfMaxAttempts for a
// single candidate (the loop stops on first 2xx anyway, but the
// upper bound must remain sane so multiple candidates get budget).
if len(csrfRecipes) > csrfMaxAttempts {
t.Fatalf("recipe matrix (%d) exceeds attempt budget (%d)", len(csrfRecipes), csrfMaxAttempts)
}
_ = atomic.LoadInt32
}
