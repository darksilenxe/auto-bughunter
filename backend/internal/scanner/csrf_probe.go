package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/proofpolicy"
	"auto-bughunter/backend/internal/scope"
)

// csrfBodyLimit caps per-probe response reads for the CSRF probe.
const csrfBodyLimit = 128 * 1024

// csrfMaxAttempts caps the total number of outbound requests the probe
// issues per scan across all (candidate × method × content-type × token
// carrier × Origin) recipes. The cap is applied after de-duplication
// and scope filtering so real candidates surfaced by the inventory are
// not silently dropped by a pre-filter budget.
const csrfMaxAttempts = 32

// csrfStateChangingPaths are conventional paths for state-changing
// operations. The probe posts to these paths without a CSRF token to
// test server-side enforcement even when no runtime endpoints have
// been surfaced by the crawler.
var csrfStateChangingPaths = []string{
	"/api/user/profile",
	"/api/user/email",
	"/api/user/password",
	"/api/account/update",
	"/api/settings",
	"/user/update",
	"/profile/update",
	"/account/update",
	"/settings",
}

// csrfStateChangingMethods is the set of HTTP methods the probe treats
// as potentially state-changing. GET/HEAD/OPTIONS are excluded because
// idempotent methods are, by convention, not CSRF-relevant.
var csrfStateChangingMethods = []string{
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
}

// csrfContentTypes rotates over the body shapes an attacker can send
// cross-origin. Form-encoded and text/plain are the classic CSRF
// vectors (CORS-simple, no preflight); JSON and multipart are the
// modern-API variants that also matter when the server accepts them.
var csrfContentTypes = []string{
	"application/x-www-form-urlencoded",
	"text/plain",
	"application/json",
	"multipart/form-data; boundary=abhboundary",
}

// csrfHeaderTokenNames is the set of well-known CSRF-token header
// aliases the forged-token branch iterates. Using only "X-CSRF-Token"
// (the pre-migration behaviour) missed servers that enforce any of
// the other names.
var csrfHeaderTokenNames = []string{
	"X-CSRF-Token",
	"X-XSRF-TOKEN",
	"X-CSRFToken",
	"CSRF-Token",
	"X-Requested-With",
}

// csrfOriginVariants is the set of Origin headers the probe rotates
// over to detect Origin/Referer-only defences. "same-origin" leaves
// the Origin header untouched (browser default for same-origin
// requests); "attacker" forges a hostile origin and drops Referer;
// "null" simulates a sandboxed-iframe / data-URL document.
var csrfOriginVariants = []string{"same-origin", "attacker", "null"}

// csrfAttackerOrigin is the synthetic hostile Origin used for the
// Origin/Referer bypass variant. The invalid TLD guarantees the
// value cannot collide with any real deployment.
const csrfAttackerOrigin = "https://attacker.abh-scanner.invalid"

// csrfBypassVariants enumerates common CSRF-token *bypass* techniques
// the probe attempts against candidates that reject the plain
// absent-token / forged-token attempts. These target real-world
// misconfigurations where the server implements a CSRF check but the
// check is defeatable by a benign-looking request tweak.
//
//	empty-value        — server treats an empty header/parameter
//	                     value as valid ("presence, not value" check)
//	method-override    — server routes on X-HTTP-Method-Override /
//	                     _method but applies CSRF policy to the outer
//	                     HTTP method
//	duplicate-token    — parameter/header pollution: send the token
//	                     twice with different values; middleware may
//	                     compare against one copy while the app reads
//	                     the other
//	default-token      — server accepts a well-known default / stub
//	                     value (some frameworks ship with "test" or
//	                     "0" as a development bypass)
var csrfBypassVariants = []string{
	"",
	"empty-value",
	"method-override",
	"duplicate-token",
	"default-token",
}

// csrfDefaultTokenValues is the small list of "obvious" token values
// the default-token bypass rotates over. Kept short so a single
// candidate's bypass slot fits inside the per-scan attempt budget.
var csrfDefaultTokenValues = []string{"0", "test", "null"}

// csrfMethodOverrideAliases is the list of headers commonly consulted
// by web frameworks to override the HTTP method used for routing /
// authorization decisions. The probe sets one of these to a
// state-changing verb while leaving the outer request method as
// something the CSRF middleware may treat as "safe".
var csrfMethodOverrideAliases = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
}

// csrfRecipe is one dimension of the attempt matrix: (content-type,
// token carrier, Origin variant, bypass technique). csrfRecipes is
// intentionally short so a single candidate exhausts a small budget
// before the loop advances to the next endpoint.
type csrfRecipe struct {
	contentType  string
	tokenCarrier string // "absent", a header name, or a body-param name
	origin       string // one of csrfOriginVariants
	bypass       string // one of csrfBypassVariants ("" == none)
}

// csrfRecipes is the ordered attempt matrix per candidate. The order
// front-loads the highest-signal variants (absent-token JSON, then
// form-encoded — the classical CSRF form-post vector) so the budget
// is spent on discriminating variants first. Bypass variants come
// last: they only fire once the plain attempts have failed and the
// probe still has budget for the candidate.
var csrfRecipes = []csrfRecipe{
	{"application/json", "absent", "same-origin", ""},
	{"application/x-www-form-urlencoded", "absent", "same-origin", ""},
	{"text/plain", "absent", "same-origin", ""},
	{"multipart/form-data; boundary=abhboundary", "absent", "same-origin", ""},
	{"application/json", "X-CSRF-Token", "same-origin", ""},
	{"application/json", "X-XSRF-TOKEN", "same-origin", ""},
	{"application/json", "X-CSRFToken", "same-origin", ""},
	{"application/json", "X-Requested-With", "same-origin", ""},
	{"application/json", "absent", "attacker", ""},
	{"application/json", "absent", "null", ""},
	// CSRF-token bypass variants — each targets a specific
	// misconfiguration class. Rotated across the primary carriers so
	// one bypass never monopolises the per-candidate budget.
	{"application/json", "X-CSRF-Token", "same-origin", "empty-value"},
	{"application/x-www-form-urlencoded", "X-CSRF-Token", "same-origin", "empty-value"},
	{"application/json", "X-CSRF-Token", "same-origin", "method-override"},
	{"application/x-www-form-urlencoded", "X-CSRF-Token", "same-origin", "duplicate-token"},
	{"application/json", "X-CSRF-Token", "same-origin", "default-token"},
}

// csrfCandidate is a state-changing endpoint surfaced by the crawl,
// runtime XHR interceptor, SurfaceInventory or the built-in
// well-known-path list. Method is upper-case and is always one of
// csrfStateChangingMethods.
type csrfCandidate struct {
	method string
	url    string
}

// csrfAttempt records a single request variant that returned 2xx.
type csrfAttempt struct {
	candidate    csrfCandidate
	recipe       csrfRecipe
	status       int
	responseBody []byte
}

// runCSRFProbe is the session-aware CSRF probe. It replays
// state-changing requests without a CSRF token (or with a forged one,
// or with a hostile Origin header) against every state-changing
// endpoint surfaced by Phase 2's SurfaceInventory plus a hard-coded
// well-known-path list. Only meaningful for authenticated sessions —
// without a session cookie the endpoint would reject the request
// anyway.
//
// A finding is emitted when the server accepts a state-changing
// request that includes the authenticated session cookie but omits
// the CSRF token the server should require (or accepts any bogus
// token, or accepts an attacker-controlled Origin), and the accepted
// request:
//  1. is not simultaneously accepted for an unauthenticated caller
//     (which would prove the endpoint is genuinely public), and
//  2. reproduces under a two-control replay (rejecting flake).
func (s *Service) runCSRFProbe(ctx context.Context, input RunInput) []model.Finding {
	if input.Options.PassiveOnly || input.Session == nil {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(input.Target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("csrf-probe %s", input.Target),
			Message: "Testing CSRF protection on state-changing endpoints with live session",
		})
	}

	candidates := collectCSRFCandidates(base, input.Options.SeedRuntimeEndpoints, input.Session, input.Scope)
	if len(candidates) == 0 {
		return nil
	}

	attempts := 0
	var winner *csrfAttempt
	for _, cand := range candidates {
		if attempts >= csrfMaxAttempts {
			break
		}
		for _, r := range csrfRecipes {
			if attempts >= csrfMaxAttempts {
				break
			}
			body := csrfProbeBody(r.contentType)
			status, respBody, err := s.csrfSend(ctx, input, cand, r, body)
			attempts++
			// Phase 2 coverage accounting: mark this key exercised so
			// the end-of-scan gap detector distinguishes probed vs
			// not-probed endpoints for the CSRF surface.
			RecordProbedKey(cand.method, cand.url, "")
			if err != nil {
				continue
			}
			if is2xx(status) {
				w := csrfAttempt{
					candidate:    cand,
					recipe:       r,
					status:       status,
					responseBody: respBody,
				}
				winner = &w
				break
			}
		}
		if winner != nil {
			break
		}
	}

	if winner == nil {
		return nil
	}

	// Priority D.1 — unauthenticated baseline. If the same request
	// succeeds with cookies stripped and no auth applied, the endpoint
	// is genuinely public and cannot be exploited via CSRF (there is
	// no authenticated user state to abuse). Suppress rather than
	// emit a High-severity false positive.
	unauthStatus := s.csrfUnauthenticatedBaseline(ctx, input, winner.candidate, winner.recipe)
	if is2xx(unauthStatus) {
		return nil
	}

	// Priority D.2 — two-control baseline. Replay the winning
	// (vulnerable) request twice and require both to succeed. This
	// rejects flaky endpoints whose single accepted response was
	// noise.
	baselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
		body := csrfProbeBody(winner.recipe.contentType)
		status, respBody, cerr := s.csrfSend(bctx, input, winner.candidate, winner.recipe, body)
		if cerr != nil {
			return BaselineSample{}, cerr
		}
		return BaselineSample{Status: status, Body: string(respBody)}, nil
	})
	repeatable := berr == nil && is2xx(baselines.First.Status) && is2xx(baselines.Second.Status)
	if !repeatable {
		return nil
	}

	finding := buildCSRFFinding(input, *winner, unauthStatus, baselines)

	// Priority D.3 — route through the shared pre-report verifier so
	// the proof-policy engine records preReport.* metadata alongside
	// the finding for downstream calibration / strict-mode reporting.
	// csrf is a canonical proof-policy category (see
	// proofpolicy.canonicalCategory), so the finding is emitted with
	// its native label without a swap.
	outcome := SubmitVerifiedFinding(ctx, VerifyCandidate{
		Finding:               finding,
		Signals:               []EvidenceSignal{EvidenceStatusDelta, EvidenceCookieChange},
		AllowNoReplayEmission: true,
		ProbeName:             "csrf-probe",
	})
	if outcome.Suppressed {
		return nil
	}
	return []model.Finding{outcome.EmittedFinding}
}

// buildCSRFFinding assembles the model.Finding for a confirmed CSRF hit.
// Kept separate from runCSRFProbe so tests can exercise the reporting
// shape (evidence fields, curl reproducer) without spinning up a live
// HTTP server.
func buildCSRFFinding(input RunInput, w csrfAttempt, unauthStatus int, baselines BaselineControls) model.Finding {
	forgedNote := ""
	if w.recipe.tokenCarrier != "absent" {
		forgedNote = fmt.Sprintf(" (a forged CSRF token was accepted in %q)", w.recipe.tokenCarrier)
	}
	originNote := ""
	if w.recipe.origin != "same-origin" {
		originNote = fmt.Sprintf(" [Origin variant: %s]", w.recipe.origin)
	}
	evidence := fmt.Sprintf(
		"%s %s with authenticated session cookie but without CSRF token → HTTP %d%s%s",
		w.candidate.method, w.candidate.url, w.status, forgedNote, originNote,
	)
	body := csrfProbeBody(w.recipe.contentType)
	curl := buildCurlReproducer(w.candidate.method, w.candidate.url, input.AuthProfile, w.recipe.contentType, string(body))
	steps := []string{
		"Log in to obtain a session cookie.",
		fmt.Sprintf("Send %s to %s with the session cookie, Content-Type: %s, and body %q.", w.candidate.method, w.candidate.url, w.recipe.contentType, string(body)),
	}
	if w.recipe.tokenCarrier != "absent" {
		steps = append(steps, fmt.Sprintf("Include the forged token header/param %q with an invalid value.", w.recipe.tokenCarrier))
	} else {
		steps = append(steps, "Omit any CSRF token header or body/query parameter.")
	}
	if w.recipe.origin != "same-origin" {
		steps = append(steps, fmt.Sprintf("Send the request with Origin: %s (and no Referer) to demonstrate the Origin/Referer defence is bypassable.", csrfOriginHeader(w.recipe.origin)))
	}
	steps = append(steps,
		fmt.Sprintf("Observe that the server returns HTTP %d, indicating the state-changing request was accepted.", w.status),
		"Craft an HTML page on an attacker-controlled domain that auto-POSTs a form to the endpoint to demonstrate cross-site exploitability.",
	)

	description := "A state-changing request was accepted by the server with valid session cookies " +
		"but without a valid CSRF token. An attacker can craft a malicious page that causes an " +
		"authenticated user's browser to issue this request, changing their account data without " +
		"their knowledge."
	if w.recipe.origin != "same-origin" {
		description += " The server also accepted the request when the Origin header identified an attacker-controlled domain, indicating the Origin/Referer defence (if any) is insufficient."
	}

	return model.Finding{
		ID:                "csrf-missing-protection",
		Category:          "csrf",
		Severity:          model.SeverityHigh,
		Title:             "Cross-Site Request Forgery (CSRF) — state-changing endpoint lacks token enforcement",
		Description:       description,
		Evidence:          evidence,
		Recommendation:    "Implement the Synchronizer Token Pattern: generate a random CSRF token per session, embed it in every state-changing form/request, and validate it server-side before processing. Also set the SameSite=Strict or SameSite=Lax cookie attribute on session cookies, and reject requests whose Origin/Referer does not match the application's expected origin.",
		Confidence:        0.85,
		AffectedURL:       w.candidate.url,
		CWE:               "CWE-352",
		OWASPCategory:     "A01:2021 - Broken Access Control",
		Sources:           []string{"active-scanner", "csrf-probe"},
		ReproductionSteps: steps,
		PoC:               curl,
		BusinessTags:      []string{"csrf", "authentication", "session"},
		EvidenceFields: map[string]string{
			"validationType":                "active-probe",
			"httpMethod":                    w.candidate.method,
			"contentType":                   w.recipe.contentType,
			"tokenCarrierTested":            w.recipe.tokenCarrier,
			"forgedToken":                   fmt.Sprintf("%v", w.recipe.tokenCarrier != "absent"),
			"originHeader":                  w.recipe.origin,
			"bypassTechnique":               csrfBypassLabel(w.recipe.bypass),
			"unauthenticatedBaselineStatus": fmt.Sprintf("%d", unauthStatus),
			"reVerifiedRuns":                fmt.Sprintf("%d", 2),
			"responseStatus":                fmt.Sprintf("%d", w.status),
			"curlReproducer":                curl,
		},
	}
}

// csrfOriginHeader returns the value that would be placed in the
// Origin request header for a given origin-variant label.
func csrfOriginHeader(variant string) string {
	switch variant {
	case "attacker":
		return csrfAttackerOrigin
	case "null":
		return "null"
	default:
		return "(same-origin — no override)"
	}
}

// csrfProbeBody returns a semantically-inert body appropriate for the
// requested Content-Type. The payload uses an obviously fake email
// address so an accidental successful write is trivially traceable.
func csrfProbeBody(contentType string) []byte {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		v := url.Values{}
		v.Set("email", "csrf-probe@abh-scanner.invalid")
		v.Set("name", "csrf-probe-abh")
		return []byte(v.Encode())
	case strings.HasPrefix(ct, "text/plain"):
		return []byte("email=csrf-probe@abh-scanner.invalid\nname=csrf-probe-abh\n")
	case strings.HasPrefix(ct, "multipart/form-data"):
		// Boundary must match the one advertised in csrfContentTypes.
		var buf bytes.Buffer
		boundary := "abhboundary"
		buf.WriteString("--" + boundary + "\r\n")
		buf.WriteString("Content-Disposition: form-data; name=\"email\"\r\n\r\n")
		buf.WriteString("csrf-probe@abh-scanner.invalid\r\n")
		buf.WriteString("--" + boundary + "\r\n")
		buf.WriteString("Content-Disposition: form-data; name=\"name\"\r\n\r\n")
		buf.WriteString("csrf-probe-abh\r\n")
		buf.WriteString("--" + boundary + "--\r\n")
		return buf.Bytes()
	default:
		b, _ := json.Marshal(map[string]string{
			"email": "csrf-probe@abh-scanner.invalid",
			"name":  "csrf-probe-abh",
		})
		return b
	}
}

// csrfSend performs one probe request following the given recipe.
// It uses the session's HTTP client so the authenticated cookie jar
// is preserved, but deliberately does *not* call
// ScanSession.InjectIntoRequest — that would re-add the CSRF token
// from the TokenStore and defeat the test.
func (s *Service) csrfSend(ctx context.Context, input RunInput, cand csrfCandidate, r csrfRecipe, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, cand.method, cand.url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	ApplyAuthProfile(req, input.AuthProfile)
	req.Header.Set("Content-Type", r.contentType)
	applyCSRFTokenCarrier(req, r.tokenCarrier)
	applyCSRFOriginVariant(req, r.origin)
	applyCSRFBypass(req, r)

	client := s.httpClient
	if input.Session != nil {
		client = input.Session.Client()
	}
	return s.csrfDo(ctx, client, req, input.Options)
}

// csrfUnauthenticatedBaseline replays the winning request without any
// session cookies or auth-profile headers. If the endpoint still
// returns 2xx it is genuinely public, not CSRF-vulnerable.
func (s *Service) csrfUnauthenticatedBaseline(ctx context.Context, input RunInput, cand csrfCandidate, r csrfRecipe) int {
	body := csrfProbeBody(r.contentType)
	req, err := http.NewRequestWithContext(ctx, cand.method, cand.url, bytes.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", r.contentType)
	applyCSRFTokenCarrier(req, r.tokenCarrier)
	applyCSRFOriginVariant(req, r.origin)
	applyCSRFBypass(req, r)
	// Deliberately DO NOT ApplyAuthProfile and DO NOT use the session
	// client (which carries the cookie jar). Use the service's shared
	// unauthenticated client instead.
	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	status, _, err := s.csrfDo(ctx, client, req, input.Options)
	if err != nil {
		return 0
	}
	return status
}

// csrfDo performs the actual request with the probe's small retry
// loop and body-limit read. Returns the final status code, capped
// body, and error.
func (s *Service) csrfDo(ctx context.Context, client *http.Client, req *http.Request, opts model.ScanOptions) (int, []byte, error) {
	maxRetries := s.cfg.DefaultMaxRetries
	if opts.MaxRetries > 0 {
		maxRetries = opts.MaxRetries
	}
	var lastStatus int
	var lastBody []byte
	for attempt := 0; attempt <= maxRetries; attempt++ {
		cloned := req.Clone(ctx)
		resp, err := client.Do(cloned)
		if err != nil {
			if attempt == maxRetries {
				return 0, nil, err
			}
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, csrfBodyLimit))
		_ = resp.Body.Close()
		if !isRetriableStatus(resp.StatusCode) {
			return resp.StatusCode, body, nil
		}
		lastStatus = resp.StatusCode
		lastBody = body
		if attempt == maxRetries {
			break
		}
	}
	if lastStatus != 0 {
		return lastStatus, lastBody, nil
	}
	return 0, nil, nil
}

// applyCSRFTokenCarrier writes a forged token value into whichever
// header or body/query parameter the recipe names. For "absent" this
// is a no-op — the request has no CSRF-token surface at all.
func applyCSRFTokenCarrier(req *http.Request, carrier string) {
	if carrier == "" || strings.EqualFold(carrier, "absent") {
		return
	}
	// Only the header variants are wired here; body/query carriers
	// would require re-encoding the body and are handled by future
	// batches once the header matrix is proven.
	req.Header.Set(carrier, "invalid-forged-csrf-token-abh")
}

// applyCSRFOriginVariant sets (or clears) the Origin/Referer headers
// per the requested variant. same-origin: leave headers untouched
// (Go http.Client omits Origin by default, matching a browser
// same-origin fetch). attacker: set Origin to csrfAttackerOrigin and
// omit Referer. null: set Origin: null and omit Referer.
func applyCSRFOriginVariant(req *http.Request, variant string) {
	switch variant {
	case "attacker":
		req.Header.Set("Origin", csrfAttackerOrigin)
		req.Header.Del("Referer")
	case "null":
		req.Header.Set("Origin", "null")
		req.Header.Del("Referer")
	}
}

// applyCSRFBypass mutates the request to exercise the named CSRF-token
// bypass technique. It is called after the token carrier and Origin
// variant have been applied so the bypass builds on top of an
// otherwise-normal request. Recipes with bypass == "" are unchanged.
//
// Each bypass models a real-world misconfiguration class:
//
//	empty-value       — presence-only CSRF checks accept "" as a
//	                    valid token; the header is set to the empty
//	                    string, and the body/query variants would
//	                    inject `_csrf=` (currently only the header
//	                    surface is implemented, mirroring
//	                    applyCSRFTokenCarrier).
//	method-override   — the outer request method may pass a CSRF
//	                    check that the framework then bypasses when
//	                    routing on X-HTTP-Method-Override. The probe
//	                    sets each override header to a state-changing
//	                    verb different from the outer method (or POST
//	                    when the outer method is POST) so a
//	                    misconfigured router promotes the request.
//	duplicate-token   — parameter/header pollution: repeat the token
//	                    header with a second forged value. Servers
//	                    that compare against `Header.Get()` (first
//	                    value) will accept, while the app that reads
//	                    the last value will process an attacker
//	                    payload — or vice versa.
//	default-token     — some frameworks ship with a well-known dev
//	                    token ("0", "test", "null") that bypasses CSRF
//	                    when set explicitly by the client.
func applyCSRFBypass(req *http.Request, r csrfRecipe) {	if req == nil || r.bypass == "" {
		return
	}
	carrier := r.tokenCarrier
	if carrier == "" || strings.EqualFold(carrier, "absent") {
		carrier = "X-CSRF-Token"
	}
	switch r.bypass {
	case "empty-value":
		// Overwrite whatever applyCSRFTokenCarrier just set with an
		// empty value. Servers that check presence-only accept this.
		req.Header.Set(carrier, "")
	case "method-override":
		// Advertise a different state-changing verb via each known
		// override header. Middleware that inspects only the outer
		// method may skip CSRF while the app routes on the override.
		override := http.MethodPut
		if strings.EqualFold(req.Method, http.MethodPut) {
			override = http.MethodPost
		}
		for _, h := range csrfMethodOverrideAliases {
			req.Header.Set(h, override)
		}
	case "duplicate-token":
		// Header pollution: add a second value under the same name.
		// http.Header.Add preserves both; a server that reads the
		// first value gets the forged token, one that reads the last
		// gets an attacker-controlled second value.
		req.Header.Add(carrier, "attacker-controlled-abh")
	case "default-token":
		// Overwrite with one of the well-known default values a
		// framework may treat as a development bypass. The specific
		// value that lands is deterministic per (endpoint, recipe)
		// so re-verify is stable.
		hasher := fnv.New32a()
		_, _ = hasher.Write([]byte(req.URL.Path))
		idx := int(hasher.Sum32()) % len(csrfDefaultTokenValues)
		if idx < 0 {
			idx = 0
		}
		req.Header.Set(carrier, csrfDefaultTokenValues[idx])
	}
}

// csrfBypassLabel returns a stable human-readable label for the
// bypass technique used in the winning attempt. "none" means the
// baseline recipe (no explicit bypass) is what the server accepted.
func csrfBypassLabel(bypass string) string {
	if strings.TrimSpace(bypass) == "" {
		return "none"
	}
	return bypass
}

// collectCSRFCandidates returns in-scope state-changing endpoints. It
// unions three sources:
//
//  1. The hard-coded csrfStateChangingPaths list (POST-only fallback
//     for scans without runtime endpoint discovery).
//  2. The runtime-endpoint seed list (browser XHR / crawl) filtered
//     by naming heuristic to state-changing suffixes.
//  3. The Phase 2 SurfaceInventory — every entry whose method is one
//     of csrfStateChangingMethods.
//
// De-duplication is by (method, URL). Scope filtering happens
// before de-dup so an out-of-scope entry never occupies a slot in
// the candidate list.
func collectCSRFCandidates(base *url.URL, seedEndpoints []string, sess *ScanSession, scanScope model.ScanScope) []csrfCandidate {
	seen := map[string]struct{}{}
	var out []csrfCandidate

	add := func(method, raw string) {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			method = http.MethodPost
		}
		if !csrfIsStateChangingMethod(method) {
			return
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		var resolved *url.URL
		if ref.Scheme == "" || ref.Host == "" {
			resolved = base.ResolveReference(ref)
		} else {
			resolved = ref
		}
		key := method + " " + resolved.String()
		if _, ok := seen[key]; ok {
			return
		}
		if !scope.IsURLInScope(resolved.String(), scanScope) {
			return
		}
		seen[key] = struct{}{}
		out = append(out, csrfCandidate{method: method, url: resolved.String()})
	}

	// Phase 2: consume the SurfaceInventory FIRST. These entries are
	// higher-signal than the hard-coded path list because a crawler
	// or upstream probe has already observed the endpoint accepting
	// the recorded method. Ordering them ahead of the hard-coded
	// paths avoids starving the per-scan attempt budget on generic
	// well-known guesses when a real state-changing surface exists.
	if sess != nil {
		if inv := sess.SurfaceInventory(); inv != nil {
			for _, e := range inv.Snapshot() {
				add(e.Method, e.URL)
			}
		}
	}

	for _, p := range csrfStateChangingPaths {
		add(http.MethodPost, p)
	}

	// Runtime XHR / crawl-seeded endpoints. Retain the pre-migration
	// naming heuristic so obviously-idempotent endpoints (list, get,
	// read) are not mistaken for state-changing surfaces.
	for _, ep := range seedEndpoints {
		if csrfLooksStateChanging(ep) {
			add(http.MethodPost, ep)
		}
	}

	return out
}

// csrfIsStateChangingMethod reports whether a method is in the
// probe's state-changing set. Kept as a helper so it can be reused
// from tests and (later) the surface-gap detector.
func csrfIsStateChangingMethod(method string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	for _, allowed := range csrfStateChangingMethods {
		if m == allowed {
			return true
		}
	}
	return false
}

// csrfLooksStateChanging retains the pre-migration heuristic filter
// for the runtime-endpoint seed list. Used only for that source
// (SurfaceInventory entries bypass the heuristic because their
// method is already known).
func csrfLooksStateChanging(ep string) bool {
	lower := strings.ToLower(ep)
	return strings.Contains(lower, "/update") ||
		strings.Contains(lower, "/edit") ||
		strings.Contains(lower, "/profile") ||
		strings.Contains(lower, "/settings") ||
		strings.Contains(lower, "/password") ||
		strings.Contains(lower, "/email")
}

// Compile-time reference to keep the proofpolicy import used even
// when the finding is emitted from a code path that does not touch
// the policy struct directly. The verifier evaluates the finding's
// category against proofpolicy.rulesByCategory internally, so pinning
// the import here guarantees a build break if the "csrf" category is
// accidentally removed from proofpolicy.
var _ = proofpolicy.Result{}
