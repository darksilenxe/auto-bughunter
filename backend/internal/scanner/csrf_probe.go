package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// csrfBodyLimit caps per-probe response reads for the CSRF probe.
const csrfBodyLimit = 128 * 1024

// csrfStateChangingPaths are conventional paths for state-changing operations.
// The probe posts to these paths without a CSRF token to test server-side
// enforcement.
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

// runCSRFProbe is a session-aware CSRF probe that replays state-changing POST
// requests without a CSRF token (or with a forged one). It uses the live
// session so the request arrives with valid authentication cookies.
//
// The test is only meaningful for authenticated sessions — without a session
// cookie, the endpoint would reject the request anyway.
//
// A finding is emitted when the server accepts a POST to a state-changing
// endpoint that includes the authenticated session cookie but omits the CSRF
// token that the server should require.
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

	candidates := collectCSRFCandidates(base, input.Options.SeedRuntimeEndpoints, input.Scope)
	if len(candidates) == 0 {
		return nil
	}

	// Build a minimal JSON body that most profile-update endpoints accept.
	probeBody, err := json.Marshal(map[string]string{
		"email": "csrf-probe@abh-scanner.invalid",
		"name":  "csrf-probe-abh",
	})
	if err != nil {
		return nil
	}

	type hit struct {
		url    string
		status int
		forged bool
	}
	var hits []hit

	const maxAttempts = 6
	for i, ep := range candidates {
		if i >= maxAttempts {
			break
		}
		// Attempt 1: POST without any CSRF token header.
		status, err := s.csrfPost(ctx, input, ep, probeBody, false)
		if err != nil {
			continue
		}
		if is2xx(status) {
			hits = append(hits, hit{url: ep, status: status, forged: false})
			continue
		}

		// Attempt 2: POST with a forged (random) CSRF token value.
		status, err = s.csrfPost(ctx, input, ep, probeBody, true)
		if err != nil {
			continue
		}
		if is2xx(status) {
			hits = append(hits, hit{url: ep, status: status, forged: true})
		}
	}

	if len(hits) == 0 {
		return nil
	}

	first := hits[0]
	forgedNote := ""
	if first.forged {
		forgedNote = " (a forged CSRF token value was accepted)"
	}
	evidence := fmt.Sprintf(
		"POST %s with authenticated session cookie but without CSRF token → HTTP %d%s",
		first.url, first.status, forgedNote,
	)
	curl := buildCurlReproducer(http.MethodPost, first.url, input.AuthProfile, `{"email":"csrf-probe@abh-scanner.invalid"}`, "application/json")
	steps := []string{
		"Log in to obtain a session cookie.",
		fmt.Sprintf("POST to %s with the session cookie but without a CSRF token (or with a forged one).", first.url),
		fmt.Sprintf("Observe that the server returns HTTP %d, indicating the state-changing request was accepted.", first.status),
		"Craft an HTML page on an attacker-controlled domain that auto-POSTs a form to the endpoint to demonstrate cross-site exploitability.",
	}

	return []model.Finding{{
		ID:       "csrf-missing-protection",
		Category: "csrf",
		Severity: model.SeverityHigh,
		Title:    "Cross-Site Request Forgery (CSRF) — state-changing endpoint lacks token enforcement",
		Description: "A state-changing POST request was accepted by the server with valid session cookies " +
			"but without the CSRF token that the server should require. An attacker can craft a " +
			"malicious page that causes an authenticated user's browser to issue this request, " +
			"changing their account data without their knowledge.",
		Evidence:       evidence,
		Recommendation: "Implement the Synchronizer Token Pattern: generate a random CSRF token per session, embed it in every state-changing form/request, and validate it server-side before processing. Also set the SameSite=Strict or SameSite=Lax cookie attribute on session cookies.",
		Confidence:     0.80,
		AffectedURL:    first.url,
		CWE:            "CWE-352",
		OWASPCategory:  "A01:2021 - Broken Access Control",
		Sources:        []string{"active-scanner", "csrf-probe"},
		ReproductionSteps: steps,
		PoC:               curl,
		BusinessTags:      []string{"csrf", "authentication", "session"},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"forgedToken":    fmt.Sprintf("%v", first.forged),
			"responseStatus": fmt.Sprintf("%d", first.status),
			"curlReproducer": curl,
		},
	}}
}

// csrfPost sends a POST to ep with the session's cookies but without (or with
// a forged) CSRF token. It returns the status code.
func (s *Service) csrfPost(ctx context.Context, input RunInput, ep string, body []byte, forgeToken bool) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	ApplyAuthProfile(req, input.AuthProfile)
	req.Header.Set("Content-Type", "application/json")
	// Explicitly unset any CSRF token that InjectIntoRequest would add.
	req.Header.Del("X-CSRF-Token")
	if forgeToken {
		req.Header.Set("X-CSRF-Token", "invalid-forged-csrf-token-abh")
	}

	resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
	if err != nil || resp == nil {
		return 0, err
	}
	_, _ = io.ReadAll(io.LimitReader(resp.Body, csrfBodyLimit))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// collectCSRFCandidates returns in-scope state-changing endpoints from
// well-known paths and session-discovered XHR endpoints.
func collectCSRFCandidates(base *url.URL, seedEndpoints []string, scanScope model.ScanScope) []string {
	seen := map[string]struct{}{}
	var out []string

	add := func(raw string) {
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
		s := resolved.String()
		if _, ok := seen[s]; ok {
			return
		}
		if !scope.IsURLInScope(s, scanScope) {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	for _, p := range csrfStateChangingPaths {
		add(p)
	}

	// Include session-discovered POST endpoints.
	for _, ep := range seedEndpoints {
		lower := strings.ToLower(ep)
		if strings.Contains(lower, "/update") ||
			strings.Contains(lower, "/edit") ||
			strings.Contains(lower, "/profile") ||
			strings.Contains(lower, "/settings") ||
			strings.Contains(lower, "/password") ||
			strings.Contains(lower, "/email") {
			add(ep)
		}
	}

	const max = 8
	if len(out) > max {
		out = out[:max]
	}
	return out
}
