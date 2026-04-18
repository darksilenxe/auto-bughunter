package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// oastBodySSRFParams are common request-body field names that often hold a
// URL the server then fetches: webhook callbacks, image proxies, avatar
// importers, "fetch this for me" form fields, etc. Server-side dereferencing
// of these values is the classic body-parameter SSRF.
var oastBodySSRFParams = []string{"url", "uri", "callback", "callback_url", "webhook", "webhook_url", "redirect", "next", "image", "image_url", "avatar", "avatar_url", "fetch", "src", "target"}

// defaultOASTBodySSRFWait mirrors defaultOASTSSRFWait (header probe) — same
// rationale: long enough to absorb queueing, short enough not to noticeably
// slow scans on non-vulnerable targets.
const defaultOASTBodySSRFWait = 6 * time.Second

// runOASTBodySSRFProbe is an active body-parameter SSRF probe. It POSTs an
// OAST callback URL into common URL-bearing body fields against
// runtime-discovered endpoints (and the target itself), then waits briefly
// for a callback. A confirmed callback yields a high-severity finding.
//
// Two body encodings are tried per endpoint: form-urlencoded and JSON. The
// probe is silently skipped when no OAST service is attached or when no
// public URL is configured.
func (s *Service) runOASTBodySSRFProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	if s.oast == nil || !s.oast.Configured() {
		return nil
	}

	// maxBodySSRFEndpoints caps the number of POST destinations to bound
	// scan time when many runtime endpoints are discovered. Two requests
	// (form + JSON) are sent per endpoint.
	const maxBodySSRFEndpoints = 6

	endpoints := extractRuntimeEndpoints(input.Target, body, input.Scope, maxBodySSRFEndpoints)
	endpoints = append(endpoints, input.Target)
	endpoints = uniqueEndpoints(endpoints)

	tok := s.oast.Issue("", "ssrf-body-probe")
	if tok.CallbackURL == "" {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("oast-ssrf-body %s", input.Target),
			Message: "Probing for body-parameter SSRF via out-of-band callback",
		})
	}

	// Build form and JSON payloads once: every URL-bearing param maps to the
	// callback URL. This is one request per (endpoint, encoding); we cap at
	// a small number of endpoints to bound scan time.
	form := url.Values{}
	jsonObj := map[string]string{}
	for _, p := range oastBodySSRFParams {
		form.Set(p, tok.CallbackURL)
		jsonObj[p] = tok.CallbackURL
	}
	jsonBody, err := json.Marshal(jsonObj)
	if err != nil {
		return nil
	}

	if len(endpoints) > maxBodySSRFEndpoints {
		endpoints = endpoints[:maxBodySSRFEndpoints]
	}

	for _, ep := range endpoints {
		if !scope.IsURLInScope(ep, input.Scope) {
			continue
		}
		// See active_xss.go for the rationale on omitting the redundant
		// safety check; endpoints come from input.Target or
		// extractRuntimeEndpoints, both already validated.
		// form-urlencoded
		if req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode())); err == nil {
			ApplyAuthProfile(req, input.AuthProfile)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if resp, err := s.doRequestWithRetry(ctx, req, input.Options); err == nil && resp != nil {
				_ = resp.Body.Close()
			}
		}
		// json
		if req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(string(jsonBody))); err == nil {
			ApplyAuthProfile(req, input.AuthProfile)
			req.Header.Set("Content-Type", "application/json")
			if resp, err := s.doRequestWithRetry(ctx, req, input.Options); err == nil && resp != nil {
				_ = resp.Body.Close()
			}
		}
	}

	wait := defaultOASTBodySSRFWait
	if input.Options.RequestDelayMillis > 0 {
		wait = wait + time.Duration(input.Options.RequestDelayMillis)*time.Millisecond
	}
	hits := s.oast.Wait(tok.Token, wait)
	if len(hits) == 0 {
		return nil
	}

	hit := hits[0]
	evidence := fmt.Sprintf(
		"Injected callback URL %s into body parameters %s on endpoints %s. Observed inbound %s %s%s from %s (User-Agent: %q) at %s.",
		tok.CallbackURL,
		strings.Join(oastBodySSRFParams, ", "),
		strings.Join(limitStrings(endpoints, 4), ", "),
		hit.Method,
		hit.Path,
		queryToken(hit.Query),
		hit.RemoteAddr,
		hit.UserAgent,
		hit.ReceivedAt.UTC().Format(time.RFC3339),
	)

	steps := []string{
		fmt.Sprintf("Issue an OAST callback URL: %s", tok.CallbackURL),
		fmt.Sprintf("Send a POST to one of %s with Content-Type application/x-www-form-urlencoded and body: %s", strings.Join(limitStrings(endpoints, 3), ", "), form.Encode()),
		fmt.Sprintf("Alternatively send the same POST with Content-Type application/json and body: %s", string(jsonBody)),
		"Observe an inbound request to the OAST listener within seconds, confirming the target dereferenced one of the body parameters.",
	}

	return []model.Finding{{
		ID:                "oast-ssrf-body-params",
		Category:          "input-validation",
		Severity:          model.SeverityHigh,
		Title:             "Out-of-band SSRF via untrusted body parameters",
		Description:       "The target made an outbound HTTP request to an attacker-controlled callback URL after the URL was supplied in a request-body parameter (form-urlencoded or JSON). This indicates server-side code is dereferencing untrusted body values, enabling Server-Side Request Forgery.",
		Evidence:          evidence,
		Recommendation:    "Treat all URL-shaped body parameters (webhook/callback/redirect/avatar/etc.) as untrusted. Validate against an explicit allow-list of hosts and schemes, and resolve them through an SSRF-safe HTTP client that blocks RFC1918/loopback/link-local addresses.",
		Confidence:        0.95,
		AffectedURL:       input.Target,
		CWE:               "CWE-918",
		OWASPCategory:     "A10:2021 - Server-Side Request Forgery (SSRF)",
		Sources:           []string{"oast"},
		ReproductionSteps: steps,
	}}
}

// uniqueEndpoints preserves order while deduplicating.
func uniqueEndpoints(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out
}
