package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// forbiddenPaths are conventional access-controlled endpoints worth probing
// for ACL-bypass when no protected path was discovered during recon.
var forbiddenPaths = []string{
	"/admin", "/administrator", "/admin/dashboard", "/manage", "/management",
	"/api/admin", "/internal", "/console", "/actuator", "/metrics",
	"/server-status", "/.well-known/security.txt",
}

// forbiddenBypassMaxBases caps how many forbidden endpoints are mutated.
const forbiddenBypassMaxBases = 6

// forbiddenBypassMaxAttemptsPerBase caps mutations attempted per base path.
const forbiddenBypassMaxAttemptsPerBase = 24

// runForbiddenBypassProbe detects broken access control by taking endpoints
// that return 401/403 and replaying them with well-known normalisation and
// header tricks (trailing dot, ;/, encoded slash, X-Original-URL,
// X-Forwarded-For 127.0.0.1, alternate verbs). A bypass is reported when a
// mutation flips a 401/403 baseline into a 2xx response.
func (s *Service) runForbiddenBypassProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(input.Target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	// Build candidate protected endpoints: discovered runtime endpoints plus a
	// curated list of conventional admin/internal paths.
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 8)
	for _, p := range forbiddenPaths {
		ref, perr := url.Parse(p)
		if perr != nil {
			continue
		}
		candidates = append(candidates, base.ResolveReference(ref).String())
	}
	candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("forbidden-bypass %s", input.Target),
			Message: "Probing 401/403 endpoints for access-control bypass",
		})
	}

	var findings []model.Finding
	basesProbed := 0
	seenBase := map[string]bool{}

	for _, raw := range candidates {
		if basesProbed >= forbiddenBypassMaxBases {
			break
		}
		u, perr := url.Parse(strings.TrimSpace(raw))
		if perr != nil || u.Host == "" {
			continue
		}
		key := u.Scheme + u.Host + u.Path
		if seenBase[key] {
			continue
		}
		if !scope.IsURLInScope(raw, input.Scope) {
			continue
		}
		if err := safety.ValidateOutboundURL(raw); err != nil {
			continue
		}

		baseStatus, ok := s.fetchStatus(ctx, http.MethodGet, raw, input, nil)
		if !ok || !isForbiddenStatus(baseStatus) {
			continue
		}
		seenBase[key] = true
		basesProbed++

		if f, found := s.tryForbiddenBypasses(ctx, input, u, baseStatus); found {
			findings = append(findings, f)
		}
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// tryForbiddenBypasses attempts path- and header-based bypasses against a
// single forbidden endpoint and returns a finding on the first success.
func (s *Service) tryForbiddenBypasses(ctx context.Context, input RunInput, u *url.URL, baseStatus int) (model.Finding, bool) {
	origin := u.Scheme + "://" + u.Host
	path := u.Path
	if path == "" {
		path = "/"
	}

	attempts := 0
	// Path-normalisation mutations.
	for _, mutated := range forbiddenPathMutations(path) {
		if attempts >= forbiddenBypassMaxAttemptsPerBase {
			break
		}
		attempts++
		probeURL := origin + mutated
		if !scope.IsURLInScope(probeURL, input.Scope) {
			continue
		}
		if err := safety.ValidateOutboundURL(probeURL); err != nil {
			continue
		}
		status, ok := s.fetchStatus(ctx, http.MethodGet, probeURL, input, nil)
		if ok && isForbiddenBypass(baseStatus, status) {
			return s.forbiddenFinding(input, u, probeURL, "path-normalisation", fmt.Sprintf("path mutation %q", mutated), baseStatus, status), true
		}
	}

	// Header-based mutations against the original URL.
	for _, hdr := range forbiddenBypassHeaders(path) {
		if attempts >= forbiddenBypassMaxAttemptsPerBase {
			break
		}
		attempts++
		status, ok := s.fetchStatus(ctx, http.MethodGet, u.String(), input, hdr)
		if ok && isForbiddenBypass(baseStatus, status) {
			return s.forbiddenFinding(input, u, u.String(), "header-override", describeHeaders(hdr), baseStatus, status), true
		}
	}

	return model.Finding{}, false
}

func (s *Service) forbiddenFinding(input RunInput, base *url.URL, probeURL, technique, detail string, baseStatus, bypassStatus int) model.Finding {
	curl := buildCurlReproducer(http.MethodGet, probeURL, input.AuthProfile, "", "")
	return model.Finding{
		ID:       "forbidden-bypass-" + hhSlug(base.Path),
		Category: "access-control",
		Severity: model.SeverityHigh,
		Title:    "Access-control bypass on protected endpoint",
		Description: fmt.Sprintf("The endpoint %s returned HTTP %d (access denied) for a normal request, but a %s bypass returned HTTP %d. "+
			"This indicates the access-control check is enforced inconsistently (e.g. only at the reverse proxy, or before path normalisation), "+
			"allowing an attacker to reach protected functionality.", base.Path, baseStatus, technique, bypassStatus),
		Evidence: fmt.Sprintf("Baseline GET %s => %d; bypass via %s => %d (%s)",
			base.String(), baseStatus, technique, bypassStatus, detail),
		Recommendation: "Enforce authorization in the application layer after full URL/path normalisation, independent of the reverse proxy. " +
			"Reject ambiguous path encodings, ignore client-supplied X-Original-URL/X-Rewrite-URL/X-Forwarded-* headers for routing or trust decisions, " +
			"and apply the same access check to every HTTP method.",
		Confidence:    0.85,
		AffectedURL:   probeURL,
		CWE:           "CWE-285",
		OWASPCategory: "A01:2021 - Broken Access Control",
		Sources:       []string{"active-scanner", "forbidden-bypass"},
		ReproductionSteps: []string{
			fmt.Sprintf("Confirm GET %s returns HTTP %d.", base.String(), baseStatus),
			fmt.Sprintf("Replay using the %s technique (%s).", technique, detail),
			fmt.Sprintf("Observe the response flips to HTTP %d, exposing the protected resource.", bypassStatus),
		},
		PoC: curl,
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"technique":      technique,
			"baseStatus":     fmt.Sprintf("%d", baseStatus),
			"bypassStatus":   fmt.Sprintf("%d", bypassStatus),
			"curlReproducer": curl,
		},
	}
}

// fetchStatus issues a request and returns the response status code. headers,
// when non-nil, are added to the request.
func (s *Service) fetchStatus(ctx context.Context, method, rawURL string, input RunInput, headers map[string]string) (int, bool) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return 0, false
	}
	ApplyAuthProfile(req, input.AuthProfile)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return 0, false
	}
	_ = resp.Body.Close()
	return resp.StatusCode, true
}

// forbiddenPathMutations returns access-control-bypass path variants for a
// protected path.
func forbiddenPathMutations(path string) []string {
	clean := strings.TrimRight(path, "/")
	if clean == "" {
		clean = "/"
	}
	variants := []string{
		path + "/",
		path + "/.",
		clean + "/..;/",
		clean + "%2e/",
		clean + "/.//",
		clean + "%2f",
		"/." + path,
		"//" + strings.TrimPrefix(path, "/"),
		path + "..;/",
		path + ";/",
		path + "%20",
		path + "%09",
		path + "?",
		path + "#",
		path + "%23",
		clean + "/%2e%2e/",
		strings.ToUpper(path),
	}
	// De-duplicate while preserving order.
	seen := map[string]bool{}
	out := make([]string, 0, len(variants))
	for _, v := range variants {
		if v == "" || v == path || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// forbiddenBypassHeaders returns header sets commonly trusted by misconfigured
// reverse proxies for routing or IP allow-listing.
func forbiddenBypassHeaders(path string) []map[string]string {
	return []map[string]string{
		{"X-Original-URL": path},
		{"X-Rewrite-URL": path},
		{"X-Forwarded-For": "127.0.0.1"},
		{"X-Forwarded-Host": "localhost"},
		{"X-Custom-IP-Authorization": "127.0.0.1"},
		{"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "127.0.0.1"},
		{"X-Originating-IP": "127.0.0.1"},
		{"Client-IP": "127.0.0.1"},
	}
}

func describeHeaders(h map[string]string) string {
	parts := make([]string, 0, len(h))
	for k, v := range h {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// isForbiddenStatus reports whether a status code denotes access denial.
func isForbiddenStatus(code int) bool {
	return code == http.StatusUnauthorized || code == http.StatusForbidden
}

// isForbiddenBypass reports whether a mutation flipped an access-denied
// baseline into a successful response.
func isForbiddenBypass(baseStatus, bypassStatus int) bool {
	if !isForbiddenStatus(baseStatus) {
		return false
	}
	return bypassStatus >= 200 && bypassStatus < 300
}
