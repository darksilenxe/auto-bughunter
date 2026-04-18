package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// Open-redirect probe — passive check that issues a small number of GET
// requests with redirect-style query parameters set to a synthetic
// external test URL, and inspects the resulting Location header for a
// redirect to that external destination.
//
// The probe never follows redirects, so it cannot exfiltrate the user's
// session and cannot leak data to the synthetic destination. The probe
// limits itself to discovered runtime endpoints + the entry-point URL,
// and at most a handful of attempts per scan, to avoid being noisy.

// openRedirectMarker is a syntactically valid URL that no real production
// system should ever legitimately redirect to. The host segment is
// reserved by RFC 6761 for testing, guaranteeing it cannot resolve to a
// live system.
const openRedirectMarker = "https://abh-redirect-probe.example/"

// openRedirectParams enumerates the most common parameter names used for
// post-login / safe-redirect flows; matched by Burp Active Scan, OWASP,
// PortSwigger labs and many bug-bounty writeups.
var openRedirectParams = []string{
	"next", "redirect", "redirect_uri", "redirect_url", "return", "return_to",
	"returnurl", "return_url", "url", "destination", "dest", "continue", "to",
	"r", "u", "callback",
}

func runOpenRedirectProbe(ctx context.Context, target, body string, auth model.ScanAuthProfile, options model.ScanOptions, scanScope model.ScanScope, service *Service) []model.Finding {
	if service == nil || service.httpClient == nil {
		return nil
	}

	// Use a no-follow client variant so we can inspect the 3xx response
	// directly. The default httpClient follows redirects by default.
	noFollow := *service.httpClient
	noFollow.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	candidates := extractRuntimeEndpoints(target, body, scanScope, 6)
	candidates = append(candidates, target)

	maxAttempts := 12
	if options.GlobalScanBudget > 0 && options.GlobalScanBudget < maxAttempts {
		maxAttempts = options.GlobalScanBudget
	}

	hits := make([]string, 0)
	attempts := 0
	seen := map[string]struct{}{}
	for _, raw := range candidates {
		if attempts >= maxAttempts {
			break
		}
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		for _, p := range openRedirectParams {
			if attempts >= maxAttempts {
				break
			}
			probe := *u
			q := probe.Query()
			q.Set(p, openRedirectMarker)
			probe.RawQuery = q.Encode()
			ps := probe.String()
			if _, ok := seen[ps]; ok {
				continue
			}
			seen[ps] = struct{}{}
			if !scope.IsURLInScope(ps, scanScope) {
				continue
			}
			if err := safety.ValidateOutboundURL(ps); err != nil {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ps, nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, auth)
			resp, err := noFollow.Do(req)
			if err != nil {
				continue
			}
			loc := strings.TrimSpace(resp.Header.Get("Location"))
			status := resp.StatusCode
			_ = resp.Body.Close()
			attempts++
			if status >= 300 && status < 400 && loc != "" && redirectsTo(loc, openRedirectMarker) {
				hits = append(hits, fmt.Sprintf("%s (param=%s, status=%d)", ps, p, status))
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return []model.Finding{{
		ID:             "open-redirect",
		Category:       "input-validation",
		Severity:       model.SeverityMedium,
		Title:          "Open redirect: server issues 3xx redirect to attacker-controlled URL",
		Description:    "One or more endpoints honoured an attacker-controlled redirect parameter and returned a 3xx response with Location pointing to an external destination. Open redirects are commonly chained with phishing or used to bypass redirect-based allow-lists in OAuth and SSO flows.",
		Evidence:       strings.Join(limitStrings(hits, 6), "; "),
		Recommendation: "Validate the redirect destination against a server-side allow-list (host/path) or use opaque server-side tokens that map to the destination instead of taking the URL from the client.",
		EvidenceFields: map[string]string{
			"validationType": "safe-observation",
			"reproStep":      "Replay listed URL with the marker value and inspect the Location response header (do not follow the redirect).",
		},
	}}
}

// redirectsTo reports whether the Location header points at the marker URL
// (either as an absolute URL exactly matching the marker host, or as a
// scheme-relative reference). Relative paths starting with `/` are
// explicitly excluded — a same-site redirect is not an open redirect even
// if the path happens to contain the marker as a substring.
func redirectsTo(location, marker string) bool {
	location = strings.TrimSpace(location)
	if location == "" {
		return false
	}
	if strings.EqualFold(location, marker) {
		return true
	}
	mu, err := url.Parse(marker)
	if err != nil {
		return false
	}
	lu, err := url.Parse(location)
	if err != nil {
		return false
	}
	if lu.Host == "" {
		return false
	}
	return strings.EqualFold(lu.Host, mu.Host)
}
