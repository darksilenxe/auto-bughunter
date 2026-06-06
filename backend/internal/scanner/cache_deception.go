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

var cacheDeceptionSuffixes = []string{".css", ".js", ".jpg", ".png", "/static/x.css"}

func (s *Service) runCacheDeceptionProbe(ctx context.Context, input RunInput) []model.Finding {
	if input.Options.PassiveOnly || !hasAnyAuthMaterial(input.AuthProfile) {
		return nil
	}
	candidates := cacheDeceptionCandidatePaths(input.Target, input.Scope)
	candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	candidates = append(candidates, input.Target)
	attempts := 0
	for _, raw := range dedupeStrings(candidates) {
		for _, suffix := range cacheDeceptionSuffixes {
			if attempts >= 4 {
				break
			}
			probeURL := appendPathSuffix(raw, suffix)
			if !scope.IsURLInScope(probeURL, input.Scope) {
				continue
			}
			_, authBody, ok := s.cacheDeceptionFetch(ctx, input, probeURL, true)
			if !ok {
				continue
			}
			unauthResp, unauthBody, ok := s.cacheDeceptionFetch(ctx, input, probeURL, false)
			attempts++
			if !ok {
				continue
			}
			if bodiesSimilar(authBody, unauthBody) && (strings.Contains(strings.ToLower(unauthResp.Header.Get("Cache-Control")), "public") || unauthResp.Header.Get("Age") != "" || strings.Contains(strings.ToUpper(unauthResp.Header.Get("X-Cache")), "HIT")) {
				return []model.Finding{{
					ID:                "web-cache-deception",
					Category:          "cache_deception",
					Severity:          model.SeverityHigh,
					Title:             "Authenticated content exposed through web cache deception",
					Description:       "An authenticated response fetched through a static-looking path suffix was later retrievable without authentication while cache headers indicated shared-cache handling. This is consistent with web cache deception on sensitive content.",
					Evidence:          fmt.Sprintf("Authenticated and unauthenticated GET %s returned similar bodies; cache headers: %s", probeURL, cacheHeaderSummary(unauthResp.Header)),
					Recommendation:    "Mark authenticated responses as Cache-Control: private, no-store, normalize path handling before caching, and ensure static-file caching rules cannot be applied to dynamic authenticated routes.",
					Confidence:        0.82,
					AffectedURL:       probeURL,
					CWE:               "CWE-525",
					OWASPCategory:     "A05:2021 - Security Misconfiguration",
					Sources:           []string{"active-scanner"},
					ReproductionSteps: []string{fmt.Sprintf("Request %s while authenticated", probeURL), fmt.Sprintf("Request %s again without authentication and compare the response body and cache headers", probeURL)},
					EvidenceFields: map[string]string{
						"validationType": "active-probe",
						"cacheHeaders":   cacheHeaderSummary(unauthResp.Header),
					},
				}}
			}
		}
	}
	return nil
}

func (s *Service) cacheDeceptionFetch(ctx context.Context, input RunInput, raw string, authenticated bool) (*http.Response, []byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, nil, false
	}
	if authenticated {
		ApplyAuthProfile(req, input.AuthProfile)
	}
	var resp *http.Response
	if authenticated && input.Session != nil {
		resp, err = s.doRequestWithSession(ctx, req, input.Options, input.Session)
	} else {
		resp, err = s.doRequestWithRetry(ctx, req, input.Options)
	}
	if err != nil || resp == nil {
		return nil, nil, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	_ = resp.Body.Close()
	return resp, body, true
}

func cacheDeceptionCandidatePaths(target string, scanScope model.ScanScope) []string {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	paths := []string{"/profile", "/account", "/me"}
	var out []string
	for _, path := range paths {
		resolved := base.ResolveReference(&url.URL{Path: path}).String()
		if scope.IsURLInScope(resolved, scanScope) {
			out = append(out, resolved)
		}
	}
	return out
}

func hasAnyAuthMaterial(profile model.ScanAuthProfile) bool {
	return profile.Username != "" || profile.Password != "" || profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "" || len(profile.Headers) > 0 || len(profile.Cookies) > 0
}

func appendPathSuffix(raw, suffix string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw + suffix
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if strings.HasPrefix(suffix, "/") {
		if strings.HasSuffix(path, "/") {
			u.Path = strings.TrimSuffix(path, "/") + suffix
		} else {
			u.Path = path + suffix
		}
	} else {
		u.Path = strings.TrimSuffix(path, "/") + suffix
	}
	return u.String()
}

func bodiesSimilar(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	if string(a) == string(b) {
		return true
	}
	delta := absInt(len(a) - len(b))
	if delta > 24 {
		return false
	}
	return strings.Contains(string(a), string(b)) || strings.Contains(string(b), string(a))
}
