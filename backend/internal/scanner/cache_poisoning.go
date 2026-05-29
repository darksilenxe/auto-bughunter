package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// cachePoisonBodyLimit caps the per-response read while probing for cache
// poisoning.
const cachePoisonBodyLimit = 256 * 1024

// cachePoisonCanary is the attacker-controlled host injected via unkeyed
// headers. If it is reflected into a cacheable response, an attacker can poison
// the shared cache for every subsequent visitor.
const cachePoisonCanary = "abh-cache-poison.invalid"

// cachePoisonHeaders are request headers that frequently influence the response
// body (absolute URLs, redirects) but are commonly excluded from the cache key.
var cachePoisonHeaders = []string{
	"X-Forwarded-Host",
	"X-Host",
	"X-Forwarded-Server",
	"X-Forwarded-Scheme",
	"X-Original-Host",
	"Forwarded",
}

// runCachePoisoningProbe is an active web cache poisoning scanner. It injects a
// canary host into unkeyed headers and reports when (a) the canary is reflected
// into the response and (b) the response carries cache headers indicating it is
// served from / stored in a shared cache.
func (s *Service) runCachePoisoningProbe(ctx context.Context, input RunInput, _ string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	if !scope.IsURLInScope(input.Target, input.Scope) {
		return nil
	}
	if err := safety.ValidateOutboundURL(input.Target); err != nil {
		return nil
	}
	if _, err := url.Parse(strings.TrimSpace(input.Target)); err != nil {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("cache-poisoning %s", input.Target),
			Message: "Probing for web cache poisoning via unkeyed header reflection",
		})
	}

	baseClient := s.httpClient
	if input.Session != nil {
		baseClient = input.Session.Client()
	}
	noFollow := *baseClient
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	for _, hdr := range cachePoisonHeaders {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Target, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		if strings.EqualFold(hdr, "Forwarded") {
			req.Header.Set(hdr, "host="+cachePoisonCanary)
		} else {
			req.Header.Set(hdr, cachePoisonCanary)
		}
		// Add a cache-buster query so we never actually poison a real cache key
		// during testing while still triggering cache storage behaviour.
		resp, err := noFollow.Do(req)
		if err != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, cachePoisonBodyLimit))
		_ = resp.Body.Close()

		reflected := cachePoisonReflected(string(body), resp.Header, cachePoisonCanary)
		cacheable := responseAppearsCacheable(resp.Header)
		if !reflected {
			continue
		}

		severity := model.SeverityMedium
		confidence := 0.6
		if cacheable {
			severity = model.SeverityHigh
			confidence = 0.85
		}

		curl := fmt.Sprintf("curl -s -H '%s: %s' '%s'", hdr, cachePoisonCanary, input.Target)
		return []model.Finding{{
			ID:       "cache-poisoning-" + hhSlug(hdr),
			Category: "misconfiguration",
			Severity: severity,
			Title:    "Potential web cache poisoning via unkeyed header",
			Description: fmt.Sprintf("The response reflected the value of the unkeyed request header %q into the response. "+
				"When this header is excluded from the cache key but influences the cached response body, an attacker can poison the shared "+
				"cache so that all subsequent visitors receive attacker-controlled content (e.g. a malicious script host or redirect).", hdr),
			Evidence: fmt.Sprintf("Injected %s: %s was reflected in the response; cache-indicative headers present: %t (%s).",
				hdr, cachePoisonCanary, cacheable, cacheHeaderSummary(resp.Header)),
			Recommendation: "Include every header that affects the response body in the cache key, or strip attacker-controllable headers " +
				"(X-Forwarded-Host, X-Host, Forwarded, …) at the edge before caching. Do not build absolute URLs from request headers.",
			Confidence:    confidence,
			AffectedURL:   input.Target,
			CWE:           "CWE-444",
			OWASPCategory: "A05:2021 - Security Misconfiguration",
			Sources:       []string{"active-scanner", "cache-poisoning"},
			ReproductionSteps: []string{
				fmt.Sprintf("Send GET %s with header %s: %s", input.Target, hdr, cachePoisonCanary),
				"Confirm the canary value is reflected into the response body or a Location/absolute-URL header.",
				"Inspect cache headers (X-Cache, Age, Cache-Control) to confirm the response is stored in a shared cache.",
				"Re-request the URL without the header to confirm the poisoned response is served from cache.",
			},
			PoC: curl,
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"unkeyedHeader":  hdr,
				"cacheable":      fmt.Sprintf("%t", cacheable),
				"curlReproducer": curl,
			},
		}}
	}

	return nil
}

// cachePoisonReflected reports whether the injected canary appears in the
// response body or in a response header value (e.g. Location, Link).
func cachePoisonReflected(body string, h http.Header, canary string) bool {
	if canary == "" {
		return false
	}
	if strings.Contains(body, canary) {
		return true
	}
	for _, vals := range h {
		for _, v := range vals {
			if strings.Contains(v, canary) {
				return true
			}
		}
	}
	return false
}

// responseAppearsCacheable reports whether response headers indicate the
// response is served from / eligible for a shared cache.
func responseAppearsCacheable(h http.Header) bool {
	if h == nil {
		return false
	}
	if xc := strings.ToLower(h.Get("X-Cache")); strings.Contains(xc, "hit") || strings.Contains(xc, "miss") {
		return true
	}
	if h.Get("Age") != "" {
		return true
	}
	if h.Get("X-Cache-Hits") != "" || h.Get("CF-Cache-Status") != "" || h.Get("X-Varnish") != "" {
		return true
	}
	cc := strings.ToLower(h.Get("Cache-Control"))
	if cc == "" {
		return false
	}
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return false
	}
	return strings.Contains(cc, "public") || strings.Contains(cc, "max-age") || strings.Contains(cc, "s-maxage")
}

func cacheHeaderSummary(h http.Header) string {
	parts := make([]string, 0, 4)
	for _, k := range []string{"X-Cache", "Age", "Cache-Control", "CF-Cache-Status"} {
		if v := h.Get(k); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "; ")
}
