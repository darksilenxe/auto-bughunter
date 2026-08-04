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
	parsed, err := url.Parse(strings.TrimSpace(input.Target))
	if err != nil {
		return nil
	}
	// Rebuild the request URL from explicit, already-validated fields of the
	// parsed target (rather than reusing the tainted input string). The host
	// can only ever equal parsed.Host, which the in-scope + ValidateOutboundURL
	// checks above already vetted. This makes the safety property locally
	// obvious and recognisable to static taint trackers.
	safe := url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path, RawQuery: parsed.RawQuery}
	targetURL := safe.String()

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("cache-poisoning %s", input.Target),
			Message: "Probing for web cache poisoning via unkeyed header reflection",
		})
	}
	// Phase 2 coverage accounting.
	RecordProbedKey(http.MethodGet, input.Target, "")

	baseClient := s.httpClient
	if input.Session != nil {
		baseClient = input.Session.Client()
	}
	noFollow := *baseClient
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// targetURL was rebuilt from the parsed target's explicit fields and the
	// target was already cleared by scope.IsURLInScope + safety.ValidateOutboundURL
	// (the SSRF guard that rejects loopback/link-local/internal hosts) above, so
	// the request below cannot reach an out-of-scope or internal destination.
	for _, hdr := range cachePoisonHeaders {
		// Give every header trial its own cache-buster query parameter. This
		// (a) stops concurrent trials from clobbering the same cache key, and
		// (b) — per PortSwigger's canonical web-cache-poisoning methodology —
		// gives us a stable, unique URL that we can re-request cleanly (no
		// injected header) to prove the response was actually served *from
		// the cache* rather than merely reflected on the poisoned request
		// itself. A per-request reflection without a confirmed cache replay
		// is not a demonstrated cache-poisoning vulnerability.
		poisonURL := withCacheBusterParam(targetURL, "abhcb", cacheBusterToken(hdr))
		// Re-validate: withCacheBusterParam only ever adds/overwrites a query
		// parameter on targetURL, but re-check explicitly so the outbound
		// destination is never trusted without a fresh SSRF/scope check.
		if err := safety.ValidateOutboundURL(poisonURL); err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, poisonURL, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		if strings.EqualFold(hdr, "Forwarded") {
			req.Header.Set(hdr, "host="+cachePoisonCanary)
		} else {
			req.Header.Set(hdr, cachePoisonCanary)
		}
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

		// PortSwigger's own true-positive test: re-fetch the exact same
		// (cache-buster) URL with no injected header. If a shared cache
		// actually stored and replayed the poisoned response, the canary
		// must still be present for this "clean visitor" request.
		confirmed, replayErr := cachePoisonReplayConfirmed(ctx, &noFollow, input, poisonURL)

		severity := model.SeverityMedium
		confidence := 0.6
		verdict := "unconfirmed"
		switch {
		case confirmed:
			severity = model.SeverityCritical
			confidence = 0.95
			verdict = "confirmed"
		case cacheable:
			severity = model.SeverityHigh
			confidence = 0.85
		}

		description := fmt.Sprintf("The response reflected the value of the unkeyed request header %q into the response. "+
			"When this header is excluded from the cache key but influences the cached response body, an attacker can poison the shared "+
			"cache so that all subsequent visitors receive attacker-controlled content (e.g. a malicious script host or redirect).", hdr)
		if confirmed {
			description += " This was confirmed by re-requesting the same URL without the injected header: the poisoned response " +
				"(carrying the canary value) was served from the shared cache to a subsequent \"clean\" request, proving real-world impact."
		} else if replayErr == nil {
			description += " A clean-request replay of the same URL did not reproduce the canary, so cache poisoning is not yet " +
				"confirmed end-to-end; this may still indicate an unkeyed-input flaw worth manual verification (e.g. cache TTL, " +
				"vary-header exclusions, or edge/CDN caching not exercised during this scan)."
		}

		curl := fmt.Sprintf("curl -s -H '%s: %s' '%s'", hdr, cachePoisonCanary, poisonURL)
		return []model.Finding{{
			ID:          "cache-poisoning-" + hhSlug(hdr),
			Category:    "misconfiguration",
			Severity:    severity,
			Title:       "Potential web cache poisoning via unkeyed header",
			Description: description,
			Evidence: fmt.Sprintf("Injected %s: %s was reflected in the response; cache-indicative headers present: %t (%s); replay verdict: %s.",
				hdr, cachePoisonCanary, cacheable, cacheHeaderSummary(resp.Header), verdict),
			Recommendation: "Include every header that affects the response body in the cache key, or strip attacker-controllable headers " +
				"(X-Forwarded-Host, X-Host, Forwarded, …) at the edge before caching. Do not build absolute URLs from request headers.",
			Confidence:    confidence,
			AffectedURL:   input.Target,
			CWE:           "CWE-444",
			OWASPCategory: "A05:2021 - Security Misconfiguration",
			Sources:       []string{"active-scanner", "cache-poisoning"},
			ReproductionSteps: []string{
				fmt.Sprintf("Send GET %s with header %s: %s", poisonURL, hdr, cachePoisonCanary),
				"Confirm the canary value is reflected into the response body or a Location/absolute-URL header.",
				"Inspect cache headers (X-Cache, Age, Cache-Control) to confirm the response is stored in a shared cache.",
				"Re-request the same URL without the header to confirm the poisoned response is served from cache.",
			},
			PoC: curl,
			EvidenceFields: map[string]string{
				"validationType":  "active-probe",
				"unkeyedHeader":   hdr,
				"cacheable":       fmt.Sprintf("%t", cacheable),
				"replayConfirmed": fmt.Sprintf("%t", confirmed),
				"curlReproducer":  curl,
			},
		}}
	}

	return nil
}

// cacheBusterToken derives a short, deterministic-per-header token so the
// per-trial cache-buster query stays stable within a single probe run while
// still being distinct per header (avoids trials clobbering each other's
// cache entries).
func cacheBusterToken(hdr string) string {
	sum := 0
	for _, r := range hdr {
		sum = sum*31 + int(r)
	}
	if sum < 0 {
		sum = -sum
	}
	return fmt.Sprintf("%s%x", cachePoisonCanary[:3], sum)
}

// withCacheBusterParam appends a unique query parameter to rawURL so the
// probe's poison and replay requests target the same, otherwise-unused cache
// key without disturbing real traffic.
func withCacheBusterParam(rawURL, param, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// cachePoisonReplayConfirmed re-fetches poisonURL with no injected header and
// reports whether the canary is still present — i.e. whether a shared cache
// actually stored and replayed the poisoned response to a subsequent "clean"
// request. This is PortSwigger's canonical distinction between a per-request
// reflection (not yet a vulnerability) and confirmed cache poisoning.
func cachePoisonReplayConfirmed(ctx context.Context, client *http.Client, input RunInput, poisonURL string) (bool, error) {
	// poisonURL is caller-constructed from an already-scope/SSRF-validated
	// target (see withCacheBusterParam call site), but re-validate here too
	// since this helper issues its own outbound request independently.
	if err := safety.ValidateOutboundURL(poisonURL); err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, poisonURL, nil)
	if err != nil {
		return false, err
	}
	ApplyAuthProfile(req, input.AuthProfile)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, cachePoisonBodyLimit))
	return cachePoisonReflected(string(body), resp.Header, cachePoisonCanary), nil
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
