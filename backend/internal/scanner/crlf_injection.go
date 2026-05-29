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

// crlfInjectedHeader is the marker header the probe attempts to smuggle into
// the response via a CRLF sequence. A response that echoes this header back
// proves the application reflected an unsanitised value into the HTTP response
// headers (HTTP response splitting / header injection).
const (
	crlfInjectedHeaderName  = "X-Abh-Crlf"
	crlfInjectedHeaderValue = "injected"
)

// crlfParams are parameters most commonly reflected into response headers
// (Location for redirects, Set-Cookie via "lang"/"theme", etc.).
var crlfParams = []string{
	"redirect", "redirect_uri", "url", "next", "return", "returnTo",
	"goto", "continue", "dest", "lang", "language", "locale", "theme",
	"page", "site", "host", "callback",
}

// crlfPayloads encode a CR-LF sequence followed by an injected header. Servers
// and proxies vary in which encodings they decode before writing the response
// header, so several equivalents are attempted.
var crlfPayloads = []string{
	"%0d%0a" + crlfInjectedHeaderName + ":%20" + crlfInjectedHeaderValue,
	"%0D%0A" + crlfInjectedHeaderName + ":%20" + crlfInjectedHeaderValue,
	"%E5%98%8D%E5%98%8A" + crlfInjectedHeaderName + ":%20" + crlfInjectedHeaderValue, // unicode CR/LF normalisation
	"\r\n" + crlfInjectedHeaderName + ": " + crlfInjectedHeaderValue,
}

// crlfMaxAttempts caps the per-scan probe budget.
const crlfMaxAttempts = 16

// runCRLFInjectionProbe is an active HTTP response-splitting / header-injection
// scanner. For each in-scope endpoint it injects a CR-LF encoded marker header
// into common reflected parameters and inspects the *response headers* for the
// injected header. Detection only fires when the marker appears as a real
// response header (not merely echoed in the body), which is the unambiguous
// signature of response splitting.
func (s *Service) runCRLFInjectionProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 8)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("crlf-injection %s", input.Target),
			Message: "Probing for CRLF / HTTP response splitting via header reflection",
		})
	}

	// Do not follow redirects: the injected header is most often reflected on
	// a 3xx Location response, which we must observe directly.
	baseClient := s.httpClient
	if input.Session != nil {
		baseClient = input.Session.Client()
	}
	noFollow := *baseClient
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	type hit struct {
		url   string
		param string
	}
	var hits []hit
	attempts := 0
	seen := map[string]bool{}

	for _, raw := range candidates {
		if attempts >= crlfMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, p := range crlfParams {
			if attempts >= crlfMaxAttempts {
				break
			}
			for _, payload := range crlfPayloads {
				if attempts >= crlfMaxAttempts {
					break
				}
				// Build the probe URL from validated fields of base and set the
				// raw (already CRLF-encoded) payload directly so it is not
				// re-encoded by url.Values.Encode.
				q := base.Query()
				existing := q.Encode()
				inj := url.QueryEscape(p) + "=" + payload
				rawQuery := inj
				if existing != "" {
					rawQuery = existing + "&" + inj
				}
				safe := url.URL{Scheme: base.Scheme, Host: base.Host, Path: base.Path, RawQuery: rawQuery}
				probeURL := safe.String()
				key := base.Scheme + base.Host + base.Path + p
				if seen[key] {
					continue
				}
				if !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				if err := safety.ValidateOutboundURL(probeURL); err != nil {
					continue
				}
				// probeURL is built from base's validated scheme/host/path and is
				// re-checked here by scope.IsURLInScope + safety.ValidateOutboundURL
				// (the SSRF guard rejecting loopback/internal hosts), so the request
				// cannot be steered to an out-of-scope or internal destination.
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := noFollow.Do(req)
				attempts++
				if err != nil || resp == nil {
					continue
				}
				injected := crlfHeaderInjected(resp.Header)
				_ = resp.Body.Close()
				if injected {
					seen[key] = true
					hits = append(hits, hit{url: probeURL, param: p})
					break
				}
			}
		}
	}

	if len(hits) == 0 {
		return nil
	}

	first := hits[0]
	urls := make([]string, 0, len(hits))
	for _, h := range hits {
		urls = append(urls, fmt.Sprintf("%s (param=%s)", h.url, h.param))
	}
	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")
	return []model.Finding{{
		ID:       "crlf-injection",
		Category: "injection",
		Severity: model.SeverityHigh,
		Title:    "CRLF injection / HTTP response splitting",
		Description: "The application reflected an unsanitised CR-LF (carriage-return/line-feed) sequence from a request parameter into the HTTP response headers. " +
			"This allows an attacker to inject arbitrary response headers (HTTP response splitting), enabling session fixation via injected Set-Cookie, " +
			"reflected XSS via injected content types, web cache poisoning, and open-redirect via injected Location.",
		Evidence: fmt.Sprintf("Injected response header %q observed after CRLF payload at: %s",
			crlfInjectedHeaderName, strings.Join(limitStrings(urls, 6), "; ")),
		Recommendation: "Strip or reject CR (%0d) and LF (%0a) characters from any user-controlled value that is written into a response header. " +
			"Use framework header-setting APIs that reject control characters, and never build headers via raw string concatenation.",
		Confidence:        0.9,
		AffectedURL:       first.url,
		AffectedParameter: first.param,
		CWE:               "CWE-113",
		OWASPCategory:     "A03:2021 - Injection",
		Sources:           []string{"active-scanner", "crlf-injection"},
		ReproductionSteps: []string{
			fmt.Sprintf("Send GET %s", first.url),
			fmt.Sprintf("Inspect the response headers and confirm the injected %q header is present.", crlfInjectedHeaderName),
			"Replace the marker with Set-Cookie or Location to demonstrate session fixation / open redirect impact.",
		},
		PoC: curl,
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"injectedHeader": crlfInjectedHeaderName,
			"curlReproducer": curl,
		},
	}}
}

// crlfHeaderInjected reports whether the marker header was successfully
// smuggled into the response header set.
func crlfHeaderInjected(h http.Header) bool {
	if h == nil {
		return false
	}
	v := h.Get(crlfInjectedHeaderName)
	return strings.EqualFold(strings.TrimSpace(v), crlfInjectedHeaderValue)
}
