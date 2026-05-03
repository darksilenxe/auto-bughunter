package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// ssrfHeaderProbeHeaders is the set of request headers commonly trusted by
// reverse proxies and application code as a source of "the original client
// URL/host". When a server-side component blindly fetches them — for example
// to render a profile picture, validate a webhook origin, or build a callback
// URL — supplying our OAST URL surfaces a blind SSRF.
var ssrfHeaderProbeHeaders = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Client-IP",
	"X-Real-IP",
	"Forwarded",
	"Referer",
	"X-HTTP-DestinationURL",
	"CF-Connecting-IP",
	"True-Client-IP",
}

// defaultOASTSSRFWait is how long the header-based SSRF probe waits for a
// callback after firing the request. Six seconds is a pragmatic middle
// ground: long enough to absorb queueing/jitter on most servers, short
// enough not to noticeably slow down a scan when the target is not
// vulnerable.
const defaultOASTSSRFWait = 6 * time.Second

// runOASTHeaderSSRFProbe sends a single request to the target with an OAST
// callback URL injected into common SSRF-prone headers, then waits briefly
// for a callback. A confirmed callback yields a high-severity finding. The
// probe is silently skipped when no OAST service is attached or when the
// service has no public URL configured.
func (s *Service) runOASTHeaderSSRFProbe(ctx context.Context, input RunInput) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	if s.oast == nil || !s.oast.Configured() {
		return nil
	}

	tok := s.oast.Issue("", "ssrf-header-probe")
	if tok.CallbackURL == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Target, nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, input.AuthProfile)
	for _, h := range ssrfHeaderProbeHeaders {
		req.Header.Set(h, tok.CallbackURL)
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("oast-ssrf-headers %s", input.Target),
			Message: "Probing for header-based SSRF via out-of-band callback",
		})
	}

	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}

	wait := defaultOASTSSRFWait
	if input.Options.RequestDelayMillis > 0 {
		// Be a little more patient when the scan is intentionally slow.
		wait = wait + time.Duration(input.Options.RequestDelayMillis)*time.Millisecond
	}
	hits := s.oast.Wait(tok.Token, wait)
	if len(hits) == 0 {
		return nil
	}

	hit := hits[0]
	evidence := fmt.Sprintf(
		"Injected callback URL %s into headers %s. Observed inbound %s %s%s from %s (User-Agent: %q) at %s.",
		tok.CallbackURL,
		strings.Join(ssrfHeaderProbeHeaders, ", "),
		hit.Method,
		hit.Path,
		queryToken(hit.Query),
		hit.RemoteAddr,
		hit.UserAgent,
		hit.ReceivedAt.UTC().Format(time.RFC3339),
	)

	return []model.Finding{{
		ID:                "oast-ssrf-headers",
		Category:          "input-validation",
		Severity:          model.SeverityHigh,
		Title:             "Out-of-band SSRF via untrusted request headers",
		Description:       "The target made an outbound HTTP request to an attacker-controlled callback URL after the URL was supplied in proxy/forwarding headers. This indicates server-side code is dereferencing untrusted header values, enabling Server-Side Request Forgery.",
		Evidence:          evidence,
		Recommendation:    "Treat all forwarding/origin headers (X-Forwarded-*, Forwarded, Referer, X-Original-URL, etc.) as untrusted input. Never construct outbound requests, redirects or fetches from raw header values; if a header must be honoured, validate it against an explicit allow-list of hosts/schemes and resolve it through an SSRF-safe HTTP client.",
		Confidence:        0.95,
		AffectedURL:       input.Target,
		CWE:               "CWE-918",
		OWASPCategory:     "A10:2021 - Server-Side Request Forgery (SSRF)",
		Sources:           []string{"oast"},
		ReproductionSteps: ssrfReproSteps(input.Target, tok.CallbackURL),
	}}
}

func ssrfReproSteps(target, callback string) []string {
	steps := []string{
		fmt.Sprintf("Issue an OAST callback URL: %s", callback),
		fmt.Sprintf("Send a single HTTP GET to %s with the following headers all set to the callback URL:", target),
	}
	for _, h := range ssrfHeaderProbeHeaders {
		steps = append(steps, fmt.Sprintf("  %s: %s", h, callback))
	}
	steps = append(steps, "Observe an inbound request to the OAST listener within seconds, confirming the target dereferenced one of the headers.")
	return steps
}

func queryToken(q string) string {
	if q == "" {
		return ""
	}
	return "?" + q
}
