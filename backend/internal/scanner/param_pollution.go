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

// hppBodyLimit caps per-response reads while probing for parameter pollution.
const hppBodyLimit = 128 * 1024

// hppParams are parameters whose duplication most often produces a
// server/back-end parsing differential (access-control identifiers, filters).
var hppParams = []string{
	"id", "user", "user_id", "uid", "account", "role", "filter",
	"q", "search", "page", "sort", "order", "lang", "redirect",
}

// hppMaxAttempts caps the per-scan probe budget.
const hppMaxAttempts = 12

// runParamPollutionProbe is an active HTTP Parameter Pollution (HPP) scanner.
// For each candidate endpoint it compares the response to a single-valued
// parameter against the response to a duplicated parameter (?p=a&p=b). A
// behavioural difference indicates the front-end and back-end disagree on which
// value wins, which attackers abuse to bypass input validation / WAF rules and
// to tamper with access-control identifiers. The probe is GET-only and never
// mutates server state.
func (s *Service) runParamPollutionProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 6)
	candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("param-pollution %s", input.Target),
			Message: "Probing for HTTP parameter pollution parsing differentials",
		})
	}

	attempts := 0
	seen := map[string]bool{}
	for _, raw := range candidates {
		if attempts >= hppMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, p := range hppParams {
			if attempts >= hppMaxAttempts {
				break
			}
			key := base.Scheme + base.Host + base.Path + p
			if seen[key] {
				continue
			}
			seen[key] = true
			attempts++

			singleURL := hppBuildURL(base, p+"=abh1")
			pollutedURL := hppBuildURL(base, p+"=abh1&"+p+"=abh2")
			if !scope.IsURLInScope(singleURL, input.Scope) || !scope.IsURLInScope(pollutedURL, input.Scope) {
				continue
			}
			if safety.ValidateOutboundURL(singleURL) != nil || safety.ValidateOutboundURL(pollutedURL) != nil {
				continue
			}

			single, ok1 := s.fetchBodyStatus(ctx, singleURL, input)
			polluted, ok2 := s.fetchBodyStatus(ctx, pollutedURL, input)
			if !ok1 || !ok2 {
				continue
			}
			if !hppDiffers(single, polluted) {
				continue
			}

			curl := fmt.Sprintf("curl -s '%s'  # vs  curl -s '%s'", singleURL, pollutedURL)
			return []model.Finding{{
				ID:       "param-pollution-" + hhSlug(base.Path+p),
				Category: "input-validation",
				Severity: model.SeverityMedium,
				Title:    "HTTP parameter pollution parsing differential",
				Description: fmt.Sprintf("Duplicating the %q parameter (?%s=a&%s=b) produced a different response than supplying it once. "+
					"This shows the application stack disagrees on which duplicate value is authoritative, which attackers exploit to bypass "+
					"input validation and WAF signatures, and to tamper with access-control or filter parameters.", p, p, p),
				Evidence: fmt.Sprintf("Single-valued request (HTTP %d) and duplicated-parameter request (HTTP %d) returned materially different responses.",
					single.status, polluted.status),
				Recommendation: "Reject or canonicalise duplicate query/body parameters before processing. Ensure the WAF/proxy and application " +
					"resolve duplicates identically, and treat access-control identifiers as single-valued.",
				Confidence:        0.6,
				AffectedURL:       pollutedURL,
				AffectedParameter: p,
				CWE:               "CWE-235",
				OWASPCategory:     "A03:2021 - Injection",
				Sources:           []string{"active-scanner", "param-pollution"},
				ReproductionSteps: []string{
					fmt.Sprintf("Send GET %s and record the response.", singleURL),
					fmt.Sprintf("Send GET %s and compare.", pollutedURL),
					"Confirm the duplicated parameter changes the response, then craft values that bypass the intended validation.",
				},
				PoC: curl,
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"parameter":      p,
					"singleStatus":   fmt.Sprintf("%d", single.status),
					"pollutedStatus": fmt.Sprintf("%d", polluted.status),
				},
			}}
		}
	}
	return nil
}

type bodyStatus struct {
	status int
	body   string
}

func (s *Service) fetchBodyStatus(ctx context.Context, rawURL string, input RunInput) (bodyStatus, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return bodyStatus{}, false
	}
	ApplyAuthProfile(req, input.AuthProfile)
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return bodyStatus{}, false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, hppBodyLimit))
	_ = resp.Body.Close()
	return bodyStatus{status: resp.StatusCode, body: string(b)}, true
}

// hppBuildURL appends an already-encoded raw query fragment to a validated base
// URL, preserving any existing query.
func hppBuildURL(base *url.URL, rawFragment string) string {
	rq := base.RawQuery
	if rq != "" {
		rq += "&" + rawFragment
	} else {
		rq = rawFragment
	}
	safe := url.URL{Scheme: base.Scheme, Host: base.Host, Path: base.Path, RawQuery: rq}
	return safe.String()
}

// hppDiffers reports whether two responses differ in a way that indicates a
// parameter-parsing differential. A different status code, or a meaningful
// change in body length, is treated as a difference; identical responses are
// not.
func hppDiffers(single, polluted bodyStatus) bool {
	if single.status != polluted.status {
		return true
	}
	if single.body == polluted.body {
		return false
	}
	// Require a non-trivial size delta to avoid flagging responses that merely
	// echo the (different) raw query string back, which is expected and benign.
	ls, lp := len(single.body), len(polluted.body)
	diff := ls - lp
	if diff < 0 {
		diff = -diff
	}
	larger := ls
	if lp > larger {
		larger = lp
	}
	if larger == 0 {
		return false
	}
	// Flag when the bodies differ by more than 5% of the larger response and by
	// at least 32 bytes (filters out trivial reflected-value differences).
	return diff >= 32 && float64(diff)/float64(larger) > 0.05
}
