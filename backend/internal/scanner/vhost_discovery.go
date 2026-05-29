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

// vhostBodyLimit caps per-response reads while probing for hidden virtual hosts.
const vhostBodyLimit = 128 * 1024

// vhostPrefixes are conventional internal/admin virtual-host labels worth
// probing against the target IP.
var vhostPrefixes = []string{
	"internal", "admin", "staging", "stage", "dev", "test", "qa",
	"preprod", "uat", "api-internal", "intranet", "private", "corp",
}

// vhostMaxAttempts caps the per-scan probe budget.
const vhostMaxAttempts = 14

// runVhostDiscoveryProbe is an active virtual-host discovery scanner. It keeps
// the TCP/TLS connection pointed at the in-scope target but overrides the HTTP
// Host header with candidate internal vhost names. A candidate that returns a
// materially different response than the default Host indicates a hidden
// virtual host (e.g. an internal admin app) served from the same server. The
// probe is GET-only and never leaves the target's IP, so it does not expand
// the network attack surface.
func (s *Service) runVhostDiscoveryProbe(ctx context.Context, input RunInput, _ string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(input.Target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	if !scope.IsURLInScope(input.Target, input.Scope) || safety.ValidateOutboundURL(input.Target) != nil {
		return nil
	}

	hostname := base.Hostname()
	apex := vhostApex(hostname)
	if apex == "" {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("vhost-discovery %s", input.Target),
			Message: "Probing for hidden virtual hosts via Host header rotation",
		})
	}

	baseline, ok := s.fetchWithHost(ctx, input, base.String(), "")
	if !ok {
		return nil
	}

	var findings []model.Finding
	attempts := 0
	seen := map[string]bool{}
	for _, prefix := range vhostPrefixes {
		if attempts >= vhostMaxAttempts {
			break
		}
		candidateHost := prefix + "." + apex
		if candidateHost == hostname || seen[candidateHost] {
			continue
		}
		seen[candidateHost] = true
		attempts++

		alt, ok := s.fetchWithHost(ctx, input, base.String(), candidateHost)
		if !ok {
			continue
		}
		if !vhostDiffers(baseline, alt) {
			continue
		}

		curl := fmt.Sprintf("curl -s -H 'Host: %s' '%s'", candidateHost, base.String())
		findings = append(findings, model.Finding{
			ID:       "vhost-" + hhSlug(candidateHost),
			Category: "discovery",
			Severity: model.SeverityMedium,
			Title:    "Hidden virtual host responds on target server",
			Description: fmt.Sprintf("Sending the Host header %q to the target server returned a response materially different from the default host. "+
				"This indicates a hidden virtual host — frequently an internal, staging, or admin application — is served from the same IP and may "+
				"lack the access controls applied to the public host.", candidateHost),
			Evidence: fmt.Sprintf("Default Host => HTTP %d (%d bytes); Host: %s => HTTP %d (%d bytes).",
				baseline.status, len(baseline.body), candidateHost, alt.status, len(alt.body)),
			Recommendation: "Restrict the server to an allow-list of expected Host values and return a default-deny response for unknown hosts. " +
				"Ensure internal/staging applications are not reachable on internet-facing IPs.",
			Confidence:    0.6,
			AffectedURL:   base.String(),
			CWE:           "CWE-200",
			OWASPCategory: "A05:2021 - Security Misconfiguration",
			Sources:       []string{"active-scanner", "vhost-discovery"},
			ReproductionSteps: []string{
				fmt.Sprintf("Send GET %s with header Host: %s", base.String(), candidateHost),
				"Compare the response to a request using the default Host header.",
				"If a distinct application is returned, enumerate it for missing access controls.",
			},
			PoC: curl,
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"vhost":          candidateHost,
				"baseStatus":     fmt.Sprintf("%d", baseline.status),
				"vhostStatus":    fmt.Sprintf("%d", alt.status),
				"curlReproducer": curl,
			},
		})
	}
	return findings
}

// fetchWithHost issues a GET to rawURL (which must remain the in-scope target)
// optionally overriding the HTTP Host header.
func (s *Service) fetchWithHost(ctx context.Context, input RunInput, rawURL, hostOverride string) (bodyStatus, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return bodyStatus{}, false
	}
	ApplyAuthProfile(req, input.AuthProfile)
	if hostOverride != "" {
		req.Host = hostOverride
	}
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		return bodyStatus{}, false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, vhostBodyLimit))
	_ = resp.Body.Close()
	return bodyStatus{status: resp.StatusCode, body: string(b)}, true
}

// vhostApex returns the registrable apex-ish domain (last two labels) of a
// hostname, or "" for IP literals / single-label hosts where vhost rotation is
// not meaningful.
func vhostApex(hostname string) string {
	hostname = strings.TrimSpace(strings.ToLower(hostname))
	if hostname == "" {
		return ""
	}
	// Skip IP literals.
	if strings.Count(hostname, ":") > 0 {
		return ""
	}
	allDigitsAndDots := true
	for _, r := range hostname {
		if r != '.' && (r < '0' || r > '9') {
			allDigitsAndDots = false
			break
		}
	}
	if allDigitsAndDots {
		return ""
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return ""
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// vhostDiffers reports whether a Host-rotated response differs enough from the
// baseline to suggest a distinct virtual host.
func vhostDiffers(baseline, alt bodyStatus) bool {
	if baseline.status != alt.status {
		// A 4xx/5xx baseline flipping to 2xx (or vice versa) is the strongest
		// signal; any status change is reported.
		return true
	}
	if baseline.body == alt.body {
		return false
	}
	lb, la := len(baseline.body), len(alt.body)
	diff := lb - la
	if diff < 0 {
		diff = -diff
	}
	larger := lb
	if la > larger {
		larger = la
	}
	if larger == 0 {
		return false
	}
	return diff >= 64 && float64(diff)/float64(larger) > 0.1
}
