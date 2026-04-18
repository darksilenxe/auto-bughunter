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

// takeoverFingerprint is a single dangling-CNAME signature for a third-party
// service that historically allows resource claim-back via the bare hostname.
// Each entry pairs the service name with a stable, fairly-unique substring
// from the unclaimed-resource response body.
//
// The list is intentionally curated to high-precision signatures only:
// generic markers like "404 Not Found" are excluded because they would
// false-positive on any normal missing page.
type takeoverFingerprint struct {
	Service     string
	BodyMarker  string
	Description string
}

// takeoverFingerprints covers the most commonly-exploitable dangling-CNAME
// services. Each marker is taken from the public unclaimed-bucket / orphaned
// app response of the named service.
var takeoverFingerprints = []takeoverFingerprint{
	{Service: "AWS S3", BodyMarker: "NoSuchBucket", Description: "S3 bucket referenced by CNAME does not exist; an attacker can register the bucket name and serve content under the dangling subdomain."},
	{Service: "GitHub Pages", BodyMarker: "There isn't a GitHub Pages site here", Description: "GitHub Pages site referenced by CNAME has been deleted; an attacker can claim the GitHub repository/organization and serve content under the dangling subdomain."},
	{Service: "Heroku", BodyMarker: "No such app", Description: "Heroku app referenced by CNAME no longer exists; an attacker can register the Heroku app name and serve content under the dangling subdomain."},
	{Service: "Shopify", BodyMarker: "Sorry, this shop is currently unavailable", Description: "Shopify storefront referenced by CNAME is unclaimed; an attacker can register the shop slug and serve content under the dangling subdomain."},
	{Service: "Fastly", BodyMarker: "Fastly error: unknown domain", Description: "Fastly service referenced by CNAME has no matching domain configured; an attacker who can claim the Fastly service can serve content under the dangling subdomain."},
	{Service: "Surge.sh", BodyMarker: "project not found", Description: "Surge.sh project referenced by CNAME has been removed; an attacker can re-publish the project name and serve content under the dangling subdomain."},
	{Service: "Tumblr", BodyMarker: "Whatever you were looking for doesn't currently exist at this address", Description: "Tumblr blog referenced by CNAME does not exist; an attacker can register the blog name and serve content under the dangling subdomain."},
	{Service: "Bitbucket", BodyMarker: "Repository not found", Description: "Bitbucket Pages repository referenced by CNAME does not exist; an attacker can create the repository and serve content under the dangling subdomain."},
	{Service: "Pantheon", BodyMarker: "The gods are wise, but do not know of the site which you seek", Description: "Pantheon site referenced by CNAME does not exist; an attacker can register the Pantheon site name and serve content under the dangling subdomain."},
	{Service: "Squarespace", BodyMarker: "No Such Account", Description: "Squarespace site referenced by CNAME has no associated account; an attacker can register the account and serve content under the dangling subdomain."},
	{Service: "Help Scout", BodyMarker: "No settings were found for this company", Description: "Help Scout Docs site referenced by CNAME has no associated company; an attacker who can register the company can serve content under the dangling subdomain."},
	{Service: "Tilda", BodyMarker: "Please renew your subscription", Description: "Tilda site referenced by CNAME has an expired/unclaimed project; an attacker can claim the Tilda project and serve content under the dangling subdomain."},
	{Service: "Unbounce", BodyMarker: "The requested URL was not found on this server", Description: "Unbounce landing page referenced by CNAME no longer exists; an attacker can recreate the page slug and serve content under the dangling subdomain."},
}

// maxTakeoverHosts caps how many candidate subdomains the probe will GET.
// Subdomain-takeover detection is one HTTPS GET per candidate (with a single
// HTTP fallback on TLS error), so cost is bounded but non-trivial.
const maxTakeoverHosts = 12

// runSubdomainTakeoverProbe scans candidate subdomains in scope for the
// classic dangling-CNAME takeover pattern: the host resolves but the
// upstream third-party service responds with a recognisable
// "this resource is unclaimed" body. The probe is silent when no candidate
// hosts are available or no fingerprint matches.
//
// Candidate hosts are derived from:
//   - the configured scan scope's IncludeHosts (literal hostnames only —
//     wildcard patterns like *.example.com are skipped because there is no
//     concrete host to GET);
//   - hostnames extracted from the runtime endpoint discovery already
//     performed on the target's response body.
//
// The probe deliberately excludes the target's own host because takeover is
// only interesting for sibling/sub hosts; the target itself is already
// covered by the rest of the scanner.
func (s *Service) runSubdomainTakeoverProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	targetHost := ""
	if u, err := url.Parse(input.Target); err == nil {
		targetHost = strings.ToLower(u.Hostname())
	}

	hosts := collectTakeoverCandidates(input.Target, body, input.Scope, targetHost, maxTakeoverHosts)
	if len(hosts) == 0 {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("subdomain-takeover %d hosts", len(hosts)),
			Message: "Probing in-scope subdomains for dangling-CNAME takeover signatures",
		})
	}

	type hit struct {
		host        string
		probedURL   string
		service     string
		description string
	}
	var hits []hit

	for _, host := range hosts {
		// Try HTTPS first, then HTTP as a fallback. Many takeover-vulnerable
		// services only serve plaintext on the dangling host (e.g. S3
		// website endpoints behind a CNAME).
		for _, scheme := range []string{"https", "http"} {
			probeURL := scheme + "://" + host + "/"
			if !scope.IsURLInScope(probeURL, input.Scope) {
				continue
			}
			if err := safety.ValidateOutboundURL(probeURL); err != nil {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				continue
			}
			ApplyAuthProfile(req, input.AuthProfile)
			resp, err := s.doRequestWithRetry(ctx, req, input.Options)
			if err != nil || resp == nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			_ = resp.Body.Close()
			if fp, ok := matchTakeoverFingerprint(string(respBody)); ok {
				hits = append(hits, hit{
					host:        host,
					probedURL:   probeURL,
					service:     fp.Service,
					description: fp.Description,
				})
				break // do not try the other scheme on a confirmed host
			}
		}
	}

	if len(hits) == 0 {
		return nil
	}

	urls := make([]string, 0, len(hits))
	services := make([]string, 0, len(hits))
	seenService := map[string]struct{}{}
	for _, h := range hits {
		urls = append(urls, h.probedURL)
		if _, ok := seenService[h.service]; !ok {
			services = append(services, h.service)
			seenService[h.service] = struct{}{}
		}
	}

	first := hits[0]
	steps := []string{
		fmt.Sprintf("Resolve %s and confirm it CNAMEs to a third-party service (%s).", first.host, first.service),
		fmt.Sprintf("Send GET %s and observe the unclaimed-resource response body matching the %s takeover fingerprint.", first.probedURL, first.service),
		"Register the underlying resource on the third-party service to demonstrate impact (with explicit program authorization).",
	}

	return []model.Finding{{
		ID:                "subdomain-takeover",
		Category:          "infrastructure",
		Severity:          model.SeverityHigh,
		Title:             "Subdomain takeover via dangling CNAME",
		Description:       fmt.Sprintf("One or more in-scope subdomains point to third-party services where the underlying resource has been deleted/unclaimed. The matched service(s): %s. %s", strings.Join(services, ", "), first.description),
		Evidence:          fmt.Sprintf("Unclaimed third-party responses observed at: %s (services: %s)", strings.Join(limitStrings(urls, 6), ", "), strings.Join(services, ", ")),
		Recommendation:    "Audit DNS records for CNAMEs pointing to third-party services. Remove records for unclaimed resources, or re-claim/re-create the upstream resource so it is owned by your organization. Adopt a continuous DNS hygiene check that flags CNAMEs whose target returns a known takeover fingerprint.",
		Confidence:        0.9,
		AffectedURL:       first.probedURL,
		CWE:               "CWE-1104",
		OWASPCategory:     "A06:2021 - Vulnerable and Outdated Components",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: steps,
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"reproStep":      "Replay the listed URL and confirm the unclaimed-resource fingerprint in the response body",
		},
	}}
}

// collectTakeoverCandidates builds a deduplicated, scope-validated list of
// subdomain hosts to probe. The target host itself is always excluded.
func collectTakeoverCandidates(target, body string, scanScope model.ScanScope, excludeHost string, max int) []string {
	if max <= 0 {
		max = maxTakeoverHosts
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, max)

	add := func(host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || host == excludeHost {
			return
		}
		// Reject wildcard patterns and anything that does not look like a
		// concrete hostname. Wildcards in scope cannot be GETed directly.
		if strings.ContainsAny(host, "*?/") {
			return
		}
		if !scope.IsHostInScope(host, scanScope) {
			return
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}

	for _, h := range scanScope.IncludeHosts {
		add(h)
		if len(out) >= max {
			return out
		}
	}

	// Re-use runtime endpoint discovery to surface sibling hostnames mentioned
	// in the target's response body (script srcs, JSON URLs, …). We do not
	// cap on the discovery side — the host-level dedup + max bound applies
	// here.
	for _, ep := range extractRuntimeEndpoints(target, body, scanScope, max*2) {
		if u, err := url.Parse(ep); err == nil {
			add(u.Hostname())
			if len(out) >= max {
				return out
			}
		}
	}

	return out
}

// matchTakeoverFingerprint returns the first fingerprint whose marker appears
// in the response body. Matching is plain substring (case-sensitive) because
// every curated marker is taken verbatim from the upstream service's stable
// error page.
func matchTakeoverFingerprint(body string) (takeoverFingerprint, bool) {
	if body == "" {
		return takeoverFingerprint{}, false
	}
	for _, fp := range takeoverFingerprints {
		if strings.Contains(body, fp.BodyMarker) {
			return fp, true
		}
	}
	return takeoverFingerprint{}, false
}
