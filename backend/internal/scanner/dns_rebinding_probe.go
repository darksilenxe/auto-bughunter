package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// dnsRebindingMaxEndpoints caps how many candidate endpoints are probed.
const dnsRebindingMaxEndpoints = 6

// dnsRebindingHostnames are public, attacker-registrable "wildcard DNS"
// hostnames that resolve directly to loopback/link-local addresses
// (PayloadsAllTheThings SSRF "DNS Rebinding" bypass technique). An SSRF
// allowlist that only checks the hostname string (not the resolved IP, and
// not re-resolved at fetch time) is bypassed because these hostnames are not
// literally "localhost"/"127.0.0.1" yet still resolve to internal addresses.
var dnsRebindingHostnames = []struct {
	label string
	url   string
}{
	{label: "loopback-nip.io", url: "http://127.0.0.1.nip.io/"},
	{label: "aws-metadata-nip.io", url: "http://169.254.169.254.nip.io/latest/meta-data/"},
	{label: "loopback-lvh.me", url: "http://localtest.me/"},
}

// dnsRebindingControlURL is a safe, external, non-internal URL used as the
// control request so we can differentiate "the app fetches any URL and
// returns similar content" (expected, not a finding on its own) from
// "the app specifically reached an internal address" (the actual signal).
const dnsRebindingControlURL = "https://example.com/"

// dnsRebindingParams are common request-body/query field names that carry a
// URL the server subsequently fetches.
var dnsRebindingParams = oastBodySSRFParams

// dnsRebindingInternalSignatures are response body substrings that strongly
// suggest the fetched resource was an internal/loopback service rather than
// the public control URL.
var dnsRebindingInternalSignatures = []string{
	"ami-id", "instance-id", "iam-security-credentials", "computeMetadata",
	"root:x:0:0", "welcome to nginx", "apache2 ubuntu default page",
	"it works!", "localhost.localdomain",
}

// runDNSRebindingProbe is an active probe for the PayloadsAllTheThings SSRF
// "DNS Rebinding" bypass class. It POSTs URL-bearing body parameters using
// public hostnames that resolve directly to loopback/link-local IPs, then
// compares the response against a control request using a safe external URL.
// A response containing internal-service signatures (or that otherwise
// diverges materially from the control while the loopback-hostname request
// succeeds) indicates the server fetched the attacker-supplied hostname
// without validating the resolved IP — the precondition exploited by full
// TOCTOU DNS-rebinding attacks against SSRF allowlists that only check the
// hostname string once, not the IP actually connected to.
func (s *Service) runDNSRebindingProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	endpoints := extractRuntimeEndpoints(input.Target, body, input.Scope, dnsRebindingMaxEndpoints)
	endpoints = append(endpoints, input.Target)
	endpoints = uniqueEndpoints(endpoints)
	if len(endpoints) > dnsRebindingMaxEndpoints {
		endpoints = endpoints[:dnsRebindingMaxEndpoints]
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("dns-rebinding %s", input.Target),
			Message: "Probing SSRF-prone parameters for DNS-rebinding-capable loopback hostnames",
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	for _, ep := range endpoints {
		if !scope.IsURLInScope(ep, input.Scope) {
			continue
		}

		controlStatus, controlBody, ok := s.dnsRebindingPost(ctx, input, ep, dnsRebindingControlURL)
		if !ok || controlStatus >= 400 {
			continue
		}

		for _, host := range dnsRebindingHostnames {
			fid := "dns-rebinding-" + host.label + "-" + hhSlug(ep)
			if emitted[fid] {
				continue
			}

			status, respBody, ok := s.dnsRebindingPost(ctx, input, ep, host.url)
			if !ok || status >= 400 {
				continue
			}

			sig := matchAnyLower(respBody, dnsRebindingInternalSignatures)
			bodyDiffers := absInt(len(respBody)-len(controlBody)) > 40
			if sig == "" && !bodyDiffers {
				continue
			}

			emitted[fid] = true
			findings = append(findings, model.Finding{
				ID:       fid,
				Category: "input-validation",
				Severity: model.SeverityHigh,
				Title:    "SSRF: server fetches attacker-supplied loopback/internal hostname (DNS rebinding class)",
				Description: fmt.Sprintf(
					"The endpoint %s dereferenced the attacker-supplied URL %s — a public hostname that resolves "+
						"to a loopback or link-local address — and returned a response distinguishable from the control "+
						"request to %s. This confirms the server-side fetcher does not validate the resolved IP address "+
						"of a user-supplied hostname, which is the precondition exploited by DNS-rebinding SSRF attacks: "+
						"an attacker-controlled DNS record can pass an initial hostname allowlist check, then re-resolve "+
						"to an internal address (169.254.169.254 cloud metadata, loopback services, RFC1918 ranges) "+
						"by the time the fetch actually occurs.",
					ep, host.url, dnsRebindingControlURL,
				),
				Evidence: fmt.Sprintf(
					"POST %s param=%s → control(%s) HTTP %d (%d bytes) vs test(%s) HTTP %d (%d bytes); internal signature: %q",
					ep, strings.Join(dnsRebindingParams, "|"), dnsRebindingControlURL, controlStatus, len(controlBody),
					host.url, status, len(respBody), sig,
				),
				Recommendation: "Re-resolve and re-validate the destination IP address immediately before every " +
					"outbound connection (not only at input-validation time), reject responses where the resolved " +
					"address is loopback/link-local/RFC1918/multicast, and pin the connection to the IP that was " +
					"validated (disable follow-on DNS re-resolution for the same request). Prefer an explicit " +
					"allowlist of destination hosts over a denylist of \"dangerous\" hostnames/IPs.",
				Confidence:    0.6,
				AffectedURL:   ep,
				CWE:           "CWE-918",
				OWASPCategory: "A10:2021 - Server-Side Request Forgery (SSRF)",
				Sources:       []string{"active-scanner", "dns-rebinding-probe"},
				ReproductionSteps: []string{
					fmt.Sprintf("POST to %s with one of %s set to %q.", ep, strings.Join(dnsRebindingParams, ", "), host.url),
					fmt.Sprintf("Compare the response against the same request with the parameter set to %q.", dnsRebindingControlURL),
					"Observe internal-service content or a materially different response, confirming the loopback hostname was fetched.",
				},
				BusinessTags: []string{"ssrf", "dns-rebinding", "input-validation"},
				EvidenceFields: map[string]string{
					"validationType":    "active-probe",
					"testHostname":      host.url,
					"controlURL":        dnsRebindingControlURL,
					"controlStatus":     fmt.Sprintf("%d", controlStatus),
					"testStatus":        fmt.Sprintf("%d", status),
					"internalSignature": sig,
				},
			})
		}
	}

	return findings
}

// dnsRebindingPost sends a POST with the URL-bearing body params (form and
// JSON encodings tried in sequence, first success used) set to targetURL,
// returning the response status and truncated body text.
func (s *Service) dnsRebindingPost(ctx context.Context, input RunInput, ep, targetURL string) (int, string, bool) {
	form := url.Values{}
	jsonObj := map[string]string{}
	for _, p := range dnsRebindingParams {
		form.Set(p, targetURL)
		jsonObj[p] = targetURL
	}
	jsonBody, err := json.Marshal(jsonObj)
	if err != nil {
		return 0, "", false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(string(jsonBody)))
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("Content-Type", "application/json")
	ApplyAuthProfile(req, input.AuthProfile)
	resp, err := s.doRequestWithRetry(ctx, req, input.Options)
	if err != nil || resp == nil {
		// Fall back to form-encoded on transport error.
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode()))
		if err2 != nil {
			return 0, "", false
		}
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ApplyAuthProfile(req2, input.AuthProfile)
		resp2, err2 := s.doRequestWithRetry(ctx, req2, input.Options)
		if err2 != nil || resp2 == nil {
			return 0, "", false
		}
		b, _ := io.ReadAll(io.LimitReader(resp2.Body, 128*1024))
		_ = resp2.Body.Close()
		return resp2.StatusCode, string(b), true
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	_ = resp.Body.Close()
	return resp.StatusCode, string(b), true
}
