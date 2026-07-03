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

	// Phase 2 reference wiring: merge miner-discovered parameter names in
	// front of the built-in LDAP wordlist (see PHASE2_AUDIT.md).
	probeParams := phase2ProbeParams(phase2DynamicParams(input.Session), ldapProbeParams)

	type hit struct {
		url          string
		param        string
		payload      string
		signature    string
		responseHdr  http.Header
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
		for _, param := range probeParams {
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
				// Phase 2 coverage accounting: record this probe key so the
				// surface-gap detector subtracts it from the inventory.
				RecordProbedKey(http.MethodGet, probeURL, param)
				if err != nil || resp == nil {
					continue
				}
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
				respHeader := resp.Header
				_ = resp.Body.Close()
				// Phase 1 shape gate: LDAP signatures echoed inside a
				// binary asset (image/PDF/etc.) are almost always coincidental
				// byte sequences, not attacker-controlled error surfaces.
				if IsBinaryShape(respHeader) {
					continue
				}
				if sig := matchAnyLower(string(respBody), ldapErrorSignatures); sig != "" || ldapLooksLikeBypass(baselineStatus, baselineLen, resp.StatusCode, len(respBody), string(respBody)) {
					if sig == "" {
						sig = "authentication bypass heuristic"
					}
					hits = append(hits, hit{url: probeURL, param: param, payload: payload, signature: sig, responseHdr: respHeader})
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

	// Phase 1 differential re-verify: fire the same request once with a
	// benign non-metacharacter value. If the LDAP signature still appears
	// (or the "bypass" heuristic still fires), the observation is baseline
	// noise — not a payload-specific injection signal. Suppresses the
	// class of false positive where the endpoint always emits an LDAP
	// error page regardless of input.
	execDifferential := func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
		u, perr := url.Parse(first.url)
		if perr != nil {
			return nil, nil, perr
		}
		q := u.Query()
		q.Set(first.param, altPayload)
		u.RawQuery = q.Encode()
		dreq, derr := http.NewRequestWithContext(dctx, http.MethodGet, u.String(), nil)
		if derr != nil {
			return nil, nil, derr
		}
		ApplyAuthProfile(dreq, input.AuthProfile)
		dresp, dcerr := s.doRequestWithRetry(dctx, dreq, input.Options)
		if dcerr != nil {
			return nil, nil, dcerr
		}
		body, _ := io.ReadAll(io.LimitReader(dresp.Body, 256*1024))
		return dresp, body, nil
	}
	lowerSig := strings.ToLower(first.signature)
	oracle := func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
		// Same signal-detection heuristic as the primary probe: an LDAP
		// error signature substring in the body counts as the oracle firing.
		return strings.Contains(strings.ToLower(string(body)), lowerSig) ||
			matchAnyLower(string(body), ldapErrorSignatures) != "", nil
	}
	diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
		ProbeName:       "active-ldap-injection",
		OriginalPayload: first.payload,
		SafePayload:     "",
		Exec:            execDifferential,
		Oracle:          oracle,
	})
	if diffOutcome.Ran && !diffOutcome.Confirmed {
		return nil
	}

	curl := buildCurlReproducer(http.MethodGet, first.url, input.AuthProfile, "", "")
	finding := model.Finding{
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
			"responseShape":  ClassifyResponseShape(first.responseHdr).String(),
		},
		BusinessTags: []string{"authentication", "directory-services"},
	}
	AttachDifferentialEvidence(&finding, diffOutcome)
	return []model.Finding{finding}
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
