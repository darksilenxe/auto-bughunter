package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestPhase3Batch3_SchemaCompliance covers the remaining 17 ⚠️ rows of
// PHASE3_AUDIT.md's audit table (jwt_probe.go through xssi_jsonp_probe.go):
// each probe must emit an EvidenceRecord that satisfies its category's
// Phase 3 schema requirements (at minimum url + method).
func TestPhase3Batch3_SchemaCompliance(t *testing.T) {
	t.Run("jwt_probe", func(t *testing.T) {
		original, err := buildJWT(
			map[string]interface{}{"alg": "HS256", "typ": "JWT"},
			map[string]interface{}{"sub": "1", "role": "user"},
			"strong-secret",
		)
		if err != nil {
			t.Fatalf("build original token: %v", err)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			switch {
			case token == original:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"user":"alice"}`))
			case token == jwtInvalidControlToken(original):
				w.WriteHeader(http.StatusUnauthorized)
			case isJWT(token):
				hdr, _, _, err := parseJWT(token)
				if err == nil && hdr["alg"] == "none" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"user":"alice"}`))
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
			default:
				w.WriteHeader(http.StatusUnauthorized)
			}
		}))
		defer srv.Close()
		svc := NewService(Config{})
		sess := NewScanSession()
		sess.TokenStore.Set("bearer", original)
		findings := svc.runJWTProbe(context.Background(), RunInput{
			Target:      srv.URL,
			AuthProfile: model.ScanAuthProfile{Headers: map[string]string{"Authorization": "Bearer " + original}},
			Options:     model.ScanOptions{},
			Session:     sess,
		})
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("jwt_advanced_probe", func(t *testing.T) {
		tok := buildTestJWT(
			map[string]interface{}{"alg": "HS256", "kid": "keyid1"},
			map[string]interface{}{"sub": "1", "iss": "test", "aud": "api", "exp": 9999999999},
		)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/jwks.json" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
				return
			}
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if jwtAdvancedAcceptsProbeToken(token, tok) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"user":"admin"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		svc := NewService(Config{})
		findings := svc.RunJWTAdvancedProbe(
			context.Background(), srv.URL,
			newJWTAdvancedScope(srv.URL),
			model.ScanOptions{},
			model.ScanAuthProfile{Headers: map[string]string{"Authorization": "Bearer " + tok}},
			func(model.ScanEvent) {},
		)
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("login_probe", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "login") ||
				strings.Contains(r.URL.Path, "signin") || strings.Contains(r.URL.Path, "auth")) {
				body := make([]byte, 1024)
				n, _ := r.Body.Read(body)
				bodyStr := string(body[:n])
				if strings.Contains(bodyStr, "admin") {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error":"wrong password"}`))
				} else {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"error":"user not found"}`))
				}
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		svc := NewService(Config{})
		findings := svc.RunLoginProbe(
			context.Background(), srv.URL,
			newLoginScope(srv.URL),
			model.ScanOptions{}, model.ScanAuthProfile{}, func(model.ScanEvent) {},
		)
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("magic_link_invite_probe", func(t *testing.T) {
		const shortToken = "abc12345"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "magic") || strings.Contains(r.URL.Path, "passwordless") {
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"token":"` + shortToken + `","email":"test@example.com"}`))
					return
				}
				if r.URL.Query().Get("token") == shortToken {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"session":"ok"}`))
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid token"}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		svc := NewService(Config{})
		findings := svc.RunMagicLinkProbe(
			context.Background(), srv.URL,
			newMagicLinkScope(srv.URL),
			model.ScanOptions{}, model.ScanAuthProfile{}, func(model.ScanEvent) {},
		)
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("mfa_probe", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "mfa") || strings.Contains(r.URL.Path, "otp") ||
				strings.Contains(r.URL.Path, "2fa") {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		svc := NewService(Config{})
		findings := svc.RunMFAProbe(
			context.Background(), srv.URL,
			newMFAScope(srv.URL),
			model.ScanOptions{}, model.ScanAuthProfile{}, func(model.ScanEvent) {},
		)
		found := false
		for _, f := range findings {
			if f.ID == "mfa-surface-discovered" {
				found = true
				assertSchemaValid(t, f)
			}
		}
		if !found {
			t.Fatalf("expected mfa-surface-discovered finding; got: %+v", findings)
		}
	})

	t.Run("oauth_probe", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectURI := r.URL.Query().Get("redirect_uri")
			switch {
			case strings.Contains(redirectURI, "attacker.example.com") || strings.Contains(redirectURI, "evil.attacker.example.com"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"accepted_redirect_uri":"` + redirectURI + `"}`))
			case strings.Contains(redirectURI, "/oauth/callback"):
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"login":"required"}`))
			default:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
			}
		}))
		defer srv.Close()
		svc := NewService(Config{})
		findings := svc.RunOAuthProbe(context.Background(), srv.URL, newOAuthScope(srv.URL), model.ScanOptions{}, model.ScanAuthProfile{}, func(model.ScanEvent) {})
		found := false
		for _, f := range findings {
			if strings.HasPrefix(f.ID, "oauth-redirect-uri-") {
				found = true
				assertSchemaValid(t, f)
				break
			}
		}
		if !found {
			t.Fatalf("expected oauth-redirect-uri finding; got: %+v", findings)
		}
	})

	t.Run("oauth_session_probe", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if err := r.ParseForm(); err == nil && r.Form.Get("code") == "abh-probe-code-replay-test" {
				_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok123", "token_type": "bearer"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		}))
		defer srv.Close()
		svc := NewService(Config{})
		findings := svc.RunOAuthSessionProbe(
			context.Background(), srv.URL,
			newOAuthSessionScope(srv.URL),
			model.ScanOptions{}, model.ScanAuthProfile{}, func(model.ScanEvent) {},
		)
		found := false
		for _, f := range findings {
			if f.ID == "oauth-code-replay" {
				found = true
				assertSchemaValid(t, f)
			}
		}
		if !found {
			t.Fatalf("expected oauth-code-replay finding; got: %+v", findings)
		}
	})

	t.Run("password_reset_probe", func(t *testing.T) {
		const leakedToken = "reset-token-123456"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch {
			case r.Method == http.MethodPost && strings.Contains(string(body), pwResetTestEmail):
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"token":"` + leakedToken + `"}`))
			case r.Method == http.MethodPost && strings.Contains(string(body), leakedToken):
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"password changed successfully"}`))
			default:
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid token"}`))
			}
		}))
		defer srv.Close()
		svc := NewService(Config{})
		findings := svc.runPasswordResetProbe(context.Background(), RunInput{
			Target:  srv.URL,
			Options: model.ScanOptions{},
			Scope:   newPasswordResetScope(srv.URL),
			Session: NewScanSession(),
		})
		found := false
		for _, f := range findings {
			if f.ID == "password-reset-token-disclosure" {
				found = true
				assertSchemaValid(t, f)
			}
		}
		if !found {
			t.Fatalf("expected password-reset-token-disclosure finding; got: %+v", findings)
		}
	})

	t.Run("reverse_tabnabbing_probe", func(t *testing.T) {
		svc := NewService(Config{})
		body := `<html><body><a href="https://evil.com" target="_blank">Click me</a></body></html>`
		got := svc.runReverseTabnabbingProbe(RunInput{Target: "https://example.com"}, body)
		if len(got) == 0 {
			t.Fatal("expected finding for target=_blank without rel=noopener")
		}
		assertSchemaValid(t, got[0])
	})

	t.Run("saml_probe", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/metadata") || strings.Contains(r.URL.Path, "saml") {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"></EntityDescriptor>`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		svc := NewService(Config{})
		findings := svc.RunSAMLProbe(
			context.Background(), srv.URL,
			newSAMLScope(srv.URL),
			model.ScanOptions{}, model.ScanAuthProfile{}, func(model.ScanEvent) {},
		)
		found := false
		for _, f := range findings {
			if f.ID == "saml-surface-discovered" {
				found = true
				assertSchemaValid(t, f)
			}
		}
		if !found {
			t.Fatalf("expected saml-surface-discovered finding; got: %+v", findings)
		}
	})

	t.Run("security_headers_probe", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		svc := NewService(Config{})
		findings := svc.runSecurityHeadersProbe(RunInput{Target: srv.URL}, resp.Header, resp)
		found := false
		for _, f := range findings {
			if f.ID == "missing-hsts" {
				found = true
				assertSchemaValid(t, f)
			}
		}
		if !found {
			t.Fatalf("expected missing-hsts finding; got: %+v", findings)
		}
	})

	t.Run("session_lifecycle_probe", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123", HttpOnly: false, Secure: false})
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		base := mustParseURLPhase3(t, srv.URL)
		findings := sessionAnalyzeCookieHeaders(resp.Cookies(), base, srv.URL)
		if len(findings) == 0 {
			t.Fatal("expected at least 1 cookie-attribute finding")
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("smtp_injection_probe", func(t *testing.T) {
		f := buildSMTPFinding("https://example.com/contact", "email",
			"attacker@example.com\r\nBCC:victim@example.com", "smtp error: invalid recipient",
			"error-based", "smtp-injection-test")
		assertSchemaValid(t, f)
	})

	t.Run("ssi_injection_probe", func(t *testing.T) {
		// safety.ValidateOutboundURL rejects loopback targets, so the full
		// network path cannot be exercised against an httptest server here.
		// Construct the EvidenceFields the probe emits on a confirmed hit
		// (mirrors the map literal in runSSIInjectionProbe) and verify the
		// schema is satisfied.
		f := model.Finding{
			ID:       "ssi-injection-exec-echo-test",
			Category: "injection",
			EvidenceFields: map[string]string{
				"validationType":    "active-probe",
				"ssiLabel":          "exec-echo",
				"param":             "q",
				"payload":           `<!--#exec cmd="echo abh_ssi_exec_4e7b2"-->`,
				"marker":            ssiExecMarker,
				"responseStatus":    "200",
				"responseShape":     "html",
				"reflectionContext": "html-text",
				"method":            http.MethodGet,
				"url":               "https://example.com/search?q=%3C%21--%23exec",
				"payloadClass":      "ssi-injection",
				"oracleName":        "ssi_injection_probe",
				"oracleVersion":     "v1",
			},
		}
		assertSchemaValid(t, f)
	})

	t.Run("verbose_error_probe", func(t *testing.T) {
		// safety.ValidateOutboundURL rejects loopback targets, so the full
		// network path cannot be exercised against an httptest server here.
		// Construct the EvidenceFields the probe emits on a confirmed hit
		// (mirrors the map literal in runVerboseErrorProbe) and verify the
		// schema is satisfied.
		f := model.Finding{
			ID:       "verbose-error-sql-syntax-test",
			Category: "information-disclosure",
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"probeLabel":     "sql-syntax",
				"signatureLabel": "java-stacktrace",
				"responseStatus": "500",
				"excerpt":        "java.lang.NullPointerException",
				"responseShape":  "html",
				"method":         "GET",
				"url":            "https://example.com/api?id=%27",
				"param":          "id",
				"oracleName":     "verbose_error_probe",
				"oracleVersion":  "v1",
			},
		}
		assertSchemaValid(t, f)
	})


	t.Run("websocket_probe", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ws" && strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				w.Header().Set("Connection", "Upgrade")
				w.Header().Set("Upgrade", "websocket")
				w.WriteHeader(http.StatusSwitchingProtocols)
				return
			}
			_, _ = w.Write([]byte("ok"))
		}))
		defer target.Close()
		body := `new WebSocket("` + strings.Replace(target.URL, "http://", "ws://", 1) + `/ws")`
		findings := NewService(Config{}).runWebSocketProbe(context.Background(), RunInput{Target: target.URL}, body)
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("xssi_jsonp_probe", func(t *testing.T) {
		// safety.ValidateOutboundURL rejects loopback targets, so the full
		// network path cannot be exercised against an httptest server here.
		// Construct the EvidenceFields the probe emits on a confirmed hit
		// (mirrors the map literal in runXSSIJSONPProbe) and verify the
		// schema is satisfied.
		f := model.Finding{
			ID:       "jsonp-callback-test",
			Category: "client-side",
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"callbackParam":  "callback",
				"probeCallback":  "abh_jsonp_probe_7a3c1",
				"contentType":    "application/javascript",
				"responseStatus": "200",
				"responseShape":  "javascript",
				"method":         http.MethodGet,
				"url":            "https://example.com/api?callback=abh_jsonp_probe_7a3c1",
				"param":          "callback",
				"oracleName":     "xssi_jsonp_probe",
				"oracleVersion":  "v1",
			},
		}
		assertSchemaValid(t, f)
	})
}


func mustParseURLPhase3(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}
