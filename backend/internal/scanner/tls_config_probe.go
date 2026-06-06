package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
)

// tlsConfigBodyLimit caps response body reads for the HTTP→HTTPS redirect check.
const tlsConfigBodyLimit = 16 * 1024

// weakTLSVersions are TLS version constants that are considered insecure.
// TLS 1.0 = 0x0301, TLS 1.1 = 0x0302.
const (
	tlsVersion10 = 0x0301
	tlsVersion11 = 0x0302
)

// weakCipherSuites is the set of IANA cipher suite IDs that are considered
// cryptographically weak. These include null ciphers, export-grade ciphers,
// RC4, DES/3DES, and anonymous DH suites.
var weakCipherSuiteIDs = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
}

// runTLSConfigProbe extends the existing inline checkTLS (which is called for
// basic connectivity + cert expiry) with additional WSTG-CRYP-01/03 checks:
//
//  1. HTTP→HTTPS redirect — verifies that plain HTTP connections are
//     redirected to HTTPS.
//  2. Weak TLS version — detects TLS 1.0/1.1 negotiation when the server
//     allows it (complementary to the TLS 1.2 minimum enforced by checkTLS).
//  3. Weak cipher suites — detects use of known-weak cipher IDs on the
//     negotiated connection.
//  4. Self-signed / untrusted certificate — detects certificate verification
//     failures that indicate a missing or invalid chain of trust.
//
// These checks are intentionally non-destructive: each uses a read-only TLS
// connection or a single GET request.
func (s *Service) runTLSConfigProbe(ctx context.Context, input RunInput) []model.Finding {
	u, err := url.Parse(input.Target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if err := safety.ValidateOutboundURL(input.Target); err != nil {
		return nil
	}

	var findings []model.Finding

	// ── 1. HTTP → HTTPS redirect check ────────────────────────────────────────
	if u.Scheme == "https" {
		httpURL := url.URL{Scheme: "http", Host: u.Host, Path: u.Path}
		f := s.checkHTTPSRedirect(ctx, input, httpURL.String(), input.Target)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	// ── 2 & 3. Weak TLS version / cipher probes ───────────────────────────────
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			return findings // no TLS checks for plain HTTP
		}
	}
	addr := net.JoinHostPort(host, port)

	findings = append(findings, checkWeakTLSVersions(addr, input.Target)...)
	findings = append(findings, checkWeakCiphers(addr, input.Target)...)
	findings = append(findings, checkUntrustedCert(addr, input.Target)...)

	return findings
}

// checkHTTPSRedirect verifies that a plain HTTP request to the target is
// redirected to HTTPS. If the server serves content over HTTP without
// redirecting, it returns a finding.
func (s *Service) checkHTTPSRedirect(ctx context.Context, input RunInput, httpURL, httpsURL string) *model.Finding {
	if err := safety.ValidateOutboundURL(httpURL); err != nil {
		return nil
	}

	noRedirect := *s.httpClient
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err != nil {
		return nil
	}
	ApplyAuthProfile(req, input.AuthProfile)

	resp, err := noRedirect.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, tlsConfigBodyLimit))

	return evaluateHTTPSRedirectResponse(httpURL, httpsURL, resp.StatusCode, resp.Header.Get("Location"))
}

// u_host extracts the host portion from a raw URL string (used only for
// human-readable strings in reproduction steps).
func u_host(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

// evaluateHTTPSRedirect inspects an HTTP response status and Location header and
// returns a finding when the server is NOT redirecting to HTTPS. It is extracted
// as a pure function so tests can exercise the detection logic without making
// real HTTP requests through safety-gated code paths.
func evaluateHTTPSRedirectResponse(httpURL, httpsURL string, statusCode int, location string) *model.Finding {
	if statusCode >= 300 && statusCode < 400 &&
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(location)), "https://") {
		return nil
	}
	return &model.Finding{
		ID:       "tls-no-https-redirect",
		Category: "tls",
		Severity: model.SeverityHigh,
		Title:    "Plain HTTP served without redirect to HTTPS",
		Description: fmt.Sprintf(
			"A plain HTTP request to %s returned HTTP %d without a redirect to HTTPS (%s). "+
				"Serving content over unencrypted HTTP allows network-level attackers to intercept "+
				"credentials, session tokens, and sensitive data, and to perform active man-in-the-middle attacks.",
			httpURL, statusCode, httpsURL,
		),
		Evidence: fmt.Sprintf(
			"GET %s → HTTP %d (Location: %q); expected 301/302/307/308 redirect to https://",
			httpURL, statusCode, location,
		),
		Recommendation: "Configure the server to return a permanent (301) redirect from HTTP to HTTPS for all requests. " +
			"Combine with HSTS to prevent initial plain-text connections. " +
			"Example nginx: 'return 301 https://$host$request_uri;'",
		Confidence:    0.95,
		AffectedURL:   httpURL,
		CWE:           "CWE-319",
		OWASPCategory: "A02:2021 - Cryptographic Failures",
		Sources:       []string{"active-scanner", "tls-config"},
		ReproductionSteps: []string{
			fmt.Sprintf("curl -I http://%s/", u_host(httpsURL)),
			"Observe that the response is not a redirect to https://.",
		},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"httpURL":        httpURL,
			"httpsURL":       httpsURL,
			"responseStatus": fmt.Sprintf("%d", statusCode),
		},
	}
}

// checkWeakTLSVersions dials the target with explicitly permissive TLS settings
// and checks whether TLS 1.0 or TLS 1.1 was negotiated.
func checkWeakTLSVersions(addr, target string) []model.Finding {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	for _, version := range []uint16{tlsVersion10, tlsVersion11} {
		cfg := &tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			InsecureSkipVerify: true, //nolint:gosec // intentional: we are probing for version support, not validating the cert
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
		if err != nil {
			continue
		}
		state := conn.ConnectionState()
		_ = conn.Close()

		if state.Version == version {
			label := "TLS 1.0"
			if version == tlsVersion11 {
				label = "TLS 1.1"
			}
			return []model.Finding{{
				ID:       fmt.Sprintf("tls-legacy-version-%x", version),
				Category: "tls",
				Severity: model.SeverityHigh,
				Title:    fmt.Sprintf("Deprecated %s protocol accepted", label),
				Description: fmt.Sprintf(
					"The server at %s accepted a TLS handshake using the deprecated %s protocol. "+
						"%s has known vulnerabilities (POODLE, BEAST) and is prohibited by PCI DSS 3.2+ and NIST SP 800-52r2. "+
						"Clients that negotiate %s are susceptible to protocol-downgrade attacks.",
					target, label, label, label,
				),
				Evidence:    fmt.Sprintf("TLS handshake to %s negotiated version 0x%04X (%s)", addr, version, label),
				Recommendation: "Disable TLS 1.0 and TLS 1.1 in your server configuration. " +
					"Enforce TLS 1.2 as minimum (TLS 1.3 as preferred). " +
					"OpenSSL: 'SSLProtocol TLSv1.2 TLSv1.3'. nginx: 'ssl_protocols TLSv1.2 TLSv1.3'.",
				Confidence:    0.95,
				AffectedURL:   target,
				CWE:           "CWE-326",
				OWASPCategory: "A02:2021 - Cryptographic Failures",
				Sources:       []string{"active-scanner", "tls-config"},
				ReproductionSteps: []string{
					fmt.Sprintf("openssl s_client -connect %s -%s", addr, strings.ToLower(strings.ReplaceAll(label, " ", ""))),
					"Observe that the handshake succeeds with the deprecated protocol.",
				},
				EvidenceFields: map[string]string{
					"validationType": "active-probe",
					"tlsVersion":     fmt.Sprintf("0x%04X", version),
					"label":          label,
				},
			}}
		}
	}
	return nil
}

// checkWeakCiphers dials the target with a permissive cipher list and reports
// if a known-weak cipher was selected.
func checkWeakCiphers(addr, target string) []model.Finding {
	weakIDs := make([]uint16, 0, len(weakCipherSuiteIDs))
	for id := range weakCipherSuiteIDs {
		weakIDs = append(weakIDs, id)
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	cfg := &tls.Config{
		CipherSuites:       weakIDs,
		InsecureSkipVerify: true, //nolint:gosec // intentional: probing cipher support only
		MinVersion:         tls.VersionTLS10,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return nil
	}
	state := conn.ConnectionState()
	_ = conn.Close()

	if name, weak := weakCipherSuiteIDs[state.CipherSuite]; weak {
		return []model.Finding{{
			ID:       fmt.Sprintf("tls-weak-cipher-%04x", state.CipherSuite),
			Category: "tls",
			Severity: model.SeverityHigh,
			Title:    fmt.Sprintf("Weak TLS cipher suite negotiated: %s", name),
			Description: fmt.Sprintf(
				"The server at %s negotiated the weak cipher suite %s (0x%04X). "+
					"This cipher suite uses an insecure algorithm (RC4, NULL, EXPORT-grade, DES/3DES, or anonymous DH) "+
					"that provides inadequate confidentiality or integrity, and is deprecated by IETF RFC 7465/8447.",
				target, name, state.CipherSuite,
			),
			Evidence: fmt.Sprintf(
				"TLS handshake to %s selected cipher 0x%04X (%s)",
				addr, state.CipherSuite, name,
			),
			Recommendation: "Configure the server to use only modern AEAD cipher suites " +
				"(AES-128/256-GCM, ChaCha20-Poly1305). Remove all RC4, NULL, EXPORT, DES, 3DES, and " +
				"anonymous DH suites from the server cipher list. " +
				"OpenSSL: 'SSLCipherSuite HIGH:!aNULL:!RC4:!DES:!3DES:!EXPORT'.",
			Confidence:    0.92,
			AffectedURL:   target,
			CWE:           "CWE-327",
			OWASPCategory: "A02:2021 - Cryptographic Failures",
			Sources:       []string{"active-scanner", "tls-config"},
			ReproductionSteps: []string{
				fmt.Sprintf("openssl s_client -connect %s -cipher %s", addr, name),
				"Confirm handshake succeeds with the weak cipher.",
			},
			EvidenceFields: map[string]string{
				"validationType": "active-probe",
				"cipherID":       fmt.Sprintf("0x%04X", state.CipherSuite),
				"cipherName":     name,
			},
		}}
	}
	return nil
}

// checkUntrustedCert dials with full certificate verification and reports a
// finding when the server presents an invalid, self-signed, or expired
// certificate that would not be trusted by a standard CA bundle.
func checkUntrustedCert(addr, target string) []model.Finding {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	_, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err == nil {
		return nil // cert is valid and trusted
	}

	// Only report certificate-specific errors, not network failures.
	if !isCertError(err) {
		return nil
	}

	return []model.Finding{{
		ID:       "tls-untrusted-certificate",
		Category: "tls",
		Severity: model.SeverityHigh,
		Title:    "TLS certificate not trusted by standard CA bundle",
		Description: fmt.Sprintf(
			"The TLS certificate presented by %s failed standard chain-of-trust validation. "+
				"Clients using browser default CA stores will display certificate warnings, and users may "+
				"be trained to click through them. Self-signed or improperly chained certificates also "+
				"enable man-in-the-middle attacks without triggering modern browser certificate pinning.",
			target,
		),
		Evidence:    fmt.Sprintf("TLS dial to %s failed certificate verification: %v", addr, err),
		Recommendation: "Obtain a certificate signed by a trusted CA (e.g. Let's Encrypt) and ensure " +
			"the complete chain (leaf + intermediates) is served. Verify with: " +
			"curl --cacert /etc/ssl/certs/ca-certificates.crt https://" + u_host(target) + "/",
		Confidence:    0.90,
		AffectedURL:   target,
		CWE:           "CWE-295",
		OWASPCategory: "A02:2021 - Cryptographic Failures",
		Sources:       []string{"active-scanner", "tls-config"},
		ReproductionSteps: []string{
			fmt.Sprintf("openssl s_client -connect %s -verify_return_error", addr),
			"Observe the certificate verification error.",
		},
		EvidenceFields: map[string]string{
			"validationType": "active-probe",
			"tlsError":       err.Error(),
		},
	}}
}

// isCertError reports whether the TLS error is certificate-related rather than
// a network connectivity failure.
func isCertError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "cert") ||
		strings.Contains(msg, "x509") ||
		strings.Contains(msg, "signed by unknown authority")
}
