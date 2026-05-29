package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ProxyConfig controls whether scanner-initiated HTTP traffic is routed
// through an upstream HTTP(S) proxy (the bundled MITM proxy on :PROXY_PORT,
// or an external one such as Burp/ZAP) instead of dialled directly.
//
// All fields are optional. The zero value disables proxying and matches the
// historical scanner behaviour.
type ProxyConfig struct {
	// Enabled is the master switch. When false, no upstream proxy is used
	// regardless of the other fields.
	Enabled bool
	// URL is the upstream proxy URL (e.g. http://127.0.0.1:8081). Required
	// when Enabled is true.
	URL string
	// CAFile is an optional path to a PEM-encoded CA certificate that the
	// scanner should trust when validating the proxy's TLS-intercepted
	// certificates. Mutually preferred over InsecureSkipVerify.
	CAFile string
	// InsecureSkipVerify disables TLS certificate verification for upstream
	// proxy interception. Use only for local development with a self-signed
	// CA that cannot be installed into the OS trust store.
	InsecureSkipVerify bool
}

// IsBundledLocal reports whether this configuration would route traffic
// through the bundled in-process intercepting proxy listening on the given
// port. Used to avoid double-capturing traffic via RecordingTransport.
func (c ProxyConfig) IsBundledLocal(bundledPort string) bool {
	if !c.Enabled || strings.TrimSpace(c.URL) == "" || strings.TrimSpace(bundledPort) == "" {
		return false
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		// Standard ports if not specified.
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	if port != strings.TrimSpace(bundledPort) {
		return false
	}
	switch host {
	case "localhost", "127.0.0.1", "::1", "backend":
		return true
	}
	return false
}

// buildTransport returns an http.RoundTripper configured according to cfg.
// When proxying is disabled or cfg.URL is empty, it returns a clone of
// http.DefaultTransport (so callers can safely mutate it without affecting
// global state).
//
// When proxying is enabled but cfg.URL is invalid, buildTransport returns
// an error so the caller can decide whether to log-and-fall-back or fail
// fast. The current callers (server bootstrap + per-scan override) log and
// fall back to direct connections.
func buildTransport(cfg ProxyConfig) (http.RoundTripper, error) {
	base := cloneDefaultTransport()
	if !cfg.Enabled {
		return base, nil
	}
	raw := strings.TrimSpace(cfg.URL)
	if raw == "" {
		return base, errors.New("scanner proxy enabled but URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
		return base, fmt.Errorf("invalid scanner proxy URL %q: %w", raw, err)
	}
	base.Proxy = http.ProxyURL(u)

	tlsCfg := base.TLSClientConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
	}
	if strings.TrimSpace(cfg.CAFile) != "" {
		pem, readErr := os.ReadFile(cfg.CAFile)
		if readErr != nil {
			return base, fmt.Errorf("read scanner proxy CA file %q: %w", cfg.CAFile, readErr)
		}
		pool := tlsCfg.RootCAs
		if pool == nil {
			if sys, sysErr := x509.SystemCertPool(); sysErr == nil && sys != nil {
				pool = sys
			} else {
				pool = x509.NewCertPool()
			}
		}
		if !pool.AppendCertsFromPEM(pem) {
			return base, fmt.Errorf("scanner proxy CA file %q contained no usable PEM certificates", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // opt-in via env for local MITM CA
	}
	base.TLSClientConfig = tlsCfg
	return base, nil
}

// cloneDefaultTransport returns a shallow copy of http.DefaultTransport with
// safe field-by-field re-initialisation so callers can mutate Proxy or
// TLSClientConfig without affecting the process-wide default.
func cloneDefaultTransport() *http.Transport {
	def, ok := http.DefaultTransport.(*http.Transport)
	if !ok || def == nil {
		return &http.Transport{}
	}
	t := def.Clone()
	// Clone() carries over DialContext/Proxy from the package default;
	// callers will replace Proxy explicitly when proxying is enabled.
	// Ensure idle-conn settings remain reasonable for the scanner workload.
	if t.IdleConnTimeout <= 0 {
		t.IdleConnTimeout = 90 * time.Second
	}
	return t
}
