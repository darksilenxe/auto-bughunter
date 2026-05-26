// Package sidecartls provides a shared TLS configuration for the
// backend's HTTPS clients that talk to the auto-bughunter sidecar mesh
// (ml-service, agents, security-knowledge, nuclei-service, zap-service).
//
// In the docker-compose stack a one-shot `tls-init` container generates a
// self-signed certificate covering every sidecar service name and writes
// it to a shared volume. The backend mounts that volume read-only and
// trusts the cert as its CA bundle via the SIDECAR_CA_BUNDLE env var.
//
// When SIDECAR_CA_BUNDLE is unset or points at a missing/empty file (e.g.
// developers running the backend outside docker, or unit tests using
// httptest.NewServer), this package returns a nil transport so callers
// fall back to http.DefaultTransport — plain http:// keeps working.
package sidecartls

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

// CABundleEnv is the env var used to locate the sidecar CA bundle file.
// The file is a PEM cert (or chain) trusted as the root for verifying
// sidecar server certificates.
const CABundleEnv = "SIDECAR_CA_BUNDLE"

var (
	once         sync.Once
	cachedConfig *tls.Config
)

// TLSConfig returns the cached *tls.Config the backend should use when
// dialing sidecar HTTPS endpoints, or nil when no CA bundle is
// configured. The result is computed once per process; subsequent calls
// reuse the cached value.
//
// Callers should treat a nil return as "no sidecar TLS configured" and
// leave their http.Client.Transport at the zero value (which falls back
// to http.DefaultTransport).
func TLSConfig() *tls.Config {
	once.Do(loadConfig)
	return cachedConfig
}

// Transport returns an http.Transport pre-wired with the sidecar CA
// bundle, or nil when no bundle is configured. The transport is a clone
// of http.DefaultTransport with TLSClientConfig set, so it preserves
// stdlib timeouts/keepalives.
func Transport() *http.Transport {
	cfg := TLSConfig()
	if cfg == nil {
		return nil
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{TLSClientConfig: cfg}
	}
	tr := base.Clone()
	tr.TLSClientConfig = cfg
	return tr
}

// ConfigureClient installs the sidecar transport on c when a CA bundle
// is configured. No-op when c is nil or no bundle is available, so it is
// safe to call unconditionally from client constructors.
func ConfigureClient(c *http.Client) {
	if c == nil {
		return
	}
	if tr := Transport(); tr != nil {
		c.Transport = tr
	}
}

func loadConfig() {
	path := strings.TrimSpace(os.Getenv(CABundleEnv))
	if path == "" {
		return
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		// Missing file is not fatal: dev/test environments often run
		// the backend outside the compose stack. Log once and let
		// callers fall back to http.DefaultTransport.
		log.Printf("sidecartls: %s=%q unreadable (%v); sidecar HTTPS clients will use the default transport", CABundleEnv, path, err)
		return
	}
	if len(pem) == 0 {
		log.Printf("sidecartls: %s=%q is empty; sidecar HTTPS clients will use the default transport", CABundleEnv, path)
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Printf("sidecartls: %s=%q contained no usable PEM certificates; sidecar HTTPS clients will use the default transport", CABundleEnv, path)
		return
	}
	cachedConfig = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	log.Printf("sidecartls: loaded sidecar CA bundle from %s", path)
}

// resetForTest clears the cached config. Intended for tests only.
func resetForTest() {
	once = sync.Once{}
	cachedConfig = nil
}
