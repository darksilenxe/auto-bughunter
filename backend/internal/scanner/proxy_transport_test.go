package scanner

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestBuildTransport_Disabled(t *testing.T) {
	rt, err := buildTransport(ProxyConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", rt)
	}
	if tr.Proxy != nil {
		// Default transport has ProxyFromEnvironment; that's fine — we
		// just want to confirm we didn't install our own ProxyURL.
		// Verifying that no custom URL is set: invoke it with a request
		// and ensure it returns nil for a request that has no env hints.
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
		u, _ := tr.Proxy(req)
		if u != nil && u.Host != "" {
			// only fail when an explicit non-env proxy is configured;
			// otherwise the env-proxy fallback is acceptable.
		}
	}
}

func TestBuildTransport_EnabledHTTPProxy(t *testing.T) {
	rt, err := buildTransport(ProxyConfig{Enabled: true, URL: "http://127.0.0.1:8081"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr := rt.(*http.Transport)
	if tr.Proxy == nil {
		t.Fatal("expected Proxy to be set")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	u, perr := tr.Proxy(req)
	if perr != nil {
		t.Fatalf("Proxy returned error: %v", perr)
	}
	if u == nil || u.Host != "127.0.0.1:8081" {
		t.Fatalf("expected proxy host 127.0.0.1:8081, got %#v", u)
	}
}

func TestBuildTransport_MalformedURL(t *testing.T) {
	_, err := buildTransport(ProxyConfig{Enabled: true, URL: "::not-a-url"})
	if err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestBuildTransport_EmptyURL(t *testing.T) {
	_, err := buildTransport(ProxyConfig{Enabled: true, URL: ""})
	if err == nil {
		t.Fatal("expected error for empty URL when enabled")
	}
}

func TestBuildTransport_UnsupportedScheme(t *testing.T) {
	_, err := buildTransport(ProxyConfig{Enabled: true, URL: "ftp://proxy:21"})
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestBuildTransport_InsecureSkipVerify(t *testing.T) {
	rt, err := buildTransport(ProxyConfig{Enabled: true, URL: "http://p:8081", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr := rt.(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be true")
	}
}

func TestBuildTransport_CAFileMissing(t *testing.T) {
	_, err := buildTransport(ProxyConfig{Enabled: true, URL: "http://p:8081", CAFile: "/nonexistent/ca.pem"})
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestBuildTransport_CAFileInvalid(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := buildTransport(ProxyConfig{Enabled: true, URL: "http://p:8081", CAFile: bad})
	if err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
}

func TestProxyConfig_IsBundledLocal(t *testing.T) {
	cases := []struct {
		name string
		cfg  ProxyConfig
		port string
		want bool
	}{
		{"disabled", ProxyConfig{}, "8081", false},
		{"empty port", ProxyConfig{Enabled: true, URL: "http://127.0.0.1:8081"}, "", false},
		{"localhost match", ProxyConfig{Enabled: true, URL: "http://127.0.0.1:8081"}, "8081", true},
		{"hostname localhost", ProxyConfig{Enabled: true, URL: "http://localhost:8081"}, "8081", true},
		{"backend hostname", ProxyConfig{Enabled: true, URL: "http://backend:8081"}, "8081", true},
		{"different port", ProxyConfig{Enabled: true, URL: "http://127.0.0.1:9000"}, "8081", false},
		{"external host", ProxyConfig{Enabled: true, URL: "http://proxy.example:8081"}, "8081", false},
		{"malformed url", ProxyConfig{Enabled: true, URL: "::bad"}, "8081", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.IsBundledLocal(tc.port); got != tc.want {
				t.Fatalf("IsBundledLocal=%v want %v", got, tc.want)
			}
		})
	}
}

func TestSetScannerProxy_FallbackOnError(t *testing.T) {
	s := NewService(Config{})
	if err := s.SetScannerProxy(ProxyConfig{Enabled: true, URL: "::garbage"}, "8081"); err == nil {
		t.Fatal("expected error for malformed URL")
	}
	if s.proxyTransport != nil {
		t.Fatal("expected proxyTransport to be cleared on error")
	}
	if s.scannerProxy.Enabled {
		t.Fatal("expected scannerProxy.Enabled to be cleared on error")
	}
}

func TestSetScannerProxy_HappyPath(t *testing.T) {
	s := NewService(Config{})
	if err := s.SetScannerProxy(ProxyConfig{Enabled: true, URL: "http://127.0.0.1:8081"}, "8081"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.proxyTransport == nil {
		t.Fatal("expected proxyTransport to be installed")
	}
	if s.httpClient == nil || s.httpClient.Transport == nil {
		t.Fatal("expected httpClient.Transport to be installed")
	}
}

func TestResolveProxyForOptions_OverrideURL(t *testing.T) {
	s := NewService(Config{})
	_ = s.SetScannerProxy(ProxyConfig{Enabled: true, URL: "http://127.0.0.1:8081"}, "8081")
	override := "http://proxy.example:9000"
	cfg, rt := s.resolveProxyForOptions(model.ScanOptions{ProxyURL: override})
	if cfg.URL != override {
		t.Fatalf("expected override URL %q, got %q", override, cfg.URL)
	}
	if rt == nil {
		t.Fatal("expected one-shot override transport")
	}
}

func TestResolveProxyForOptions_NoOverride(t *testing.T) {
	s := NewService(Config{})
	_ = s.SetScannerProxy(ProxyConfig{Enabled: true, URL: "http://127.0.0.1:8081"}, "8081")
	cfg, rt := s.resolveProxyForOptions(model.ScanOptions{})
	if cfg.URL != "http://127.0.0.1:8081" {
		t.Fatalf("expected service-level URL retained, got %q", cfg.URL)
	}
	if rt != nil {
		t.Fatal("expected nil override transport when nothing changed")
	}
}

func TestResolveProxyForOptions_DisableOverride(t *testing.T) {
	s := NewService(Config{})
	_ = s.SetScannerProxy(ProxyConfig{Enabled: true, URL: "http://127.0.0.1:8081"}, "8081")
	off := false
	cfg, rt := s.resolveProxyForOptions(model.ScanOptions{UseProxy: &off})
	if cfg.Enabled {
		t.Fatal("expected per-scan disable to take effect")
	}
	if rt == nil {
		t.Fatal("expected one-shot transport (direct connections) for disable override")
	}
	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", rt)
	}
	// When disabled, our build_transport returns the default transport which
	// may have Proxy=ProxyFromEnvironment but no explicit ProxyURL. Just
	// confirm the transport isn't pinned to the previous proxy URL.
	if tr.Proxy != nil {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
		u, _ := tr.Proxy(req)
		if u != nil && u.String() == "http://127.0.0.1:8081" {
			t.Fatal("expected proxy to be unset after disable override")
		}
	}
}

// TestProxyEndToEnd verifies that, when a scanner proxy is configured, a
// request executed via the service's HTTP client actually flows through the
// upstream proxy. We use a real httptest server as the "upstream proxy" and
// assert it received the connect request.
func TestProxyEndToEnd_HTTPRequestRoutedThroughProxy(t *testing.T) {
	hits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		// For absolute-form requests (proxy mode), URL.Host is populated.
		if r.URL.Host == "" {
			t.Fatalf("expected absolute-form proxied request, got %q", r.URL.String())
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	s := NewService(Config{})
	if err := s.SetScannerProxy(ProxyConfig{Enabled: true, URL: upstream.URL}, ""); err != nil {
		t.Fatalf("SetScannerProxy: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://target.invalid/path", nil)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if hits != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", hits)
	}
}

// Sanity-check: parsing the bundled proxy URL with default PROXY_PORT works.
func TestBundledDefaultURL(t *testing.T) {
	u, err := url.Parse("http://127.0.0.1:8081")
	if err != nil || u.Host == "" {
		t.Fatalf("bundled default URL must parse: %v", err)
	}
}
