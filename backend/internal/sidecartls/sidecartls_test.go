package sidecartls

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const samplePEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dy7WTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----
`

func TestTLSConfigUnsetEnvReturnsNil(t *testing.T) {
	t.Setenv(CABundleEnv, "")
	resetForTest()
	if got := TLSConfig(); got != nil {
		t.Fatalf("TLSConfig() = %v, want nil when env unset", got)
	}
	if got := Transport(); got != nil {
		t.Fatalf("Transport() = %v, want nil when env unset", got)
	}
	c := &http.Client{}
	ConfigureClient(c)
	if c.Transport != nil {
		t.Fatalf("ConfigureClient set Transport=%v, want nil when env unset", c.Transport)
	}
}

func TestTLSConfigMissingFileReturnsNil(t *testing.T) {
	t.Setenv(CABundleEnv, filepath.Join(t.TempDir(), "does-not-exist.crt"))
	resetForTest()
	if got := TLSConfig(); got != nil {
		t.Fatalf("TLSConfig() = %v, want nil for missing file", got)
	}
}

func TestTLSConfigEmptyFileReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.crt")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CABundleEnv, path)
	resetForTest()
	if got := TLSConfig(); got != nil {
		t.Fatalf("TLSConfig() = %v, want nil for empty file", got)
	}
}

func TestTLSConfigInvalidPEMReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.crt")
	if err := os.WriteFile(path, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CABundleEnv, path)
	resetForTest()
	if got := TLSConfig(); got != nil {
		t.Fatalf("TLSConfig() = %v, want nil for invalid PEM", got)
	}
}

func TestTLSConfigValidPEMLoadsRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, []byte(samplePEM), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CABundleEnv, path)
	resetForTest()
	cfg := TLSConfig()
	if cfg == nil {
		t.Fatal("TLSConfig() = nil, want non-nil for valid PEM")
	}
	if cfg.RootCAs == nil {
		t.Fatal("TLSConfig().RootCAs = nil, want pool populated from bundle")
	}
	if cfg.MinVersion < 0x0303 { // TLS 1.2
		t.Fatalf("TLSConfig().MinVersion = %#x, want >= TLS 1.2", cfg.MinVersion)
	}
	tr := Transport()
	if tr == nil {
		t.Fatal("Transport() = nil, want non-nil")
	}
	if tr.TLSClientConfig != cfg {
		t.Fatal("Transport().TLSClientConfig should match TLSConfig()")
	}
	c := &http.Client{}
	ConfigureClient(c)
	if c.Transport == nil {
		t.Fatal("ConfigureClient did not install transport")
	}
}

func TestConfigureClientNilSafe(t *testing.T) {
	resetForTest()
	ConfigureClient(nil) // must not panic
}
