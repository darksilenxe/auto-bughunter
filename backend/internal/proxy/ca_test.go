package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadOrGenerateCA_AutoGenerateCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	ca, err := LoadOrGenerateCA(CAOptions{
		CertFile:     certPath,
		KeyFile:      keyPath,
		AutoGenerate: true,
	})
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if ca == nil {
		t.Fatal("expected non-nil CA")
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert file not written: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not written: %v", err)
	}
	if !strings.HasPrefix(string(ca.CertificatePEM()), "-----BEGIN CERTIFICATE-----") {
		t.Error("CertificatePEM did not return PEM-encoded data")
	}
	if ca.Fingerprint() == "" {
		t.Error("Fingerprint must not be empty")
	}
	if ca.NotAfter().Before(time.Now()) {
		t.Error("CA expiry should be in the future")
	}
}

func TestLoadOrGenerateCA_NoAutoGenerateMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadOrGenerateCA(CAOptions{
		CertFile:     filepath.Join(dir, "missing.pem"),
		KeyFile:      filepath.Join(dir, "missing.key"),
		AutoGenerate: false,
	})
	if err == nil {
		t.Fatal("expected error when CA files missing and auto-generate disabled")
	}
}

func TestLoadOrGenerateCA_EmptyPathsReturnsNil(t *testing.T) {
	ca, err := LoadOrGenerateCA(CAOptions{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if ca != nil {
		t.Fatalf("expected nil CA when paths empty")
	}
}

func TestLoadOrGenerateCA_RoundTripFromDisk(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	first, err := LoadOrGenerateCA(CAOptions{CertFile: certPath, KeyFile: keyPath, AutoGenerate: true})
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := LoadOrGenerateCA(CAOptions{CertFile: certPath, KeyFile: keyPath, AutoGenerate: false})
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !bytes.Equal(first.CertificatePEM(), second.CertificatePEM()) {
		t.Error("CA cert should be byte-identical between loads")
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Error("fingerprint must be stable across loads")
	}
}

func TestCA_LeafCertificateChainsToCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(CAOptions{
		CertFile:     filepath.Join(dir, "ca.pem"),
		KeyFile:      filepath.Join(dir, "ca.key"),
		AutoGenerate: true,
	})
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	leaf, err := ca.LeafCertificate("example.com")
	if err != nil {
		t.Fatalf("LeafCertificate: %v", err)
	}
	tlsCert, ok := leaf.PrivateKey.(interface{ Public() any })
	if !ok || tlsCert == nil {
		// Just ensure the struct is well-formed for use as a tls.Certificate.
		_ = tls.Certificate(*leaf)
	}
	if len(leaf.Certificate) < 2 {
		t.Fatalf("expected leaf+CA in chain, got %d certs", len(leaf.Certificate))
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "example.com",
	}); err != nil {
		t.Errorf("leaf must verify against CA: %v", err)
	}
}

func TestCA_LeafCertificateCachesPerHost(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(CAOptions{
		CertFile:     filepath.Join(dir, "ca.pem"),
		KeyFile:      filepath.Join(dir, "ca.key"),
		AutoGenerate: true,
	})
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	a, _ := ca.LeafCertificate("example.com")
	b, _ := ca.LeafCertificate("example.com")
	if a != b {
		t.Error("repeated lookups should return cached *tls.Certificate")
	}
	c, _ := ca.LeafCertificate("other.example.com")
	if a == c {
		t.Error("different hosts must get different leaf certs")
	}
}

func TestCA_LeafCertificateForIPHostUsesIPSAN(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(CAOptions{
		CertFile:     filepath.Join(dir, "ca.pem"),
		KeyFile:      filepath.Join(dir, "ca.key"),
		AutoGenerate: true,
	})
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	leaf, err := ca.LeafCertificate("203.0.113.5")
	if err != nil {
		t.Fatalf("LeafCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cert.IPAddresses) == 0 {
		t.Fatal("expected IP SAN on leaf certificate for IP host")
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("did not expect DNS SAN for IP host, got %v", cert.DNSNames)
	}
}
