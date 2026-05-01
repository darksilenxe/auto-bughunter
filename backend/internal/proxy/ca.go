package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CA is a self-signed certificate authority used to mint per-host leaf
// certificates on the fly so the intercepting proxy can decrypt HTTPS
// CONNECT tunnels (Burp-style "MITM").
//
// Leaf certificates are cached in memory keyed by SNI/host so repeat
// connections to the same upstream are inexpensive.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *rsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// CAOptions configures CA bootstrap. CertFile/KeyFile point at PEM files on
// disk. If both are missing and AutoGenerate is true, a fresh CA is created
// and persisted at those paths.
type CAOptions struct {
	CertFile     string
	KeyFile      string
	AutoGenerate bool
	// CommonName overrides the CA certificate subject CN. Defaults to
	// "Auto BugHunter Proxy CA" when empty.
	CommonName string
	// ValidFor controls the CA validity window. Defaults to 5 years when
	// zero so air-gapped operators don't have to rotate frequently.
	ValidFor time.Duration
}

// LoadOrGenerateCA returns a usable CA, creating one on disk when both the
// cert and key files are missing and AutoGenerate is true. Returns nil when
// CertFile/KeyFile are empty, signalling MITM is disabled.
func LoadOrGenerateCA(opts CAOptions) (*CA, error) {
	certPath := strings.TrimSpace(opts.CertFile)
	keyPath := strings.TrimSpace(opts.KeyFile)
	if certPath == "" || keyPath == "" {
		return nil, nil
	}

	certBytes, certErr := os.ReadFile(certPath)
	keyBytes, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		return parseCA(certBytes, keyBytes)
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		if !opts.AutoGenerate {
			return nil, fmt.Errorf("proxy CA files missing and auto-generate disabled (%s, %s)", certPath, keyPath)
		}
	case certErr != nil:
		return nil, fmt.Errorf("read CA cert %s: %w", certPath, certErr)
	case keyErr != nil:
		return nil, fmt.Errorf("read CA key %s: %w", keyPath, keyErr)
	}

	ca, err := generateCA(opts)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return nil, fmt.Errorf("create CA cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, fmt.Errorf("create CA key dir: %w", err)
	}
	if err := os.WriteFile(certPath, ca.certPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA cert %s: %w", certPath, err)
	}
	keyPEM, err := encodePrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA key %s: %w", keyPath, err)
	}
	return ca, nil
}

func generateCA(opts CAOptions) (*CA, error) {
	cn := strings.TrimSpace(opts.CommonName)
	if cn == "" {
		cn = "Auto BugHunter Proxy CA"
	}
	validFor := opts.ValidFor
	if validFor <= 0 {
		validFor = 5 * 365 * 24 * time.Hour
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA private key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Auto BugHunter"}},
		NotBefore:             time.Now().Add(-1 * time.Hour).UTC(),
		NotAfter:              time.Now().Add(validFor).UTC(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &CA{
		cert:    cert,
		certPEM: pemBytes,
		key:     key,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func parseCA(certBytes, keyBytes []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA cert PEM block missing or wrong type")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("CA key PEM block missing")
	}
	var key *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		parsed, perr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("parse PKCS8 CA key: %w", perr)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA key must be RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported CA key PEM block type %q", keyBlock.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock.Bytes}),
		key:     key,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func encodePrivateKey(key any) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("marshal EC private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
}

// CertificatePEM returns the PEM-encoded CA certificate suitable for browser
// trust-store installation.
func (c *CA) CertificatePEM() []byte {
	if c == nil {
		return nil
	}
	out := make([]byte, len(c.certPEM))
	copy(out, c.certPEM)
	return out
}

// Fingerprint returns the SHA-256 fingerprint (hex) of the CA certificate
// for display in the UI so operators can verify the cert before trusting it.
func (c *CA) Fingerprint() string {
	if c == nil || c.cert == nil {
		return ""
	}
	sum := sha256.Sum256(c.cert.Raw)
	return strings.ToUpper(hexColons(sum[:]))
}

// NotAfter returns the CA expiry timestamp.
func (c *CA) NotAfter() time.Time {
	if c == nil || c.cert == nil {
		return time.Time{}
	}
	return c.cert.NotAfter
}

// LeafCertificate returns a TLS certificate for the requested host, signed by
// this CA and cached in memory. It is safe for concurrent use.
func (c *CA) LeafCertificate(host string) (*tls.Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("CA is nil")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}

	c.mu.Lock()
	if cached, ok := c.cache[host]; ok {
		c.mu.Unlock()
		return cached, nil
	}
	c.mu.Unlock()

	leaf, err := c.mintLeaf(host)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[host] = leaf
	c.mu.Unlock()
	return leaf, nil
}

func (c *CA) mintLeaf(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour).UTC(),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour).UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        mustParse(der),
	}, nil
}

func mustParse(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert
}

func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func hexColons(in []byte) string {
	const hexDigits = "0123456789abcdef"
	if len(in) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(in)*3-1)
	for i, b := range in {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(buf)
}
