package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

type Service struct {
	httpClient *http.Client
	cfg        Config
}

type Config struct {
	EnableNuclei      bool
	EnableZAPBaseline bool
	EnableSubfinder   bool
	EnableHttpx       bool
	EnableNaabu       bool
	EnableDnsx        bool
	EnableShuffleDNS  bool
	EnableCertTrans   bool
	EnableAmass       bool
	EnableKatana      bool
	EnableTlsx        bool
	EnableCdncheck    bool
	EnableAsnmap      bool
	EnableWPScan      bool
	EnableNikto       bool
	EnableSQLMap      bool
	EnableFFUF        bool
	EnableGobuster    bool
	AllowDestructive  bool
	NucleiBinary      string
	ZAPBaselineBinary string
	SubfinderBinary   string
	HttpxBinary       string
	NaabuBinary       string
	DnsxBinary        string
	ShuffleDNSBinary  string
	KatanaBinary      string
	TlsxBinary        string
	CdncheckBinary    string
	AsnmapBinary      string
	FFUFBinary        string
	GobusterBinary    string

	IntegrationTimeout time.Duration
}

type RunInput struct {
	Target      string
	AuthProfile model.ScanAuthProfile
	Options     model.ScanOptions
	Scope       model.ScanScope
}

func NewService(cfg Config) *Service {
	if cfg.IntegrationTimeout <= 0 {
		cfg.IntegrationTimeout = 90 * time.Second
	}
	if strings.TrimSpace(cfg.NucleiBinary) == "" {
		cfg.NucleiBinary = "nuclei"
	}
	if strings.TrimSpace(cfg.ZAPBaselineBinary) == "" {
		cfg.ZAPBaselineBinary = "zap-baseline.py"
	}
	if strings.TrimSpace(cfg.SubfinderBinary) == "" {
		cfg.SubfinderBinary = "subfinder"
	}
	if strings.TrimSpace(cfg.HttpxBinary) == "" {
		cfg.HttpxBinary = "httpx"
	}
	if strings.TrimSpace(cfg.NaabuBinary) == "" {
		cfg.NaabuBinary = "naabu"
	}
	if strings.TrimSpace(cfg.DnsxBinary) == "" {
		cfg.DnsxBinary = "dnsx"
	}
	if strings.TrimSpace(cfg.ShuffleDNSBinary) == "" {
		cfg.ShuffleDNSBinary = "shuffledns"
	}
	if strings.TrimSpace(cfg.KatanaBinary) == "" {
		cfg.KatanaBinary = "katana"
	}
	if strings.TrimSpace(cfg.TlsxBinary) == "" {
		cfg.TlsxBinary = "tlsx"
	}
	if strings.TrimSpace(cfg.CdncheckBinary) == "" {
		cfg.CdncheckBinary = "cdncheck"
	}
	if strings.TrimSpace(cfg.AsnmapBinary) == "" {
		cfg.AsnmapBinary = "asnmap"
	}
	if strings.TrimSpace(cfg.FFUFBinary) == "" {
		cfg.FFUFBinary = "ffuf"
	}
	if strings.TrimSpace(cfg.GobusterBinary) == "" {
		cfg.GobusterBinary = "gobuster"
	}

	return &Service{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cfg:        cfg,
	}
}

func (s *Service) Run(ctx context.Context, input RunInput) ([]model.Finding, error) {
	u, err := url.Parse(input.Target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme")
	}
	if !scope.IsURLInScope(input.Target, input.Scope) {
		return nil, fmt.Errorf("target is outside configured scan scope")
	}

	var findings []model.Finding

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, input.Target, nil)
	ApplyAuthProfile(req, input.AuthProfile)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	findings = append(findings, checkSecurityHeaders(resp.Header)...)
	findings = append(findings, checkCookies(resp)...)
	if u.Scheme == "https" {
		findings = append(findings, checkTLS(u.Host)...)
	}

	browserFindings, err := headlessChecks(ctx, input.Target, input.AuthProfile)
	if err != nil {
		findings = append(findings, model.Finding{
			ID:             "browser-error",
			Category:       "scanner",
			Severity:       model.SeverityLow,
			Title:          "Headless browser check failed",
			Description:    "The headless browser module could not complete on this target.",
			Evidence:       err.Error(),
			Recommendation: "Validate target accessibility and Chromium dependencies in the runner.",
		})
	} else {
		findings = append(findings, browserFindings...)
	}

	integrationFindings := s.runOptionalIntegrations(ctx, input)
	findings = append(findings, integrationFindings...)

	return findings, nil
}

func ApplyAuthProfile(req *http.Request, profile model.ScanAuthProfile) {
	if req == nil {
		return
	}
	for key, value := range profile.Headers {
		if strings.TrimSpace(key) != "" {
			req.Header.Set(key, value)
		}
	}
	if profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}
	if profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "" {
		req.SetBasicAuth(profile.BasicAuthUsername, profile.BasicAuthPassword)
	}
	if len(profile.Cookies) > 0 {
		names := make([]string, 0, len(profile.Cookies))
		for name := range profile.Cookies {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, name+"="+profile.Cookies[name])
		}
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
}

func checkSecurityHeaders(h http.Header) []model.Finding {
	required := map[string]string{
		"Content-Security-Policy": "Define a strict CSP to reduce script injection risk.",
		"X-Frame-Options":         "Set DENY or SAMEORIGIN to prevent clickjacking.",
		"X-Content-Type-Options":  "Set nosniff to prevent MIME sniffing.",
		"Referrer-Policy":         "Set a restrictive referrer policy.",
	}

	findings := make([]model.Finding, 0, len(required))
	for header, rec := range required {
		if strings.TrimSpace(h.Get(header)) == "" {
			findings = append(findings, model.Finding{
				ID:             "missing-header-" + strings.ToLower(strings.ReplaceAll(header, "-", "_")),
				Category:       "headers",
				Severity:       model.SeverityMedium,
				Title:          "Missing security header: " + header,
				Description:    "The response is missing a commonly recommended security header.",
				Evidence:       header + " not present",
				Recommendation: rec,
			})
		}
	}
	return findings
}

func checkCookies(resp *http.Response) []model.Finding {
	findings := []model.Finding{}
	for _, c := range resp.Cookies() {
		if !c.HttpOnly {
			findings = append(findings, model.Finding{
				ID:             "cookie-httponly-" + c.Name,
				Category:       "cookies",
				Severity:       model.SeverityMedium,
				Title:          "Cookie missing HttpOnly",
				Description:    "A cookie was observed without HttpOnly.",
				Evidence:       c.Name,
				Recommendation: "Set HttpOnly for session/auth cookies.",
			})
		}
		if !c.Secure && resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme == "https" {
			findings = append(findings, model.Finding{
				ID:             "cookie-secure-" + c.Name,
				Category:       "cookies",
				Severity:       model.SeverityMedium,
				Title:          "Cookie missing Secure",
				Description:    "A cookie was observed without Secure on an HTTPS target.",
				Evidence:       c.Name,
				Recommendation: "Set Secure for sensitive cookies.",
			})
		}
	}
	return findings
}

func checkTLS(host string) []model.Finding {
	findings := []model.Finding{}
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":443"
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12})
	if err != nil {
		findings = append(findings, model.Finding{
			ID:             "tls-connectivity",
			Category:       "tls",
			Severity:       model.SeverityMedium,
			Title:          "TLS handshake issue",
			Description:    "Could not complete TLS handshake with minimum TLS 1.2.",
			Evidence:       err.Error(),
			Recommendation: "Ensure valid certificates and modern TLS configuration.",
		})
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, model.Finding{
			ID:             "tls-legacy-version",
			Category:       "tls",
			Severity:       model.SeverityHigh,
			Title:          "Legacy TLS version negotiated",
			Description:    "The endpoint negotiated an outdated TLS version.",
			Evidence:       fmt.Sprintf("tlsVersion=%x", state.Version),
			Recommendation: "Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
		})
	}

	if len(state.PeerCertificates) > 0 {
		notAfter := state.PeerCertificates[0].NotAfter
		if time.Until(notAfter) < (14 * 24 * time.Hour) {
			findings = append(findings, model.Finding{
				ID:             "tls-cert-expiring",
				Category:       "tls",
				Severity:       model.SeverityLow,
				Title:          "Certificate expiring soon",
				Description:    "Leaf certificate is close to expiration.",
				Evidence:       notAfter.UTC().Format(time.RFC3339),
				Recommendation: "Rotate certificate before expiration to avoid outages.",
			})
		}
	}

	return findings
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
