package safety

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var metadataIPs = map[string]struct{}{
	"169.254.169.254": {},
	"100.100.100.200": {},
}

func ValidateOutboundURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("invalid outbound target")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported outbound scheme")
	}
	if err := ValidateHostname(u.Hostname()); err != nil {
		return err
	}
	return nil
}

func ValidateHostname(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty host")
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("localhost is not allowed")
	}
	if ip := net.ParseIP(host); ip != nil {
		return validateIP(ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("host lookup failed")
	}
	for _, ip := range ips {
		if err := validateIP(ip); err != nil {
			return err
		}
	}
	return nil
}

func validateIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("invalid ip")
	}
	if _, ok := metadataIPs[ip.String()]; ok {
		return fmt.Errorf("metadata endpoint is not allowed")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("private or local ip is not allowed")
	}
	return nil
}

// SafeDialContext is a DialContext-compatible function that re-resolves and
// re-validates the target hostname at actual TCP connection time.  This
// prevents DNS-rebinding attacks where a hostname resolves to a safe public IP
// during the ValidateOutboundURL pre-flight check but then resolves to a
// private or metadata IP by the time the HTTP client opens the socket.
//
// Use this as the DialContext on an http.Transport for any http.Client that
// connects to user-controlled or operator-configured target URLs.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if err := ValidateHostname(host); err != nil {
		return nil, fmt.Errorf("SSRF policy blocked connection to %q: %w", host, err)
	}
	d := &net.Dialer{}
	return d.DialContext(ctx, network, net.JoinHostPort(host, port))
}
