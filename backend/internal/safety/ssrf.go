package safety

import (
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
