// Package secureurl provides a startup-time guard that enforces HTTPS for
// env-configured outbound endpoints which should never be reached over
// cleartext (AI providers, sidecar services, optional integrations).
//
// Scope: this guard intentionally only inspects URLs that the operator
// configures via environment variables for *known third-party / internal*
// services. It does NOT touch:
//
//   - URLs of scan targets supplied at request time
//   - OAST callback payloads or scanner-issued probe URLs
//   - Anything constructed dynamically from user input
//
// Scanner-issued traffic is intentionally protocol-agnostic — the tool
// must be able to scan plain-HTTP targets.
package secureurl

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidationError describes a single env var whose URL was rejected.
type ValidationError struct {
	Name   string
	Value  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s=%q rejected: %s", e.Name, e.Value, e.Reason)
}

// Validate checks a single env-var URL. An empty value is allowed (means
// the integration is disabled).
//
// Rules when the value is non-empty:
//   - Must parse and have a scheme of http or https.
//   - https:// → always OK.
//   - http:// → allowed only for loopback (localhost, 127.0.0.0/8, ::1),
//     RFC1918 / link-local IPs, or single-label hostnames (no dots) which
//     we treat as docker-compose service names on a private network
//     (e.g. "ollama", "agents", "burp-enterprise").
//   - Public (multi-label) hostnames or public IPs over http:// →
//     rejected unless the caller passes allowInsecure=true (the operator
//     escape hatch `ALLOW_INSECURE_OUTBOUND_URLS=true`).
//   - Any other scheme (bolt://, ws://, etc.) is out of scope and ignored.
func Validate(name, raw string, allowInsecure bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return &ValidationError{Name: name, Value: raw, Reason: "not a valid URL: " + err.Error()}
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		if u.Hostname() == "" {
			return &ValidationError{Name: name, Value: raw, Reason: "URL has no host"}
		}
		return nil
	case "http":
		// fall through to host check
	case "":
		return &ValidationError{Name: name, Value: raw, Reason: "missing scheme (expected https://)"}
	default:
		// e.g. bolt://, ws://, file:// — out of scope for this guard.
		return nil
	}

	host := u.Hostname()
	if host == "" {
		return &ValidationError{Name: name, Value: raw, Reason: "URL has no host"}
	}
	if isPrivateHost(host) {
		return nil
	}
	if allowInsecure {
		return nil
	}
	return &ValidationError{
		Name:  name,
		Value: raw,
		Reason: "must use https:// for public hosts; set ALLOW_INSECURE_OUTBOUND_URLS=true to override " +
			"(only do this if the link is already encrypted by another means, e.g. a service mesh)",
	}
}

// ValidateMany validates a set of named URLs and returns the combined error
// (joined with errors.Join). Returns nil if all values pass.
func ValidateMany(entries map[string]string, allowInsecure bool) error {
	var errs []error
	for name, value := range entries {
		if err := Validate(name, value, allowInsecure); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// isPrivateHost reports whether the host is a loopback address, a private
// IP, or a single-label DNS name (i.e. a docker-compose service name on a
// private network).
func isPrivateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	// Treat any hostname without a dot as a docker-compose service name
	// (e.g. "ollama", "agents"). These are unreachable from outside the
	// compose network.
	return !strings.Contains(host, ".")
}
