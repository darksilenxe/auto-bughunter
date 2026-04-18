package scanner

import (
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// buildCurlReproducer renders a single-line curl(1) invocation that mirrors
// what the scanner sent so a triager (or the program owner) can paste it
// straight into a terminal and reproduce a finding.
//
// The output deliberately omits cookies / Authorization headers so the
// reproducer does not leak per-engagement secrets if the report is shared.
// Where authentication is required, a redacted placeholder is included so
// the operator knows to fill it in manually.
//
// `method` is the HTTP verb. `targetURL` is the full request URL.
// `contentType` and `body` are optional; when present, the body is wrapped
// in `--data` and the Content-Type header is set explicitly.
func buildCurlReproducer(method, targetURL string, profile model.ScanAuthProfile, contentType, body string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	if strings.TrimSpace(targetURL) == "" {
		return ""
	}

	parts := []string{"curl", "-i", "-sS", "--max-redirs", "0", "-X", method}

	// Mirror non-secret headers verbatim so the request shape (e.g. a
	// custom User-Agent or `X-Requested-With`) is preserved. Secret-bearing
	// header names are replaced with a placeholder.
	if len(profile.Headers) > 0 {
		names := make([]string, 0, len(profile.Headers))
		for name := range profile.Headers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			value := profile.Headers[name]
			if isSensitiveHeaderName(name) {
				value = "<REDACTED>"
			}
			parts = append(parts, "-H", shellQuote(name+": "+value))
		}
	}
	if profile.UserAgent != "" {
		parts = append(parts, "-H", shellQuote("User-Agent: "+profile.UserAgent))
	}
	if profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "" {
		parts = append(parts, "-u", shellQuote(profile.BasicAuthUsername+":<REDACTED>"))
	}
	if len(profile.Cookies) > 0 {
		parts = append(parts, "-H", shellQuote("Cookie: <REDACTED-SESSION>"))
	}
	if contentType != "" {
		parts = append(parts, "-H", shellQuote("Content-Type: "+contentType))
	}
	if body != "" {
		parts = append(parts, "--data", shellQuote(body))
	}
	parts = append(parts, shellQuote(targetURL))
	return strings.Join(parts, " ")
}

// shellQuote single-quotes a value for safe inclusion on a POSIX shell
// command line. Embedded single quotes are escaped using the standard
// `'\''` trick.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// isSensitiveHeaderName returns true for header names that typically carry
// session/auth secrets and should never be inlined into a sharable
// reproducer.
func isSensitiveHeaderName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization",
		"cookie", "set-cookie",
		"x-api-key", "x-auth-token", "x-csrf-token",
		"x-access-token", "x-session-token":
		return true
	}
	return false
}

// withCurlReproducer mutates a finding to attach `curlReproducer` to its
// EvidenceFields and (when empty) to PoC, so downstream rendering layers
// (Markdown, HTML, PDF, bug-bounty submissions) can surface it without
// further plumbing.
//
// Used by probes that already populate AffectedURL but call buildCurlReproducer
// from the call site for richer body/content-type wrapping.
func withCurlReproducer(f model.Finding, curl string) model.Finding {
	if curl == "" {
		return f
	}
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	f.EvidenceFields["curlReproducer"] = curl
	if f.PoC == "" {
		f.PoC = curl
	}
	return f
}
