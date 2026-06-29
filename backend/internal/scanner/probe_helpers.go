package scanner

import (
	"mime"
	"net/http"
	"regexp"
	"strings"
)

// dynamicTokenPatterns matches tokens that vary between requests and are
// not security-meaningful for differential comparison: UUIDs, Unix
// timestamps, CSRF nonces, and arbitrary session hex strings.
var dynamicTokenPatterns = []*regexp.Regexp{
	// UUID v1–v5
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	// Unix epoch seconds (10 digits) or milliseconds (13 digits)
	regexp.MustCompile(`\b(?:17\d{8}|1[5-9]\d{8}|\d{13})\b`),
	// Long hex strings ≥ 16 chars (CSRF tokens, session IDs, nonces)
	regexp.MustCompile(`[0-9a-fA-F]{16,}`),
	// Base64 strings ≥ 24 chars (JWTs, bearer tokens)
	regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`),
}

// NormalizeResponseBody replaces dynamic, per-request tokens (UUIDs,
// timestamps, CSRF nonces, session hex) with a stable placeholder so
// that two responses that differ only in ephemeral tokens are treated as
// structurally equivalent. This is used by probes that compare a baseline
// response with a probed response to avoid false-positive signals caused
// solely by token rotation.
func NormalizeResponseBody(body string) string {
	for _, pat := range dynamicTokenPatterns {
		body = pat.ReplaceAllString(body, "<token>")
	}
	return body
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func matchAnyLower(body string, signatures []string) string {
	lower := strings.ToLower(body)
	for _, signature := range signatures {
		sig := strings.ToLower(strings.TrimSpace(signature))
		if sig != "" && strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}

// isHTMLLikeContentType returns true when the Content-Type header signals
// that the response body is rendered as HTML in a browser. This is used by
// probes that only make sense for HTML responses — for example, clickjacking
// (framing only matters if the page renders as HTML) and reflected-XSS (a
// payload echoed into a JSON or plain-text body is not executable in an HTML
// context). When the Content-Type header is absent or empty the function
// returns true to preserve conservative behaviour for legacy endpoints that
// omit the header.
func isHTMLLikeContentType(h http.Header) bool {
	ct := strings.TrimSpace(h.Get("Content-Type"))
	if ct == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		// Unparseable content-type — treat as HTML to stay conservative.
		return true
	}
	mediaType = strings.ToLower(mediaType)
	switch mediaType {
	case "text/html", "application/xhtml+xml", "text/xhtml":
		return true
	default:
		return false
	}
}
