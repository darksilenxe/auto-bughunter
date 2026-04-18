package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// Secret scanner — passive detection of common high-entropy / well-known
// credential patterns in HTTP response bodies. Runs against the body that
// the scanner has already retrieved (so it adds zero outbound requests).
//
// The patterns intentionally mirror well-known signatures (AWS, GitHub,
// Slack, JWT, RSA/SSH private keys, generic API keys) — anything matched
// should be reviewed by a human; false positives are possible but the
// signatures are tight enough to keep noise low for passive scanning.
//
// All findings include the secret type and a redacted snippet rather than
// the full secret to avoid leaking material into logs/SARIF reports.

type secretPattern struct {
	id          string
	name        string
	severity    model.Severity
	re          *regexp.Regexp
	description string
}

// compiledSecretPatterns is built once at package init. The patterns are
// anchored on context (`AKIA…`, `ghp_…`, `xoxb-…`, etc.) to keep false
// positives manageable. Generic-key patterns require both a contextual
// keyword (api[_-]?key, secret, token, password) and a high-entropy value.
var compiledSecretPatterns = []secretPattern{
	{
		id:          "secret-aws-access-key",
		name:        "AWS access key",
		severity:    model.SeverityHigh,
		re:          regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		description: "Response body contains what appears to be an AWS access key ID.",
	},
	{
		id:          "secret-aws-secret-key",
		name:        "AWS secret access key",
		severity:    model.SeverityHigh,
		re:          regexp.MustCompile(`(?i)aws(.{0,20})?(secret|private)?(.{0,20})?key["'\s:=]+["']?([A-Za-z0-9/+=]{40})["']?`),
		description: "Response body contains a string that matches the format of an AWS secret access key.",
	},
	{
		id:          "secret-github-token",
		name:        "GitHub token",
		severity:    model.SeverityHigh,
		re:          regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`),
		description: "Response body contains a GitHub personal access, OAuth, user-to-server, server-to-server or refresh token.",
	},
	{
		id:          "secret-slack-token",
		name:        "Slack token",
		severity:    model.SeverityHigh,
		re:          regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`),
		description: "Response body contains a Slack API token.",
	},
	{
		id:          "secret-google-api-key",
		name:        "Google API key",
		severity:    model.SeverityMedium,
		re:          regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
		description: "Response body contains what appears to be a Google API key.",
	},
	{
		id:          "secret-stripe-key",
		name:        "Stripe key",
		severity:    model.SeverityHigh,
		re:          regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b`),
		description: "Response body contains a Stripe live or test secret/restricted key.",
	},
	{
		id:          "secret-private-key-block",
		name:        "PEM private key",
		severity:    model.SeverityHigh,
		re:          regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
		description: "Response body contains a PEM-encoded private key header.",
	},
	{
		id:          "secret-jwt",
		name:        "JSON Web Token",
		severity:    model.SeverityMedium,
		re:          regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`),
		description: "Response body contains a value that matches the JSON Web Token serialization format.",
	},
	{
		id:          "secret-generic-api-key",
		name:        "Generic API key/token",
		severity:    model.SeverityMedium,
		re:          regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)["'\s:=]+["']?([A-Za-z0-9_\-]{24,})["']?`),
		description: "Response body assigns a long opaque value to an api-key/secret-key/token style identifier.",
	},
}

// scanForSecrets returns one finding per matched secret type (deduplicated
// across the body). The caller is responsible for emitting the findings.
//
// The body is scanned as-is — callers should already have applied any
// reasonable size limits before passing it in to avoid runaway regex on
// pathologically large responses.
func scanForSecrets(target, body string) []model.Finding {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	findings := make([]model.Finding, 0, 2)
	seen := map[string]struct{}{}
	for _, p := range compiledSecretPatterns {
		matches := p.re.FindAllStringIndex(body, -1)
		if len(matches) == 0 {
			continue
		}
		if _, ok := seen[p.id]; ok {
			continue
		}
		seen[p.id] = struct{}{}
		// Render up to three redacted samples so reviewers have positional
		// context without us writing the secret material into reports.
		samples := make([]string, 0, 3)
		for i, m := range matches {
			if i >= 3 {
				break
			}
			samples = append(samples, redactedSnippet(body, m[0], m[1]))
		}
		findings = append(findings, model.Finding{
			ID:             p.id,
			Category:       "information-disclosure",
			Severity:       p.severity,
			Title:          "Possible secret in response body: " + p.name,
			Description:    p.description + " Manual confirmation is recommended; rotate the credential immediately if confirmed.",
			Evidence:       fmt.Sprintf("%d match(es) at %s; samples: %s", len(matches), target, strings.Join(samples, " | ")),
			Recommendation: "Remove the secret from the response, rotate the credential at the issuer, audit access logs and add a server-side response filter or build-time scan to prevent recurrence.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      "GET the listed URL and grep the response body for the redacted pattern",
				"secretType":     p.name,
				"matchCount":     fmt.Sprintf("%d", len(matches)),
			},
		})
	}
	return findings
}

// redactedSnippet returns a short window around the match with the matched
// substring itself replaced with "<redacted>" so we never echo the secret
// into reports. Surrounding context is kept (max 24 chars on each side) so
// reviewers can still locate the match in source by context.
func redactedSnippet(body string, start, end int) string {
	if start < 0 || end > len(body) || start >= end {
		return "<redacted>"
	}
	const window = 24
	leftStart := start - window
	if leftStart < 0 {
		leftStart = 0
	}
	rightEnd := end + window
	if rightEnd > len(body) {
		rightEnd = len(body)
	}
	left := strings.ReplaceAll(body[leftStart:start], "\n", " ")
	right := strings.ReplaceAll(body[end:rightEnd], "\n", " ")
	return strings.TrimSpace(left) + "<redacted>" + strings.TrimSpace(right)
}
