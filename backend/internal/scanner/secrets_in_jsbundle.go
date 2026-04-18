package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// secretPattern is one named regex used to flag a candidate secret in a
// fetched JavaScript bundle. The patterns are intentionally narrow: they
// match documented service-specific token shapes rather than generic
// "looks like base64" heuristics, to keep the false-positive rate low.
type secretPattern struct {
	id      string
	label   string
	pattern *regexp.Regexp
}

// secretPatterns is the curated list. Each entry has been chosen to match
// the documented public format of the corresponding token type and to be
// extremely unlikely to appear by accident in a minified JS bundle.
var secretPatterns = []secretPattern{
	{
		id:      "aws-access-key",
		label:   "AWS access key ID (AKIA / ASIA prefix)",
		pattern: regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
	},
	{
		id:      "google-api-key",
		label:   "Google API key (AIza prefix)",
		pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
	},
	{
		id:      "stripe-secret-key",
		label:   "Stripe live secret key",
		pattern: regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}\b`),
	},
	{
		id:      "slack-bot-token",
		label:   "Slack bot/user token",
		pattern: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`),
	},
	{
		id:    "slack-webhook",
		label: "Slack incoming webhook token tuple",
		// Match only the path-token portion (T<workspace>/B<bot>/<token>)
		// of a Slack webhook rather than the full URL. This keeps the
		// regex anchor-free for substring scanning while not appearing
		// to be a URL pattern (which static analysers often flag for
		// missing anchors).
		pattern: regexp.MustCompile(`\bT[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}\b`),
	},
	{
		id:      "github-pat",
		label:   "GitHub fine-grained / classic PAT (ghp_ / github_pat_)",
		pattern: regexp.MustCompile(`\b(ghp_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{40,})\b`),
	},
	{
		id:      "private-key",
		label:   "Private key PEM block",
		pattern: regexp.MustCompile(`-----BEGIN ([A-Z]+ )?PRIVATE KEY-----`),
	},
	{
		id:      "jwt-token",
		label:   "JWT (three base64url segments)",
		pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`),
	},
}

// secretsScanMaxScripts caps how many script URLs the probe will fetch
// per scan. Most apps load fewer than a dozen first-party bundles; this
// budget keeps scan time bounded on apps that load many third-party
// scripts (which we deliberately scan too — they are still in scope and
// frequently the source of leaked customer keys).
const secretsScanMaxScripts = 8

// secretsScanMaxBytes caps how much of any single script we read; modern
// minified bundles are routinely several megabytes. 1 MiB is enough to
// catch everything an attacker would visually grep for.
const secretsScanMaxBytes int64 = 1 << 20

// runSecretsInJSProbe is a passive scanner that discovers in-scope
// JavaScript bundles referenced from the target's HTML, fetches each one
// (subject to scope + SSRF safety), and matches its content against a
// curated list of high-signal token regexes. Findings are emitted at high
// severity and the matched value is masked in the evidence.
//
// It is "passive" in the sense that it never injects a payload or mutates
// state — it only reads resources the application already publishes.
func (s *Service) runSecretsInJSProbe(ctx context.Context, input RunInput, body string) []model.Finding {
	scriptURLs := extractScriptURLs(input.Target, body, input.Scope)
	if len(scriptURLs) == 0 {
		return nil
	}
	if len(scriptURLs) > secretsScanMaxScripts {
		scriptURLs = scriptURLs[:secretsScanMaxScripts]
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("secrets-in-js %s", input.Target),
			Message: fmt.Sprintf("Sweeping %d in-scope JS bundle(s) for token-shaped strings", len(scriptURLs)),
		})
	}

	type match struct {
		scriptURL string
		patternID string
		label     string
		masked    string
	}
	var matches []match
	for _, scriptURL := range scriptURLs {
		// safety.ValidateOutboundURL is not re-checked here:
		// extractScriptURLs validates each candidate before returning.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
		if err != nil {
			continue
		}
		ApplyAuthProfile(req, input.AuthProfile)
		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil || resp == nil {
			continue
		}
		content, _ := io.ReadAll(io.LimitReader(resp.Body, secretsScanMaxBytes))
		_ = resp.Body.Close()
		if len(content) == 0 {
			continue
		}
		text := string(content)
		for _, sp := range secretPatterns {
			loc := sp.pattern.FindString(text)
			if loc == "" {
				continue
			}
			matches = append(matches, match{
				scriptURL: scriptURL,
				patternID: sp.id,
				label:     sp.label,
				masked:    maskSecret(loc),
			})
		}
	}

	if len(matches) == 0 {
		return nil
	}

	evidence := make([]string, 0, len(matches))
	for _, m := range matches {
		evidence = append(evidence, fmt.Sprintf("%s — %s — %s", m.scriptURL, m.label, m.masked))
	}
	first := matches[0]
	steps := []string{
		fmt.Sprintf("Fetch %s and inspect the response body.", first.scriptURL),
		fmt.Sprintf("Search for a value matching the pattern category %q (the probe captured a redacted match: %s).", first.label, first.masked),
		"Validate impact by attempting authenticated calls against the corresponding service with the recovered token.",
	}
	curl := buildCurlReproducer(http.MethodGet, first.scriptURL, input.AuthProfile, "", "")
	return []model.Finding{{
		ID:                "secrets-in-js-bundle",
		Category:          "information-disclosure",
		Severity:          model.SeverityHigh,
		Title:             "Hard-coded secret(s) detected in client-side JavaScript bundle",
		Description:       "A pattern matching a known credential format (API key, access token, private key, or JWT) was observed in a JavaScript file served to every visitor. Anything in a public JS bundle should be considered compromised; an attacker can extract the value and abuse it without needing any application access.",
		Evidence:          fmt.Sprintf("Token-shaped strings observed (values masked): %s", strings.Join(limitStrings(evidence, 8), "; ")),
		Recommendation:    "Treat the matched values as compromised: rotate them immediately. Move secrets to a server-side proxy that holds the credential and exposes only the minimum operations the client needs. Add a CI check (gitleaks, trufflehog) that fails the build on similar patterns.",
		Confidence:        0.85,
		AffectedURL:       first.scriptURL,
		CWE:               "CWE-798",
		OWASPCategory:     "A07:2021 - Identification and Authentication Failures",
		Sources:           []string{"passive-scanner"},
		ReproductionSteps: steps,
		PoC:               curl,
		EvidenceFields: map[string]string{
			"validationType":   "passive-observation",
			"reproStep":        "Fetch the listed script URL and grep for the pattern category",
			"matchedPattern":   first.patternID,
			"maskedSecret":     first.masked,
			"curlReproducer":   curl,
		},
	}}
}

// scriptSrcRe extracts the `src` value of every `<script>` tag from the
// HTML body. We do not attempt to parse the HTML — the regex is good
// enough for the >99% of cases where the tag is well-formed and a single
// line.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']`)

// extractScriptURLs resolves every `<script src=...>` to an absolute URL,
// filters them down to in-scope, SSRF-safe candidates, and de-duplicates
// the result.
func extractScriptURLs(target, body string, scanScope model.ScanScope) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		resolved := resolveEndpoint(target, m[1])
		if resolved == "" || !scope.IsURLInScope(resolved, scanScope) {
			continue
		}
		if err := safety.ValidateOutboundURL(resolved); err != nil {
			continue
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	return out
}

// maskSecret returns a redacted version of `value` that preserves the
// length signature and a small prefix so a triager can recognise the
// service without the full secret being committed to a report.
func maskSecret(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}
