package scanner

import (
	"regexp"
	"strings"
)

// ReflectionContext classifies where inside a response body a
// reflected payload landed. Reflection-based probes (XSS, header
// injection, open redirect, SSRF echo) must match the payload's break-
// out to the context before reporting: a `<script>` payload reflected
// inside an HTML text node is exploitable; the same payload reflected
// inside a JavaScript string literal without a `</script>` break-out
// is not.
//
// The classifier is deliberately conservative: it returns
// ContextUnknown when the surrounding bytes do not clearly place the
// marker inside a recognised syntactic context. Probes should treat
// ContextUnknown as "do not report" for High/Critical severity.
type ReflectionContext int

const (
	// ContextUnknown means the surrounding bytes did not match any
	// recognised context. Probes must not report High/Critical XSS-
	// style findings against this context.
	ContextUnknown ReflectionContext = iota
	// ContextHTMLText — reflection appears inside HTML text between
	// element tags. `<script>` and `<img onerror=...>` payloads are
	// executable when break-out is possible.
	ContextHTMLText
	// ContextHTMLAttrDouble — reflection is inside a `"..."` attribute
	// value. Break-out requires an un-encoded `"`.
	ContextHTMLAttrDouble
	// ContextHTMLAttrSingle — reflection is inside a `'...'` attribute
	// value. Break-out requires an un-encoded `'`.
	ContextHTMLAttrSingle
	// ContextHTMLAttrUnquoted — reflection is inside an unquoted attr
	// value. Break-out requires whitespace / `>` / `=`.
	ContextHTMLAttrUnquoted
	// ContextHTMLComment — reflection is inside `<!-- ... -->`.
	// Break-out requires `-->`.
	ContextHTMLComment
	// ContextJSString — reflection is inside a JavaScript string
	// literal (single or double quote). Break-out requires the same
	// quote un-escaped, or a `</script>` when inside an inline script.
	ContextJSString
	// ContextJSBlock — reflection is inside a `<script>...</script>`
	// block outside any string. Any JS expression executes.
	ContextJSBlock
	// ContextCSSValue — reflection is inside a CSS property value
	// (rare but exploitable via `expression()` on old IE and via
	// url()-based data exfil).
	ContextCSSValue
	// ContextURL — reflection is inside a URL context (href, src,
	// action). Break-out requires `javascript:` or protocol-relative
	// URL manipulation.
	ContextURL
	// ContextHeader — reflection is inside a response header value.
	// Break-out requires CR/LF.
	ContextHeader
)

// String returns a stable lowercase label suitable for evidence /
// metrics fields.
func (c ReflectionContext) String() string {
	switch c {
	case ContextHTMLText:
		return "html_text"
	case ContextHTMLAttrDouble:
		return "html_attr_double"
	case ContextHTMLAttrSingle:
		return "html_attr_single"
	case ContextHTMLAttrUnquoted:
		return "html_attr_unquoted"
	case ContextHTMLComment:
		return "html_comment"
	case ContextJSString:
		return "js_string"
	case ContextJSBlock:
		return "js_block"
	case ContextCSSValue:
		return "css_value"
	case ContextURL:
		return "url"
	case ContextHeader:
		return "header"
	default:
		return "unknown"
	}
}

// contextWindowChars is how many bytes on either side of the reflected
// marker the classifier inspects. 128 chars is enough to reliably see
// the containing tag and quote character without inspecting the whole
// body.
const contextWindowChars = 128

// ClassifyReflectionContext locates the first occurrence of marker in
// body and returns the syntactic context in which it appears. When
// marker is empty or not present, ContextUnknown is returned.
//
// The classifier is intentionally lightweight and heuristic — it does
// not parse the full HTML/JS grammar. It works by inspecting the
// preceding bytes for structural indicators. Callers that need higher
// fidelity (e.g. DOM XSS confirmation) should still run a headless
// browser oracle.
func ClassifyReflectionContext(body, marker string) ReflectionContext {
	if marker == "" || body == "" {
		return ContextUnknown
	}
	idx := strings.Index(body, marker)
	if idx < 0 {
		return ContextUnknown
	}
	start := idx - contextWindowChars
	if start < 0 {
		start = 0
	}
	end := idx + len(marker) + contextWindowChars
	if end > len(body) {
		end = len(body)
	}
	before := body[start:idx]
	after := body[idx+len(marker) : end]
	return classifyWindow(before, after)
}

// scriptOpenRE matches an unclosed <script ...> tag before the marker
// with no intervening </script>.
var scriptOpenRE = regexp.MustCompile(`(?is)<script\b[^>]*>`)
var scriptCloseRE = regexp.MustCompile(`(?is)</script\s*>`)
var styleOpenRE = regexp.MustCompile(`(?is)<style\b[^>]*>`)
var styleCloseRE = regexp.MustCompile(`(?is)</style\s*>`)
var htmlCommentOpenRE = regexp.MustCompile(`<!--`)
var htmlCommentCloseRE = regexp.MustCompile(`-->`)

// tagOpenRE matches the last unclosed `<tag ...` before the marker
// (i.e. the marker is inside a tag's attribute area, not in text).
var tagOpenRE = regexp.MustCompile(`<[a-zA-Z][^<>]*$`)

// urlAttrRE matches attributes whose values are URLs.
var urlAttrRE = regexp.MustCompile(`(?i)\b(?:href|src|action|formaction|xlink:href|data|poster|manifest|background|cite|codebase|longdesc|profile|usemap)\s*=\s*("|')?[^"'>]*$`)

// lastQuotedAttrRE finds the last unterminated quoted attribute value
// before the marker.
var lastDoubleQuotedRE = regexp.MustCompile(`="[^"]*$`)
var lastSingleQuotedRE = regexp.MustCompile(`='[^']*$`)
var lastUnquotedAttrRE = regexp.MustCompile(`=[^"'\s>]*$`)

func classifyWindow(before, after string) ReflectionContext {
	// 1. HTML comment context.
	if isInsideOpen(before, after, htmlCommentOpenRE, htmlCommentCloseRE) {
		return ContextHTMLComment
	}
	// 2. <script> block — need to distinguish JS-string vs JS-block.
	if isInsideOpen(before, after, scriptOpenRE, scriptCloseRE) {
		if quote, inside := insideJSString(before); inside {
			_ = quote
			return ContextJSString
		}
		return ContextJSBlock
	}
	// 3. <style> block.
	if isInsideOpen(before, after, styleOpenRE, styleCloseRE) {
		return ContextCSSValue
	}
	// 4. Inside a tag's attribute area?
	if tagOpenRE.MatchString(before) {
		// URL-bearing attribute?
		if urlAttrRE.MatchString(before) {
			return ContextURL
		}
		if lastDoubleQuotedRE.MatchString(before) {
			return ContextHTMLAttrDouble
		}
		if lastSingleQuotedRE.MatchString(before) {
			return ContextHTMLAttrSingle
		}
		if lastUnquotedAttrRE.MatchString(before) {
			return ContextHTMLAttrUnquoted
		}
		// Inside a tag but not obviously in an attribute value — treat
		// as unquoted attribute context so break-out still requires
		// whitespace / `>`.
		return ContextHTMLAttrUnquoted
	}
	// 5. Default: HTML text if there's any tag context earlier in the
	// window, otherwise Unknown.
	if strings.Contains(before, "<") || strings.Contains(after, ">") || strings.Contains(before, ">") {
		return ContextHTMLText
	}
	return ContextUnknown
}

// isInsideOpen returns true when `before` contains an open token with
// no matching close token, AND `after` contains a close token
// (confirming we are inside the pair).
func isInsideOpen(before, after string, open, close *regexp.Regexp) bool {
	openIdx := open.FindAllStringIndex(before, -1)
	if len(openIdx) == 0 {
		return false
	}
	lastOpen := openIdx[len(openIdx)-1][1]
	// Is there a close after the last open, inside `before`?
	if idx := close.FindStringIndex(before[lastOpen:]); idx != nil {
		return false
	}
	// Confirm a close appears somewhere in `after`.
	return close.MatchString(after)
}

// insideJSString scans `before` (which is inside a <script> block) and
// returns (quote, true) if the marker is inside a currently-open
// string literal.
func insideJSString(before string) (byte, bool) {
	inSingle, inDouble, inBacktick := false, false, false
	esc := false
	for i := 0; i < len(before); i++ {
		c := before[i]
		if esc {
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		switch {
		case c == '\'' && !inDouble && !inBacktick:
			inSingle = !inSingle
		case c == '"' && !inSingle && !inBacktick:
			inDouble = !inDouble
		case c == '`' && !inSingle && !inDouble:
			inBacktick = !inBacktick
		}
	}
	switch {
	case inSingle:
		return '\'', true
	case inDouble:
		return '"', true
	case inBacktick:
		return '`', true
	}
	return 0, false
}

// PayloadEscapesContext returns true when payload contains the syntax
// required to break out of ctx and reach an executable position. It is
// a heuristic filter probes call before reporting High/Critical XSS-
// style findings: a payload that does not contain the required break-
// out for its landing context cannot be exploited from that reflection.
//
// ContextUnknown always returns false — the caller has no evidence the
// payload landed anywhere useful.
func PayloadEscapesContext(ctx ReflectionContext, payload string) bool {
	if payload == "" {
		return false
	}
	switch ctx {
	case ContextHTMLText:
		return strings.Contains(payload, "<")
	case ContextHTMLAttrDouble:
		return strings.Contains(payload, `"`)
	case ContextHTMLAttrSingle:
		return strings.Contains(payload, `'`)
	case ContextHTMLAttrUnquoted:
		return strings.ContainsAny(payload, " \t\n\r>=")
	case ContextHTMLComment:
		return strings.Contains(payload, "-->")
	case ContextJSString:
		// Any un-escaped quote, or a </script> which closes the block
		// unconditionally.
		return strings.ContainsAny(payload, `"'`+"`") || strings.Contains(strings.ToLower(payload), "</script")
	case ContextJSBlock:
		// Already in an executable position — any non-empty payload
		// is a candidate; require at least one JS-syntax character to
		// avoid trivially-safe reflections like whitespace.
		return strings.ContainsAny(payload, "();=+-*/[]{}.,!<>|&^~?:")
	case ContextCSSValue:
		return strings.ContainsAny(payload, "(){};:")
	case ContextURL:
		lower := strings.ToLower(strings.TrimSpace(payload))
		return strings.HasPrefix(lower, "javascript:") ||
			strings.HasPrefix(lower, "data:") ||
			strings.HasPrefix(lower, "vbscript:") ||
			strings.HasPrefix(lower, "//")
	case ContextHeader:
		return strings.ContainsAny(payload, "\r\n")
	}
	return false
}
