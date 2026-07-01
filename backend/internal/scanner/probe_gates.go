package scanner

import (
	"mime"
	"net/http"
	"strings"
)

// probe_gates provides content-type and response-shape gates that every
// active probe should consult before reporting a finding. Extending the
// existing isHTMLLikeContentType pattern, the gates encode:
//
//   - HTML-only probes (XSS, clickjacking, CSP, mixed content, dangling
//     markup) should bail out on JSON/binary responses.
//   - JSON-only probes (mass assignment, IDOR on APIs, prototype
//     pollution against JSON APIs) should bail out on HTML responses.
//   - XML-only probes (XXE, XPath) should require an XML content type.
//   - Every reflection probe should bail out on binary responses
//     (images, audio, video, PDFs, archives) where reflection is not
//     meaningful and pattern matching produces false positives.
//
// The helpers are pure functions on http.Header so they are trivial to
// unit-test and safe to call from any goroutine.

// ResponseShape classifies a response body's likely rendering context
// from its Content-Type header. Probes gate reporting on shape to
// prevent false positives where a payload is echoed into a body that
// does not execute or interpret it.
type ResponseShape int

const (
	// ShapeUnknown is returned when Content-Type is absent or
	// unparseable. Callers should treat this conservatively — for
	// HTML-oriented probes it means "probably HTML, keep probing"; for
	// strict shape gates it means "do not report".
	ShapeUnknown ResponseShape = iota
	// ShapeHTML covers text/html, application/xhtml+xml and text/xhtml.
	ShapeHTML
	// ShapeJSON covers application/json and any +json subtype.
	ShapeJSON
	// ShapeXML covers application/xml, text/xml and any +xml subtype
	// (excluding xhtml which classifies as HTML).
	ShapeXML
	// ShapeJavaScript covers application/javascript, text/javascript
	// and the ECMAScript variants.
	ShapeJavaScript
	// ShapeCSS covers text/css.
	ShapeCSS
	// ShapePlainText covers text/plain and other text/* not otherwise
	// classified.
	ShapePlainText
	// ShapeBinary covers image/*, audio/*, video/*, font/*,
	// application/octet-stream and common binary application types
	// (pdf, zip, tar, gzip, msword, protobuf, ...). Reflection probes
	// must not report against binary responses.
	ShapeBinary
	// ShapeOther is a text-adjacent media type we don't specifically
	// classify (e.g. application/x-www-form-urlencoded response bodies,
	// application/graphql). Callers should treat it as non-HTML,
	// non-binary.
	ShapeOther
)

// String returns a stable lowercase label suitable for evidence /
// metrics fields.
func (s ResponseShape) String() string {
	switch s {
	case ShapeHTML:
		return "html"
	case ShapeJSON:
		return "json"
	case ShapeXML:
		return "xml"
	case ShapeJavaScript:
		return "javascript"
	case ShapeCSS:
		return "css"
	case ShapePlainText:
		return "text"
	case ShapeBinary:
		return "binary"
	case ShapeOther:
		return "other"
	default:
		return "unknown"
	}
}

// binaryMediaExact lists application/* media types that are always
// treated as binary regardless of the +suffix rule.
var binaryMediaExact = map[string]struct{}{
	"application/octet-stream": {},
	"application/pdf":          {},
	"application/zip":          {},
	"application/x-tar":        {},
	"application/gzip":         {},
	"application/x-gzip":       {},
	"application/x-bzip2":      {},
	"application/x-7z-compressed": {},
	"application/x-rar-compressed": {},
	"application/msword":       {},
	"application/vnd.ms-excel": {},
	"application/vnd.ms-powerpoint": {},
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": {},
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":       {},
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": {},
	"application/x-protobuf":   {},
	"application/protobuf":     {},
	"application/wasm":         {},
	"application/x-shockwave-flash": {},
	"application/java-archive": {},
}

// ClassifyResponseShape inspects the Content-Type header and returns
// the ResponseShape. When Content-Type is missing the caller receives
// ShapeUnknown; probes that want the pre-existing conservative
// behaviour (treat missing as HTML) should call IsHTMLShape which
// preserves that legacy default.
func ClassifyResponseShape(h http.Header) ResponseShape {
	ct := strings.TrimSpace(h.Get("Content-Type"))
	if ct == "" {
		return ShapeUnknown
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ShapeUnknown
	}
	mediaType = strings.ToLower(mediaType)

	if _, ok := binaryMediaExact[mediaType]; ok {
		return ShapeBinary
	}
	switch {
	case mediaType == "text/html", mediaType == "application/xhtml+xml", mediaType == "text/xhtml":
		return ShapeHTML
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return ShapeJSON
	case mediaType == "application/xml", mediaType == "text/xml":
		return ShapeXML
	case strings.HasSuffix(mediaType, "+xml"):
		// +xml (SVG, Atom, RSS, XSLT, ...) — treat as XML for XXE
		// gating but note that SVG can also carry active content;
		// callers that need HTML-context gating should special-case.
		return ShapeXML
	case mediaType == "application/javascript",
		mediaType == "application/ecmascript",
		mediaType == "text/javascript",
		mediaType == "text/ecmascript":
		return ShapeJavaScript
	case mediaType == "text/css":
		return ShapeCSS
	case strings.HasPrefix(mediaType, "image/"),
		strings.HasPrefix(mediaType, "audio/"),
		strings.HasPrefix(mediaType, "video/"),
		strings.HasPrefix(mediaType, "font/"):
		return ShapeBinary
	case strings.HasPrefix(mediaType, "text/"):
		return ShapePlainText
	default:
		return ShapeOther
	}
}

// IsHTMLShape returns true when the response should be treated as HTML
// for gating purposes. Matches the legacy isHTMLLikeContentType
// behaviour: missing/unparseable Content-Type is conservatively treated
// as HTML so probes on legacy endpoints that omit the header still run.
func IsHTMLShape(h http.Header) bool {
	shape := ClassifyResponseShape(h)
	return shape == ShapeHTML || shape == ShapeUnknown
}

// IsJSONShape returns true only when the response is explicitly a JSON
// media type. Missing Content-Type returns false — JSON-only probes
// must have positive evidence of a JSON body before reporting.
func IsJSONShape(h http.Header) bool {
	return ClassifyResponseShape(h) == ShapeJSON
}

// IsXMLShape returns true only when the response is explicitly an XML
// media type (application/xml, text/xml, or any +xml suffix). Missing
// Content-Type returns false.
func IsXMLShape(h http.Header) bool {
	return ClassifyResponseShape(h) == ShapeXML
}

// IsBinaryShape returns true when the response is a binary media type
// where reflection / pattern-matching probes must not report. Missing
// Content-Type returns false — binary bail-out only triggers on
// positive evidence.
func IsBinaryShape(h http.Header) bool {
	return ClassifyResponseShape(h) == ShapeBinary
}

// IsReflectionSafeShape returns true when a reflection probe (XSS,
// SSRF echo, header injection, CRLF, open redirect) can meaningfully
// reason about the body. Binary responses always return false; every
// other shape (including Unknown, JSON, XML, JavaScript, CSS, HTML,
// plain text) returns true so probes retain conservative coverage.
func IsReflectionSafeShape(h http.Header) bool {
	return !IsBinaryShape(h)
}
