package scanner

import (
	"net/http"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// defaultWappalyze is a package-level singleton loaded once at startup. It
// embeds Wappalyzer's fingerprint database so no external process or network
// call is needed. A nil value (set when New() fails) degrades gracefully to
// an empty TechStack.
var defaultWappalyze *wappalyzer.Wappalyze

func init() {
	w, err := wappalyzer.New()
	if err == nil {
		defaultWappalyze = w
	}
}

// TechStack holds the set of technology names detected from an HTTP response.
// Names are stored in lower-case so Has() lookups are case-insensitive.
// The zero value is a valid, empty TechStack (no detections).
type TechStack struct {
	techs map[string]struct{}
}

// Has reports whether tech (matched case-insensitively) was detected in the
// response. Typical labels match Wappalyzer's technology names lowercased,
// e.g. "mysql", "django", "angular", "ruby on rails", "asp.net".
func (ts TechStack) Has(tech string) bool {
	if ts.techs == nil {
		return false
	}
	_, ok := ts.techs[strings.ToLower(tech)]
	return ok
}

// Labels returns all detected technology labels (lower-case, arbitrary order).
func (ts TechStack) Labels() []string {
	out := make([]string, 0, len(ts.techs))
	for k := range ts.techs {
		out = append(out, k)
	}
	return out
}

// detectTechStack fingerprints the technology stack from the HTTP response
// headers and HTML body using the embedded Wappalyzer database. The result is
// used to prioritize probe payloads toward the most-likely engine family,
// reducing probe-budget waste on wrong-engine variants.
//
// Returns an empty TechStack when Wappalyzer failed to initialise (nil
// defaultWappalyze) or when no technologies are recognised — all callers
// handle both cases identically through TechStack.Has.
func detectTechStack(header http.Header, body []byte) TechStack {
	if defaultWappalyze == nil {
		return TechStack{}
	}
	// wappalyzergo.Fingerprint expects map[string][]string — the same
	// underlying type as http.Header — and returns a set of tech names
	// (keys of map[string]struct{}).
	raw := defaultWappalyze.Fingerprint(map[string][]string(header), body)
	if len(raw) == 0 {
		return TechStack{}
	}
	// Normalize all keys to lower-case so Has() is O(1) without any
	// case-folding on every call. Also store a version-stripped form so
	// Has("php") matches wappalyzergo's "PHP:8.2.0" output.
	normalized := make(map[string]struct{}, len(raw)*2)
	for k := range raw {
		lower := strings.ToLower(k)
		normalized[lower] = struct{}{}
		// Strip version qualifier (e.g. "php:8.2.0" → also store "php").
		if idx := strings.IndexByte(lower, ':'); idx > 0 {
			normalized[lower[:idx]] = struct{}{}
		}
	}
	return TechStack{techs: normalized}
}

// --- Tech-stack inference helpers used by the probes ---

// sqlDBFamily returns the primary relational database family inferred from the
// detected tech stack. Returns "" when no DB hint is found.
func sqlDBFamily(tech TechStack) string {
	switch {
	case tech.Has("mysql") || tech.Has("mariadb") || tech.Has("wordpress") || tech.Has("woocommerce"):
		return "mysql"
	case tech.Has("postgresql") || tech.Has("postgis") || tech.Has("django"):
		return "postgresql"
	case tech.Has("microsoft sql server") || tech.Has("mssql") || tech.Has("asp.net") || tech.Has("asp.net mvc"):
		return "mssql"
	case tech.Has("oracle database") || tech.Has("oracle"):
		return "oracle"
	case tech.Has("sqlite"):
		return "sqlite"
	default:
		return ""
	}
}

// sstiEngineFamily returns the most likely server-side template engine family
// inferred from the detected tech stack. Returns "" when no hint is found.
func sstiEngineFamily(tech TechStack) string {
	switch {
	// Python backends use Jinja2 (Flask) or Django's template engine
	// (which also accepts Jinja2 syntax with its "jinja2" backend).
	case tech.Has("python") || tech.Has("django") || tech.Has("flask"):
		return "jinja2/twig"
	// PHP ecosystems — Twig is the dominant PHP template engine and shares
	// Jinja2 syntax, so "jinja2/twig" covers both.
	case tech.Has("php") || tech.Has("twig") || tech.Has("symfony") || tech.Has("laravel"):
		return "jinja2/twig"
	// Ruby: ERB (Rails views) / EJS / ASP template share the <%= %> delimiter.
	case tech.Has("ruby") || tech.Has("ruby on rails"):
		return "erb/ejs/asp"
	// Java app servers: Spring SpEL / Velocity / JSP all use ${ }.
	case tech.Has("java") || tech.Has("spring") || tech.Has("spring boot") ||
		tech.Has("tomcat") || tech.Has("jsp") || tech.Has("struts"):
		return "jsp-el/spel"
	// ASP.NET Razor also uses @{ } / <%= %> syntax.
	case tech.Has("asp.net") || tech.Has("asp.net mvc"):
		return "erb/ejs/asp"
	// AngularJS sandbox-escape via {{ }} template expression.
	case tech.Has("angularjs") || tech.Has("angular"):
		return "angular"
	// Node.js runtimes: EJS (<%= %>) is common, Pug/Nunjucks use {{ }}.
	// Default to erb/ejs/asp since EJS is the most popular choice.
	case tech.Has("node.js") || tech.Has("express") || tech.Has("next.js"):
		return "erb/ejs/asp"
	default:
		return ""
	}
}
