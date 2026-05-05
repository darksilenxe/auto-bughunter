package scanner

import (
	"net/http"
	"strings"
	"testing"
)

// TestTechStack_Has verifies case-insensitive lookup on a populated TechStack.
func TestTechStack_Has(t *testing.T) {
	ts := TechStack{techs: map[string]struct{}{
		"mysql":   {},
		"php":     {},
		"angular": {},
	}}

	for _, tech := range []string{"mysql", "MySQL", "MYSQL", "php", "PHP", "angular", "Angular"} {
		if !ts.Has(tech) {
			t.Errorf("Has(%q) = false, want true", tech)
		}
	}
	for _, tech := range []string{"postgresql", "django", "react", ""} {
		if ts.Has(tech) {
			t.Errorf("Has(%q) = true, want false", tech)
		}
	}
}

// TestTechStack_Has_ZeroValue confirms that Has returns false on a zero-value
// TechStack (nil map) and does not panic.
func TestTechStack_Has_ZeroValue(t *testing.T) {
	var ts TechStack
	if ts.Has("mysql") {
		t.Error("zero-value TechStack.Has must return false")
	}
}

// TestDetectTechStack_Headers checks that common HTTP headers produce the
// expected technology labels.
func TestDetectTechStack_Headers(t *testing.T) {
	if defaultWappalyze == nil {
		t.Skip("wappalyzergo not initialised — skipping header detection tests")
	}

	cases := []struct {
		name    string
		headers map[string]string
		body    string
		wantAny []string // at least one of these labels must be detected
	}{
		{
			name:    "PHP via X-Powered-By",
			headers: map[string]string{"X-Powered-By": "PHP/8.2.0"},
			wantAny: []string{"php"},
		},
		{
			name:    "ASP.NET via X-Powered-By",
			headers: map[string]string{"X-Powered-By": "ASP.NET"},
			wantAny: []string{"asp.net", "iis", "microsoft asp.net"},
		},
		{
			name:    "WordPress via meta generator",
			body:    `<meta name="generator" content="WordPress 6.4.3">`,
			wantAny: []string{"wordpress", "php"},
		},
		{
			name:    "Django CSRF token",
			body:    `<input type="hidden" name="csrfmiddlewaretoken" value="abc123">`,
			wantAny: []string{"django", "python"},
		},
		{
			name:    "Angular via ng-app attribute",
			body:    `<div ng-app="myApp"></div>`,
			wantAny: []string{"angularjs", "angular"},
		},
		{
			name:    "React/Next.js via X-Powered-By header",
			headers: map[string]string{"X-Powered-By": "Next.js"},
			wantAny: []string{"react", "next.js", "node.js"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := make(http.Header)
			for k, v := range tc.headers {
				h.Set(k, v)
			}
			ts := detectTechStack(h, []byte(tc.body))
			found := false
			for _, want := range tc.wantAny {
				if ts.Has(want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("detectTechStack did not detect any of %v; got labels: %v",
					tc.wantAny, ts.Labels())
			}
		})
	}
}

// TestSQLDBFamily verifies that the DB-family inference helper maps common
// tech labels to the expected DB family string.
func TestSQLDBFamily(t *testing.T) {
	cases := []struct {
		techs  map[string]struct{}
		family string
	}{
		{map[string]struct{}{"wordpress": {}}, "mysql"},
		{map[string]struct{}{"mysql": {}}, "mysql"},
		{map[string]struct{}{"django": {}}, "postgresql"},
		{map[string]struct{}{"postgresql": {}}, "postgresql"},
		{map[string]struct{}{"asp.net": {}}, "mssql"},
		{map[string]struct{}{"oracle database": {}}, "oracle"},
		{map[string]struct{}{"sqlite": {}}, "sqlite"},
		{map[string]struct{}{"nginx": {}}, ""},
	}
	for _, tc := range cases {
		got := sqlDBFamily(TechStack{techs: tc.techs})
		if got != tc.family {
			t.Errorf("sqlDBFamily(%v) = %q, want %q", tc.techs, got, tc.family)
		}
	}
}

// TestSSTIEngineFamily verifies that the SSTI engine-family inference maps
// expected tech labels correctly.
func TestSSTIEngineFamily(t *testing.T) {
	cases := []struct {
		techs  map[string]struct{}
		family string
	}{
		{map[string]struct{}{"django": {}}, "jinja2/twig"},
		{map[string]struct{}{"python": {}}, "jinja2/twig"},
		{map[string]struct{}{"php": {}}, "jinja2/twig"},
		{map[string]struct{}{"twig": {}}, "jinja2/twig"},
		{map[string]struct{}{"ruby on rails": {}}, "erb/ejs/asp"},
		{map[string]struct{}{"ruby": {}}, "erb/ejs/asp"},
		{map[string]struct{}{"java": {}}, "jsp-el/spel"},
		{map[string]struct{}{"spring": {}}, "jsp-el/spel"},
		{map[string]struct{}{"tomcat": {}}, "jsp-el/spel"},
		{map[string]struct{}{"asp.net": {}}, "erb/ejs/asp"},
		{map[string]struct{}{"angularjs": {}}, "angular"},
		{map[string]struct{}{"node.js": {}}, "erb/ejs/asp"},
		{map[string]struct{}{"nginx": {}}, ""},
	}
	for _, tc := range cases {
		got := sstiEngineFamily(TechStack{techs: tc.techs})
		if got != tc.family {
			t.Errorf("sstiEngineFamily(%v) = %q, want %q", tc.techs, got, tc.family)
		}
	}
}

// TestTechPrioritizedSSTIPayloads verifies that the correct engine family is
// moved to the front and all canonical payloads are preserved.
func TestTechPrioritizedSSTIPayloads(t *testing.T) {
	djangoStack := TechStack{techs: map[string]struct{}{"django": {}}}
	payloads := techPrioritizedSSTIPayloads(djangoStack)

	if len(payloads) != len(sstiPayloads) {
		t.Fatalf("expected %d payloads, got %d", len(sstiPayloads), len(payloads))
	}
	if payloads[0].engine != "jinja2/twig" {
		t.Errorf("first payload engine = %q, want %q", payloads[0].engine, "jinja2/twig")
	}

	// Verify all canonical payloads are present.
	present := make(map[string]bool)
	for _, p := range payloads {
		present[p.payload] = true
	}
	for _, cp := range sstiPayloads {
		if !present[cp.payload] {
			t.Errorf("canonical payload %q missing from tech-prioritized list", cp.payload)
		}
	}

	// With Java stack, SpEL should come first.
	javaStack := TechStack{techs: map[string]struct{}{"spring": {}}}
	javaPayloads := techPrioritizedSSTIPayloads(javaStack)
	if javaPayloads[0].engine != "jsp-el/spel" {
		t.Errorf("Java stack: first payload engine = %q, want %q", javaPayloads[0].engine, "jsp-el/spel")
	}

	// Unknown stack: order must match canonical order.
	emptyStack := TechStack{}
	emptyPayloads := techPrioritizedSSTIPayloads(emptyStack)
	for i, p := range emptyPayloads {
		if p.payload != sstiPayloads[i].payload {
			t.Errorf("empty stack: payload[%d] = %q, want canonical %q", i, p.payload, sstiPayloads[i].payload)
		}
	}
}

// TestTechPrioritizedSQLiSignatures verifies that the correct DB family's
// signatures appear first and all signatures are preserved.
func TestTechPrioritizedSQLiSignatures(t *testing.T) {
	wpStack := TechStack{techs: map[string]struct{}{"wordpress": {}}}
	sigs := techPrioritizedSQLiSignatures(wpStack)

	if len(sigs) != len(sqlErrorSignatures) {
		t.Fatalf("expected %d signatures, got %d", len(sqlErrorSignatures), len(sigs))
	}
	// MySQL signature must be first.
	if !strings.Contains(sigs[0], "mysql") && sigs[0] != "you have an error in your sql syntax" {
		t.Errorf("WordPress stack: first signature = %q, expected a MySQL signature", sigs[0])
	}

	// All original signatures must still be present.
	present := make(map[string]bool)
	for _, s := range sigs {
		present[s] = true
	}
	for _, orig := range sqlErrorSignatures {
		if !present[orig] {
			t.Errorf("signature %q missing from tech-prioritized list", orig)
		}
	}

	// Empty stack: must return the original slice unchanged.
	emptySigs := techPrioritizedSQLiSignatures(TechStack{})
	for i, s := range emptySigs {
		if s != sqlErrorSignatures[i] {
			t.Errorf("empty stack: sig[%d] = %q, want %q", i, s, sqlErrorSignatures[i])
		}
	}
}

// TestTechAwareXSSProbeParams verifies that framework-specific params are
// moved to the front and all params are preserved.
func TestTechAwareXSSProbeParams(t *testing.T) {
	wpStack := TechStack{techs: map[string]struct{}{"wordpress": {}}}
	params := techAwareXSSProbeParams(wpStack)

	if len(params) != len(xssProbeParams) {
		t.Fatalf("WordPress stack: expected %d params, got %d", len(xssProbeParams), len(params))
	}
	// "s" should come first for WordPress.
	if params[0] != "s" {
		t.Errorf("WordPress stack: first param = %q, want %q", params[0], "s")
	}

	// All original params must be present.
	present := make(map[string]bool)
	for _, p := range params {
		present[p] = true
	}
	for _, orig := range xssProbeParams {
		if !present[orig] {
			t.Errorf("param %q missing from tech-aware list", orig)
		}
	}

	// No-tech stack: must return the canonical slice unchanged.
	emptyParams := techAwareXSSProbeParams(TechStack{})
	for i, p := range emptyParams {
		if p != xssProbeParams[i] {
			t.Errorf("empty stack: param[%d] = %q, want %q", i, p, xssProbeParams[i])
		}
	}
}
