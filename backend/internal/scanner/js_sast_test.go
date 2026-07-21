package scanner

import (
	"context"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestSASTBugPatterns_MatchKnownDefects(t *testing.T) {
	cases := map[string]string{
		"bug-assignment-in-condition": "if (user = getUser()) { go(); }",
		"bug-empty-catch":             "try { risky(); } catch (e) {}",
		"bug-compare-to-nan":          "if (total === NaN) { reset(); }",
		"bug-debugger-statement":      "function f(){ debugger; return 1; }",
	}
	for wantID, body := range cases {
		matched := false
		for _, bp := range sastBugPatterns {
			if bp.id != wantID {
				continue
			}
			if bp.pattern.FindString(body) == "" {
				t.Errorf("bug pattern %s did not match %q", wantID, body)
			} else {
				matched = true
			}
		}
		if !matched {
			t.Errorf("no bug pattern with id %q registered", wantID)
		}
	}
}

func TestSASTBugPatterns_NoFalsePositiveOnComparisons(t *testing.T) {
	// Proper comparisons and handled catch blocks must not be flagged.
	clean := "if (a == b) { use(); } try { x(); } catch (e) { log(e); }"
	for _, bp := range sastBugPatterns {
		if bp.pattern.FindString(clean) != "" {
			t.Errorf("bug pattern %s false-positive on clean code: %q", bp.id, clean)
		}
	}
}

func TestSASTSinkPatterns_MatchKnownSinks(t *testing.T) {
	cases := map[string]string{
		"dom-xss-innerhtml":       "el.innerHTML = userInput;",
		"dom-xss-document-write":  "document.write(data);",
		"dom-xss-insert-adjacent": "node.insertAdjacentHTML('beforeend', x);",
		"dom-xss-dangerously-set": "return {dangerouslySetInnerHTML:{__html:y}};",
		"code-exec-eval":          "var r = eval(expr);",
		"code-exec-function-ctor": "var f = new Function('a','return a');",
		"open-redirect-location":  "window.location = nextUrl;",
		"insecure-postmessage":    "window.addEventListener('message', handler);",
		"client-storage-token":    "localStorage.setItem('auth_token', t);",
	}
	for wantID, body := range cases {
		matched := false
		for _, sp := range sastSinkPatterns {
			if sp.id != wantID {
				continue
			}
			if sp.pattern.FindString(body) == "" {
				t.Errorf("pattern %s did not match %q", wantID, body)
			} else {
				matched = true
			}
		}
		if !matched {
			t.Errorf("no sink pattern with id %q registered", wantID)
		}
	}
}

func TestSASTSinkPatterns_NoMatchOnCleanCode(t *testing.T) {
	clean := "function add(a,b){ return a+b; } console.log(add(1,2));"
	for _, sp := range sastSinkPatterns {
		if sp.pattern.FindString(clean) != "" {
			t.Errorf("pattern %s false-positive on clean code", sp.id)
		}
	}
}

func TestExtractRoutesFromJS_FindsAndNormalizes(t *testing.T) {
	target := "https://1.1.1.1/"
	scanScope := model.ScanScope{IncludeHosts: []string{"1.1.1.1"}}
	js := `
		fetch("/api/users");
		axios.get('/api/v1/orders');
		var cfg = { url: "/internal/health" };
		xhr.open("POST", "/auth/login");
		const routes = [{ path: "/admin/dashboard" }];
		fetch("https://1.1.1.1/api/same-origin");
		fetch("https://evil.example.com/api/cross-origin");
		import("/static/app.js");
	`
	got := extractRoutesFromJS(js, target, scanScope)
	want := map[string]bool{
		"/api/users":         true,
		"/api/v1/orders":     true,
		"/internal/health":   true,
		"/auth/login":        true,
		"/admin/dashboard":   true,
		"/api/same-origin":   true,
	}
	for _, r := range got {
		if !want[r] {
			t.Errorf("unexpected route extracted: %q (all: %v)", r, got)
		}
		delete(want, r)
	}
	if len(want) != 0 {
		t.Errorf("missing expected routes: %v (got: %v)", want, got)
	}
	for _, r := range got {
		if strings.Contains(r, "cross-origin") {
			t.Errorf("cross-origin route should be dropped: %q", r)
		}
		if strings.HasSuffix(r, ".js") {
			t.Errorf("static asset should be dropped: %q", r)
		}
	}
}

func TestNormalizeDiscoveredRoute(t *testing.T) {
	target := "https://1.1.1.1/"
	scanScope := model.ScanScope{IncludeHosts: []string{"1.1.1.1"}}
	cases := map[string]string{
		"/api/users":              "/api/users",
		"/api/users/":             "/api/users",
		"/api/users?id=1":         "/api/users",
		"relative/path":           "",
		"/static/main.js":         "",
		"${dynamic}":              "",
		"//cdn.example.com/x":     "",
		"https://1.1.1.1/api/ok":  "/api/ok",
		"https://evil.com/api/no": "",
	}
	for in, want := range cases {
		if got := normalizeDiscoveredRoute(in, target, scanScope); got != want {
			t.Errorf("normalizeDiscoveredRoute(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunJavaScriptSAST_NoScriptsNoResult(t *testing.T) {
	svc := NewService(Config{})
	res := svc.runJavaScriptSAST(context.TODO(), RunInput{Target: "https://1.1.1.1/"}, "<html><body>no scripts</body></html>")
	if len(res.Findings) != 0 || len(res.Routes) != 0 || res.ScriptsAnalyzed != 0 {
		t.Fatalf("expected empty SAST result, got %+v", res)
	}
}

func TestSASTSeverityWeight_Ordering(t *testing.T) {
	if sastSeverityWeight(model.SeverityHigh) <= sastSeverityWeight(model.SeverityMedium) {
		t.Error("High should outrank Medium")
	}
	if sastSeverityWeight(model.SeverityMedium) <= sastSeverityWeight(model.SeverityLow) {
		t.Error("Medium should outrank Low")
	}
}
