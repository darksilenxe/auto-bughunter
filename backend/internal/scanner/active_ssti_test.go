package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunActiveSSTIProbe_FindsEvaluatedTemplate(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		v := r.URL.Query().Get("name")
		// "Render" the input by evaluating Jinja2-style {{7*7}}.
		if strings.Contains(v, "{{7*7}}") {
			v = strings.ReplaceAll(v, "{{7*7}}", "49")
		}
		_, _ = fmt.Fprintf(w, "<h1>Hello, %s</h1>", v)
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveSSTIProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 SSTI finding, got %d", len(findings))
	}
	if findings[0].CWE != "CWE-1336" {
		t.Fatalf("expected CWE-1336, got %q", findings[0].CWE)
	}
}

func TestRunActiveSSTIProbe_NoFindingOnReflection(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo verbatim: literal payload appears AND no evaluation. The
		// strict isSSTIEvaluation check requires both `49` present and
		// payload absent — reflection of `{{7*7}}` itself must not match.
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<p>%s</p>", r.URL.Query().Get("name"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveSSTIProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("reflection of payload must not flag SSTI, got %d findings", len(findings))
	}
}

func TestIsSSTIEvaluation(t *testing.T) {
	if !isSSTIEvaluation("Hello 49!", "{{7*7}}", "49") {
		t.Fatal("expected evaluation match")
	}
	if isSSTIEvaluation("Hello {{7*7}}", "{{7*7}}", "49") {
		t.Fatal("payload echoed verbatim must not match")
	}
	if isSSTIEvaluation("Hello world", "{{7*7}}", "49") {
		t.Fatal("missing expected value must not match")
	}
}

func TestRunActiveSSTIProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("49"))
	}))
	defer target.Close()
	svc := NewService(Config{})
	in := RunInput{Target: target.URL}
	in.Options.PassiveOnly = true
	if got := svc.runActiveSSTIProbe(context.Background(), in, ""); len(got) != 0 {
		t.Fatalf("PassiveOnly must disable, got %d findings", len(got))
	}
}

// silence unused import warning when http is only used transitively via
// httptest above.
var _ = http.MethodGet
