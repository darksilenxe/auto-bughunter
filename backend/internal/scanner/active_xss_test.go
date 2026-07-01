package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestRunActiveXSSProbe_FindsReflection stands up a target that reflects
// the q parameter unescaped into HTML and expects a single high-severity
// finding.
func TestRunActiveXSSProbe_FindsReflection(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Reflect the q value verbatim — the canonical XSS sink.
		_, _ = w.Write([]byte("<html><body>You searched: " + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")

	if len(findings) != 1 {
		t.Fatalf("expected 1 XSS finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "active-xss-reflected" || f.Severity != model.SeverityHigh {
		t.Fatalf("unexpected finding shape: %+v", f)
	}
	if f.AffectedParameter == "" {
		t.Fatalf("expected affected parameter to be populated, got empty")
	}
	if f.CWE != "CWE-79" {
		t.Fatalf("expected CWE-79, got %q", f.CWE)
	}
}

// TestRunActiveXSSProbe_NoFindingWhenEncoded ensures the probe does not
// false-positive when the target HTML-encodes the reflected payload.
func TestRunActiveXSSProbe_NoFindingWhenEncoded(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		v := r.URL.Query().Get("q")
		// Minimal HTML encoding of the dangerous chars.
		v = strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v)
		_, _ = w.Write([]byte("<html><body>You searched: " + v + "</body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no finding on encoded reflection, got %d: %+v", len(findings), findings)
	}
}

// TestIsHTMLContextReflection covers the trivial helper.
func TestIsHTMLContextReflection(t *testing.T) {
	if !isHTMLContextReflection("xx"+xssMarker+"yy", xssMarker) {
		t.Fatal("expected reflection match")
	}
	if isHTMLContextReflection("&lt;svg/onload=...&gt;", xssMarker) {
		t.Fatal("encoded form must not match")
	}
	if isHTMLContextReflection("", xssMarker) || isHTMLContextReflection("body", "") {
		t.Fatal("empty inputs must not match")
	}
}

// TestRunActiveXSSProbe_NoFindingForJSONResponse verifies that the probe does
// not raise a false positive when the target reflects the payload into a JSON
// response body. A payload inside JSON is not executed as HTML; reporting it
// as XSS would be a false positive on SPA API endpoints.
func TestRunActiveXSSProbe_NoFindingForJSONResponse(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// JSON body that reflects the query parameter verbatim.
		q := r.URL.Query().Get("q")
		_, _ = w.Write([]byte(`{"query":"` + q + `"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("JSON response: expected 0 findings (not an HTML context), got %d", len(findings))
	}
}

// TestRunActiveXSSProbe_TagsResponseShapeAndReflectionContext confirms that
// the migrated probe stamps the shared Phase 1 evidence fields
// (`responseShape`, `reflectionContext`, `preReport.*`, `differentialReVerify`)
// so downstream normalisation, strict-mode reporting, and automation metrics
// can attribute the finding.
func TestRunActiveXSSProbe_TagsResponseShapeAndReflectionContext(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>You searched: " + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 XSS finding, got %d", len(findings))
	}
	ev := findings[0].EvidenceFields
	if got := ev["responseShape"]; got != "html" {
		t.Fatalf("expected responseShape=html, got %q", got)
	}
	if got := ev["reflectionContext"]; got != "html_text" {
		t.Fatalf("expected reflectionContext=html_text, got %q", got)
	}
	if got := ev["preReport.verifiedBy"]; got == "" {
		t.Fatal("expected preReport.verifiedBy stamp, got empty")
	}
	if got := ev["differentialReVerify"]; got != "confirmed" {
		t.Fatalf("expected differentialReVerify=confirmed, got %q", got)
	}
}

// TestRunActiveXSSProbe_SuppressedWhenBaselineAlreadyContainsMarker exercises
// the shared control-baseline gate: if the clean, un-probed response already
// contains the marker string, the probe must suppress the finding as a
// baseline artefact rather than emitting a false positive.
func TestRunActiveXSSProbe_SuppressedWhenBaselineAlreadyContainsMarker(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Pathological target: always emits the exact marker, regardless
		// of the query parameter. Any reflection probe that reports here
		// would be flagging its own marker showing up in unrelated
		// content.
		_, _ = w.Write([]byte("<html><body>" + xssMarker + " " + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("baseline-contains-marker: expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestRunActiveXSSProbe_SuppressedWhenDifferentialControlAlsoReflects covers
// the DifferentialReVerify contract. A target that reflects *any* input into
// the same HTML sink (an echo server) reflects the benign random control
// exactly as it reflects the exploit payload; the finding must be suppressed
// because the exploit is not specific to the marker's dangerous characters.
func TestRunActiveXSSProbe_SuppressedWhenDifferentialControlAlsoReflects(t *testing.T) {
	// Handler reflects the raw q value only when q equals xssMarker OR
	// xssConfirmMarker (so the initial dual-marker check passes), AND when
	// q equals the differential benign-random payload (so the differential
	// oracle also sees the *original* marker come back). To achieve the
	// second half we make the handler also echo xssMarker whenever any
	// long-enough alphanumeric q is present — mimicking an echo server
	// whose output contains attacker-controlled and pre-canned strings.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		body := "<html><body>echo: " + q
		// Simulate a page that always renders the xssMarker string in a
		// static banner, regardless of what the caller sends. The
		// differential re-verify oracle will see the marker come back
		// even when the caller sent a benign random payload, and must
		// suppress the candidate.
		body += " <!-- static banner: " + xssMarker + " -->"
		body += "</body></html>"
		_, _ = w.Write([]byte(body))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("differential-fp: expected 0 findings, got %d: %+v", len(findings), findings)
	}
}
