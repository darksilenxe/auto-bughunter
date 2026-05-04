package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestRunActiveXXEProbe_ReflectedFileRead simulates an endpoint that parses
// XML and reflects the entity value (file content) in its response.
func TestRunActiveXXEProbe_ReflectedFileRead(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if r.Method == http.MethodPost && strings.Contains(ct, "xml") {
			// Simulate an XML parser that reflects the resolved entity.
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte("<result>root:x:0:0:root:/root:/bin/bash\n</result>"))
			return
		}
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXXEProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 XXE finding (reflected file read), got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "active-xxe" {
		t.Fatalf("unexpected finding ID: %q", f.ID)
	}
	if f.Severity != model.SeverityHigh {
		t.Fatalf("expected high severity, got %q", f.Severity)
	}
	if f.CWE != "CWE-611" {
		t.Fatalf("expected CWE-611, got %q", f.CWE)
	}
}

// TestRunActiveXXEProbe_ErrorBased simulates an endpoint that returns an XML
// parser error when the error-based blind XXE payload is sent.
func TestRunActiveXXEProbe_ErrorBased(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if r.Method == http.MethodPost && strings.Contains(ct, "xml") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"XMLSyntaxError: SAXParseException: entity not found"}`))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXXEProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 XXE finding (error-based), got %d", len(findings))
	}
	if findings[0].EvidenceFields["technique"] != "error-based" {
		t.Fatalf("expected technique=error-based, got %q", findings[0].EvidenceFields["technique"])
	}
}

// TestRunActiveXXEProbe_NoFindingWhenSafe ensures the probe stays quiet when
// the target returns normal responses for all XML payloads.
func TestRunActiveXXEProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<result>ok</result>`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveXXEProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no XXE findings, got %d: %+v", len(findings), findings)
	}
}

// TestRunActiveXXEProbe_PassiveOnlyDisables verifies the probe respects
// the PassiveOnly flag.
func TestRunActiveXXEProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("root:x:0:0:"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{Target: target.URL}
	in.Options.PassiveOnly = true
	if got := svc.runActiveXXEProbe(context.Background(), in, ""); len(got) != 0 {
		t.Fatalf("PassiveOnly must disable XXE probe, got %d findings", len(got))
	}
}

// TestMatchXXEErrorSignature validates the XML parser error signature matcher.
func TestMatchXXEErrorSignature(t *testing.T) {
	cases := map[string]string{
		// "saxparseexception" comes before "entity not found" in the list.
		`SAXParseException: entity not found at line 3`:  "saxparseexception",
		`org.xml.sax.SAXException: malformed`:            "org.xml.sax",
		`<html>200 OK, nothing interesting here</html>`:  "",
		``:                                               "",
		`XMLSyntaxError: SAXParseException: parse error`: "saxparseexception",
		`entity not found in document`:                   "entity not found",
	}
	for body, want := range cases {
		got := matchXXEErrorSignature(body)
		if got != want {
			t.Fatalf("matchXXEErrorSignature(%q) = %q, want %q", body, got, want)
		}
	}
}

// TestIsLikelyXMLEndpoint validates the XML endpoint heuristic.
func TestIsLikelyXMLEndpoint(t *testing.T) {
	if !isLikelyXMLEndpoint("http://example.com/api/xml/import") {
		t.Fatal("expected xml endpoint to match")
	}
	if !isLikelyXMLEndpoint("http://example.com/soap/service") {
		t.Fatal("expected soap endpoint to match")
	}
	if isLikelyXMLEndpoint("http://example.com/api/users") {
		t.Fatal("expected /api/users not to match")
	}
}
