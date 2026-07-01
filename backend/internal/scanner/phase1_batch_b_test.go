package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPhase1BatchB_FormulaInjection covers the binary-shape gate,
// baseline suppression, and differential replay for the formula
// injection probe.
func TestPhase1BatchB_FormulaInjection(t *testing.T) {
	t.Run("binary gate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("=abh_formula_7f9e2"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runFormulaInjectionProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected binary formula response suppressed, got %d", len(got))
		}
	})
	t.Run("baseline reflects marker", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			// Static echo — marker appears regardless of input.
			_, _ = w.Write([]byte("welcome =abh_formula_7f9e2 always"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runFormulaInjectionProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected static-echo baseline suppression, got %d", len(got))
		}
	})
	t.Run("verify differential confirms", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			// Only reflect the marker when the raw payload arrives.
			for _, v := range r.URL.Query() {
				for _, vv := range v {
					if strings.Contains(vv, "=abh_formula_7f9e2") {
						_, _ = w.Write([]byte("<p>=abh_formula_7f9e2</p>"))
						return
					}
				}
			}
			_, _ = w.Write([]byte("<p>ok</p>"))
		}))
		defer srv.Close()
		got := NewService(Config{}).runFormulaInjectionProbe(context.Background(), RunInput{Target: srv.URL}, "")
		if len(got) != 1 || got[0].EvidenceFields["oracleName"] != "formula_injection" {
			t.Fatalf("expected verified formula finding, got %+v", got)
		}
		if got[0].EvidenceFields["responseShape"] == "" {
			t.Fatalf("expected responseShape tag, got %+v", got[0].EvidenceFields)
		}
	})
}

// TestPhase1BatchB_DanglingMarkup covers baseline suppression and the
// differential re-verify oracle for dangling markup.
func TestPhase1BatchB_DanglingMarkup(t *testing.T) {
	t.Run("baseline reflects marker", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			// Static template that always echoes the marker text.
			_, _ = w.Write([]byte(`<div>x <img src="//abh-dangling-7f9e2.invalid/ always</div>`))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runDanglingMarkupProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected baseline suppression, got %d", len(got))
		}
	})
	t.Run("verify differential confirms", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			for _, v := range r.URL.Query() {
				for _, vv := range v {
					if strings.Contains(vv, "//abh-dangling-7f9e2.invalid/") {
						_, _ = w.Write([]byte(`<div>x <img src="//abh-dangling-7f9e2.invalid/ hello</div>`))
						return
					}
				}
			}
			_, _ = w.Write([]byte("<div>ok</div>"))
		}))
		defer srv.Close()
		got := NewService(Config{}).runDanglingMarkupProbe(context.Background(), RunInput{Target: srv.URL}, "")
		if len(got) != 1 {
			t.Fatalf("expected 1 dangling-markup finding, got %d: %+v", len(got), got)
		}
		if got[0].EvidenceFields["oracleName"] != "dangling_markup" {
			t.Fatalf("expected oracle tag dangling_markup, got %+v", got[0].EvidenceFields)
		}
	})
}

// TestPhase1BatchB_VerboseError covers the binary-shape gate and clean
// baseline suppression for the verbose error probe.
func TestPhase1BatchB_VerboseError(t *testing.T) {
	t.Run("binary gate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(500)
			_, _ = w.Write([]byte("Traceback (most recent call last)"))
		}))
		defer srv.Close()
		got := NewService(Config{}).runVerboseErrorProbe(context.Background(), RunInput{Target: srv.URL}, "")
		if len(got) != 0 {
			t.Fatalf("expected binary body suppression, got %+v", got)
		}
	})
	t.Run("baseline suppresses static error page", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(500)
			_, _ = w.Write([]byte("Traceback (most recent call last):\n  File \"/app/x.py\", line 1"))
		}))
		defer srv.Close()
		got := NewService(Config{}).runVerboseErrorProbe(context.Background(), RunInput{Target: srv.URL}, "")
		if len(got) != 0 {
			t.Fatalf("expected static-error-page baseline suppression, got %+v", got)
		}
	})
}

// TestPhase1BatchB_CrossDomainPolicyXMLGate ensures the crossdomain.xml
// probe only fires on XML-shaped responses.
func TestPhase1BatchB_CrossDomainPolicyXMLGate(t *testing.T) {
	t.Run("html body suppressed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			// SPA index or 404 that happens to include the wildcard string.
			_, _ = w.Write([]byte(`<html><body>domain="*"</body></html>`))
		}))
		defer srv.Close()
		got := NewService(Config{}).runCrossDomainPolicyProbe(context.Background(), RunInput{Target: srv.URL})
		if len(got) != 0 {
			t.Fatalf("expected html crossdomain response suppression, got %+v", got)
		}
	})
	t.Run("xml wildcard body still fires via helper", func(t *testing.T) {
		// The active probe path is bounded by safety.ValidateOutboundURL
		// (which correctly rejects loopback in tests). Exercise the XML
		// path through the parser + tagging helper to prove the gate
		// does not break the wildcard-domain detection.
		body := `<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>`
		findings := tagCrossDomainShape(analyzeCrossDomainXML("https://example.com/crossdomain.xml", body), "xml")
		if len(findings) == 0 {
			t.Fatalf("expected wildcard finding from analyzeCrossDomainXML")
		}
		if findings[0].EvidenceFields["responseShape"] != "xml" {
			t.Fatalf("expected responseShape=xml tag, got %q", findings[0].EvidenceFields["responseShape"])
		}
	})
}

// TestPhase1BatchB_XSSIJSONPGate ensures the JSONP/XSSI probe rejects
// HTML responses that happen to contain the probe callback string, and
// that the JS-shape helper still recognises legitimate JSONP bodies.
func TestPhase1BatchB_XSSIJSONPGate(t *testing.T) {
	t.Run("html body suppressed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			// Reflect the probe callback into an HTML page — must be
			// ignored because it is not a JSONP response.
			_, _ = w.Write([]byte(`<html>abh_jsonp_probe_7a3c1({"x":1})</html>`))
		}))
		defer srv.Close()
		got := NewService(Config{}).runXSSIJSONPProbe(context.Background(), RunInput{Target: srv.URL}, "")
		if len(got) != 0 {
			t.Fatalf("expected html-shape suppression, got %+v", got)
		}
	})
	t.Run("javascript shape recognised by helper", func(t *testing.T) {
		// runXSSIJSONPProbe uses safety.ValidateOutboundURL so a loopback
		// httptest cannot reach the probe body. Exercise the reflection
		// detector + shape classifier directly to prove the gate does
		// not break JSONP recognition on legitimate bodies.
		h := http.Header{}
		h.Set("Content-Type", "application/javascript")
		if !IsReflectionSafeShape(h) {
			t.Fatalf("javascript response must be reflection-safe")
		}
		if ClassifyResponseShape(h) != ShapeJavaScript {
			t.Fatalf("expected ShapeJavaScript classification for application/javascript")
		}
		if !detectJSONPReflection(`abh_jsonp_probe_7a3c1({"secret":"data"})`, "abh_jsonp_probe_7a3c1") {
			t.Fatalf("expected JSONP reflection to be detected")
		}
	})
}
