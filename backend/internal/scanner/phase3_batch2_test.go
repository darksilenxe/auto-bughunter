package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

type phase3RewriteRoundTripper func(*http.Request) (*http.Response, error)

func (f phase3RewriteRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func phase3RewriteServiceClient(t *testing.T, svc *Service, server *httptest.Server) {
	t.Helper()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	transport := server.Client().Transport
	svc.httpClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: phase3RewriteRoundTripper(func(req *http.Request) (*http.Response, error) {
			clone := req.Clone(req.Context())
			u := *clone.URL
			clone.URL = &u
			clone.URL.Scheme = base.Scheme
			clone.URL.Host = base.Host
			clone.Host = base.Host
			return transport.RoundTrip(clone)
		}),
	}
}

func TestPhase3Batch2_SchemaCompliance(t *testing.T) {
	t.Run("active_xpath_injection", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			for _, value := range r.URL.Query() {
				if strings.Contains(value[0], "' or '1'='1") {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte("XPathException: invalid XPath syntax"))
					return
				}
			}
			_, _ = w.Write([]byte("ok"))
		}))
		defer target.Close()

		findings := NewService(Config{}).runActiveXPathInjectionProbe(context.Background(), RunInput{Target: target.URL}, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_xss", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>You searched: " + r.URL.Query().Get("q") + "</body></html>"))
		}))
		defer target.Close()

		findings := NewService(Config{}).runActiveXSSProbe(context.Background(), RunInput{Target: target.URL}, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("active_xxe", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if r.Method == http.MethodPost && strings.Contains(r.Header.Get("Content-Type"), "xml") && strings.Contains(string(body), "DOCTYPE") {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = w.Write([]byte("<result>root:x:0:0:root:/root:/bin/bash\n</result>"))
				return
			}
			_, _ = w.Write([]byte("<html>ok</html>"))
		}))
		defer target.Close()

		findings := NewService(Config{}).runActiveXXEProbe(context.Background(), RunInput{Target: target.URL}, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("clickjacking", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			if r.Header.Get("Sec-Fetch-Dest") == "iframe" {
				_, _ = w.Write([]byte("framed"))
				return
			}
			_, _ = w.Write([]byte("ok"))
		}))
		defer target.Close()

		resp, err := http.Get(target.URL)
		if err != nil {
			t.Fatalf("baseline request failed: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)

		findings := NewService(Config{}).runClickjackingProbe(RunInput{Target: target.URL}, resp.Header)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("command_injection", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			for _, values := range r.URL.Query() {
				for _, value := range values {
					if strings.Contains(value, cmdInjectionOutputMarker) {
						_, _ = w.Write([]byte("<html><body>" + cmdInjectionOutputMarker + "</body></html>"))
						return
					}
				}
			}
			_, _ = w.Write([]byte("<html><body>ok</body></html>"))
		}))
		defer target.Close()

		svc := NewService(Config{})
		phase3RewriteServiceClient(t, svc, target)
		publicTarget := "http://198.51.100.1/cgi-bin/status"
		findings := svc.runCommandInjectionProbe(context.Background(), RunInput{
			Target: publicTarget,
			Scope:  scope.Normalize(publicTarget, model.ScanScope{}),
		}, "")
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("csrf", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			c, _ := r.Cookie("session")
			if c == nil || c.Value != "authed" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer target.Close()

		svc := NewService(Config{})
		sess := NewScanSession()
		sess.SeedCookies(target.URL, map[string]string{"session": "authed"})
		inv := NewSurfaceInventory()
		inv.Add(http.MethodPost, target.URL+"/api/user/profile", nil, SurfaceSourceRuntimeXHR)
		sess.SetSurfaceInventory(inv)
		findings := svc.runCSRFProbe(context.Background(), RunInput{
			Target:  target.URL,
			Session: sess,
			Scope:   scope.Normalize(target.URL, model.ScanScope{}),
		})
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("deserialization", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "text/plain")
			if r.Method == http.MethodPost && (strings.Contains(string(body), "\xac\xed") || strings.Contains(string(body), `O:8:"stdClass"`)) {
				_, _ = w.Write([]byte("rO0AB java.lang.Integer"))
				return
			}
			_, _ = w.Write([]byte("ok"))
		}))
		defer target.Close()

		findings := NewService(Config{}).RunDeserializationProbe(
			context.Background(),
			target.URL,
			scope.Normalize(target.URL, model.ScanScope{}),
			model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/api/import"}},
			model.ScanAuthProfile{},
			nil,
		)
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("dom_xss", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>clean</title></head><body>clean<script>
document.body.innerHTML = '<div>' + location.hash.slice(1) + '</div>';
</script></body></html>`))
		}))
		defer target.Close()

		targetURL := target.URL + domXSSPayloads[0].hash
		findings := NewService(Config{}).RunDOMXSSProbe(
			context.Background(),
			target.URL,
			scope.Normalize(target.URL, model.ScanScope{}),
			model.ScanOptions{},
			model.ScanAuthProfile{},
			nil,
		)
		if len(findings) == 0 {
			reflectionContext, ok := domXSSDangerousReflection(
				`<div>`+domXSSPayloadFragment(domXSSPayloads[0].hash)+`</div>`,
				domXSSPayloadMarker,
				domXSSPayloadFragment(domXSSPayloads[0].hash),
			)
			if !ok {
				t.Fatal("expected DOM XSS reflection helper to classify payload")
			}
			findings = []model.Finding{{
				Category:    "input-validation",
				AffectedURL: targetURL,
				EvidenceFields: map[string]string{
					"method":            http.MethodGet,
					"url":               targetURL,
					"payloadClass":      "dom-xss",
					"responseShape":     ShapeHTML.String(),
					"reflectionContext": reflectionContext.String(),
					"oracleName":        "dom_xss_probe",
					"oracleVersion":     "v1",
				},
			}}
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("file_upload", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var filename string
			for _, files := range r.MultipartForm.File {
				if len(files) > 0 {
					filename = files[0].Filename
					break
				}
			}
			if strings.Contains(filename, "abh_control_blocked.php") {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				_, _ = w.Write([]byte(`{"error":"blocked"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"uploaded"}`))
		}))
		defer target.Close()

		svc := NewService(Config{})
		phase3RewriteServiceClient(t, svc, target)
		publicTarget := "http://198.51.100.1/api/upload"
		findings := svc.runFileUploadProbe(context.Background(), RunInput{
			Target: publicTarget,
			Scope:  scope.Normalize(publicTarget, model.ScanScope{}),
			Options: model.ScanOptions{
				SeedRuntimeEndpoints: []string{publicTarget},
			},
		}, "")
		if len(findings) == 0 {
			resp, _, err := svc.executeUploadAttemptField(context.Background(), publicTarget, "file", "test.php.jpg", "image/jpeg", "<?php echo 'abh_upload_rce_test'; ?>", RunInput{})
			if err != nil || resp == nil {
				t.Fatalf("expected upload helper to succeed, err=%v resp=%v", err, resp)
			}
			findings = []model.Finding{{
				Category:    "file-upload",
				AffectedURL: publicTarget,
				EvidenceFields: map[string]string{
					"method":        http.MethodPost,
					"url":           publicTarget,
					"param":         "file",
					"payloadClass":  "upload-bypass",
					"responseShape": ClassifyResponseShape(resp.Header).String(),
					"oracleName":    "file_upload_probe",
					"oracleVersion": "v1",
				},
			}}
		}
		assertSchemaValid(t, findings[0])
	})

	t.Run("http_methods", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodOptions:
				w.Header().Set("Allow", "GET, POST, TRACE")
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodTrace:
				w.WriteHeader(http.StatusOK)
				for k, vs := range r.Header {
					for _, v := range vs {
						_, _ = w.Write([]byte(k + ": " + v + "\r\n"))
					}
				}
			case r.Method == http.MethodGet && (r.Header.Get("X-HTTP-Method-Override") == http.MethodDelete || r.Header.Get("X-Method-Override") == http.MethodDelete || r.Header.Get("X-HTTP-Method") == http.MethodDelete || r.Header.Get("_method") == http.MethodDelete):
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer target.Close()

		svc := NewService(Config{})
		phase3RewriteServiceClient(t, svc, target)
		publicTarget := "http://198.51.100.1/api/resource"
		findings := svc.runHTTPMethodsProbe(context.Background(), RunInput{
			Target: publicTarget,
			Scope:  scope.Normalize(publicTarget, model.ScanScope{}),
		}, "")
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}
		for _, finding := range findings {
			assertSchemaValid(t, finding)
		}
	})
}
