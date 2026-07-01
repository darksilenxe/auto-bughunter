package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestPhase1BatchA_SQLiGatesBaselineAndVerify(t *testing.T) {
	t.Run("binary gate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("you have an error in your sql syntax"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runActiveSQLiProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected binary SQLi response suppressed, got %d", len(got))
		}
	})
	t.Run("baseline", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("You have an error in your SQL syntax"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runActiveSQLiProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected baseline SQLi response suppressed, got %d", len(got))
		}
	})
	t.Run("verify", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("id"), "'") {
				_, _ = w.Write([]byte("You have an error in your SQL syntax"))
				return
			}
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()
		got := NewService(Config{}).runActiveSQLiProbe(context.Background(), RunInput{Target: srv.URL}, "")
		if len(got) != 1 || !strings.HasPrefix(got[0].EvidenceFields["preReport.verifiedBy"], "active-sqli") {
			t.Fatalf("expected verified SQLi finding, got %+v", got)
		}
	})
}

func TestPhase1BatchA_SSTIGatesBaselineAndVerify(t *testing.T) {
	t.Run("binary gate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("<p>49</p>"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runActiveSSTIProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected binary SSTI response suppressed, got %d", len(got))
		}
	})
	t.Run("baseline", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>49</body></html>"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runActiveSSTIProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected baseline SSTI response suppressed, got %d", len(got))
		}
	})
	t.Run("verify", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			if strings.Contains(r.URL.RawQuery, "%7B%7B7%2A7%7D%7D") || strings.Contains(r.URL.RawQuery, "7%2A7") {
				_, _ = w.Write([]byte("<html><body>49</body></html>"))
				return
			}
			_, _ = w.Write([]byte("<html><body>ok</body></html>"))
		}))
		defer srv.Close()
		got := NewService(Config{}).runActiveSSTIProbe(context.Background(), RunInput{Target: srv.URL}, "")
		if len(got) != 1 || !strings.HasPrefix(got[0].EvidenceFields["preReport.verifiedBy"], "active-ssti") {
			t.Fatalf("expected verified SSTI finding, got %+v", got)
		}
	})
}

func TestPhase1BatchA_XMLAndPathControls(t *testing.T) {
	t.Run("xpath image gate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("XPathException: invalid XPath"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runActiveXPathInjectionProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected XPath binary response suppressed, got %d", len(got))
		}
	})
	t.Run("path baseline", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runActivePathTraversalProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected path traversal baseline suppressed, got %d", len(got))
		}
	})
	t.Run("path verify", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			if strings.Contains(r.URL.Query().Get("file"), "..") {
				_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
				return
			}
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()
		got := NewService(Config{}).runActivePathTraversalProbe(context.Background(), RunInput{Target: srv.URL}, "")
		if len(got) != 1 || !strings.HasPrefix(got[0].EvidenceFields["preReport.verifiedBy"], "active-path-traversal") {
			t.Fatalf("expected verified path traversal finding, got %+v", got)
		}
	})
}

func TestPhase1BatchA_XXEAndDeserializationControls(t *testing.T) {
	t.Run("xxe binary gate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runActiveXXEProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected XXE binary response suppressed, got %d", len(got))
		}
	})
	t.Run("deserialization binary gate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("rO0AB"))
		}))
		defer srv.Close()
		got := NewService(Config{}).RunDeserializationProbe(context.Background(), srv.URL, model.ScanScope{}, model.ScanOptions{SeedRuntimeEndpoints: []string{srv.URL}}, model.ScanAuthProfile{}, nil)
		if len(got) != 0 {
			t.Fatalf("expected deserialization binary response suppressed, got %d", len(got))
		}
	})
}

func TestPhase1BatchA_CommandSMTPSSIControls(t *testing.T) {
	t.Run("command binary gate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte(cmdInjectionOutputMarker))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runCommandInjectionProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected command binary response suppressed, got %d", len(got))
		}
	})
	t.Run("smtp baseline", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("smtp error: relay access denied"))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runSMTPInjectionProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected SMTP baseline suppressed, got %d", len(got))
		}
	})
	t.Run("ssi html gate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte(ssiExecMarker))
		}))
		defer srv.Close()
		if got := NewService(Config{}).runSSIInjectionProbe(context.Background(), RunInput{Target: srv.URL}, ""); len(got) != 0 {
			t.Fatalf("expected SSI non-HTML response suppressed, got %d", len(got))
		}
	})
}

func TestPhase1BatchA_DifferentialSuppressesEchoNoise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query()
		if v := q.Get("q"); v != "guest" && v != "" {
			_, _ = fmt.Fprintf(w, "<html><body>49</body></html>")
			return
		}
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()
	got := NewService(Config{}).runActiveSSTIProbe(context.Background(), RunInput{Target: srv.URL}, "")
	if len(got) != 0 {
		t.Fatalf("expected differential to suppress SSTI echo noise, got %+v", got)
	}
}
