package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestRunActivePathTraversalProbe_FindsEtcPasswd simulates a vulnerable
// endpoint that returns /etc/passwd contents when a traversal sequence is
// injected into the "file" parameter.
func TestRunActivePathTraversalProbe_FindsEtcPasswd(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "..") {
			// Simulate leaking /etc/passwd contents.
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActivePathTraversalProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 path traversal finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "active-path-traversal" {
		t.Fatalf("unexpected finding ID: %q", f.ID)
	}
	if f.Severity != model.SeverityHigh {
		t.Fatalf("expected high severity, got %q", f.Severity)
	}
	if f.CWE != "CWE-22" {
		t.Fatalf("expected CWE-22, got %q", f.CWE)
	}
	if f.AffectedParameter != "file" {
		t.Fatalf("expected param=file, got %q", f.AffectedParameter)
	}
}

// TestRunActivePathTraversalProbe_FindsWinIni simulates a Windows-style
// endpoint that leaks win.ini content on traversal.
func TestRunActivePathTraversalProbe_FindsWinIni(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if strings.Contains(path, "..") || strings.Contains(path, "..%") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("; for 16-bit app support\n[fonts]\n[extensions]\n[files]\n"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActivePathTraversalProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 path traversal finding from win.ini, got %d", len(findings))
	}
}

// TestRunActivePathTraversalProbe_NoFindingWhenSafe ensures the probe stays
// quiet when the target returns a normal response without file content.
func TestRunActivePathTraversalProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Welcome</body></html>"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActivePathTraversalProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no path traversal findings, got %d: %+v", len(findings), findings)
	}
}

// TestRunActivePathTraversalProbe_PassiveOnlyDisables verifies the probe
// respects the PassiveOnly flag.
func TestRunActivePathTraversalProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("root:x:0:0:"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{Target: target.URL}
	in.Options.PassiveOnly = true
	if got := svc.runActivePathTraversalProbe(context.Background(), in, ""); len(got) != 0 {
		t.Fatalf("PassiveOnly must disable path traversal probe, got %d findings", len(got))
	}
}

// TestMatchPathTraversalSignature validates the file-content matcher.
func TestMatchPathTraversalSignature(t *testing.T) {
	cases := []struct {
		body    string
		matched bool
		want    string
	}{
		{"root:x:0:0:root:/root:/bin/bash\n", true, "root:x:0:0:"},
		{"[fonts]\n[extensions]\n", true, "[fonts]"},
		{"<html>no file content</html>", false, ""},
		{"", false, ""},
	}
	for _, c := range cases {
		got, ok := matchPathTraversalSignature(c.body)
		if ok != c.matched {
			t.Fatalf("matchPathTraversalSignature(%q) matched=%v, want %v", c.body, ok, c.matched)
		}
		if c.matched && got != c.want {
			t.Fatalf("matchPathTraversalSignature(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}
