package scanner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunSecurityHeadersProbe_MissingHSTS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	svc := NewService(Config{})
	findings := svc.runSecurityHeadersProbe(RunInput{Target: srv.URL}, resp.Header, resp)

	found := false
	for _, f := range findings {
		if f.ID == "missing-hsts" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected missing-hsts finding when HSTS header absent")
	}
}

func TestRunSecurityHeadersProbe_HSTSPresentNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	svc := NewService(Config{})
	findings := svc.runSecurityHeadersProbe(RunInput{Target: srv.URL}, resp.Header, resp)

	for _, f := range findings {
		if f.ID == "missing-hsts" || f.ID == "missing-permissions-policy" {
			t.Fatalf("unexpected finding %q when headers are set", f.ID)
		}
	}
}

func TestRunSecurityHeadersProbe_HSTSMissingDirectives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=300")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	svc := NewService(Config{})
	findings := svc.runSecurityHeadersProbe(RunInput{Target: srv.URL}, resp.Header, resp)

	hasInclude := false
	hasPreload := false
	for _, f := range findings {
		if f.ID == "hsts-missing-includesubdomains" {
			hasInclude = true
		}
		if f.ID == "hsts-missing-preload" {
			hasPreload = true
		}
	}
	if !hasInclude {
		t.Error("expected hsts-missing-includesubdomains finding")
	}
	if !hasPreload {
		t.Error("expected hsts-missing-preload finding")
	}
}

func TestRunSecurityHeadersProbe_MissingPermissionsPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	svc := NewService(Config{})
	findings := svc.runSecurityHeadersProbe(RunInput{Target: srv.URL}, resp.Header, resp)

	found := false
	for _, f := range findings {
		if f.ID == "missing-permissions-policy" {
			found = true
			if f.Severity != model.SeverityLow {
				t.Errorf("expected SeverityLow, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected missing-permissions-policy finding")
	}
}

func TestRunSecurityHeadersProbe_CookieSameSiteMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	svc := NewService(Config{})
	findings := svc.runSecurityHeadersProbe(RunInput{Target: srv.URL}, resp.Header, resp)

	found := false
	for _, f := range findings {
		if f.ID == "cookie-samesite-session" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected cookie-samesite-session finding when SameSite attribute absent")
	}
}

func TestCookieSameSite_ParsesValue(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc; Path=/; SameSite=Strict")
	h.Add("Set-Cookie", "pref=xyz; Path=/; SameSite=Lax")
	h.Add("Set-Cookie", "other=1; Path=/")

	if v := cookieSameSite(h, "session"); v != "Strict" {
		t.Errorf("expected Strict, got %q", v)
	}
	if v := cookieSameSite(h, "pref"); v != "Lax" {
		t.Errorf("expected Lax, got %q", v)
	}
	if v := cookieSameSite(h, "other"); v != "" {
		t.Errorf("expected empty, got %q", v)
	}
}
