package proxy

import (
	"net/http"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestPassiveScanStoreDetectsLikelySPA(t *testing.T) {
	store := NewPassiveScanStore()
	body := `<!doctype html><html><head><title>App</title><script src="/assets/app.9ab12c34.js"></script></head><body><div id="root"></div></body></html>`

	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
		},
		ResponseBody: body,
	})
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/products",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
		},
		ResponseBody: body,
	})
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/account/settings",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
		},
		ResponseBody: body,
	})

	findings := store.List()
	for _, f := range findings {
		if f.ID == "proxy-site-likely-spa" {
			if f.Severity != model.SeverityInfo {
				t.Fatalf("expected info severity, got %q", f.Severity)
			}
			return
		}
	}
	t.Fatalf("expected proxy-site-likely-spa finding")
}

func TestPassiveScanStoreDoesNotDetectSPAForDifferentStructures(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
		},
		ResponseBody: `<!doctype html><html><head><title>Home</title></head><body><main><h1>Home</h1></main></body></html>`,
	})
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/blog",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
		},
		ResponseBody: `<!doctype html><html><head><title>Blog</title></head><body><article><h1>Post</h1></article></body></html>`,
	})
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/contact",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
		},
		ResponseBody: `<!doctype html><html><head><title>Contact</title></head><body><section><form></form></section></body></html>`,
	})

	for _, f := range store.List() {
		if f.ID == "proxy-site-likely-spa" {
			t.Fatalf("did not expect proxy-site-likely-spa finding")
		}
	}
}

func hasFindingID(findings []PassiveFinding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestPassiveCheckPrivacyHeaders(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:          http.MethodGet,
		URL:             "https://example.test/",
		ResponseStatus:  http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "text/html"},
		ResponseBody:    "<!doctype html><html><body>hi</body></html>",
	})
	findings := store.List()
	if !hasFindingID(findings, "proxy-no-referrer-policy") {
		t.Fatalf("expected proxy-no-referrer-policy finding")
	}
	if !hasFindingID(findings, "proxy-no-permissions-policy") {
		t.Fatalf("expected proxy-no-permissions-policy finding")
	}
}

func TestPassiveCheckDirectoryListing(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:          http.MethodGet,
		URL:             "https://example.test/backup/",
		ResponseStatus:  http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "text/html"},
		ResponseBody:    "<html><head><title>Index of /backup</title></head><body>...</body></html>",
	})
	if !hasFindingID(store.List(), "proxy-directory-listing") {
		t.Fatalf("expected proxy-directory-listing finding")
	}
}

func TestPassiveCheckVerboseErrors(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:          http.MethodGet,
		URL:             "https://example.test/api",
		ResponseStatus:  http.StatusInternalServerError,
		ResponseHeaders: map[string]string{"Content-Type": "text/html"},
		ResponseBody:    "Warning: mysql_fetch_array() expects parameter 1 to be resource",
	})
	if !hasFindingID(store.List(), "proxy-verbose-error") {
		t.Fatalf("expected proxy-verbose-error finding")
	}
}

func TestPassiveCheckInternalIPDisclosure(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:          http.MethodGet,
		URL:             "https://example.test/status",
		ResponseStatus:  http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "application/json"},
		ResponseBody:    `{"host":"10.0.5.23","status":"ok"}`,
	})
	if !hasFindingID(store.List(), "proxy-internal-ip-disclosure") {
		t.Fatalf("expected proxy-internal-ip-disclosure finding")
	}
}

func TestPassiveCheckMixedContent(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:          http.MethodGet,
		URL:             "https://example.test/",
		ResponseStatus:  http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "text/html"},
		ResponseBody:    `<!doctype html><html><body><script src="http://cdn.example.com/lib.js"></script></body></html>`,
	})
	if !hasFindingID(store.List(), "proxy-mixed-content") {
		t.Fatalf("expected proxy-mixed-content finding")
	}
}

func TestPassiveCheckSensitiveURLParams(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:          http.MethodGet,
		URL:             "https://example.test/reset?token=abc123",
		ResponseStatus:  http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "text/html"},
		ResponseBody:    "<html></html>",
	})
	if !hasFindingID(store.List(), "proxy-sensitive-data-in-url") {
		t.Fatalf("expected proxy-sensitive-data-in-url finding")
	}
}

func TestPassiveCheckAutocompletePassword(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:          http.MethodGet,
		URL:             "https://example.test/login",
		ResponseStatus:  http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "text/html"},
		ResponseBody:    `<html><body><form><input type="password" name="pwd"></form></body></html>`,
	})
	if !hasFindingID(store.List(), "proxy-password-autocomplete-enabled") {
		t.Fatalf("expected proxy-password-autocomplete-enabled finding")
	}

	store2 := NewPassiveScanStore()
	store2.Analyze(&model.ProxyRequest{
		Method:          http.MethodGet,
		URL:             "https://example.test/login",
		ResponseStatus:  http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "text/html"},
		ResponseBody:    `<html><body><form><input type="password" name="pwd" autocomplete="new-password"></form></body></html>`,
	})
	if hasFindingID(store2.List(), "proxy-password-autocomplete-enabled") {
		t.Fatalf("did not expect proxy-password-autocomplete-enabled finding")
	}
}

func TestPassiveCheckCacheableSensitive(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/account",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html",
			"Set-Cookie":   "session=abc123; Path=/",
		},
		ResponseBody: "<html></html>",
	})
	if !hasFindingID(store.List(), "proxy-cacheable-set-cookie-response") {
		t.Fatalf("expected proxy-cacheable-set-cookie-response finding")
	}

	store2 := NewPassiveScanStore()
	store2.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/account",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type":  "text/html",
			"Set-Cookie":    "session=abc123; Path=/",
			"Cache-Control": "no-store",
		},
		ResponseBody: "<html></html>",
	})
	if hasFindingID(store2.List(), "proxy-cacheable-set-cookie-response") {
		t.Fatalf("did not expect proxy-cacheable-set-cookie-response finding")
	}
}

func TestPassiveCheckReflectedOriginCORS(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://api.example.test/data",
		RequestHeaders: map[string]string{"Origin": "https://evil.test"},
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type":                     "application/json",
			"Access-Control-Allow-Origin":      "https://evil.test",
			"Access-Control-Allow-Credentials": "true",
		},
		ResponseBody: "{}",
	})
	if !hasFindingID(store.List(), "proxy-cors-reflected-origin-creds") {
		t.Fatalf("expected proxy-cors-reflected-origin-creds finding")
	}
}

func TestPassiveCheckCookieSameSite(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html",
			"Set-Cookie":   "session=abc123; Path=/; HttpOnly; Secure",
		},
		ResponseBody: "<html></html>",
	})
	if !hasFindingID(store.List(), "proxy-cookie-no-samesite") {
		t.Fatalf("expected proxy-cookie-no-samesite finding")
	}
}
