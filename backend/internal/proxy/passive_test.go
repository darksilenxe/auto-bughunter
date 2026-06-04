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
