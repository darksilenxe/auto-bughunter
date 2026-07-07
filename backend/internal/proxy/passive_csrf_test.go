package proxy

import (
	"net/http"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestPassiveCheckAdditionalCSRF_FormMissingToken(t *testing.T) {
	store := NewPassiveScanStore()
	body := `<html><body>
		<form method="POST" action="/transfer">
			<input type="text" name="amount">
			<input type="submit" value="Send">
		</form>
	</body></html>`
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/transfer-form",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
			"Set-Cookie":   "session=abc123; HttpOnly",
		},
		ResponseBody: body,
	})

	findings := store.List()
	found := false
	for _, f := range findings {
		if f.ID == "proxy-csrf-form-missing-token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected proxy-csrf-form-missing-token finding, got %+v", findings)
	}
}

func TestPassiveCheckAdditionalCSRF_FormWithTokenNoFinding(t *testing.T) {
	store := NewPassiveScanStore()
	body := `<html><body>
		<form method="POST" action="/transfer">
			<input type="hidden" name="csrf_token" value="xyz">
			<input type="text" name="amount">
		</form>
	</body></html>`
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/transfer-form-safe",
		ResponseStatus: http.StatusOK,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
			"Set-Cookie":   "session=abc123; HttpOnly",
		},
		ResponseBody: body,
	})

	findings := store.List()
	for _, f := range findings {
		if f.ID == "proxy-csrf-form-missing-token" {
			t.Fatalf("did not expect a missing-token finding when form has a csrf_token field")
		}
	}
}

func TestPassiveCheckAdditionalCSRF_RequestMissingToken(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodPost,
		URL:            "https://example.test/api/transfer",
		ResponseStatus: http.StatusOK,
		RequestHeaders: map[string]string{
			"Cookie":       "session=abc123",
			"Content-Type": "application/json",
		},
		RequestBody: `{"amount":100}`,
	})

	findings := store.List()
	found := false
	for _, f := range findings {
		if f.ID == "proxy-csrf-request-missing-token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected proxy-csrf-request-missing-token finding, got %+v", findings)
	}
}

func TestPassiveCheckAdditionalCSRF_RequestWithTokenNoFinding(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodPost,
		URL:            "https://example.test/api/transfer-safe",
		ResponseStatus: http.StatusOK,
		RequestHeaders: map[string]string{
			"Cookie":       "session=abc123",
			"X-CSRF-Token": "sometoken",
		},
		RequestBody: `{"amount":100}`,
	})

	findings := store.List()
	for _, f := range findings {
		if f.ID == "proxy-csrf-request-missing-token" {
			t.Fatalf("did not expect a missing-token finding when X-CSRF-Token header is present")
		}
	}
}

func TestPassiveCheckAdditionalCSRF_GetRequestNotFlagged(t *testing.T) {
	store := NewPassiveScanStore()
	store.Analyze(&model.ProxyRequest{
		Method:         http.MethodGet,
		URL:            "https://example.test/api/data",
		ResponseStatus: http.StatusOK,
		RequestHeaders: map[string]string{
			"Cookie": "session=abc123",
		},
	})

	findings := store.List()
	for _, f := range findings {
		if f.ID == "proxy-csrf-request-missing-token" {
			t.Fatalf("did not expect a CSRF finding for a GET request")
		}
	}
}
