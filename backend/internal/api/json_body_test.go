package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONBodyRejectsOversizedBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"x":"`+strings.Repeat("a", maxJSONBodyBytes)+`"}`))
	rec := httptest.NewRecorder()

	var dst map[string]string
	err := decodeJSONBody(rec, req, &dst)

	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("expected MaxBytesError, got %T: %v", err, err)
	}
}

func TestExtractAPIKeyOnlyAllowsQueryForBrowserOnlyEndpoints(t *testing.T) {
	blocked := httptest.NewRequest(http.MethodGet, "/api/report/scan-1?api_key=leaky", nil)
	if got := extractAPIKey(blocked); got != "" {
		t.Fatalf("expected report query api key to be ignored, got %q", got)
	}

	allowed := httptest.NewRequest(http.MethodGet, "/api/scan/scan-1/events?api_key=stream", nil)
	if got := extractAPIKey(allowed); got != "stream" {
		t.Fatalf("expected events query api key, got %q", got)
	}

	browse := httptest.NewRequest(http.MethodGet, "/api/proxy/browse?api_key=leaky", nil)
	if got := extractAPIKey(browse); got != "" {
		t.Fatalf("expected proxy browse query api key to be ignored, got %q", got)
	}
}
