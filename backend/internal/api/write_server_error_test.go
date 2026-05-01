package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteServerError_DoesNotLeakInternalDetail(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/secret", nil)

	internal := errors.New("connection refused: dial tcp 10.0.0.5:5432: i/o timeout")
	writeServerError(rr, req, "list scans", internal)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Result().Body)
	if strings.Contains(string(body), "10.0.0.5") || strings.Contains(string(body), "dial tcp") {
		t.Fatalf("response body leaked internal error detail: %s", body)
	}
	var resp map[string]string
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, body)
	}
	if got := resp["error"]; got != "internal server error" {
		t.Fatalf("expected sanitized error, got %q", got)
	}
}

func TestWriteServerError_NilErrorIsSafe(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	writeServerError(rr, req, "noop", nil)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 even when err is nil, got %d", rr.Code)
	}
}
