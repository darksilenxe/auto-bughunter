package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/proxy"
)

func TestHandleProxyBypass403_UnconfiguredProxyReturns503(t *testing.T) {
	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/proxy/bypass403", bytes.NewReader([]byte(`{"requestId":"x"}`)))
	srv.handleProxyBypass403(rec, req)
	if rec.Code != 503 {
		t.Fatalf("expected 503 when proxy is not configured, got %d", rec.Code)
	}
}

func TestHandleProxyBypass403_MissingRequestID(t *testing.T) {
	p := proxy.NewServer(proxy.NewMemStore())
	srv := &Server{proxyServer: p}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/proxy/bypass403", bytes.NewReader([]byte(`{}`)))
	srv.handleProxyBypass403(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for missing requestId, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleProxyBypass403_WrongMethod(t *testing.T) {
	p := proxy.NewServer(proxy.NewMemStore())
	srv := &Server{proxyServer: p}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/proxy/bypass403", nil)
	srv.handleProxyBypass403(rec, req)
	if rec.Code != 405 {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHandleProxyBypass403_UnknownRequestReturns400(t *testing.T) {
	p := proxy.NewServer(proxy.NewMemStore())
	srv := &Server{proxyServer: p}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/proxy/bypass403", bytes.NewReader([]byte(`{"requestId":"missing"}`)))
	srv.handleProxyBypass403(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for unknown request id, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleProxyBypass429_UnconfiguredProxyReturns503(t *testing.T) {
	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/proxy/bypass429", bytes.NewReader([]byte(`{"requestId":"x"}`)))
	srv.handleProxyBypass429(rec, req)
	if rec.Code != 503 {
		t.Fatalf("expected 503 when proxy is not configured, got %d", rec.Code)
	}
}

func TestHandleProxyActiveScanPlusPlus_UnconfiguredProxyReturns503(t *testing.T) {
	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/proxy/activescan-plusplus", bytes.NewReader([]byte(`{"requestId":"x"}`)))
	srv.handleProxyActiveScanPlusPlus(rec, req)
	if rec.Code != 503 {
		t.Fatalf("expected 503 when proxy is not configured, got %d", rec.Code)
	}
}

func TestHandleProxyAntiCSRFReferer_UnconfiguredProxyReturns503(t *testing.T) {
	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/proxy/anticsrf-referer", bytes.NewReader([]byte(`{"requestId":"x"}`)))
	srv.handleProxyAntiCSRFReferer(rec, req)
	if rec.Code != 503 {
		t.Fatalf("expected 503 when proxy is not configured, got %d", rec.Code)
	}
}

func TestHandleProxyAntiCSRFReferer_MissingRequestIDValidJSON(t *testing.T) {
	p := proxy.NewServer(proxy.NewMemStore())
	srv := &Server{proxyServer: p}
	body, _ := json.Marshal(map[string]string{"requestId": ""})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/proxy/anticsrf-referer", bytes.NewReader(body))
	srv.handleProxyAntiCSRFReferer(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for empty requestId, got %d body=%s", rec.Code, rec.Body.String())
	}
}
