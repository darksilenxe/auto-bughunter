package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/proxy"
)

func TestHandleProxyScope_UnconfiguredProxyReturns503(t *testing.T) {
	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/proxy/scope", nil)
	srv.handleProxyScope(rec, req)
	if rec.Code != 503 {
		t.Fatalf("expected 503 when proxy is not configured, got %d", rec.Code)
	}
}

func TestHandleProxyScope_GetReturnsCurrentScope(t *testing.T) {
	p := proxy.NewServer(nil)
	srv := &Server{proxyServer: p}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/proxy/scope", nil)
	srv.handleProxyScope(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleProxyScope_PutUpdatesScope(t *testing.T) {
	p := proxy.NewServer(nil)
	srv := &Server{proxyServer: p}

	body, _ := json.Marshal(map[string]any{
		"includeHosts": []string{"Example.com", "*.Example.com"},
		"excludePaths": []string{"logout"},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/proxy/scope", bytes.NewReader(body))
	srv.handleProxyScope(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	scope := p.Scope()
	if len(scope.IncludeHosts) != 2 || scope.IncludeHosts[0] != "example.com" {
		t.Fatalf("expected normalized lowercase include hosts, got %+v", scope.IncludeHosts)
	}
	if len(scope.ExcludePaths) != 1 || scope.ExcludePaths[0] != "/logout" {
		t.Fatalf("expected normalized leading-slash exclude path, got %+v", scope.ExcludePaths)
	}

	if !p.InScope("https://api.example.com/dashboard") {
		t.Fatalf("expected api.example.com to be in scope after update")
	}
	if p.InScope("https://api.example.com/logout") {
		t.Fatalf("expected /logout path to be excluded after update")
	}
	if p.InScope("https://evil.test/dashboard") {
		t.Fatalf("expected evil.test to be out of scope after update")
	}
}

func TestHandleProxyScope_InvalidMethodRejected(t *testing.T) {
	p := proxy.NewServer(nil)
	srv := &Server{proxyServer: p}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/proxy/scope", nil)
	srv.handleProxyScope(rec, req)
	if rec.Code != 405 {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
