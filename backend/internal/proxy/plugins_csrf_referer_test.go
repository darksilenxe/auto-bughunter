package proxy

import (
	"context"
	"net/http"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestExtractCSRFToken_HiddenInputDjangoStyle(t *testing.T) {
	html := `<html><body><form method="post">
		<input type="hidden" name="csrfmiddlewaretoken" value="abc123XYZ">
		<input type="text" name="username">
	</form></body></html>`
	name, value, found := extractCSRFToken(html)
	if !found {
		t.Fatalf("expected to find a CSRF token")
	}
	if name != "csrfmiddlewaretoken" {
		t.Fatalf("expected field name csrfmiddlewaretoken, got %q", name)
	}
	if value != "abc123XYZ" {
		t.Fatalf("expected value abc123XYZ, got %q", value)
	}
}

func TestExtractCSRFToken_MetaTag(t *testing.T) {
	html := `<html><head><meta name="csrf-token" content="metatoken456"></head><body></body></html>`
	name, value, found := extractCSRFToken(html)
	if !found {
		t.Fatalf("expected to find a CSRF token from meta tag")
	}
	if name != "csrf-token" {
		t.Fatalf("expected field name csrf-token, got %q", name)
	}
	if value != "metatoken456" {
		t.Fatalf("expected value metatoken456, got %q", value)
	}
}

func TestExtractCSRFToken_NoneFound(t *testing.T) {
	html := `<html><body><form method="post"><input type="text" name="username"></form></body></html>`
	_, _, found := extractCSRFToken(html)
	if found {
		t.Fatalf("expected no CSRF token to be found")
	}
}

func TestReplaceFormFieldValue(t *testing.T) {
	body := "username=bob&csrf_token=old&******"
	got := replaceFormFieldValue(body, "csrf_token", "new value")
	want := "username=bob&csrf_token=new+value&******"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestReplaceFormFieldValue_FieldAtStart(t *testing.T) {
	body := "csrf_token=old&username=bob"
	got := replaceFormFieldValue(body, "csrf_token", "fresh")
	want := "csrf_token=fresh&username=bob"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestRunAntiCSRFFromReferer_NoRefererHeader(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)
	req := &model.ProxyRequest{
		ID:     "req-no-referer",
		Method: http.MethodPost,
		URL:    "https://example.test/action",
	}
	if err := store.SaveProxyRequest(context.Background(), req); err != nil {
		t.Fatalf("save: %v", err)
	}
	_, err := RunAntiCSRFFromReferer(context.Background(), srv, "req-no-referer")
	if err == nil {
		t.Fatalf("expected error for request with no Referer header")
	}
}

func TestRunAntiCSRFFromReferer_UnknownRequestID(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)
	_, err := RunAntiCSRFFromReferer(context.Background(), srv, "missing")
	if err == nil {
		t.Fatalf("expected error for unknown request id")
	}
}

func TestRunAntiCSRFFromReferer_LoopbackRefererBlocked(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)
	req := &model.ProxyRequest{
		ID:     "req-loopback-referer",
		Method: http.MethodPost,
		URL:    "https://example.test/action",
		RequestHeaders: map[string]string{
			"Referer": "http://127.0.0.1:9/page",
		},
	}
	if err := store.SaveProxyRequest(context.Background(), req); err != nil {
		t.Fatalf("save: %v", err)
	}
	result, err := RunAntiCSRFFromReferer(context.Background(), srv, "req-loopback-referer")
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if result.Error == "" {
		t.Fatalf("expected result-level error for blocked loopback referer, got %+v", result)
	}
}
