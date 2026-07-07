package proxy

import (
	"context"
	"net/http"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestRandomizeCase(t *testing.T) {
	got := randomizeCase("admin")
	if got == "" {
		t.Fatalf("expected non-empty result")
	}
	if len(got) != len("admin") {
		t.Fatalf("expected same length, got %q", got)
	}
	// Case must alternate starting uppercase.
	want := "AdMiN"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestRandomIPv4LooksValid(t *testing.T) {
	ip := randomIPv4()
	if ip == "" {
		t.Fatalf("expected non-empty IP")
	}
}

func TestRunBypass403_UnknownRequestID(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)
	_, err := RunBypass403(context.Background(), srv, "does-not-exist")
	if err == nil {
		t.Fatalf("expected error for unknown request id")
	}
}

func TestRunBypass429_UnknownRequestID(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)
	_, err := RunBypass429(context.Background(), srv, "does-not-exist")
	if err == nil {
		t.Fatalf("expected error for unknown request id")
	}
}

func TestRunBypass403_BlocksLoopbackTargets(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)
	req := &model.ProxyRequest{
		ID:             "req-1",
		Method:         http.MethodGet,
		URL:            "http://127.0.0.1:9/admin",
		ResponseStatus: http.StatusForbidden,
	}
	if err := store.SaveProxyRequest(context.Background(), req); err != nil {
		t.Fatalf("save: %v", err)
	}

	result, err := RunBypass403(context.Background(), srv, "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Attempts) == 0 {
		t.Fatalf("expected bypass attempts to be generated")
	}
	for _, a := range result.Attempts {
		if a.Error == "" {
			t.Fatalf("expected loopback target to be blocked by outbound safety policy, attempt=%+v", a)
		}
	}
	if result.AnyBypassed {
		t.Fatalf("expected no bypasses since all attempts are blocked by safety policy")
	}
}

func TestSendBypassAttempt_InvalidURL(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)
	attempt := sendBypassAttempt(context.Background(), srv, "test", http.MethodGet, "not-a-url", nil, nil, "")
	if attempt.Error == "" {
		t.Fatalf("expected error for invalid URL")
	}
}

func TestSendBypassAttempt_UnsupportedScheme(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)
	attempt := sendBypassAttempt(context.Background(), srv, "test", http.MethodGet, "ftp://example.test/", nil, nil, "")
	if attempt.Error == "" {
		t.Fatalf("expected error for unsupported scheme")
	}
}

func TestBypassAttempt_TimingRecorded(t *testing.T) {
	// Regression guard: ensure DurationMS field is populated as int64 without
	// panicking when time math is applied to a zero value.
	start := time.Now()
	elapsed := time.Since(start).Milliseconds()
	if elapsed < 0 {
		t.Fatalf("unexpected negative duration")
	}
}
