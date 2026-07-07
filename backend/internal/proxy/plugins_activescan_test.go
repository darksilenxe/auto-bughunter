package proxy

import (
	"context"
	"testing"
)

func TestRunActiveScanPlusPlus_UnknownRequestID(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)
	_, err := RunActiveScanPlusPlus(context.Background(), srv, "does-not-exist")
	if err == nil {
		t.Fatalf("expected error for unknown request id")
	}
}

func TestErrString(t *testing.T) {
	if errString(nil) != "" {
		t.Fatalf("expected empty string for nil error")
	}
	if errString(errTestSentinel{}) != "boom" {
		t.Fatalf("expected 'boom', got %q", errString(errTestSentinel{}))
	}
}

type errTestSentinel struct{}

func (errTestSentinel) Error() string { return "boom" }
