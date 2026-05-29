package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestCRLFHeaderInjected(t *testing.T) {
	h := http.Header{}
	if crlfHeaderInjected(h) {
		t.Fatal("empty headers must not match")
	}
	h.Set(crlfInjectedHeaderName, crlfInjectedHeaderValue)
	if !crlfHeaderInjected(h) {
		t.Fatal("injected marker header must be detected")
	}
	h2 := http.Header{}
	h2.Set(crlfInjectedHeaderName, "somethingelse")
	if crlfHeaderInjected(h2) {
		t.Fatal("wrong marker value must not match")
	}
}

func TestRunCRLFInjectionProbe_PassiveOnlyDisables(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	got := svc.runCRLFInjectionProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}
