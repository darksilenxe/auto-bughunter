package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunCommandInjectionProbe_PassiveOnlyDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runCommandInjectionProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestCheckOutputMarker_Detected(t *testing.T) {
	body := "output: " + cmdInjectionOutputMarker + " done"
	if !checkOutputMarker(body) {
		t.Fatal("expected output marker detection")
	}
}

func TestCheckOutputMarker_NotDetected(t *testing.T) {
	if checkOutputMarker(`{"ok":true}`) {
		t.Fatal("unexpected output marker detection in clean body")
	}
}

func TestRunCommandInjectionProbe_CleanResponseNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runCommandInjectionProbe(context.Background(), RunInput{
		Target: srv.URL,
	}, "")
	if len(got) != 0 {
		t.Fatalf("expected no findings for clean response, got %d", len(got))
	}
}

