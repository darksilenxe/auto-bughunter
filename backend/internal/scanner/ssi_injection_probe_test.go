package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunSSIInjectionProbe_PassiveOnlyDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runSSIInjectionProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestDetectSSIMarker_ExecMarkerDetected(t *testing.T) {
	// Simulate a response where the SSI exec directive was evaluated and
	// the ssiExecMarker appears in the output (the raw payload is absent).
	body := "Hello World " + ssiExecMarker + " goodbye"
	hit := detectSSIMarker(body)
	if hit == nil {
		t.Fatal("expected SSI marker detection for exec-echo payload response")
	}
	if hit.label != "exec-echo" {
		t.Errorf("expected label exec-echo, got %s", hit.label)
	}
}

func TestDetectSSIMarker_RawEchoNotConfirmed(t *testing.T) {
	// Simulate a server that echoes the raw payload back verbatim — SSI not processed.
	rawPayload := ssiPayloads[0].payload // exec-echo payload
	body := rawPayload                   // verbatim echo
	hit := detectSSIMarker(body)
	// exec-echo: raw payload contains the marker, so raw-echo should be skipped.
	// The marker appears in the body but so does the raw payload → not confirmed.
	if hit != nil && hit.label == "exec-echo" {
		t.Error("expected no exec-echo confirmation when raw payload is echoed back verbatim")
	}
}

func TestDetectSSIMarker_ArithmeticMarkerDetected(t *testing.T) {
	body := "Result: 49 done"
	hit := detectSSIMarker(body)
	if hit == nil {
		t.Fatal("expected detection for ssiOutputMarker (arithmetic eval)")
	}
}

func TestDetectSSIMarker_CleanBodyNoMatch(t *testing.T) {
	body := `{"ok":true}`
	hit := detectSSIMarker(body)
	if hit != nil {
		t.Fatalf("expected nil for clean body, got %+v", hit)
	}
}

