package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunXSSIJSONPProbe_PassiveOnlyDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runXSSIJSONPProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) == 0 {
		// PassiveOnly returns nil — pass.
		return
	}
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestDetectJSONPReflection_Reflected(t *testing.T) {
	const probeCallback = "abh_jsonp_probe_7a3c1"
	body := probeCallback + `({"user":"alice","token":"secret"})`
	if !detectJSONPReflection(body, probeCallback) {
		t.Fatal("expected JSONP reflection detection when body starts with probe callback")
	}
}

func TestDetectJSONPReflection_NotReflected(t *testing.T) {
	const probeCallback = "abh_jsonp_probe_7a3c1"
	body := `{"user":"alice","token":"secret"}`
	if detectJSONPReflection(body, probeCallback) {
		t.Fatal("unexpected JSONP reflection detection for plain JSON body")
	}
}

func TestDetectXSSIArray_JavaScriptContentType(t *testing.T) {
	body := `[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]`
	if !detectXSSIArray(body, "application/javascript") {
		t.Fatal("expected XSSI array detection for JS content-type with top-level array")
	}
}

func TestDetectXSSIArray_JSONContentType_NoFinding(t *testing.T) {
	body := `[{"id":1}]`
	if detectXSSIArray(body, "application/json") {
		t.Fatal("unexpected XSSI array detection for application/json content-type")
	}
}

