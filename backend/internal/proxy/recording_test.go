package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

type recordingStoreStub struct{}

func (recordingStoreStub) SaveProxyRequest(_ context.Context, _ *model.ProxyRequest) error {
	return nil
}
func (recordingStoreStub) ListProxyRequests(_ context.Context) ([]*model.ProxyRequest, error) {
	return nil, nil
}
func (recordingStoreStub) GetProxyRequest(_ context.Context, _ string) (*model.ProxyRequest, error) {
	return nil, nil
}
func (recordingStoreStub) ClearProxyRequests(_ context.Context) error { return nil }

func TestRecordingTransportFeedsPassiveStore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	passive := NewPassiveScanStore()
	rt := &RecordingTransport{
		Wrapped:      http.DefaultTransport,
		Store:        recordingStoreStub{},
		PassiveStore: passive,
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/profile?token=secret", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	_ = resp.Body.Close()

	found := false
	for _, f := range passive.List() {
		if f.ID == "proxy-sensitive-data-in-url" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected passive finding proxy-sensitive-data-in-url, got %+v", passive.List())
	}
}
