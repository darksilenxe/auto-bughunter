package scanner

import (
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/proxy"
)

func TestPassiveFindingsForTargetSinceFiltersByHost(t *testing.T) {
	s := NewService(Config{})
	passive := proxy.NewPassiveScanStore()
	s.SetPassiveScanStore(passive)

	since := time.Now().UTC().Add(-time.Minute)
	passive.Analyze(proxyRequestForPassive("https://app.example/account?token=abc"))
	passive.Analyze(proxyRequestForPassive("https://other.example/account?token=abc"))

	got := s.passiveFindingsForTargetSince("https://app.example", since)
	if len(got) == 0 {
		t.Fatalf("expected at least one passive finding for target host")
	}
	for _, f := range got {
		if f.AffectedURL == "" || hostFromRawURL(f.AffectedURL) != "app.example" {
			t.Fatalf("expected only app.example findings, got %+v", got)
		}
	}
}

func proxyRequestForPassive(rawURL string) *model.ProxyRequest {
	return &model.ProxyRequest{
		Method:         "GET",
		URL:            rawURL,
		ResponseStatus: 200,
		ResponseHeaders: map[string]string{
			"Content-Type": "text/html",
		},
		ResponseBody: "<html><body>ok</body></html>",
	}
}
