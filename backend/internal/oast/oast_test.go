package oast

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIssueAndRecord(t *testing.T) {
	svc := NewService(Config{PublicBaseURL: "http://oast.test"})
	tok := svc.Issue("scan-1", "ssrf-header-probe")

	if tok.Token == "" || !strings.HasPrefix(tok.CallbackURL, "http://oast.test/") {
		t.Fatalf("unexpected token/url: %+v", tok)
	}
	if tok.ScanID != "scan-1" || tok.Label != "ssrf-header-probe" {
		t.Fatalf("metadata not preserved: %+v", tok)
	}

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/" + tok.Token + "/cb?x=1")
	if err != nil {
		t.Fatalf("callback request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from known token, got %d", resp.StatusCode)
	}

	hits, ok := svc.Hits(tok.Token)
	if !ok || len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d (ok=%v)", len(hits), ok)
	}
	if hits[0].Method != "GET" || hits[0].Path != "/cb" || hits[0].Query != "x=1" {
		t.Fatalf("unexpected hit captured: %+v", hits[0])
	}
}

func TestUnknownTokenReturns404(t *testing.T) {
	svc := NewService(Config{PublicBaseURL: "http://oast.test"})
	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/deadbeef")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestExpiry(t *testing.T) {
	svc := NewService(Config{PublicBaseURL: "http://oast.test", TTL: 50 * time.Millisecond})
	base := time.Now()
	svc.now = func() time.Time { return base }
	tok := svc.Issue("", "")

	// Before expiry the token is known.
	if _, ok := svc.Hits(tok.Token); !ok {
		t.Fatalf("token should be known immediately after issue")
	}
	// Advance the clock past expiry; record should refuse.
	svc.now = func() time.Time { return base.Add(time.Hour) }
	if ok := svc.record(Hit{Token: tok.Token, Method: "GET", Path: "/"}); ok {
		t.Fatalf("expired token should not record")
	}
	// gc runs on next Issue; old token is evicted.
	svc.Issue("", "")
	if list := svc.Tokens(""); len(list) != 1 {
		t.Fatalf("expected only the new token after gc, got %d", len(list))
	}
}

func TestWaitReturnsOnHit(t *testing.T) {
	svc := NewService(Config{PublicBaseURL: "http://oast.test"})
	tok := svc.Issue("", "")
	go func() {
		time.Sleep(20 * time.Millisecond)
		svc.record(Hit{Token: tok.Token, Method: "GET", Path: "/", ReceivedAt: time.Now()})
	}()
	hits := svc.Wait(tok.Token, time.Second)
	if len(hits) != 1 {
		t.Fatalf("expected Wait to return 1 hit, got %d", len(hits))
	}
}

func TestWaitTimesOut(t *testing.T) {
	svc := NewService(Config{PublicBaseURL: "http://oast.test"})
	tok := svc.Issue("", "")
	start := time.Now()
	hits := svc.Wait(tok.Token, 30*time.Millisecond)
	if len(hits) != 0 {
		t.Fatalf("expected no hits, got %d", len(hits))
	}
	if time.Since(start) < 25*time.Millisecond {
		t.Fatalf("Wait returned too quickly")
	}
}

func TestTokensFilterByScan(t *testing.T) {
	svc := NewService(Config{PublicBaseURL: "http://oast.test"})
	svc.Issue("scan-a", "")
	svc.Issue("scan-a", "")
	svc.Issue("scan-b", "")
	if got := len(svc.Tokens("scan-a")); got != 2 {
		t.Fatalf("expected 2 tokens for scan-a, got %d", got)
	}
	if got := len(svc.Tokens("")); got != 3 {
		t.Fatalf("expected 3 tokens overall, got %d", got)
	}
}

func TestMaxHitsPerTokenIsBounded(t *testing.T) {
	svc := NewService(Config{PublicBaseURL: "http://oast.test", MaxHitsPerToken: 3})
	tok := svc.Issue("", "")
	for i := 0; i < 10; i++ {
		svc.record(Hit{Token: tok.Token, Method: "GET", Path: "/"})
	}
	hits, _ := svc.Hits(tok.Token)
	if len(hits) != 3 {
		t.Fatalf("expected hits to be capped at 3, got %d", len(hits))
	}
}

func TestConfiguredReportsState(t *testing.T) {
	if NewService(Config{}).Configured() {
		t.Fatalf("empty PublicBaseURL must report not configured")
	}
	if !NewService(Config{PublicBaseURL: "http://x"}).Configured() {
		t.Fatalf("non-empty PublicBaseURL must report configured")
	}
}
