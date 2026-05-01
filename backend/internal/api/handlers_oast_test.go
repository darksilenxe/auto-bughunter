package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/oast"
)

func newOASTTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	o := oast.NewService(oast.Config{PublicBaseURL: "http://oast.test"})
	s := &Server{}
	s.SetOAST(o)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oast/tokens", s.handleOASTTokens)
	mux.HandleFunc("/api/oast/hits/", s.handleOASTHits)
	return s, httptest.NewServer(mux)
}

func TestOASTHandlers_DisabledWhenServiceMissing(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oast/tokens", s.handleOASTTokens)
	mux.HandleFunc("/api/oast/hits/", s.handleOASTHits)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{"/api/oast/tokens", "/api/oast/hits/abc"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 for %s without OAST, got %d", path, resp.StatusCode)
		}
	}
}

func TestOASTHandlers_IssueListAndHits(t *testing.T) {
	_, srv := newOASTTestServer(t)
	defer srv.Close()

	// Issue a token.
	resp, err := http.Post(srv.URL+"/api/oast/tokens", "application/json",
		strings.NewReader(`{"scanId":"scan-x","label":"manual"}`))
	if err != nil {
		t.Fatalf("POST tokens: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 issuing token, got %d: %s", resp.StatusCode, body)
	}
	var issued struct {
		Token struct {
			Token       string `json:"token"`
			CallbackURL string `json:"callbackUrl"`
			ScanID      string `json:"scanId"`
		} `json:"token"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		t.Fatalf("parse issue body: %v (%s)", err, body)
	}
	if issued.Token.Token == "" || issued.Token.ScanID != "scan-x" {
		t.Fatalf("unexpected token payload: %+v", issued)
	}

	// List tokens filtered by scanId.
	resp, err = http.Get(srv.URL + "/api/oast/tokens?scanId=scan-x")
	if err != nil {
		t.Fatalf("GET tokens: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), issued.Token.Token) {
		t.Fatalf("listed tokens should contain issued token: %s", body)
	}

	// Hits for an unknown token = 404.
	resp, err = http.Get(srv.URL + "/api/oast/hits/deadbeef")
	if err != nil {
		t.Fatalf("GET hits: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown token, got %d", resp.StatusCode)
	}

	// Hits for the known token = 200 with empty list.
	resp, err = http.Get(srv.URL + "/api/oast/hits/" + issued.Token.Token)
	if err != nil {
		t.Fatalf("GET hits: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"hits":[]`) {
		t.Fatalf("expected empty hits list, got: %s", body)
	}
}

func TestOASTHandlers_IssueRejectsMalformedJSON(t *testing.T) {
	_, srv := newOASTTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/oast/tokens", "application/json",
		strings.NewReader(`{"scanId": not-json`))
	if err != nil {
		t.Fatalf("POST tokens: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d", resp.StatusCode)
	}
}

func TestOASTHandlers_IssueAcceptsEmptyBody(t *testing.T) {
	_, srv := newOASTTestServer(t)
	defer srv.Close()

	// Empty body must remain valid (both fields are optional).
	resp, err := http.Post(srv.URL+"/api/oast/tokens", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST tokens: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for empty body, got %d", resp.StatusCode)
	}
}
