package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func newJWTProbeSession(token string) *ScanSession {
	sess := NewScanSession()
	sess.TokenStore.Set("bearer", token)
	return sess
}

func TestJWTProbe_AlgNoneConfirmedAgainstInvalidControl(t *testing.T) {
	original, err := buildJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "1", "role": "user"},
		"strong-secret",
	)
	if err != nil {
		t.Fatalf("build original token: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case token == original:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":"alice"}`))
		case token == jwtInvalidControlToken(original):
			w.WriteHeader(http.StatusUnauthorized)
		case isJWT(token):
			hdr, _, _, err := parseJWT(token)
			if err == nil && hdr["alg"] == "none" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"user":"alice"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.runJWTProbe(context.Background(), RunInput{
		Target:      srv.URL,
		AuthProfile: model.ScanAuthProfile{Headers: map[string]string{"Authorization": "Bearer " + original}},
		Options:     model.ScanOptions{},
		Session:     newJWTProbeSession(original),
	})

	found := false
	for _, f := range findings {
		if f.ID == "jwt-alg-none" {
			found = true
			if f.EvidenceFields["differentialConfirmed"] != "true" {
				t.Fatalf("expected differential confirmation, got %+v", f.EvidenceFields)
			}
		}
	}
	if !found {
		t.Fatalf("expected jwt-alg-none finding, got %+v", findings)
	}
}

func TestJWTProbe_WeakSecretConfirmedAgainstInvalidControl(t *testing.T) {
	payload := map[string]interface{}{"sub": "1", "role": "user"}
	original, err := buildJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		payload,
		"server-secret",
	)
	if err != nil {
		t.Fatalf("build original token: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case token == original:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":"alice"}`))
		case token == jwtInvalidControlToken(original):
			w.WriteHeader(http.StatusUnauthorized)
		case !isJWT(token):
			w.WriteHeader(http.StatusUnauthorized)
		default:
			hdr, pay, _, err := parseJWT(token)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			rebuilt, err := buildJWT(hdr, pay, "secret")
			if err == nil && rebuilt == token {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"user":"alice"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.runJWTProbe(context.Background(), RunInput{
		Target:      srv.URL,
		AuthProfile: model.ScanAuthProfile{Headers: map[string]string{"Authorization": "Bearer " + original}},
		Options:     model.ScanOptions{},
		Session:     newJWTProbeSession(original),
	})

	found := false
	for _, f := range findings {
		if f.ID == "jwt-weak-secret" {
			found = true
			if f.EvidenceFields["differentialConfirmed"] != "true" {
				t.Fatalf("expected differential confirmation, got %+v", f.EvidenceFields)
			}
		}
	}
	if !found {
		t.Fatalf("expected jwt-weak-secret finding, got %+v", findings)
	}
}

func TestJWTProbe_SuppressesWhenInvalidControlMatchesBaseline(t *testing.T) {
	original, err := buildJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "1", "role": "user"},
		"strong-secret",
	)
	if err != nil {
		t.Fatalf("build original token: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"public":true}`))
	}))
	defer srv.Close()

	svc := NewService(Config{})
	findings := svc.runJWTProbe(context.Background(), RunInput{
		Target:      srv.URL,
		AuthProfile: model.ScanAuthProfile{Headers: map[string]string{"Authorization": "Bearer " + original}},
		Options:     model.ScanOptions{},
		Session:     newJWTProbeSession(original),
	})

	if len(findings) != 0 {
		t.Fatalf("expected controls to suppress findings, got %+v", findings)
	}
}
