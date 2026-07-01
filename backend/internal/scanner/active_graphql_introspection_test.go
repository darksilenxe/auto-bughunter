package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunActiveGraphQLIntrospectionProbe_FindsEnabledIntrospection(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/graphql") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"name":"User"}]}}}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	// Provide /graphql via SeedRuntimeEndpoints so we don't need to mine
	// the body.
	in := RunInput{
		Target: target.URL,
		Options: model.ScanOptions{
			SeedRuntimeEndpoints: []string{target.URL + "/graphql"},
		},
	}
	findings := svc.runActiveGraphQLIntrospectionProbe(context.Background(), in, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 introspection finding, got %d", len(findings))
	}
	if findings[0].ID != "active-graphql-introspection" {
		t.Fatalf("unexpected ID %q", findings[0].ID)
	}
}

func TestRunActiveGraphQLIntrospectionProbe_NoFindingWhenDisabled(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"GraphQL introspection is disabled"}]}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{
		Target:  target.URL,
		Options: model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/graphql"}},
	}
	findings := svc.runActiveGraphQLIntrospectionProbe(context.Background(), in, "")
	if len(findings) != 0 {
		t.Fatalf("expected no finding when introspection disabled, got %d", len(findings))
	}
}

func TestRunActiveGraphQLIntrospectionProbe_SkipsNonGraphQLEndpoints(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Non-GraphQL endpoint that would erroneously echo something
		// containing __schema and queryType — must still be skipped
		// because the URL does not match a GraphQL hint.
		w.Write([]byte(`{"__schema":{"queryType":{"name":"x"}}}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{
		Target:  target.URL,
		Options: model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/api/users"}},
	}
	findings := svc.runActiveGraphQLIntrospectionProbe(context.Background(), in, "")
	if len(findings) != 0 {
		t.Fatalf("non-GraphQL endpoints must be skipped, got %d findings", len(findings))
	}
}

func TestIsGraphQLIntrospectionResponse(t *testing.T) {
	if !isGraphQLIntrospectionResponse(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`) {
		t.Fatal("expected positive match")
	}
	if isGraphQLIntrospectionResponse(`{"errors":[{"message":"introspection disabled"}]}`) {
		t.Fatal("error envelope must not match")
	}
	if isGraphQLIntrospectionResponse("") {
		t.Fatal("empty body must not match")
	}
}

// TestRunActiveGraphQLIntrospectionProbe_SkipsNonJSONResponses verifies the
// Phase 1 JSON-shape gate: an HTML error page that happens to mention
// `__schema` / `queryType` must not be treated as introspection evidence.
func TestRunActiveGraphQLIntrospectionProbe_SkipsNonJSONResponses(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body>Blocked: __schema queryType access denied</body></html>`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{
		Target:  target.URL,
		Options: model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/graphql"}},
	}
	findings := svc.runActiveGraphQLIntrospectionProbe(context.Background(), in, "")
	if len(findings) != 0 {
		t.Fatalf("non-JSON response must be skipped by the shape gate, got %d findings", len(findings))
	}
}

// TestRunActiveGraphQLIntrospectionProbe_EmitsResponseShapeTag verifies the
// Phase 1 shape tag is present on the emitted finding for downstream
// evidence normalisation.
func TestRunActiveGraphQLIntrospectionProbe_EmitsResponseShapeTag(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{
		Target:  target.URL,
		Options: model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/graphql"}},
	}
	findings := svc.runActiveGraphQLIntrospectionProbe(context.Background(), in, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := findings[0].EvidenceFields["responseShape"]; got != ShapeJSON.String() {
		t.Fatalf("expected responseShape=%q, got %q", ShapeJSON.String(), got)
	}
}
