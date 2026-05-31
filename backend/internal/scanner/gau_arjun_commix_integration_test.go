package scanner

import (
	"context"
	"reflect"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestParseGauURLs_FiltersAndDedupes(t *testing.T) {
	raw := "https://example.com/a\n" +
		"https://example.com/a\n" + // duplicate
		"http://example.com/b?x=1\n" +
		"ftp://example.com/skip\n" + // non-http(s)
		"not-a-url\n" +
		"   \n" +
		"https://evil.test/out-of-scope\n"
	scope := model.ScanScope{IncludeHosts: []string{"example.com"}}
	got := parseGauURLs(raw, scope)
	want := []string{
		"http://example.com/b?x=1",
		"https://example.com/a",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGauURLs = %v, want %v", got, want)
	}
}

func TestParseArjunParams_ListShape(t *testing.T) {
	data := []byte(`{"https://example.com/api": ["id", "token", "id"]}`)
	got := parseArjunParams(data)
	want := []string{"id", "token"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseArjunParams (list) = %v, want %v", got, want)
	}
}

func TestParseArjunParams_ObjectShape(t *testing.T) {
	data := []byte(`{"https://example.com/api": {"params": ["q", "page"], "method": "GET"}}`)
	got := parseArjunParams(data)
	want := []string{"page", "q"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseArjunParams (object) = %v, want %v", got, want)
	}
}

func TestParseArjunParams_EmptyOrInvalid(t *testing.T) {
	if got := parseArjunParams(nil); got != nil {
		t.Fatalf("expected nil for nil input, got %v", got)
	}
	if got := parseArjunParams([]byte("not json")); got != nil {
		t.Fatalf("expected nil for invalid json, got %v", got)
	}
}

func TestCommixReportsVulnerable(t *testing.T) {
	cases := map[string]bool{
		"The parameter 'cmd' is vulnerable to command injection": true,
		"target appears to be injectable":                        true,
		"all tested parameters do not appear to be injectable":   true, // contains "injectable"
		"no vulnerabilities were identified":                     false,
		"":                                                       false,
	}
	for in, want := range cases {
		if got := commixReportsVulnerable(in); got != want {
			t.Errorf("commixReportsVulnerable(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestJoinCookieHeader(t *testing.T) {
	if got := joinCookieHeader(nil); got != "" {
		t.Fatalf("expected empty for nil map, got %q", got)
	}
	got := joinCookieHeader(map[string]string{"b": "2", "a": "1"})
	want := "a=1; b=2"
	if got != want {
		t.Fatalf("joinCookieHeader = %q, want %q", got, want)
	}
}

func TestRunGau_DisabledReturnsInfoFinding(t *testing.T) {
	s := NewService(Config{EnableGau: false})
	findings := s.runGau(context.Background(), "https://example.com", model.ScanScope{}, nil)
	if len(findings) != 1 || findings[0].ID != "gau-disabled" {
		t.Fatalf("expected gau-disabled finding, got %+v", findings)
	}
}

func TestRunArjun_DisabledReturnsInfoFinding(t *testing.T) {
	s := NewService(Config{EnableArjun: false})
	findings := s.runArjun(context.Background(), "https://example.com", model.ScanScope{}, nil)
	if len(findings) != 1 || findings[0].ID != "arjun-disabled" {
		t.Fatalf("expected arjun-disabled finding, got %+v", findings)
	}
}

func TestRunCommix_DisabledReturnsInfoFinding(t *testing.T) {
	s := NewService(Config{EnableCommix: false})
	findings := s.runCommix(context.Background(), "https://example.com", model.ScanAuthProfile{})
	if len(findings) != 1 || findings[0].ID != "commix-disabled" {
		t.Fatalf("expected commix-disabled finding, got %+v", findings)
	}
}

func TestRunGau_BinaryMissing(t *testing.T) {
	s := NewService(Config{EnableGau: true, GauBinary: "definitely-not-a-real-binary-xyz"})
	findings := s.runGau(context.Background(), "https://example.com", model.ScanScope{}, nil)
	if len(findings) != 1 || findings[0].ID != "gau-binary-missing" {
		t.Fatalf("expected gau-binary-missing finding, got %+v", findings)
	}
}

func TestRunArjun_BinaryMissing(t *testing.T) {
	s := NewService(Config{EnableArjun: true, ArjunBinary: "definitely-not-a-real-binary-xyz"})
	findings := s.runArjun(context.Background(), "https://example.com", model.ScanScope{}, nil)
	if len(findings) != 1 || findings[0].ID != "arjun-binary-missing" {
		t.Fatalf("expected arjun-binary-missing finding, got %+v", findings)
	}
}

func TestRunCommix_BinaryMissing(t *testing.T) {
	s := NewService(Config{EnableCommix: true, CommixBinary: "definitely-not-a-real-binary-xyz"})
	findings := s.runCommix(context.Background(), "https://example.com", model.ScanAuthProfile{})
	if len(findings) != 1 || findings[0].ID != "commix-binary-missing" {
		t.Fatalf("expected commix-binary-missing finding, got %+v", findings)
	}
}
