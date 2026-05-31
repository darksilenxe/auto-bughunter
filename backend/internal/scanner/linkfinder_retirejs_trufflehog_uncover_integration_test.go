package scanner

import (
	"context"
	"reflect"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestParseLinkFinderEndpoints_ResolvesAndFilters(t *testing.T) {
	raw := "/api/users\n" +
		"/api/users\n" + // duplicate
		"https://example.com/v2/orders\n" +
		"https://evil.test/out-of-scope\n" + // out of scope
		"noslash\n" + // not an endpoint
		"   \n"
	scanScope := model.ScanScope{IncludeHosts: []string{"example.com"}}
	got := parseLinkFinderEndpoints(raw, "https://example.com/app", scanScope)
	want := []string{
		"https://example.com/api/users",
		"https://example.com/v2/orders",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseLinkFinderEndpoints = %v, want %v", got, want)
	}
}

func TestParseRetireJSVulns_WrapperShape(t *testing.T) {
	data := []byte(`{"data":[{"file":"script-0.js","results":[{"component":"jquery","version":"1.7.2","vulnerabilities":[{"severity":"medium","identifiers":{"CVE":["CVE-2012-6708"]}},{"severity":"high","identifiers":{"CVE":["CVE-2015-9251"]}}]}]}]}`)
	got := parseRetireJSVulns(data)
	if len(got) != 1 {
		t.Fatalf("expected 1 vuln component, got %d (%+v)", len(got), got)
	}
	if got[0].component != "jquery" || got[0].version != "1.7.2" {
		t.Fatalf("unexpected component: %+v", got[0])
	}
	if got[0].severity != model.SeverityHigh {
		t.Fatalf("expected highest severity high, got %s", got[0].severity)
	}
	if !reflect.DeepEqual(got[0].identifiers, []string{"CVE-2012-6708", "CVE-2015-9251"}) {
		t.Fatalf("unexpected identifiers: %v", got[0].identifiers)
	}
}

func TestParseRetireJSVulns_ArrayShape(t *testing.T) {
	data := []byte(`[{"file":"a.js","results":[{"component":"lodash","version":"4.17.4","vulnerabilities":[{"severity":"critical","identifiers":{"CVE":["CVE-2019-10744"]}}]}]}]`)
	got := parseRetireJSVulns(data)
	if len(got) != 1 || got[0].component != "lodash" || got[0].severity != model.SeverityCritical {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestParseRetireJSVulns_EmptyOrInvalid(t *testing.T) {
	if got := parseRetireJSVulns(nil); got != nil {
		t.Fatalf("expected nil for nil input, got %v", got)
	}
	if got := parseRetireJSVulns([]byte("not json")); got != nil {
		t.Fatalf("expected nil for invalid json, got %v", got)
	}
}

func TestParseTruffleHogSecrets(t *testing.T) {
	raw := "starting scan\n" +
		`{"DetectorName":"AWS","Verified":true}` + "\n" +
		`{"DetectorName":"AWS","Verified":false}` + "\n" + // duplicate detector
		`{"DetectorName":"Slack","Verified":false}` + "\n" +
		"not json\n"
	detectors, verified := parseTruffleHogSecrets(raw)
	want := []string{"AWS", "Slack"}
	if !reflect.DeepEqual(detectors, want) {
		t.Fatalf("parseTruffleHogSecrets detectors = %v, want %v", detectors, want)
	}
	if !verified {
		t.Fatalf("expected verified=true")
	}
}

func TestRunLinkFinder_DisabledReturnsInfoFinding(t *testing.T) {
	s := NewService(Config{EnableLinkFinder: false})
	findings := s.runLinkFinder(context.Background(), "https://example.com", model.ScanScope{}, nil)
	if len(findings) != 1 || findings[0].ID != "linkfinder-disabled" {
		t.Fatalf("expected linkfinder-disabled finding, got %+v", findings)
	}
}

func TestRunLinkFinder_BinaryMissing(t *testing.T) {
	s := NewService(Config{EnableLinkFinder: true, LinkFinderBinary: "definitely-not-a-real-binary-xyz"})
	findings := s.runLinkFinder(context.Background(), "https://example.com", model.ScanScope{}, nil)
	if len(findings) != 1 || findings[0].ID != "linkfinder-binary-missing" {
		t.Fatalf("expected linkfinder-binary-missing finding, got %+v", findings)
	}
}

func TestRunRetireJS_DisabledReturnsInfoFinding(t *testing.T) {
	s := NewService(Config{EnableRetireJS: false})
	findings := s.runRetireJS(context.Background(), RunInput{Target: "https://example.com"})
	if len(findings) != 1 || findings[0].ID != "retirejs-disabled" {
		t.Fatalf("expected retirejs-disabled finding, got %+v", findings)
	}
}

func TestRunRetireJS_BinaryMissing(t *testing.T) {
	s := NewService(Config{EnableRetireJS: true, RetireJSBinary: "definitely-not-a-real-binary-xyz"})
	findings := s.runRetireJS(context.Background(), RunInput{Target: "https://example.com"})
	if len(findings) != 1 || findings[0].ID != "retirejs-binary-missing" {
		t.Fatalf("expected retirejs-binary-missing finding, got %+v", findings)
	}
}

func TestRunTruffleHog_DisabledReturnsInfoFinding(t *testing.T) {
	s := NewService(Config{EnableTruffleHog: false})
	findings := s.runTruffleHog(context.Background(), RunInput{Target: "https://example.com"})
	if len(findings) != 1 || findings[0].ID != "trufflehog-disabled" {
		t.Fatalf("expected trufflehog-disabled finding, got %+v", findings)
	}
}

func TestRunTruffleHog_BinaryMissing(t *testing.T) {
	s := NewService(Config{EnableTruffleHog: true, TruffleHogBinary: "definitely-not-a-real-binary-xyz"})
	findings := s.runTruffleHog(context.Background(), RunInput{Target: "https://example.com"})
	if len(findings) != 1 || findings[0].ID != "trufflehog-binary-missing" {
		t.Fatalf("expected trufflehog-binary-missing finding, got %+v", findings)
	}
}

func TestRunUncover_DisabledReturnsInfoFinding(t *testing.T) {
	s := NewService(Config{EnableUncover: false})
	findings := s.runUncover(context.Background(), "https://example.com", &integrationState{SkippedReasons: map[string]int{}}, model.ScanScope{})
	if len(findings) != 1 || findings[0].ID != "uncover-disabled" {
		t.Fatalf("expected uncover-disabled finding, got %+v", findings)
	}
}

func TestRunUncover_BinaryMissing(t *testing.T) {
	s := NewService(Config{EnableUncover: true, UncoverBinary: "definitely-not-a-real-binary-xyz"})
	findings := s.runUncover(context.Background(), "https://example.com", &integrationState{SkippedReasons: map[string]int{}}, model.ScanScope{})
	if len(findings) != 1 || findings[0].ID != "uncover-binary-missing" {
		t.Fatalf("expected uncover-binary-missing finding, got %+v", findings)
	}
}
