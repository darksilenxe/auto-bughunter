package scanner

import (
	"fmt"
	"strings"
	"testing"
)

// makeTestBody assembles a body string that contains synthetic values
// shaped like real credentials. The pattern fragments are concatenated at
// runtime so that no full-shaped secret literal appears in the source
// file (which would trip pre-commit secret scanners).
func makeTestBody() string {
	stripeKey := "sk_" + "live_" + strings.Repeat("X", 26)
	awsKey := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	ghToken := "ghp_" + strings.Repeat("a", 36)
	slackToken := "xoxb-" + strings.Repeat("1", 12) + "-AbCdEfGhIjKlMnOp"
	googleKey := "AIza" + strings.Repeat("z", 35)
	jwt := "eyJ" + strings.Repeat("a", 12) + ".eyJ" + strings.Repeat("b", 12) + "." + strings.Repeat("c", 12)
	apiKey := "abcdef0123456789ABCDEF0123456789xyzwabcd"
	return fmt.Sprintf(`
		# config dump
		AWS_ACCESS_KEY_ID=%s
		github_token: %s
		slack_webhook: %s
		google_api_key: %s
		stripe: %s
		jwt_token = %s
		api_key="%s"
		-----BEGIN RSA PRIVATE KEY-----
		MIIBOQIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q
	`, awsKey, ghToken, slackToken, googleKey, stripeKey, jwt, apiKey)
}

func TestScanForSecrets_DetectsKnownPatterns(t *testing.T) {
	body := makeTestBody()
	findings := scanForSecrets("https://example.com/", body)
	wantIDs := []string{
		"secret-aws-access-key",
		"secret-github-token",
		"secret-slack-token",
		"secret-google-api-key",
		"secret-stripe-key",
		"secret-jwt",
		"secret-private-key-block",
		"secret-generic-api-key",
	}
	got := map[string]bool{}
	awsLiteral := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	ghLiteral := "ghp_" + strings.Repeat("a", 36)
	stripeLiteral := "sk_" + "live_" + strings.Repeat("X", 26)
	for _, f := range findings {
		got[f.ID] = true
		// Evidence must never include the raw secret material itself.
		if strings.Contains(f.Evidence, awsLiteral) ||
			strings.Contains(f.Evidence, ghLiteral) ||
			strings.Contains(f.Evidence, stripeLiteral) {
			t.Errorf("evidence for %s leaks raw secret: %q", f.ID, f.Evidence)
		}
		if !strings.Contains(f.Evidence, "<redacted>") {
			t.Errorf("evidence for %s missing <redacted> marker: %q", f.ID, f.Evidence)
		}
	}
	for _, id := range wantIDs {
		if !got[id] {
			t.Errorf("expected finding %s, got %v", id, got)
		}
	}
}

func TestScanForSecrets_NoMatches(t *testing.T) {
	body := "<html><body>nothing to see here</body></html>"
	if got := scanForSecrets("https://example.com/", body); len(got) != 0 {
		t.Errorf("expected no findings, got %d", len(got))
	}
}

func TestScanForSecrets_EmptyBody(t *testing.T) {
	if got := scanForSecrets("https://example.com/", ""); got != nil {
		t.Errorf("expected nil for empty body, got %v", got)
	}
}

func TestRedactedSnippet_BoundsAndRedaction(t *testing.T) {
	awsLiteral := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	body := "prefix-" + awsLiteral + "-suffix"
	idx := strings.Index(body, "AKIA")
	got := redactedSnippet(body, idx, idx+20)
	if strings.Contains(got, awsLiteral) {
		t.Fatalf("snippet should not contain raw secret: %q", got)
	}
	if !strings.Contains(got, "<redacted>") {
		t.Fatalf("snippet should contain <redacted>: %q", got)
	}
	// Out-of-bounds is handled.
	if got := redactedSnippet("abc", -1, 100); got != "<redacted>" {
		t.Errorf("expected fallback for invalid bounds, got %q", got)
	}
}
