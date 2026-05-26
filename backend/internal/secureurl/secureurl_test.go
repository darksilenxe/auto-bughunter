package secureurl

import (
	"errors"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name          string
		value         string
		allowInsecure bool
		wantErr       bool
	}{
		// Empty values are always OK (means integration disabled).
		{"empty", "", false, false},
		{"whitespace only", "   ", false, false},

		// HTTPS public hosts are always OK.
		{"https public", "https://api.openai.com/v1", false, false},
		{"https with port", "https://example.com:8443/api", false, false},

		// HTTP loopback and private hosts are OK.
		{"http localhost", "http://localhost:8080", false, false},
		{"http loopback ip", "http://127.0.0.1:8090", false, false},
		{"http ipv6 loopback", "http://[::1]:8090", false, false},
		{"http rfc1918", "http://10.0.0.5:8090", false, false},
		{"http 192.168", "http://192.168.1.1", false, false},

		// HTTP single-label hostnames (compose service names) OK.
		{"http compose svc", "http://ollama:11434/v1", false, false},
		{"http compose svc dashed", "http://nuclei-service:8093", false, false},
		{"http burp compose", "http://burp-enterprise:8443", false, false},

		// HTTP public hosts are rejected unless escape hatch is set.
		{"http public host", "http://api.openai.com/v1", false, true},
		{"http public host with escape", "http://api.openai.com/v1", true, false},
		{"http public ip", "http://8.8.8.8/", false, true},
		{"http public ip with escape", "http://8.8.8.8/", true, false},

		// Bad input.
		{"missing scheme", "api.openai.com/v1", false, true},
		{"only scheme", "https://", false, true},

		// Out-of-scope schemes are ignored (Neo4j Bolt, websockets, etc.).
		{"bolt scheme", "bolt://neo4j:7687", false, false},
		{"ws scheme", "ws://socket.example.com/", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate("TEST_VAR", tc.value, tc.allowInsecure)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidationErrorMessage(t *testing.T) {
	err := Validate("AI_API_BASE", "http://api.openai.com/v1", false)
	if err == nil {
		t.Fatal("expected error")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Name != "AI_API_BASE" {
		t.Errorf("Name = %q, want AI_API_BASE", ve.Name)
	}
	if !strings.Contains(ve.Error(), "AI_API_BASE") {
		t.Errorf("error string %q does not mention env var name", ve.Error())
	}
	if !strings.Contains(ve.Error(), "ALLOW_INSECURE_OUTBOUND_URLS") {
		t.Errorf("error string %q does not mention escape hatch", ve.Error())
	}
}

func TestValidateMany(t *testing.T) {
	entries := map[string]string{
		"AI_API_BASE":          "http://api.openai.com/v1",      // bad
		"AGENT_LEARNER_URL":    "http://agents:8091",            // ok (compose)
		"KNOWLEDGE_SERVICE_URL": "https://kb.example.com",       // ok (https)
		"MSF_RPC_URL":          "",                              // ok (empty)
		"BURP_API_URL":         "http://burp.public.example",    // bad
	}

	err := ValidateMany(entries, false)
	if err == nil {
		t.Fatal("expected combined error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "AI_API_BASE") {
		t.Errorf("missing AI_API_BASE in error: %s", msg)
	}
	if !strings.Contains(msg, "BURP_API_URL") {
		t.Errorf("missing BURP_API_URL in error: %s", msg)
	}
	if strings.Contains(msg, "AGENT_LEARNER_URL") || strings.Contains(msg, "KNOWLEDGE_SERVICE_URL") || strings.Contains(msg, "MSF_RPC_URL") {
		t.Errorf("unexpected entries in error: %s", msg)
	}

	// With escape hatch, everything passes.
	if err := ValidateMany(entries, true); err != nil {
		t.Fatalf("unexpected error with escape hatch: %v", err)
	}

	// All-good map returns nil.
	if err := ValidateMany(map[string]string{
		"AI_API_BASE": "https://api.openai.com/v1",
	}, false); err != nil {
		t.Fatalf("unexpected error on clean input: %v", err)
	}
}
