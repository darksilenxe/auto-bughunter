package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"auto-bughunter/backend/internal/model"
)

type fakeKnowledgeRetriever struct {
	stage string
	query string
	limit int
}

func (f *fakeKnowledgeRetriever) RetrieveForContext(_ context.Context, stage, query string, _ []string, limit int) *model.SecurityKnowledgeContext {
	f.stage = stage
	f.query = query
	f.limit = limit
	return &model.SecurityKnowledgeContext{
		Query:         query,
		Stage:         stage,
		CurationMode:  "full-text-rag",
		LicenseNotice: "attribution required",
		References: []model.KnowledgeReference{
			{
				ID:                 "hacktricks-xss",
				Title:              "HackTricks — XSS",
				URL:                "https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting.html",
				SourceType:         "hacktricks",
				License:            "source-url-only",
				Topic:              "xss payloads",
				VulnerabilityClass: "cross-site scripting",
				Technique:          "context-aware payload selection",
				Passage:            "Prefer context-matched payloads and bypass variants.",
			},
		},
	}
}

type captureServer struct {
	t       *testing.T
	mu      sync.Mutex
	payload map[string]any
}

func (c *captureServer) handler(response string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			c.t.Fatalf("decode request: %v", err)
		}
		messages, _ := body["messages"].([]any)
		if len(messages) < 2 {
			c.t.Fatalf("expected at least 2 messages, got %d", len(messages))
		}
		userMessage, _ := messages[len(messages)-1].(map[string]any)
		content, _ := userMessage["content"].(string)
		// Some AI methods (AdaptTechniqueCommands, GenerateTool, PlanToolCall)
		// emit the trusted JSON context followed by XML-delimited untrusted data.
		// Extract only the leading JSON object for comparison.
		jsonPart := content
		if idx := strings.Index(content, "\n<"); idx != -1 {
			jsonPart = content[:idx]
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(jsonPart), &payload); err != nil {
			c.t.Fatalf("decode user payload: %v", err)
		}
		c.mu.Lock()
		c.payload = payload
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fakeCompletion(c.t, response)))
	}
}

func (c *captureServer) lastPayload() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.payload
}

func assertKnowledgeGuidancePresent(t *testing.T, payload map[string]any) {
	t.Helper()
	raw, _ := payload["knowledgeGuidance"].(string)
	if raw == "" {
		t.Fatalf("expected knowledgeGuidance in payload, got %#v", payload)
	}
}

func TestAdviseAgentIncludesKnowledgeGuidance(t *testing.T) {
	capture := &captureServer{t: t}
	srv := httptest.NewServer(capture.handler(`{"thinking":"focus xss","priorityChecks":["xss"],"skipChecks":[],"focusEndpoints":["http://example.com/search"],"rationale":"reflection sink found"}`))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", "test-model")
	client.SetKnowledgeRetriever(&fakeKnowledgeRetriever{})
	_ = client.AdviseAgent(context.Background(), "input_validation", "http://example.com", []string{"xss", "sqli"}, []model.Finding{{Category: "input_validation", Title: "Reflected input"}}, "route=/search")

	assertKnowledgeGuidancePresent(t, capture.lastPayload())
}

func TestHypothesizeIncludesKnowledgeGuidance(t *testing.T) {
	capture := &captureServer{t: t}
	srv := httptest.NewServer(capture.handler(`{"hypotheses":[]}`))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", "test-model")
	client.SetKnowledgeRetriever(&fakeKnowledgeRetriever{})
	_ = client.Hypothesize(context.Background(), "http://example.com", []model.Finding{{Category: "xss", Title: "Reflected input"}}, []string{"http://example.com/search"})

	assertKnowledgeGuidancePresent(t, capture.lastPayload())
}

func TestReflectIncludesKnowledgeGuidance(t *testing.T) {
	capture := &captureServer{t: t}
	srv := httptest.NewServer(capture.handler(`{"gapAnalysis":"need xss evasion","iterationRationale":"waf blocked payload","focusAreas":["xss"],"refinedHints":[],"shouldEscalate":false,"skipCategories":[]}`))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key", "test-model")
	client.SetKnowledgeRetriever(&fakeKnowledgeRetriever{})
	_ = client.Reflect(
		context.Background(),
		"http://example.com",
		1,
		[]model.Finding{{Category: "xss", Title: "Reflected input"}},
		[]model.ProbeResult{{Category: "xss", Endpoint: "http://example.com/search", ParamName: "q"}},
		map[string][]string{"xss": []string{"http://example.com/search"}},
	)

	assertKnowledgeGuidancePresent(t, capture.lastPayload())
}

func TestKnowledgeGuidanceIncludedForAgentExpertCalls(t *testing.T) {
	tests := []struct {
		name     string
		response string
		invoke   func(*Client)
	}{
		{
			name:     "adapt technique commands",
			response: `{"commands":[{"binary":"curl","args":["-I","http://example.com"],"rationale":"confirm"}]}`,
			invoke: func(c *Client) {
				_ = c.AdaptTechniqueCommands(context.Background(), []string{"curl -I {{TARGET}}"}, "XSS finding", "parameter q reflected", "http://example.com")
			},
		},
		{
			name:     "openhack expert",
			response: `{"expertId":"expert","decision":"candidate","recommendedSeverity":"medium","confidence":0.8,"rationale":"needs follow-up"}`,
			invoke: func(c *Client) {
				_ = c.RunOpenHackExpert(context.Background(), "expert-system-prompt", "expert", model.Finding{Category: "xss", Title: "Reflected XSS", Evidence: "<script>alert(1)</script>"})
			},
		},
		{
			name:     "openhack triage",
			response: `{"decision":"needs_context","finalSeverity":"medium","severityRationale":"need more proof","confidence":0.7}`,
			invoke: func(c *Client) {
				_ = c.RunOpenHackTriage(context.Background(), "triage-system-prompt", model.Finding{Category: "xss", Title: "Reflected XSS", Evidence: "<script>alert(1)</script>"})
			},
		},
		{
			name:     "chain synthesis",
			response: `{"chains":[{"id":"chain-1","title":"XSS to takeover","steps":["steal token","reuse token"],"impact":"account takeover","sourceIds":["f-1"],"confidence":0.9}]}`,
			invoke: func(c *Client) {
				_ = c.SynthesizeChains(context.Background(), "http://example.com", []map[string]string{{"id": "f-1", "category": "xss", "title": "Reflected XSS"}}, nil)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capture := &captureServer{t: t}
			srv := httptest.NewServer(capture.handler(tc.response))
			defer srv.Close()

			client := NewClient(srv.URL, "test-key", "test-model")
			client.SetKnowledgeRetriever(&fakeKnowledgeRetriever{})
			tc.invoke(client)

			assertKnowledgeGuidancePresent(t, capture.lastPayload())
		})
	}
}
