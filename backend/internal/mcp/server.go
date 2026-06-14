package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/ai"
)

type Message struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
	Text        string `json:"text,omitempty"`
}

type prompt struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type tool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type samplingMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type samplingRequest struct {
	SystemPrompt string            `json:"systemPrompt"`
	Messages     []samplingMessage `json:"messages"`
}

type Server struct {
	aiClient        *ai.Client
	contextProvider func() []Resource
}

func NewServer(aiClient *ai.Client) *Server {
	return &Server{aiClient: aiClient}
}

func (s *Server) SetContextProvider(provider func() []Resource) {
	if s == nil {
		return
	}
	s.contextProvider = provider
}

func (s *Server) resources() []Resource {
	if s == nil || s.contextProvider == nil {
		return nil
	}
	return s.contextProvider()
}

func (s *Server) HandleRequest(ctx context.Context, req Message) Message {
	resp := Message{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"serverInfo": map[string]any{
				"name":    "auto-bughunter-mcp",
				"version": "0.1.0",
			},
			"capabilities": map[string]any{
				"resources": map[string]any{},
				"prompts":   map[string]any{},
				"tools":     map[string]any{},
				"sampling":  map[string]any{},
			},
		}
	case "resources/list":
		resp.Result = map[string]any{"resources": s.resources()}
	case "resources/read":
		var params struct {
			URI string `json:"uri"`
		}
		if err := decodeParams(req.Params, &params); err != nil {
			return errorMessage(req.ID, -32602, err.Error())
		}
		for _, resource := range s.resources() {
			if resource.URI == params.URI {
				resp.Result = map[string]any{
					"contents": []map[string]any{{
						"uri":      resource.URI,
						"mimeType": resource.MimeType,
						"text":     resource.Text,
					}},
				}
				return resp
			}
		}
		return errorMessage(req.ID, -32004, "resource not found")
	case "prompts/list":
		resp.Result = map[string]any{"prompts": []prompt{{
			Name:        "analyze-findings",
			Description: "Review recent findings context before asking the AI to reason about exploitability.",
		}}}
	case "sampling/createMessage":
		var params samplingRequest
		if err := decodeParams(req.Params, &params); err != nil {
			return errorMessage(req.ID, -32602, err.Error())
		}
		if s == nil || s.aiClient == nil {
			return errorMessage(req.ID, -32001, "ai client not configured")
		}
		messages := make([]ai.Message, 0, len(params.Messages))
		for _, msg := range params.Messages {
			messages = append(messages, ai.Message{Role: msg.Role, Content: msg.Content})
		}
		chatCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		text, err := s.aiClient.Chat(chatCtx, params.SystemPrompt, messages)
		if err != nil {
			return errorMessage(req.ID, -32002, err.Error())
		}
		resp.Result = map[string]any{
			"message": samplingMessage{Role: "assistant", Content: text},
		}
	case "tools/list":
		resp.Result = map[string]any{"tools": []tool{}}
	default:
		return errorMessage(req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
	}
	return resp
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stream") {
		raw := r.URL.Query().Get("request")
		if strings.TrimSpace(raw) == "" {
			http.Error(w, "missing request query parameter", http.StatusBadRequest)
			return
		}
		var req Message
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			http.Error(w, "invalid request payload", http.StatusBadRequest)
			return
		}
		resp := s.HandleRequest(r.Context(), req)
		blob, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		_, _ = fmt.Fprintf(w, "data: %s\n\n", blob)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req Message
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorMessage(nil, -32700, "invalid json-rpc request"))
		return
	}
	writeJSON(w, http.StatusOK, s.HandleRequest(r.Context(), req))
}

func decodeParams(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	return nil
}

func errorMessage(id any, code int, message string) Message {
	return Message{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
