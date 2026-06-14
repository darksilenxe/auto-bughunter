package agent

import (
	"fmt"
	"strings"
	"sync"

	"auto-bughunter/backend/internal/model"
)

// DiscoveryKind categorises what kind of discovery was made.
type DiscoveryKind string

const (
	DiscoveryTechStack     DiscoveryKind = "tech_stack"
	DiscoveryAuthMechanism DiscoveryKind = "auth_mechanism"
	DiscoveryEndpoint      DiscoveryKind = "endpoint"
	DiscoveryParameter     DiscoveryKind = "parameter"
	DiscoverySensitiveData DiscoveryKind = "sensitive_data"
	DiscoverySecret        DiscoveryKind = "secret"
	DiscoveryGraphQL       DiscoveryKind = "graphql"
	DiscoveryAdminPanel    DiscoveryKind = "admin_panel"
	DiscoveryAPIRoute      DiscoveryKind = "api_route"
	DiscoveryJWT           DiscoveryKind = "jwt"
	DiscoveryGeneric       DiscoveryKind = "generic"
)

// DiscoveryEvent is a lightweight, unconfirmed signal emitted by any agent.
// Unlike findings, discoveries do not require HTTP-level confirmation —
// they represent structural observations (endpoints found, tech stack
// identified, auth mechanisms detected) that guide subsequent agents.
type DiscoveryEvent struct {
	Kind        DiscoveryKind `json:"kind"`
	Value       string        `json:"value"`
	SourceAgent string        `json:"sourceAgent"`
	Confidence  float64       `json:"confidence"`
}

// SharedScanContext is a thread-safe blackboard shared across all agent
// rounds in a single scan. Any agent can write discoveries and notes;
// subsequent agents read them to bias their strategy.
type SharedScanContext struct {
	mu          sync.RWMutex
	techStack   []string
	authMechs   []string
	endpoints   []string
	discoveries []DiscoveryEvent
	notes       map[string]string // keyed by agent name
}

// NewSharedScanContext creates an empty blackboard.
func NewSharedScanContext() *SharedScanContext {
	return &SharedScanContext{notes: map[string]string{}}
}

// SetTechStack replaces the detected tech stack (e.g. ["Rails", "Devise", "PostgreSQL"]).
func (s *SharedScanContext) SetTechStack(stack []string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.techStack = dedupeTrimmed(stack)
	s.mu.Unlock()
}

// GetTechStack returns a copy of the current tech stack.
func (s *SharedScanContext) GetTechStack() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.techStack...)
}

// AddAuthMechanism records a detected authentication mechanism (e.g. "JWT", "OAuth2", "SAML").
func (s *SharedScanContext) AddAuthMechanism(mech string) {
	if s == nil {
		return
	}
	mech = strings.TrimSpace(mech)
	if mech == "" {
		return
	}
	s.mu.Lock()
	s.authMechs = appendUniqueContextValue(s.authMechs, mech)
	s.mu.Unlock()
}

// GetAuthMechanisms returns a copy of all detected auth mechanisms.
func (s *SharedScanContext) GetAuthMechanisms() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.authMechs...)
}

// AddEndpoint adds a newly discovered endpoint URL if not already known.
func (s *SharedScanContext) AddEndpoint(url string) {
	if s == nil {
		return
	}
	url = strings.TrimSpace(url)
	if url == "" {
		return
	}
	s.mu.Lock()
	s.endpoints = appendUniqueContextValue(s.endpoints, url)
	s.mu.Unlock()
}

// GetEndpoints returns all discovered endpoints.
func (s *SharedScanContext) GetEndpoints() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.endpoints...)
}

// AddDiscovery appends a discovery event and emits the Emitter callback if non-nil.
func (s *SharedScanContext) AddDiscovery(d DiscoveryEvent, emit Emitter) {
	if s == nil {
		return
	}
	d.Value = strings.TrimSpace(d.Value)
	d.SourceAgent = strings.TrimSpace(d.SourceAgent)
	if d.Value == "" {
		return
	}
	s.mu.Lock()
	s.discoveries = append(s.discoveries, d)
	s.mu.Unlock()
	if emit != nil {
		Emit(emit, model.ScanEvent{
			Type:      model.ScanEventDiscovery,
			AgentName: d.SourceAgent,
			Message:   fmt.Sprintf("%s discovered: %s", discoveryKindLabel(d.Kind), d.Value),
			Metadata: map[string]string{
				"kind":        string(d.Kind),
				"value":       d.Value,
				"sourceAgent": d.SourceAgent,
				"confidence":  fmt.Sprintf("%.2f", d.Confidence),
			},
		})
	}
}

// GetDiscoveries returns all discovery events seen so far.
func (s *SharedScanContext) GetDiscoveries() []DiscoveryEvent {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]DiscoveryEvent(nil), s.discoveries...)
}

// SetNote stores a freeform note from a specific agent (overwrites).
func (s *SharedScanContext) SetNote(agent, note string) {
	if s == nil {
		return
	}
	agent = strings.TrimSpace(agent)
	if agent == "" {
		return
	}
	s.mu.Lock()
	if s.notes == nil {
		s.notes = map[string]string{}
	}
	s.notes[agent] = strings.TrimSpace(note)
	s.mu.Unlock()
}

// GetNote returns the note left by a specific agent (empty string if none).
func (s *SharedScanContext) GetNote(agent string) string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.notes[strings.TrimSpace(agent)]
}

// DiscoverySummary returns a compact, prompt-ready summary of all discoveries
// for injection into AI prompts. Returns empty string when nothing is known.
func (s *SharedScanContext) DiscoverySummary() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	parts := make([]string, 0, 4)
	if len(s.techStack) > 0 {
		parts = append(parts, "Tech stack: "+strings.Join(s.techStack, ", ")+".")
	}
	if len(s.authMechs) > 0 {
		parts = append(parts, "Auth: "+strings.Join(s.authMechs, ", ")+".")
	}
	if len(s.endpoints) > 0 {
		parts = append(parts, "Endpoints: "+strings.Join(s.endpoints, ", ")+".")
	}
	if len(s.discoveries) > 0 {
		start := 0
		if len(s.discoveries) > 5 {
			start = len(s.discoveries) - 5
		}
		recent := make([]string, 0, len(s.discoveries)-start)
		for _, d := range s.discoveries[start:] {
			recent = append(recent, fmt.Sprintf("%s at %s (confidence %.2f)", discoveryKindLabel(d.Kind), d.Value, d.Confidence))
		}
		parts = append(parts, "Recent discoveries: "+strings.Join(recent, ", ")+".")
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func appendUniqueContextValue(items []string, value string) []string {
	for _, existing := range items {
		if strings.EqualFold(existing, value) {
			return items
		}
	}
	return append(items, value)
}

func dedupeTrimmed(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = appendUniqueContextValue(out, item)
	}
	return out
}

func discoveryKindLabel(kind DiscoveryKind) string {
	label := strings.ReplaceAll(string(kind), "_", " ")
	if label == "" {
		return string(DiscoveryGeneric)
	}
	return label
}
