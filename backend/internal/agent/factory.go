package agent

import (
	"fmt"
	"sort"
	"sync"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/scanner"
)

// AgentBuilder produces a fresh Agent instance on demand. Builders should
// always return enabled agents because the orchestrator only requests an agent
// when the planner has decided to run it.
type AgentBuilder func() Agent

// Factory creates Agent instances by name. Builders may be the default ones
// pre-registered in NewFactory or ones registered by callers via Register.
type Factory struct {
	mu       sync.RWMutex
	builders map[string]AgentBuilder
}

// NewFactory wires up the standard agent builders, all enabled by default.
// scanService and mlService may be nil; agents that require them will simply
// produce empty findings when the dependency is missing.
func NewFactory(scanService *scanner.Service, mlService *ml.Service) *Factory {
	f := &Factory{builders: map[string]AgentBuilder{}}

	f.Register("reconnaissance", func() Agent { return NewReconnaissanceAgent(true) })
	f.Register("scanning", func() Agent { return NewScanningAgent(scanService, true) })
	f.Register("input_validation", func() Agent { return NewInputValidationAgent(true) })
	f.Register("information_disclosure", func() Agent { return NewInformationDisclosureAgent(true) })
	f.Register("access_control", func() Agent { return NewAccessControlAgent(true) })
	f.Register("api_security", func() Agent { return NewAPISecurityAgent(true) })
	f.Register("cors_redirect", func() Agent { return NewCORSRedirectAgent(true) })
	f.Register("ssrf", func() Agent { return NewSSRFAgent(true) })
	f.Register("auth_bypass", func() Agent { return NewAuthBypassAgent(true) })
	f.Register("file_upload", func() Agent { return NewFileUploadAgent(true) })
	f.Register("metasploit", func() Agent { return NewMetasploitAgent(true) })
	f.Register("burp", func() Agent { return NewBurpAgent(true) })
	f.Register("wordlist", func() Agent { return NewWordlistAgent(true) })
	f.Register("tool_builder", func() Agent { return NewToolBuilderAgent(true, nil) })
	f.Register("analysis", func() Agent { return NewAnalysisAgent(true) })
	f.Register("ml_triage", func() Agent { return NewMLTriageAgent(mlService, true) })
	f.Register("attack_path", func() Agent { return NewAttackPathAgent(mlService, true) })
	f.Register("false_positive_review", func() Agent { return NewFalsePositiveReviewAgent(mlService, true) })
	f.Register("remediation_planner", func() Agent { return NewRemediationPlannerAgent(mlService, true) })
	f.Register("reporting", func() Agent { return NewReportingAgent(true) })

	// Exploit-chain agent: deterministic multi-step attack-chain analysis.
	// No external dependencies; registered unconditionally.
	f.Register("exploit_chain", func() Agent { return NewExploitChainAgent(true) })

	// HypothesisAgent: registered with nil AI client by default.
	// Callers that have an AI client should call SetAIClient to upgrade the
	// agent to LLM-powered hypothesis generation; it falls back to the local
	// rule-based reasoner when the client is nil or has no provider configured.
	f.Register("hypothesis", func() Agent { return NewHypothesisAgent(nil, scanService, true) })

	return f
}

// SetAIClient re-registers agents that benefit from an AI client:
//   - "hypothesis" uses the primary model for hypothesis generation.
//   - "tool_builder" uses the coding model for on-the-fly Python tool synthesis.
//
// This is called after NewFactory once the AI client is available. It is safe
// to call concurrently with other factory operations.
func (f *Factory) SetAIClient(c *ai.Client, scanService *scanner.Service) {
	if f == nil {
		return
	}
	f.Register("hypothesis", func() Agent { return NewHypothesisAgent(c, scanService, true) })
	f.Register("tool_builder", func() Agent { return NewToolBuilderAgent(true, c) })
}

// Register adds or replaces a builder for the given agent name.
func (f *Factory) Register(name string, builder AgentBuilder) {
	if f == nil || name == "" || builder == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.builders[name] = builder
}

// Create constructs a new Agent instance for the named builder. An error is
// returned when no builder is registered for the requested name.
func (f *Factory) Create(name string) (Agent, error) {
	if f == nil {
		return nil, fmt.Errorf("agent factory not configured")
	}
	f.mu.RLock()
	builder, ok := f.builders[name]
	f.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown agent %q", name)
	}
	agent := builder()
	if agent == nil {
		return nil, fmt.Errorf("builder for %q produced nil agent", name)
	}
	return agent, nil
}

// Names returns the sorted list of agent names this factory can create.
// It is primarily used to advertise the menu of options to the AI planner.
func (f *Factory) Names() []string {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	names := make([]string, 0, len(f.builders))
	for name := range f.builders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
