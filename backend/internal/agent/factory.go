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
	f.Register("ai_tool_calling", func() Agent { return NewAIToolCallingAgent(nil, true) })
	f.Register("tool_builder", func() Agent { return NewToolBuilderAgent(true, nil) })
	f.Register("analysis", func() Agent { return NewAnalysisAgent(true) })
	f.Register("ml_triage", func() Agent { return NewMLTriageAgent(mlService, true) })
	f.Register("attack_path", func() Agent { return NewAttackPathAgent(mlService, true) })
	f.Register("false_positive_review", func() Agent { return NewFalsePositiveReviewAgent(mlService, true) })
	f.Register("remediation_planner", func() Agent { return NewRemediationPlannerAgent(mlService, true) })
	f.Register("impact_verifier", func() Agent { return NewImpactVerifierAgent(true) })
	f.Register("reporting", func() Agent { return NewReportingAgent(true) })

	// Exploit-chain agent: deterministic multi-step attack-chain analysis.
	// No external dependencies; registered unconditionally.
	f.Register("exploit_chain", func() Agent { return NewExploitChainAgent(true) })

	// HypothesisAgent: registered with nil AI client by default.
	// Callers that have an AI client should call SetAIClient to upgrade the
	// agent to LLM-powered hypothesis generation; it falls back to the local
	// rule-based reasoner when the client is nil or has no provider configured.
	f.Register("hypothesis", func() Agent { return NewHypothesisAgent(nil, scanService, true) })

	// HackTricksAgent: links curated HackTricks command templates to live execution.
	// Registered with nil AI client by default; SetAIClient upgrades it to
	// coding-LLM-adapted template instantiation.
	f.Register("hacktricks_techniques", func() Agent { return NewHackTricksAgent(true, nil) })

	// LLMChainSynthesisAgent: reasons across the full finding set to identify
	// novel multi-step attack chains. Registered with nil AI client by default.
	f.Register("llm_chain_synthesis", func() Agent { return NewLLMChainSynthesisAgent(nil, true) })

	// AdaptiveProbeAgent: true observe→decide→act loop where the AI chooses
	// one probe at a time based on live HTTP observations.
	f.Register("adaptive_probe", func() Agent {
		return NewAdaptiveProbeAgent(nil, scanService, defaultAdaptiveStepBudget, true)
	})

	// PentestLoopAgent: drives the iterative hypothesis→verify→chain inner
	// loop inside a single agent execution. Registered with nil AI client by
	// default; SetAIClient upgrades it to LLM-powered hypothesis generation.
	f.Register("pentest_loop", func() Agent {
		return NewPentestLoopAgent(nil, scanService, defaultInnerRounds, true)
	})

	// ReasoningIterationAgent: adaptive, self-correcting pentest loop that
	// reflects after each round to identify gaps and pivot strategy.
	// Registered with nil AI client by default; SetAIClient upgrades it.
	f.Register("reasoning_iteration", func() Agent {
		return NewReasoningIterationAgent(nil, scanService, defaultReasoningRounds, true)
	})

	// OpenHack expert / triage agents: drive the LLM with the imported
	// OpenHack prompt pack (docs/openhack/) and enrich findings with
	// expert-grade review and finding-triage decisions. Registered with a
	// nil AI client by default; SetAIClient upgrades them. The embedded
	// prompt pack is loaded lazily inside each constructor so the agents
	// always have prompt text regardless of how they were registered.
	f.Register("openhack_expert", func() Agent { return NewOpenHackExpertAgent(nil, nil, true) })
	f.Register("openhack_triage", func() Agent { return NewOpenHackTriageAgent(nil, nil, true) })

	return f
}

// SetAIClient re-registers agents that benefit from an AI client:
//   - "hypothesis" uses the primary model for hypothesis generation.
//   - "ai_tool_calling" uses the coding/planning model for bounded tool choices.
//   - "tool_builder" uses the coding model for on-the-fly Python tool synthesis.
//   - "hacktricks_techniques" uses the coding model to adapt HackTricks templates.
//   - "llm_chain_synthesis" uses the coding model to synthesize novel attack chains.
//   - "adaptive_probe" uses the planning model for one-probe-at-a-time AI decisions.
//   - "reasoning_iteration" uses the planning model for reflection and iteration rationale.
//
// This is called after NewFactory once the AI client is available. It is safe
// to call concurrently with other factory operations.
func (f *Factory) SetAIClient(c *ai.Client, scanService *scanner.Service) {
	if f == nil {
		return
	}
	f.Register("hypothesis", func() Agent { return NewHypothesisAgent(c, scanService, true) })
	f.Register("ai_tool_calling", func() Agent { return NewAIToolCallingAgent(c, true) })
	f.Register("tool_builder", func() Agent { return NewToolBuilderAgent(true, c) })
	f.Register("hacktricks_techniques", func() Agent { return NewHackTricksAgent(true, c) })
	f.Register("llm_chain_synthesis", func() Agent { return NewLLMChainSynthesisAgent(c, true) })
	f.Register("pentest_loop", func() Agent {
		return NewPentestLoopAgent(c, scanService, defaultInnerRounds, true)
	})
	f.Register("adaptive_probe", func() Agent {
		return NewAdaptiveProbeAgent(c, scanService, defaultAdaptiveStepBudget, true)
	})
	f.Register("reasoning_iteration", func() Agent {
		return NewReasoningIterationAgent(c, scanService, defaultReasoningRounds, true)
	})
	// OpenHack agents share the same AI client so local Ollama deployments
	// and external OpenAI/Anthropic/Gemini/Bedrock providers both drive
	// the embedded OpenHack expert/triage prompts via the standard
	// provider routing in ai.Client (planningComplete).
	f.Register("openhack_expert", func() Agent { return NewOpenHackExpertAgent(c, nil, true) })
	f.Register("openhack_triage", func() Agent { return NewOpenHackTriageAgent(c, nil, true) })
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
