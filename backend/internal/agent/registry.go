package agent

import (
	"context"
	"fmt"

	"auto-bughunter/backend/internal/model"
)

type Agent interface {
	Name() string
	Enabled() bool
	Run(ctx context.Context, input AgentInput) (AgentOutput, error)
}

type AgentInput struct {
	Target      string
	AuthProfile model.ScanAuthProfile
	Options     model.ScanOptions
	Scope       model.ScanScope
	Previous    AgentOutput
}

type AgentOutput struct {
	AgentName  string
	Findings   []model.Finding
	Metadata   map[string]string
	Status     string
	DebugNotes string
}

type Registry struct {
	agents map[string]Agent
	order  []string
}

func NewRegistry() *Registry {
	return &Registry{
		agents: make(map[string]Agent),
		order:  make([]string, 0),
	}
}

func (r *Registry) Register(agent Agent) {
	if agent == nil {
		return
	}
	r.agents[agent.Name()] = agent
	r.order = append(r.order, agent.Name())
}

func (r *Registry) Get(name string) Agent {
	return r.agents[name]
}

func (r *Registry) RunAll(ctx context.Context, input AgentInput) ([]AgentOutput, []model.Finding, error) {
	outputs := make([]AgentOutput, 0, len(r.order))
	allFindings := make([]model.Finding, 0)
	cumulativeFindings := make([]model.Finding, 0)

	for _, name := range r.order {
		agent := r.agents[name]
		if !agent.Enabled() {
			continue
		}

		select {
		case <-ctx.Done():
			return outputs, allFindings, ctx.Err()
		default:
		}

		input.Previous = AgentOutput{Findings: append([]model.Finding(nil), cumulativeFindings...)}

		output, err := agent.Run(ctx, input)
		if err != nil {
			output.Status = "error"
			output.DebugNotes = err.Error()
		}
		if output.AgentName == "" {
			output.AgentName = agent.Name()
		}
		outputs = append(outputs, output)
		cumulativeFindings = append(cumulativeFindings, output.Findings...)
		allFindings = append(allFindings, output.Findings...)
	}

	return outputs, combineFindingsWithDedup(allFindings), nil
}

func combineFindingsWithDedup(findings []model.Finding) []model.Finding {
	seen := make(map[string]struct{})
	deduped := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%s", f.Category, f.Title, f.Evidence)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, f)
	}
	return deduped
}
