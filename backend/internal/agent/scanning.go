package agent

import (
	"context"
	"fmt"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

type ScanningAgent struct {
	scanService *scanner.Service
	enabled     bool
}

func NewScanningAgent(scanService *scanner.Service, enabled bool) *ScanningAgent {
	return &ScanningAgent{
		scanService: scanService,
		enabled:     enabled,
	}
}

func (a *ScanningAgent) Name() string {
	return "scanning"
}

func (a *ScanningAgent) Enabled() bool {
	return a.enabled
}

func (a *ScanningAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	findings, err := a.scanService.Run(ctx, scanner.RunInput{
		Target:      input.Target,
		AuthProfile: input.AuthProfile,
		Options:     input.Options,
		Scope:       input.Scope,
	})
	if err != nil {
		return output, err
	}

	output.Findings = findings
	output.Metadata["findings_count"] = fmt.Sprintf("%d", len(findings))
	output.DebugNotes = "Built-in security checks executed."
	return output, nil
}
