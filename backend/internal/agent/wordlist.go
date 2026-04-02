package agent

import (
	"context"
	"fmt"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

type WordlistAgent struct {
	wordlistScanner *scanner.WordlistScanner
	enabled         bool
}

func NewWordlistAgent(enabled bool) *WordlistAgent {
	return &WordlistAgent{
		wordlistScanner: scanner.NewWordlistScanner(5, 0),
		enabled:         enabled,
	}
}

func (a *WordlistAgent) Name() string {
	return "wordlist"
}

func (a *WordlistAgent) Enabled() bool {
	return a.enabled
}

func (a *WordlistAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	dirs := a.wordlistScanner.ScanDirectories(ctx, input.Target, input.AuthProfile)
	output.Findings = append(output.Findings, dirs...)

	subs := a.wordlistScanner.ScanSubdomains(ctx, input.Target)
	output.Findings = append(output.Findings, subs...)

	apis := a.wordlistScanner.ScanAPIEndpoints(ctx, input.Target, input.AuthProfile)
	output.Findings = append(output.Findings, apis...)

	output.Metadata["directories_found"] = fmt.Sprintf("%d", len(dirs))
	output.Metadata["subdomains_found"] = fmt.Sprintf("%d", len(subs))
	output.Metadata["api_endpoints_found"] = fmt.Sprintf("%d", len(apis))
	output.Metadata["total_found"] = fmt.Sprintf("%d", len(output.Findings))

	output.DebugNotes = fmt.Sprintf("Wordlist scanning completed: %d directories, %d subdomains, %d API endpoints discovered.", len(dirs), len(subs), len(apis))

	return output, nil
}
