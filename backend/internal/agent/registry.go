package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

type Agent interface {
	Name() string
	Enabled() bool
	Run(ctx context.Context, input AgentInput) (AgentOutput, error)
}

// Emitter is a function that publishes a ScanEvent to the live event bus.
// It is nil-safe: callers may call it unconditionally and it is a no-op when nil.
type Emitter func(model.ScanEvent)

// Emit is a nil-safe helper that calls e if it is non-nil.
func Emit(e Emitter, evt model.ScanEvent) {
	if e != nil {
		e(evt)
	}
}

type AgentInput struct {
	Target      string
	AuthProfile model.ScanAuthProfile
	Options     model.ScanOptions
	Scope       model.ScanScope
	// AutonomyMemory persists target/workspace execution learnings that can
	// guide scheduling decisions in future runs.
	AutonomyMemory model.AutonomyMemory
	Previous       AgentOutput
	History        []AgentOutput
	AllFindings    []model.Finding
	// Emit is an optional callback for publishing live scan events to the event bus.
	// Agents should use the package-level Emit helper to call it safely.
	Emit Emitter
}

type AgentOutput struct {
	AgentName   string
	Findings    []model.Finding
	Metadata    map[string]string
	Status      string
	DebugNotes  string
	StartedAt   time.Time
	CompletedAt time.Time
	DurationMs  int64
	TimedOut    bool
	Error       string
	Telemetry   model.AgentRunTelemetry
}

// Spawner is an optional callback that the registry calls during autonomous
// orchestration.  It supplements the built-in rules with learned Q-values from
// the agents service.
type Spawner interface {
	Recommend(ctx context.Context, sourceAgent string, findings []model.Finding, topK int, threshold float64) []string
}

type Registry struct {
	agents  map[string]Agent
	order   []string
	spawner Spawner
	factory *Factory
}

func NewRegistry() *Registry {
	return &Registry{
		agents: make(map[string]Agent),
		order:  make([]string, 0),
	}
}

// SetSpawner attaches a learned-spawn recommender to the registry.
func (r *Registry) SetSpawner(s Spawner) {
	r.spawner = s
}

func (r *Registry) Register(agent Agent) {
	if agent == nil {
		return
	}
	r.agents[agent.Name()] = agent
	r.order = append(r.order, agent.Name())
}

// RegisterFactory attaches a Factory used as a fallback when Get is asked for
// an agent that has not been pre-registered. This lets the orchestrator and
// the registry share a single source of truth for dynamic agent creation.
func (r *Registry) RegisterFactory(factory *Factory) {
	r.factory = factory
}

// Get returns a previously registered agent or, if not found and a factory
// has been registered, a freshly built instance from the factory. Returns nil
// when neither source can satisfy the request.
func (r *Registry) Get(name string) Agent {
	if a, ok := r.agents[name]; ok {
		return a
	}
	if r.factory != nil {
		if a, err := r.factory.Create(name); err == nil {
			return a
		}
	}
	return nil
}

// Order returns the ordered list of statically registered agent names.
func (r *Registry) Order() []string {
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

func (r *Registry) RunAll(ctx context.Context, input AgentInput) ([]AgentOutput, []model.Finding, error) {
	outputs := make([]AgentOutput, 0, len(r.order))
	allFindings := make([]model.Finding, 0)
	cumulativeFindings := make([]model.Finding, 0)

	// Build a mutable work queue starting from the registered agent order so
	// that the orchestrator can dynamically append follow-up agents.
	queue := make([]string, len(r.order))
	copy(queue, r.order)
	seen := make(map[string]bool, len(r.order))

	for i := 0; i < len(queue); i++ {
		name := queue[i]
		ag := r.Get(name)
		if ag == nil || !ag.Enabled() {
			continue
		}

		select {
		case <-ctx.Done():
			return outputs, allFindings, ctx.Err()
		default:
		}

		input.Previous = AgentOutput{}
		if len(outputs) > 0 {
			input.Previous = outputs[len(outputs)-1]
		}
		input.AllFindings = append([]model.Finding(nil), cumulativeFindings...)

		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventAgentStart,
			AgentName: ag.Name(),
			Message:   fmt.Sprintf("Agent %q started", ag.Name()),
		})

		startedAt := time.Now().UTC()
		output, err := ag.Run(ctx, input)
		completedAt := time.Now().UTC()
		if err != nil {
			output.Status = "error"
			output.DebugNotes = err.Error()
			output.Error = err.Error()
			output.TimedOut = strings.Contains(strings.ToLower(err.Error()), "deadline exceeded")
		}
		if output.AgentName == "" {
			output.AgentName = ag.Name()
		}
		if output.Status == "" {
			output.Status = "completed"
		}
		output.StartedAt = startedAt
		output.CompletedAt = completedAt
		output.DurationMs = completedAt.Sub(startedAt).Milliseconds()
		output.Telemetry = model.AgentRunTelemetry{
			AgentName:   output.AgentName,
			Status:      output.Status,
			StartedAt:   output.StartedAt,
			CompletedAt: output.CompletedAt,
			DurationMs:  output.DurationMs,
			TimedOut:    output.TimedOut,
			Error:       output.Error,
			Metadata:    output.Metadata,
		}

		// Emit individual finding events so the frontend can show them live.
		for _, f := range output.Findings {
			Emit(input.Emit, model.ScanEvent{
				Type:         model.ScanEventFinding,
				AgentName:    ag.Name(),
				FindingTitle: f.Title,
				Severity:     string(f.Severity),
				Message:      fmt.Sprintf("[%s] %s", f.Severity, f.Title),
			})
		}

		Emit(input.Emit, model.ScanEvent{
			Type:      model.ScanEventAgentComplete,
			AgentName: ag.Name(),
			Message:   fmt.Sprintf("Agent %q completed in %dms with %d finding(s)", ag.Name(), output.DurationMs, len(output.Findings)),
			Metadata:  output.Metadata,
		})

		outputs = append(outputs, output)
		cumulativeFindings = append(cumulativeFindings, output.Findings...)
		allFindings = append(allFindings, output.Findings...)
		seen[name] = true

		// Autonomous orchestration: merge static rules with learned Q-values.
		// Use a set to track already-queued agents for O(1) lookup.
		queuedSet := make(map[string]bool, len(queue))
		for _, q := range queue[i+1:] {
			queuedSet[q] = true
		}

		candidates := r.orchestrate(ctx, ag.Name(), output, cumulativeFindings)
		for _, spawned := range candidates {
			if !seen[spawned] && !queuedSet[spawned] && r.Get(spawned) != nil {
				queue = append(queue, spawned)
				queuedSet[spawned] = true
				Emit(input.Emit, model.ScanEvent{
					Type:      model.ScanEventAgentSpawned,
					AgentName: spawned,
					Message:   fmt.Sprintf("Autonomous decision: queuing agent %q based on findings from %q", spawned, ag.Name()),
				})
			}
		}
	}

	return outputs, combineFindingsWithDedup(allFindings), nil
}

// orchestrate returns the names of agents that should be spawned autonomously
// after completedAgent finishes, given the accumulated findings so far.
// It merges static rules with recommendations from the neural agent learner.
func (r *Registry) orchestrate(ctx context.Context, completedAgent string, output AgentOutput, allFindings []model.Finding) []string {
	spawned := make([]string, 0)

	hasHigh := false
	hasSQLi := false
	hasWordPress := false
	hasManyForms := false
	hasSSRFIndicator := false
	hasAuthIssue := false
	hasUploadEndpoint := false
	hasRCEIndicator := false
	for _, f := range allFindings {
		if f.Severity == model.SeverityHigh {
			hasHigh = true
		}
		cat := strings.ToLower(f.Category)
		title := strings.ToLower(f.Title)
		ev := strings.ToLower(f.Evidence)
		if strings.Contains(cat, "injection") || strings.Contains(title, "sql") || strings.Contains(ev, "sql") {
			hasSQLi = true
		}
		if strings.Contains(title, "wordpress") || strings.Contains(ev, "wordpress") || strings.Contains(ev, "wp-content") {
			hasWordPress = true
		}
		if strings.Contains(title, "form") && (strings.Contains(title, "csrf") || strings.Contains(ev, "forms=")) {
			hasManyForms = true
		}
		if strings.Contains(cat, "ssrf") || strings.Contains(title, "ssrf") ||
			strings.Contains(title, "server-side request") || strings.Contains(title, "proxy") ||
			strings.Contains(ev, "param=url") || strings.Contains(ev, "param=fetch") ||
			strings.Contains(ev, "param=proxy") || strings.Contains(ev, "param=src") {
			hasSSRFIndicator = true
		}
		if strings.Contains(cat, "access_control") || strings.Contains(cat, "auth") ||
			strings.Contains(title, "authentication") || strings.Contains(title, "session") ||
			strings.Contains(title, "jwt") || strings.Contains(title, "token") ||
			strings.Contains(title, "credential") {
			hasAuthIssue = true
		}
		if strings.Contains(title, "upload") || strings.Contains(ev, "upload") ||
			strings.Contains(title, "file") || strings.Contains(ev, "multipart") {
			hasUploadEndpoint = true
		}
		if strings.Contains(cat, "remote_code_execution") || strings.Contains(cat, "rce") ||
			strings.Contains(title, "rce") || strings.Contains(title, "remote code") ||
			strings.Contains(title, "log4shell") || strings.Contains(title, "spring4shell") ||
			strings.Contains(title, "shellshock") || strings.Contains(title, "struts") ||
			strings.Contains(title, "path traversal") || strings.Contains(title, "webshell") {
			hasRCEIndicator = true
		}
	}

	_ = hasSQLi
	_ = hasWordPress

	// Static rules.
	switch completedAgent {
	case "scanning":
		if hasHigh {
			spawned = append(spawned, "attack_path")
		}
		// Any high-severity finding during scanning warrants Metasploit exploit probes.
		if hasHigh || hasRCEIndicator {
			spawned = append(spawned, "metasploit")
		}
		// Burp active scan runs after any scanning phase.
		spawned = append(spawned, "burp")
		if strings.EqualFold(strings.TrimSpace(output.Metadata["aggressive_exploitation"]), "true") {
			spawned = append(spawned, "metasploit", "auth_bypass", "file_upload")
		}
	case "input_validation":
		if hasManyForms {
			spawned = append(spawned, "cors_redirect")
		}
		// SQL/command injection findings warrant deeper auth and SSRF testing.
		if hasSQLi {
			spawned = append(spawned, "auth_bypass")
		}
		// Burp active scan complements input validation for injection checks.
		spawned = append(spawned, "burp")
	case "api_security":
		// API proxy/fetch patterns often co-occur with SSRF.
		if hasSSRFIndicator {
			spawned = append(spawned, "ssrf")
		}
	case "access_control":
		// Weak/missing auth warrants dedicated auth bypass testing.
		if hasAuthIssue || hasHigh {
			spawned = append(spawned, "auth_bypass")
		}
	case "information_disclosure":
		// Exposed endpoints may accept file uploads; also check auth.
		if hasUploadEndpoint {
			spawned = append(spawned, "file_upload")
		}
		if hasAuthIssue {
			spawned = append(spawned, "auth_bypass")
		}
	case "reconnaissance":
		// Upload surface discovered during recon.
		if hasUploadEndpoint {
			spawned = append(spawned, "file_upload")
		}
		// Any server-side fetcher hint from recon data.
		if hasSSRFIndicator {
			spawned = append(spawned, "ssrf")
		}
		// Burp active scan after recon surfaces new endpoints.
		spawned = append(spawned, "burp")
	case "wordlist":
		if len(output.Findings) > 0 {
			spawned = append(spawned, "analysis")
		}
		// Wordlist may expose upload endpoints.
		if hasUploadEndpoint {
			spawned = append(spawned, "file_upload")
		}
	case "analysis":
		if hasHigh {
			spawned = append(spawned, "ml_triage")
		}
		// RCE-class findings trigger Metasploit exploit verification.
		if hasRCEIndicator {
			spawned = append(spawned, "metasploit")
		}
	case "attack_path":
		// After attack path analysis, if RCE indicators exist escalate to Metasploit.
		if hasRCEIndicator || hasHigh {
			spawned = append(spawned, "metasploit")
		}
	}

	// Global adaptive autonomy rules.
	if hasHigh {
		spawned = append(spawned, "attack_path")
	}
	if hasAuthIssue {
		spawned = append(spawned, "auth_bypass")
	}
	if hasSSRFIndicator {
		spawned = append(spawned, "ssrf")
	}
	if hasRCEIndicator {
		spawned = append(spawned, "metasploit")
	}

	// Neural learner recommendations (augment static rules).
	if r.spawner != nil {
		learned := r.spawner.Recommend(ctx, completedAgent, allFindings, 3, 0.65)
		for _, l := range learned {
			if l != "" {
				spawned = append(spawned, l)
			}
		}
	}

	return dedupeAgentNames(spawned)
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

func dedupeAgentNames(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	deduped := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		deduped = append(deduped, item)
	}
	return deduped
}
