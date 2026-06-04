package model

import "time"

// ScanEventType classifies the kind of event emitted during an autonomous scan.
type ScanEventType string

const (
	ScanEventAgentStart    ScanEventType = "agent_start"
	ScanEventAgentComplete ScanEventType = "agent_complete"
	ScanEventAgentSpawned  ScanEventType = "agent_spawned"
	ScanEventFinding       ScanEventType = "finding"
	ScanEventCommand       ScanEventType = "command"
	ScanEventCommandResult ScanEventType = "command_result"
	ScanEventScreenshot    ScanEventType = "screenshot"
	ScanEventInfo          ScanEventType = "info"
	// ScanEventReasoningLoop is emitted by the ReasoningIterationAgent after
	// each reflection step so the frontend can show the live reasoning process.
	ScanEventReasoningLoop ScanEventType = "reasoning_loop"
)

// ScanEvent is a structured real-time event emitted during scan execution.
// It is serialised to JSON and streamed over SSE to the frontend.
type ScanEvent struct {
	// Type classifies the event.
	Type ScanEventType `json:"type"`
	// Timestamp is when the event was created (UTC).
	Timestamp time.Time `json:"timestamp"`
	// AgentName is the name of the agent that produced the event (may be empty for global events).
	AgentName string `json:"agentName,omitempty"`
	// Message is a human-readable description of the event.
	Message string `json:"message,omitempty"`
	// Command holds the shell/tool invocation string for command events.
	Command string `json:"command,omitempty"`
	// Output holds the command stdout/stderr for command result events.
	Output string `json:"output,omitempty"`
	// FindingTitle is the finding title for finding events.
	FindingTitle string `json:"findingTitle,omitempty"`
	// Severity is the finding severity for finding events.
	Severity string `json:"severity,omitempty"`
	// Screenshot is a base64-encoded PNG image for screenshot events.
	Screenshot string `json:"screenshot,omitempty"`
	// Metadata carries additional structured key/value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`
}
