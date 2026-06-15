package api

// handlers_agent_dispatch.go — Agent Console endpoint.
//
// POST /api/agent/dispatch
//
// Accepts a JSON body:
//
//	{
//	  "agentName":    "reconnaissance",          // required; must be a registered agent
//	  "target":       "https://example.com",     // required; validated as a URL
//	  "instructions": "focus on admin panels",   // optional; appended to AttackPathHints
//	  "options":      { ... }                    // optional; ScanOptions subset
//	}
//
// Returns HTTP 202 with:
//
//	{
//	  "jobId":     "<uuid>",
//	  "agentName": "<name>",
//	  "eventsUrl": "/api/scan/<uuid>/events"
//	}
//
// The caller can then open an EventSource to eventsUrl to receive live
// ScanEvents from the agent as it runs.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
)

// agentDispatchRequest is the JSON body accepted by handleAgentDispatch.
type agentDispatchRequest struct {
	AgentName    string            `json:"agentName"`
	Target       string            `json:"target"`
	Instructions string            `json:"instructions,omitempty"`
	Options      model.ScanOptions `json:"options,omitempty"`
}

// handleAgentDispatch creates a lightweight scan job that runs a single named
// agent and returns immediately.  Callers stream events via the existing SSE
// endpoint at /api/scan/{jobId}/events.
func (s *Server) handleAgentDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// GET with no body returns the list of available agent names.
	if r.Method == http.MethodGet {
		names := s.agentRegistry.Order()
		writeJSON(w, http.StatusOK, map[string]any{"agents": names})
		return
	}

	var req agentDispatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Validate required fields.
	req.AgentName = strings.TrimSpace(req.AgentName)
	if req.AgentName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agentName is required"})
		return
	}
	if s.agentRegistry.Get(req.AgentName) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unknown agent %q; GET /api/agent/dispatch for available agents", req.AgentName),
		})
		return
	}

	target, _, err := normalizeAndValidateTarget(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := safety.ValidateOutboundURL(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target blocked by outbound safety policy"})
		return
	}

	// Merge caller instructions into OperatorHints so they flow into AI
	// prompts without requiring changes to every agent implementation.
	if instr := strings.TrimSpace(req.Instructions); instr != "" {
		req.Options.OperatorHints = append(req.Options.OperatorHints, instr)
	}

	jobID := uuid.NewString()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:          jobID,
		Target:      target,
		WorkspaceID: "console",
		RequestedBy: requesterFromRequest(r),
		PolicyPack:  defaultPolicyPack(),
		Status:      "queued",
		StartedAt:   now,
		Options:     req.Options,
	}
	{
		ctx, cancel := s.persistenceContext()
		defer cancel()
		if err := s.repo.CreateJob(ctx, job); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist dispatch job"})
			return
		}
	}
	s.appendAuditEvent(jobID, "queued", fmt.Sprintf("Agent Console: dispatching agent %q on %s", req.AgentName, target))

	go s.runDispatchedAgent(jobID, req.AgentName, target, req.Options)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"jobId":     jobID,
		"agentName": req.AgentName,
		"eventsUrl": "/api/scan/" + jobID + "/events",
	})
}

// runDispatchedAgent runs a single agent in a goroutine, emitting events and
// persisting findings exactly like a normal scan job, but without the full
// orchestration overhead.
func (s *Server) runDispatchedAgent(jobID, agentName, target string, options model.ScanOptions) {
	rawEmit := s.eventBus.EmitterFor(jobID)
	emit := func(event model.ScanEvent) {
		if shouldPersistAgentEvent(event.Type) {
			go func(e model.ScanEvent) {
				if err := s.repo.SaveAgentEvent(context.Background(), jobID, e); err != nil {
					log.Printf("agent dispatch: failed to save event for scan %s: %v", jobID, err)
				}
			}(event)
		}
		rawEmit(event)
	}

	// Mark running.
	job, err := s.loadJobForRun(jobID)
	if err != nil || job == nil {
		log.Printf("agent dispatch: failed to load job %s: %v", jobID, err)
		return
	}
	job.Status = "running"
	if err := s.persistJob(job); err != nil {
		log.Printf("agent dispatch: failed to mark job %s running: %v", jobID, err)
	}

	emit(model.ScanEvent{
		Type:    model.ScanEventInfo,
		Message: fmt.Sprintf("Agent Console: running agent %q on %s", agentName, target),
	})

	ctx, cancel := context.WithTimeout(context.Background(), agentDispatchTimeout)
	defer cancel()

	a := s.agentRegistry.Get(agentName)
	if a == nil {
		emit(model.ScanEvent{Type: model.ScanEventInfo, Message: fmt.Sprintf("agent %q not found in registry", agentName)})
		job.Status = "failed"
		_ = s.persistJob(job)
		return
	}

	input := agent.AgentInput{
		Target:            target,
		Options:           options,
		ScanID:            jobID,
		Emit:              agent.Emitter(emit),
		SharedScanContext: agent.NewSharedScanContext(),
		MemoryStore:       s.memoryStore,
	}

	started := time.Now()
	output, runErr := a.Run(ctx, input)
	elapsed := time.Since(started)

	if runErr != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventInfo,
			Message: fmt.Sprintf("Agent %q completed with error after %s: %v", agentName, elapsed.Round(time.Second), runErr),
		})
	} else {
		emit(model.ScanEvent{
			Type:    model.ScanEventInfo,
			Message: fmt.Sprintf("Agent %q completed in %s (%d finding(s))", agentName, elapsed.Round(time.Second), len(output.Findings)),
		})
	}

	// Persist findings.
	job.Findings = append(job.Findings, output.Findings...)
	now := time.Now().UTC()
	job.CompletedAt = &now
	if runErr != nil && ctx.Err() == nil {
		job.Status = "failed"
	} else {
		job.Status = "completed"
	}
	_ = s.persistJob(job)
	s.appendAuditEvent(jobID, job.Status, fmt.Sprintf("Agent Console: agent %q finished with %d finding(s)", agentName, len(output.Findings)))
}

// agentDispatchTimeout caps how long a single dispatched agent may run.  A
// generous 30-minute cap lets even slow tool-calling agents complete.
const agentDispatchTimeout = 30 * time.Minute
