package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/scope"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

func (s *Server) handleAutomationEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req model.AutomationEventRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Type == "" {
		req.Type = "deploy"
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
	if err := validateAuthProfile(req.AuthProfile); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req.Scope = scope.Normalize(target, req.Scope)
	if !scope.IsURLInScope(target, req.Scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target is out of configured scope profile"})
		return
	}
	req.Options.DeepScanOnHighSignal = true
	req.Options.RescanIntervalMinutes = 0
	req.Options.AutomationMode = normalizeAutomationMode(req.Options.AutomationMode)
	req.Options = s.applySafetyModePolicy(req.Options)
	req.Options.MinExpectedROIUSD = maxFloat(req.Options.MinExpectedROIUSD, s.defaultMinROI)
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	if blocked, reason := s.shouldDeferForDailyBudget(r.Context(), workspaceID, req.Options); blocked {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": reason})
		return
	}
	jobID := uuid.NewString()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:                 jobID,
		Target:             target,
		WorkspaceID:        workspaceID,
		RequestedBy:        requesterFromRequest(r),
		PolicyPack:         defaultPolicyPack(),
		Status:             "queued",
		StartedAt:          now,
		AuthProfileSummary: model.SummarizeAuthProfile(req.AuthProfile),
		Options:            req.Options,
		Scope:              req.Scope,
		ProgramName:        strings.TrimSpace(req.ProgramName),
	}
	if err := s.repo.CreateJob(r.Context(), job); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist automation scan job"})
		return
	}
	s.appendAuditEvent(jobID, "automation-event", "Event-driven scan queued: "+req.Type)
	if len(req.Assets) > 0 {
		s.appendAuditEvent(jobID, "asset-discovery", fmt.Sprintf("Auto-enrolled %d externally discovered assets", len(req.Assets)))
	}
	go s.runJob(jobID, target, req.AuthProfile, nil, req.Options, req.Scope)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": jobID, "status": "queued", "eventType": req.Type})
}

func (s *Server) handleAutomationCampaigns(w http.ResponseWriter, r *http.Request) {
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		activeOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("activeOnly")), "true")
		items, err := s.repo.ListAutomationCampaigns(r.Context(), workspaceID, activeOnly, 500)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list automation campaigns"})
			return
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost, http.MethodPut:
		var req model.AutomationCampaignUpsertRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		target, _, err := normalizeAndValidateTarget(req.Target)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if req.IntervalMin < 5 || req.IntervalMin > 10080 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "intervalMin must be between 5 and 10080"})
			return
		}
		req.ScheduleType = normalizeScheduleType(req.ScheduleType)
		if err := validateCampaignSchedule(req.ScheduleType, req.ScheduleValue, req.RunWindow, req.BlackoutWindows); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := validateAuthProfile(req.AuthProfile); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.Scope = scope.Normalize(target, req.Scope)
		if !scope.IsURLInScope(target, req.Scope) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "target is out of configured scope profile"})
			return
		}
		now := time.Now().UTC()
		if strings.TrimSpace(req.ID) == "" {
			req.ID = uuid.NewString()
		}
		if r.Method == http.MethodPost {
			req.Active = true
		}
		req.Options.AutomationMode = normalizeAutomationMode(req.Options.AutomationMode)
		req.Options = s.applySafetyModePolicy(req.Options)
		req.PolicyPack = normalizePolicyPackName(req.PolicyPack)
		req.AuthorizationEvidence = normalizeAuthorizationEvidence(req.AuthorizationEvidence)
		if err := validateCampaignAuthorization(req, now); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		policyVersion := 0
		req.Options, policyVersion = s.applyAutomationPolicyPack(r.Context(), workspaceID, req.PolicyPack, req.Options)
		req.Options.MinExpectedROIUSD = maxFloat(req.Options.MinExpectedROIUSD, s.defaultMinROI)
		nextRunAt := computeNextCampaignRun(now, req)
		item := model.AutomationCampaign{
			ID:                    req.ID,
			Target:                target,
			WorkspaceID:           workspaceID,
			RequestedBy:           requesterFromRequest(r),
			PolicyPack:            req.PolicyPack,
			PolicyVersion:         policyVersion,
			AuthorizationApproval: req.AuthorizationApproval,
			AuthorizationEvidence: req.AuthorizationEvidence,
			Name:                  strings.TrimSpace(req.Name),
			ProgramName:           strings.TrimSpace(req.ProgramName),
			IntervalMin:           req.IntervalMin,
			ScheduleType:          req.ScheduleType,
			ScheduleValue:         strings.TrimSpace(req.ScheduleValue),
			RunWindow:             strings.TrimSpace(req.RunWindow),
			BlackoutWindows:       req.BlackoutWindows,
			NextRunAt:             nextRunAt,
			MaxAttempts:           maxInt(3, req.MaxAttempts),
			Active:                req.Active,
			AuthProfile:           req.AuthProfile,
			Options:               req.Options,
			Scope:                 req.Scope,
			CreatedAt:             now,
			UpdatedAt:             now,
		}
		if item.PolicyPack == "" {
			item.PolicyPack = defaultPolicyPack()
		}
		item.AuthorizationDigest = campaignAuthorizationDigest(item)
		if !req.Active {
			item.NextRunAt = time.Time{}
		}
		if err := s.repo.UpsertAutomationCampaign(r.Context(), item); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save automation campaign"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"id": item.ID, "status": "saved"})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id query parameter is required"})
			return
		}
		if err := s.repo.DeleteAutomationCampaign(r.Context(), id, workspaceID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete automation campaign"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAutomationCampaignAuthorizationExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	campaignID := strings.TrimSpace(r.URL.Query().Get("id"))
	if campaignID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id query parameter is required"})
		return
	}
	items, err := s.repo.ListAutomationCampaigns(r.Context(), workspaceID, false, 1000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list automation campaigns"})
		return
	}
	var campaign *model.AutomationCampaign
	for i := range items {
		if strings.TrimSpace(items[i].ID) == campaignID {
			campaign = &items[i]
			break
		}
	}
	if campaign == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "campaign not found"})
		return
	}
	evidence := normalizeAuthorizationEvidence(campaign.AuthorizationEvidence)
	exportedAt := time.Now().UTC()
	payload := map[string]any{
		"schemaVersion":         "authorization-evidence.v1",
		"campaignId":            campaign.ID,
		"workspaceId":           campaign.WorkspaceID,
		"target":                campaign.Target,
		"policyPack":            campaign.PolicyPack,
		"policyVersion":         campaign.PolicyVersion,
		"authorizationApproval": campaign.AuthorizationApproval,
		"authorizationEvidence": evidence,
		"authorizationDigest":   firstNonEmpty(strings.TrimSpace(campaign.AuthorizationDigest), campaignAuthorizationDigest(*campaign)),
		"exportedAt":            exportedAt,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate authorization export"})
		return
	}
	sum := sha256.Sum256(raw)
	payload["exportHash"] = hex.EncodeToString(sum[:])
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleAutomationReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	jobs, err := s.repo.ListCompletedJobs(r.Context(), 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load completed jobs"})
		return
	}
	feedback, _ := s.repo.ListFeedback(r.Context(), 1000)
	openTickets, _ := s.repo.ListOpenAutomationTickets(r.Context(), "", 1000)

	report := model.ExecutiveReport{
		GeneratedAt:            time.Now().UTC(),
		AgentAcceptedRate:      map[string]float64{},
		AgentPayoutPerScanHour: map[string]float64{},
		AgentFalsePositiveRate: map[string]float64{},
		ROISparkline:           []float64{},
	}
	agentRuns := map[string]int{}
	agentScanHours := map[string]float64{}
	for _, job := range jobs {
		if !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
			continue
		}
		report.TotalCompletedScans++
		if job.Dashboard != nil {
			report.AverageExpectedROIUSD += maxFloat(0, job.Dashboard.ExpectedROIUSD)
			if job.Dashboard.MeetsROIGate {
				report.HighROICompletedScans++
			}
			report.ROISparkline = append(report.ROISparkline, roundTo2(job.Dashboard.ExpectedROIUSD))
		}
		if job.CompletedAt != nil {
			durationHours := maxFloat(0.05, job.CompletedAt.Sub(job.StartedAt).Hours())
			for _, run := range job.AgentRuns {
				name := strings.TrimSpace(run.AgentName)
				if name == "" {
					continue
				}
				agentRuns[name]++
				agentScanHours[name] += durationHours
			}
		}
		for _, finding := range job.Findings {
			switch strings.ToLower(strings.TrimSpace(finding.DriftStatus)) {
			case "new":
				report.NewFindings++
			case "changed":
				report.ChangedFindings++
			case "resolved":
				report.ResolvedFindings++
			}
			if finding.Severity == model.SeverityHigh || finding.Severity == model.SeverityMedium {
				report.HighOrMediumFindings++
			}
		}
	}
	ws := workspaceFromRequest(r)
	if ws == "" {
		report.OpenAutomationTickets = len(openTickets)
	} else {
		for _, ticket := range openTickets {
			if strings.HasPrefix(ticket.Target, ws+"::") {
				report.OpenAutomationTickets++
			}
		}
	}
	for _, item := range feedback {
		switch strings.ToLower(strings.TrimSpace(item.Outcome)) {
		case "accepted":
			report.AcceptedFeedback++
		case "rejected":
			report.RejectedFeedback++
		case "duplicate":
			report.DuplicateFeedback++
		}
	}
	if report.TotalCompletedScans > 0 {
		report.AverageExpectedROIUSD /= float64(report.TotalCompletedScans)
	}
	acceptedPayout := 0.0
	for _, item := range feedback {
		if strings.EqualFold(strings.TrimSpace(item.Outcome), "accepted") {
			acceptedPayout += maxFloat(0, item.PayoutUSD)
		}
	}
	if report.TotalCompletedScans > 0 {
		report.AcceptedPayoutPerScanUSD = acceptedPayout / float64(report.TotalCompletedScans)
	}
	acceptedRate := 0.0
	if totalReviewed := report.AcceptedFeedback + report.RejectedFeedback + report.DuplicateFeedback; totalReviewed > 0 {
		acceptedRate = float64(report.AcceptedFeedback) / float64(totalReviewed)
	}
	totalReviewed := report.AcceptedFeedback + report.RejectedFeedback + report.DuplicateFeedback
	if totalReviewed > 0 {
		report.FalsePositiveRate = float64(report.RejectedFeedback+report.DuplicateFeedback) / float64(totalReviewed)
	}
	for agentName, runs := range agentRuns {
		hours := maxFloat(0.1, agentScanHours[agentName])
		report.AgentAcceptedRate[agentName] = roundTo2(acceptedRate)
		report.AgentPayoutPerScanHour[agentName] = roundTo2(acceptedPayout / hours)
		report.AgentFalsePositiveRate[agentName] = roundTo2(report.FalsePositiveRate)
		if runs == 0 {
			delete(report.AgentAcceptedRate, agentName)
			delete(report.AgentPayoutPerScanHour, agentName)
			delete(report.AgentFalsePositiveRate, agentName)
		}
	}
	_ = openTickets
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleAutomationROIOverrides(w http.ResponseWriter, r *http.Request) {
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.repo.ListProgramROIOverrides(r.Context(), workspaceID, 500)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list roi overrides"})
			return
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost, http.MethodPut:
		var req struct {
			ProgramName       string  `json:"programName"`
			MinExpectedROIUSD float64 `json:"minExpectedRoiUsd"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if strings.TrimSpace(req.ProgramName) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "programName is required"})
			return
		}
		item := model.ProgramROIOverride{
			WorkspaceID:       workspaceID,
			ProgramName:       strings.TrimSpace(req.ProgramName),
			MinExpectedROIUSD: maxFloat(0, req.MinExpectedROIUSD),
			UpdatedAt:         time.Now().UTC(),
		}
		if err := s.repo.UpsertProgramROIOverride(r.Context(), item); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save roi override"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "saved"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAutomationTickets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if ws := workspaceFromRequest(r); ws != "" && target != "" {
		target = ws + "::" + target
	}
	tickets, err := s.repo.ListOpenAutomationTickets(r.Context(), target, 200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list automation tickets"})
		return
	}
	if ws := workspaceFromRequest(r); ws != "" {
		filtered := make([]model.AutomationTicket, 0, len(tickets))
		for _, ticket := range tickets {
			if strings.HasPrefix(ticket.Target, ws+"::") {
				ticket.Target = strings.TrimPrefix(ticket.Target, ws+"::")
				filtered = append(filtered, ticket)
			}
		}
		writeJSON(w, http.StatusOK, filtered)
		return
	}
	writeJSON(w, http.StatusOK, tickets)
}

func normalizePolicyPackName(raw string) string {
	pack := strings.ToLower(strings.TrimSpace(raw))
	if pack == "" {
		return defaultPolicyPack()
	}
	return pack
}

func (s *Server) applyAutomationPolicyPack(ctx context.Context, workspaceID, packName string, options model.ScanOptions) (model.ScanOptions, int) {
	packName = normalizePolicyPackName(packName)
	pack, err := s.repo.GetAutomationPolicyPack(ctx, firstNonEmpty(workspaceID, "default"), packName)
	if err != nil || pack == nil {
		return options, 0
	}
	if mode := normalizeAutomationMode(pack.AutomationMode); mode != "" {
		options.AutomationMode = mode
	}
	options.AutonomyCanaryPercent = maxInt(0, minInt(100, pack.CanaryPercent))
	options.MinExpectedROIUSD = maxFloat(options.MinExpectedROIUSD, pack.MinExpectedROIUSD)
	if pack.MaxAutomationConcurrency > 0 {
		if options.MaxAutomationConcurrency <= 0 {
			options.MaxAutomationConcurrency = pack.MaxAutomationConcurrency
		} else {
			options.MaxAutomationConcurrency = minInt(options.MaxAutomationConcurrency, pack.MaxAutomationConcurrency)
		}
	}
	if pack.MaxPerTargetConcurrency > 0 {
		if options.MaxPerTargetConcurrency <= 0 {
			options.MaxPerTargetConcurrency = pack.MaxPerTargetConcurrency
		} else {
			options.MaxPerTargetConcurrency = minInt(options.MaxPerTargetConcurrency, pack.MaxPerTargetConcurrency)
		}
	}
	if pack.MaxExploitAttempts >= 0 {
		if options.MaxExploitAttempts <= 0 {
			options.MaxExploitAttempts = pack.MaxExploitAttempts
		} else {
			options.MaxExploitAttempts = minInt(options.MaxExploitAttempts, pack.MaxExploitAttempts)
		}
	}
	if pack.DailyScanLimit > 0 {
		if options.DailyScanLimit <= 0 {
			options.DailyScanLimit = pack.DailyScanLimit
		} else {
			options.DailyScanLimit = minInt(options.DailyScanLimit, pack.DailyScanLimit)
		}
	}
	if pack.DailyRuntimeLimitMinutes > 0 {
		if options.DailyRuntimeLimitMinutes <= 0 {
			options.DailyRuntimeLimitMinutes = pack.DailyRuntimeLimitMinutes
		} else {
			options.DailyRuntimeLimitMinutes = minInt(options.DailyRuntimeLimitMinutes, pack.DailyRuntimeLimitMinutes)
		}
	}
	if pack.DailyProbeLimit > 0 {
		if options.DailyProbeLimit <= 0 {
			options.DailyProbeLimit = pack.DailyProbeLimit
		} else {
			options.DailyProbeLimit = minInt(options.DailyProbeLimit, pack.DailyProbeLimit)
		}
	}
	options = applyGovernancePolicy(options, pack.GovernanceProfile)
	return options, maxInt(1, pack.StrategyVersion)
}

func applyGovernancePolicy(options model.ScanOptions, governance model.AutonomyGovernanceProfile) model.ScanOptions {
	if governance.FailureHandling.MaxNoNoveltyRounds > 0 {
		options.AutonomyMaxNoNoveltyRounds = governance.FailureHandling.MaxNoNoveltyRounds
	}
	if governance.FailureHandling.MaxConsecutiveFailureRounds > 0 {
		options.AutonomyMaxConsecutiveFailRounds = governance.FailureHandling.MaxConsecutiveFailureRounds
	}
	if governance.FailureHandling.BackoffMillis > 0 {
		options.BackoffMillis = maxInt(options.BackoffMillis, governance.FailureHandling.BackoffMillis)
	}
	if governance.FailureHandling.AutoRetryOnFailure {
		options.AutonomyFallbackRerun = true
	}
	if lock := strings.ToLower(strings.TrimSpace(governance.FailureHandling.FallbackPlanner)); lock == "static" || lock == "fallback" || lock == "ai" {
		if strings.TrimSpace(options.AutonomyPlannerLock) == "" {
			options.AutonomyPlannerLock = lock
		}
	}
	if governance.MemoryPolicy.RetentionDays > 0 {
		options.AutonomyMemoryRetentionDays = governance.MemoryPolicy.RetentionDays
	}
	if governance.RiskMatrix.RetryLimit > 0 {
		if options.MaxRetries <= 0 {
			options.MaxRetries = governance.RiskMatrix.RetryLimit
		} else {
			options.MaxRetries = minInt(options.MaxRetries, governance.RiskMatrix.RetryLimit)
		}
	}
	stage := strings.ToLower(strings.TrimSpace(os.Getenv("AUTOMATION_ENV_STAGE")))
	if stage == "" {
		stage = "dev"
	}
	if criteria, ok := governance.SuccessCriteria[stage]; ok {
		marginal := criteria.NovelFindingsRateMin
		if criteria.FalsePositiveRateMax > 0 {
			marginal *= maxFloat(0.1, 1.0-criteria.FalsePositiveRateMax*0.5)
		}
		if marginal > 0 {
			options.AutonomyMinMarginalScore = maxFloat(options.AutonomyMinMarginalScore, minFloat(0.95, marginal))
		}
	}
	if governance.RolloutControl.CanaryPercentByStage != nil {
		if p, ok := governance.RolloutControl.CanaryPercentByStage[stage]; ok {
			p = maxInt(0, minInt(100, p))
			if options.AutonomyCanaryPercent <= 0 {
				options.AutonomyCanaryPercent = p
			} else {
				options.AutonomyCanaryPercent = minInt(options.AutonomyCanaryPercent, p)
			}
			if p == 0 {
				options.MaxAutomationConcurrency = 1
				options.AutonomyExplorationBudgetPercent = 0
			} else {
				options.AutonomyExplorationBudgetPercent = maxInt(options.AutonomyExplorationBudgetPercent, minInt(25, maxInt(5, p/4)))
			}
		}
	}
	tenantTier := strings.ToLower(strings.TrimSpace(options.AutonomyTenantTier))
	if tenantTier == "" {
		tenantTier = "default"
	}
	if budget, ok := governance.TenantRiskBudgets[tenantTier]; ok {
		if budget.MaxExploitAttempts >= 0 {
			if options.MaxExploitAttempts <= 0 {
				options.MaxExploitAttempts = budget.MaxExploitAttempts
			} else {
				options.MaxExploitAttempts = minInt(options.MaxExploitAttempts, budget.MaxExploitAttempts)
			}
		}
		if budget.MaxPerTargetConcurrency > 0 {
			if options.MaxPerTargetConcurrency <= 0 {
				options.MaxPerTargetConcurrency = budget.MaxPerTargetConcurrency
			} else {
				options.MaxPerTargetConcurrency = minInt(options.MaxPerTargetConcurrency, budget.MaxPerTargetConcurrency)
			}
		}
		if budget.MaxAutomationConcurrency > 0 {
			if options.MaxAutomationConcurrency <= 0 {
				options.MaxAutomationConcurrency = budget.MaxAutomationConcurrency
			} else {
				options.MaxAutomationConcurrency = minInt(options.MaxAutomationConcurrency, budget.MaxAutomationConcurrency)
			}
		}
		if budget.DailyScanLimit > 0 {
			if options.DailyScanLimit <= 0 {
				options.DailyScanLimit = budget.DailyScanLimit
			} else {
				options.DailyScanLimit = minInt(options.DailyScanLimit, budget.DailyScanLimit)
			}
		}
		if budget.DailyRuntimeLimitMinutes > 0 {
			if options.DailyRuntimeLimitMinutes <= 0 {
				options.DailyRuntimeLimitMinutes = budget.DailyRuntimeLimitMinutes
			} else {
				options.DailyRuntimeLimitMinutes = minInt(options.DailyRuntimeLimitMinutes, budget.DailyRuntimeLimitMinutes)
			}
		}
		if budget.DailyProbeLimit > 0 {
			if options.DailyProbeLimit <= 0 {
				options.DailyProbeLimit = budget.DailyProbeLimit
			} else {
				options.DailyProbeLimit = minInt(options.DailyProbeLimit, budget.DailyProbeLimit)
			}
		}
	}
	if governance.CostControls.MaxRoundCostUnits > 0 {
		options.AutonomyMaxRoundCostUnits = governance.CostControls.MaxRoundCostUnits
	}
	if governance.CostControls.CostWeight > 0 {
		options.AutonomyCostWeight = clampFloat(governance.CostControls.CostWeight, 0.01, 1.0)
	}
	if !governance.OperatorOverride.AllowForceRun {
		options.AutonomyForceRunAgents = nil
	}
	if !governance.OperatorOverride.AllowSuppress {
		options.AutonomySuppressAgents = nil
	}
	if !governance.OperatorOverride.AllowPlannerLock {
		options.AutonomyPlannerLock = ""
	}
	if !governance.OperatorOverride.AllowFallbackRerun {
		options.AutonomyFallbackRerun = false
	}
	if !governance.OperatorOverride.AllowEmergencyStop {
		options.AutonomyEmergencyStop = false
	}
	return options
}

func validateGovernanceProfile(profile model.AutonomyGovernanceProfile) error {
	for env, c := range profile.SuccessCriteria {
		if strings.TrimSpace(env) == "" {
			return errors.New("successCriteria environment key is required")
		}
		if c.NovelFindingsRateMin < 0 || c.NovelFindingsRateMin > 1 {
			return fmt.Errorf("successCriteria[%s].novelFindingsRateMin must be between 0 and 1", env)
		}
		if c.FalsePositiveRateMax < 0 || c.FalsePositiveRateMax > 1 {
			return fmt.Errorf("successCriteria[%s].falsePositiveRateMax must be between 0 and 1", env)
		}
		if c.DuplicateSuppressionRateMin < 0 || c.DuplicateSuppressionRateMin > 1 {
			return fmt.Errorf("successCriteria[%s].duplicateSuppressionRateMin must be between 0 and 1", env)
		}
		if c.FailureRecoveryRateMin < 0 || c.FailureRecoveryRateMin > 1 {
			return fmt.Errorf("successCriteria[%s].failureRecoveryRateMin must be between 0 and 1", env)
		}
		if c.ScanDurationCapMinutes < 0 {
			return fmt.Errorf("successCriteria[%s].scanDurationCapMinutes must be >= 0", env)
		}
	}
	if profile.RiskMatrix.RetryLimit < 0 {
		return errors.New("riskMatrix.retryLimit must be >= 0")
	}
	if profile.FailureHandling.BackoffMillis < 0 ||
		profile.FailureHandling.MaxNoNoveltyRounds < 0 ||
		profile.FailureHandling.MaxConsecutiveFailureRounds < 0 ||
		profile.FailureHandling.PauseForOperatorAfterFailures < 0 {
		return errors.New("failureHandling numeric values must be >= 0")
	}
	if profile.MemoryPolicy.RetentionDays < 0 {
		return errors.New("memoryPolicy.retentionDays must be >= 0")
	}
	if profile.EvaluationGate.MinKPIDeltaScore < 0 {
		return errors.New("evaluationGate.minKpiDeltaScore must be >= 0")
	}
	for stage, pct := range profile.RolloutControl.CanaryPercentByStage {
		if strings.TrimSpace(stage) == "" {
			return errors.New("rolloutControl.canaryPercentByStage stage key is required")
		}
		if pct < 0 || pct > 100 {
			return fmt.Errorf("rolloutControl.canaryPercentByStage[%s] must be between 0 and 100", stage)
		}
	}
	for tier, budget := range profile.TenantRiskBudgets {
		if strings.TrimSpace(tier) == "" {
			return errors.New("tenantRiskBudgets tier key is required")
		}
		if budget.MaxExploitAttempts < 0 ||
			budget.MaxPerTargetConcurrency < 0 ||
			budget.MaxAutomationConcurrency < 0 ||
			budget.DailyScanLimit < 0 ||
			budget.DailyRuntimeLimitMinutes < 0 ||
			budget.DailyProbeLimit < 0 {
			return fmt.Errorf("tenantRiskBudgets[%s] values must be >= 0", tier)
		}
	}
	if profile.CostControls.MaxRoundCostUnits < 0 {
		return errors.New("costControls.maxRoundCostUnits must be >= 0")
	}
	if profile.CostControls.CostWeight < 0 || profile.CostControls.CostWeight > 1 {
		return errors.New("costControls.costWeight must be between 0 and 1")
	}
	return nil
}

// PolicyProfileBudgetSpec describes the explicit risk-budget bounds enforced
// for a given default automation profile (safe / autonomous / aggressive /
// canary). Bounds are expressed as inclusive ranges and surface to operators
// via the /api/automation/policy-profile-defaults endpoint so that the UI can
// render guidance and the API can reject out-of-range policy packs.
type PolicyProfileBudgetSpec struct {
	Mode                        string  `json:"automationMode"`
	Description                 string  `json:"description,omitempty"`
	MaxExploitAttemptsMin       int     `json:"maxExploitAttemptsMin"`
	MaxExploitAttemptsMax       int     `json:"maxExploitAttemptsMax"`
	MaxAutomationConcurrencyMin int     `json:"maxAutomationConcurrencyMin"`
	MaxAutomationConcurrencyMax int     `json:"maxAutomationConcurrencyMax"`
	MaxPerTargetConcurrencyMin  int     `json:"maxPerTargetConcurrencyMin"`
	MaxPerTargetConcurrencyMax  int     `json:"maxPerTargetConcurrencyMax"`
	DailyScanLimitMin           int     `json:"dailyScanLimitMin"`
	DailyScanLimitMax           int     `json:"dailyScanLimitMax"`
	DailyRuntimeLimitMinutesMin int     `json:"dailyRuntimeLimitMinutesMin"`
	DailyRuntimeLimitMinutesMax int     `json:"dailyRuntimeLimitMinutesMax"`
	DailyProbeLimitMin          int     `json:"dailyProbeLimitMin"`
	DailyProbeLimitMax          int     `json:"dailyProbeLimitMax"`
	MinExpectedROIUSDMin        float64 `json:"minExpectedRoiUsdMin"`
}

// policyProfileBudgetSpecs returns the canonical risk-budget envelopes for
// each supported automation mode. Operators must publish a policy pack whose
// values fall inside these envelopes; this is what makes "every automated run
// is attached to a policy profile and budget decision record" enforceable
// rather than advisory.
func policyProfileBudgetSpecs() map[string]PolicyProfileBudgetSpec {
	return map[string]PolicyProfileBudgetSpec{
		"safe": {
			Mode:                        "safe",
			Description:                 "Read-mostly profile: no exploit attempts, single-stream concurrency, conservative daily caps.",
			MaxExploitAttemptsMin:       0,
			MaxExploitAttemptsMax:       0,
			MaxAutomationConcurrencyMin: 1,
			MaxAutomationConcurrencyMax: 1,
			MaxPerTargetConcurrencyMin:  1,
			MaxPerTargetConcurrencyMax:  1,
			DailyScanLimitMin:           1,
			DailyScanLimitMax:           50,
			DailyRuntimeLimitMinutesMin: 15,
			DailyRuntimeLimitMinutesMax: 240,
			DailyProbeLimitMin:          1,
			DailyProbeLimitMax:          2000,
			MinExpectedROIUSDMin:        0,
		},
		"autonomous": {
			Mode:                        "autonomous",
			Description:                 "Default unattended profile: bounded exploitation, modest concurrency, mandatory daily caps.",
			MaxExploitAttemptsMin:       1,
			MaxExploitAttemptsMax:       3,
			MaxAutomationConcurrencyMin: 1,
			MaxAutomationConcurrencyMax: 4,
			MaxPerTargetConcurrencyMin:  1,
			MaxPerTargetConcurrencyMax:  3,
			DailyScanLimitMin:           1,
			DailyScanLimitMax:           200,
			DailyRuntimeLimitMinutesMin: 30,
			DailyRuntimeLimitMinutesMax: 720,
			DailyProbeLimitMin:          100,
			DailyProbeLimitMax:          10000,
			MinExpectedROIUSDMin:        25,
		},
		"aggressive": {
			Mode:                        "aggressive",
			Description:                 "Bug-bounty profile: deep exploitation allowed, higher concurrency, larger daily caps still required.",
			MaxExploitAttemptsMin:       3,
			MaxExploitAttemptsMax:       12,
			MaxAutomationConcurrencyMin: 2,
			MaxAutomationConcurrencyMax: 8,
			MaxPerTargetConcurrencyMin:  2,
			MaxPerTargetConcurrencyMax:  6,
			DailyScanLimitMin:           5,
			DailyScanLimitMax:           500,
			DailyRuntimeLimitMinutesMin: 60,
			DailyRuntimeLimitMinutesMax: 1440,
			DailyProbeLimitMin:          500,
			DailyProbeLimitMax:          50000,
			MinExpectedROIUSDMin:        50,
		},
		"canary": {
			Mode:                        "canary",
			Description:                 "Gradual-rollout profile: minimal exploit attempts and single-stream concurrency for new strategies.",
			MaxExploitAttemptsMin:       0,
			MaxExploitAttemptsMax:       1,
			MaxAutomationConcurrencyMin: 1,
			MaxAutomationConcurrencyMax: 1,
			MaxPerTargetConcurrencyMin:  1,
			MaxPerTargetConcurrencyMax:  1,
			DailyScanLimitMin:           1,
			DailyScanLimitMax:           50,
			DailyRuntimeLimitMinutesMin: 15,
			DailyRuntimeLimitMinutesMax: 240,
			DailyProbeLimitMin:          1,
			DailyProbeLimitMax:          5000,
			MinExpectedROIUSDMin:        0,
		},
	}
}

// validatePolicyPackBudgets enforces the per-profile budget envelope on an
// AutomationPolicyPack upsert request. Returning an error rejects the upsert
// with a descriptive 400 so operators understand which budget knob is
// out-of-range. Required values that are zero/empty are reported as
// "must be set" — the goal is to make budget decisions explicit, not silent.
func validatePolicyPackBudgets(req model.AutomationPolicyPack) error {
	mode := normalizeAutomationMode(req.AutomationMode)
	spec, ok := policyProfileBudgetSpecs()[mode]
	if !ok {
		return fmt.Errorf("unknown automationMode %q", req.AutomationMode)
	}
	check := func(field string, value, min, max int) error {
		if value < min {
			if value == 0 && min > 0 {
				return fmt.Errorf("%s must be set for %s profile (min %d)", field, mode, min)
			}
			return fmt.Errorf("%s=%d is below %s profile minimum %d", field, value, mode, min)
		}
		if value > max {
			return fmt.Errorf("%s=%d exceeds %s profile maximum %d", field, value, mode, max)
		}
		return nil
	}
	if err := check("maxExploitAttempts", req.MaxExploitAttempts, spec.MaxExploitAttemptsMin, spec.MaxExploitAttemptsMax); err != nil {
		return err
	}
	if err := check("maxAutomationConcurrency", req.MaxAutomationConcurrency, spec.MaxAutomationConcurrencyMin, spec.MaxAutomationConcurrencyMax); err != nil {
		return err
	}
	if err := check("maxPerTargetConcurrency", req.MaxPerTargetConcurrency, spec.MaxPerTargetConcurrencyMin, spec.MaxPerTargetConcurrencyMax); err != nil {
		return err
	}
	if err := check("dailyScanLimit", req.DailyScanLimit, spec.DailyScanLimitMin, spec.DailyScanLimitMax); err != nil {
		return err
	}
	if err := check("dailyRuntimeLimitMinutes", req.DailyRuntimeLimitMinutes, spec.DailyRuntimeLimitMinutesMin, spec.DailyRuntimeLimitMinutesMax); err != nil {
		return err
	}
	if err := check("dailyProbeLimit", req.DailyProbeLimit, spec.DailyProbeLimitMin, spec.DailyProbeLimitMax); err != nil {
		return err
	}
	if req.MinExpectedROIUSD < spec.MinExpectedROIUSDMin {
		return fmt.Errorf("minExpectedRoiUsd=%.2f is below %s profile minimum %.2f", req.MinExpectedROIUSD, mode, spec.MinExpectedROIUSDMin)
	}
	return nil
}

func (s *Server) handlePolicyProfileDefaults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	specs := policyProfileBudgetSpecs()
	out := make([]PolicyProfileBudgetSpec, 0, len(specs))
	for _, mode := range []string{"safe", "autonomous", "aggressive", "canary"} {
		if v, ok := specs[mode]; ok {
			out = append(out, v)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func shouldPersistAgentEvent(eventType model.ScanEventType) bool {
	switch eventType {
	case model.ScanEventAgentStart,
		model.ScanEventAgentComplete,
		model.ScanEventAgentSpawned,
		model.ScanEventInfo,
		model.ScanEventReasoningLoop,
		model.ScanEventThinking,
		model.ScanEventDiscovery,
		model.ScanEventCommand,
		model.ScanEventCommandResult,
		model.ScanEventFinding,
		model.ScanEventScreenshot:
		return true
	default:
		return false
	}
}

func (s *Server) handleAutomationPolicyPacks(w http.ResponseWriter, r *http.Request) {
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.repo.ListAutomationPolicyPacks(r.Context(), workspaceID, 200)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list policy packs"})
			return
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost, http.MethodPut:
		if !hasRole(r.Context(), model.APIKeyRoleAdmin) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
			return
		}
		var req model.AutomationPolicyPack
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		req.WorkspaceID = workspaceID
		req.Name = normalizePolicyPackName(req.Name)
		req.UpdatedBy = requesterFromRequest(r)
		if req.StrategyVersion <= 0 {
			req.StrategyVersion = 1
		}
		if err := validateGovernanceProfile(req.GovernanceProfile); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := validatePolicyPackBudgets(req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		before, _ := s.repo.GetAutomationPolicyPack(r.Context(), workspaceID, req.Name)
		req.UpdatedAt = time.Now().UTC()
		if err := s.repo.UpsertAutomationPolicyPack(r.Context(), req); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save policy pack"})
			return
		}
		after, _ := json.Marshal(req)
		beforeJSON := ""
		if before != nil {
			if b, err := json.Marshal(before); err == nil {
				beforeJSON = string(b)
			}
		}
		_ = s.repo.AppendAutomationPolicyAudit(r.Context(), model.AutomationPolicyAuditEvent{
			ID:              uuid.NewString(),
			WorkspaceID:     workspaceID,
			PolicyPack:      req.Name,
			StrategyVersion: req.StrategyVersion,
			Action:          "upsert",
			ChangedBy:       requesterFromRequest(r),
			ChangedAt:       time.Now().UTC(),
			BeforeJSON:      beforeJSON,
			AfterJSON:       string(after),
		})
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "saved"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAutomationPolicyAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	pack := normalizePolicyPackName(r.URL.Query().Get("policyPack"))
	if strings.TrimSpace(r.URL.Query().Get("policyPack")) == "" {
		pack = ""
	}
	items, err := s.repo.ListAutomationPolicyAudit(r.Context(), workspaceID, pack, 300)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list policy audit"})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleAutomationMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	campaigns, err := s.repo.ListAutomationCampaigns(r.Context(), workspaceID, false, 1000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load campaigns"})
		return
	}
	now := time.Now().UTC()
	preReport := scanner.GetVerificationMetrics()
	clusterMetrics := scanner.GetClusterMetrics()
	diffMetrics := scanner.GetDifferentialMetrics()
	surfaceMetrics := scanner.GetSurfaceCoverageMetrics()
	paramMetrics := scanner.GetParamDiscoveryMetrics()
	evidenceMetrics := scanner.GetEvidenceMetrics()
	calibrationMetrics := scanner.GetCalibrationApplyMetrics()
	lagSum := 0.0
	lagCount := 0
	maxLag := 0.0
	retrying := 0
	dlq := 0
	for _, c := range campaigns {
		if c.DeadLetter {
			dlq++
		}
		if c.RetryCount > 0 {
			retrying++
		}
		dueAt := c.NextRunAt
		if c.NextRetryAt != nil && !c.NextRetryAt.IsZero() {
			dueAt = *c.NextRetryAt
		}
		if !dueAt.IsZero() && dueAt.Before(now) {
			lag := now.Sub(dueAt).Seconds()
			lagSum += lag
			lagCount++
			maxLag = maxFloat(maxLag, lag)
		}
	}
	jobs, _ := s.repo.ListCompletedJobs(r.Context(), 1000)
	strategyROI := map[string]float64{}
	strategyCounts := map[string]int{}
	outcomeByStrategy := map[string]float64{}
	outcomeSamplesByStrategy := map[string]int{}
	canaryByPolicy := map[string]int{}
	failedRuns := 0
	totalRuns := 0
	fallbackRuns := 0
	fallbackRecoveredRuns := 0
	outcomeScoreTotal := 0.0
	outcomeScoreSamples := 0
	verifiedSampled := 0
	rejectedCount := 0
	verifiedByCategory := map[string]int{}
	rejectedByCategory := map[string]int{}
	strictScans := 0
	strictSuppressed := 0
	for _, job := range jobs {
		if !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
			continue
		}
		strategy := normalizePolicyPackName(job.PolicyPack)
		if strategy == "" {
			strategy = "internal"
		}
		if job.Dashboard != nil {
			strategyROI[strategy] += maxFloat(0, job.Dashboard.ExpectedROIUSD)
		}
		outcomeScore := autonomyOutcomeScore(job)
		outcomeByStrategy[strategy] += outcomeScore
		outcomeSamplesByStrategy[strategy]++
		outcomeScoreTotal += outcomeScore
		outcomeScoreSamples++
		strategyCounts[strategy]++
		for _, run := range job.AgentRuns {
			totalRuns++
			if strings.EqualFold(strings.TrimSpace(run.Status), "failed") || run.TimedOut {
				failedRuns++
			}
			if run.Metadata != nil && strings.EqualFold(strings.TrimSpace(run.Metadata["autonomy_fallback"]), "static") {
				fallbackRuns++
				if strings.EqualFold(strings.TrimSpace(run.Status), "completed") && !run.TimedOut && strings.TrimSpace(run.Error) == "" {
					fallbackRecoveredRuns++
				}
			}
		}
		if job.Options.StrictReporting {
			strictScans++
			if filtered, suppressed, _, applied := applyStrictReportingFilter(job, nil); applied && filtered != nil {
				strictSuppressed += suppressed
			}
		}
		findingCategory := map[string]string{}
		for _, finding := range job.Findings {
			key := strings.TrimSpace(finding.ID)
			if key == "" {
				continue
			}
			findingCategory[key] = strings.ToLower(strings.TrimSpace(finding.Category))
		}
		if verifications, err := s.repo.GetLatestFindingVerifications(r.Context(), job.ID); err == nil {
			for _, v := range verifications {
				cat := strings.TrimSpace(findingCategory[strings.TrimSpace(v.FindingID)])
				switch findingLifecycleAliases(v.Status) {
				case "verified", "rejected", "suppressed", "accepted", "remediated":
					verifiedSampled++
					if cat != "" {
						verifiedByCategory[cat]++
					}
				}
				switch findingLifecycleAliases(v.Status) {
				case "rejected", "suppressed":
					rejectedCount++
					if cat != "" {
						rejectedByCategory[cat]++
					}
				}
			}
		}
	}
	falsePositiveByCategory := map[string]float64{}
	for cat, total := range verifiedByCategory {
		if total <= 0 {
			continue
		}
		falsePositiveByCategory[cat] = roundTo2(float64(rejectedByCategory[cat]) / float64(total))
	}
	shadowAlignmentByCategory := map[string]float64{}
	shadowSamplesByCategory := map[string]int{}
	shadowAlignedByCategory := map[string]int{}
	shadowSamples := 0
	shadowAligned := 0
	if reader, ok := s.repo.(shadowDecisionReader); ok {
		if shadowRows, err := reader.ListShadowDecisions(r.Context(), now.Add(-90*24*time.Hour), 10000); err == nil {
			for _, row := range shadowRows {
				shadowSamples++
				if row.Aligned {
					shadowAligned++
				}
				cat := strings.ToLower(strings.TrimSpace(row.Category))
				if cat != "" {
					shadowSamplesByCategory[cat]++
					if row.Aligned {
						shadowAlignedByCategory[cat]++
					}
				}
			}
		}
	}
	for cat, total := range shadowSamplesByCategory {
		if total <= 0 {
			continue
		}
		shadowAlignmentByCategory[cat] = roundTo2(float64(shadowAlignedByCategory[cat]) / float64(total))
	}
	if packs, err := s.repo.ListAutomationPolicyPacks(r.Context(), workspaceID, 200); err == nil {
		for _, pack := range packs {
			name := normalizePolicyPackName(pack.Name)
			if name == "" {
				continue
			}
			canaryByPolicy[name] = maxInt(0, minInt(100, pack.CanaryPercent))
		}
	}
	rollbackEventsRecent := 0
	if auditItems, err := s.repo.ListAutomationPolicyAudit(r.Context(), workspaceID, "", 300); err == nil {
		for _, item := range auditItems {
			action := strings.ToLower(strings.TrimSpace(item.Action))
			if strings.Contains(action, "rollback") {
				rollbackEventsRecent++
			}
		}
	}
	for name, total := range strategyCounts {
		if total > 0 {
			strategyROI[name] = roundTo2(strategyROI[name] / float64(total))
		}
	}
	for name, total := range outcomeSamplesByStrategy {
		if total > 0 {
			outcomeByStrategy[name] = roundTo2(outcomeByStrategy[name] / float64(total))
		}
	}
	avgLag := 0.0
	if lagCount > 0 {
		avgLag = lagSum / float64(lagCount)
	}
	retryRate := 0.0
	if len(campaigns) > 0 {
		retryRate = float64(retrying) / float64(len(campaigns))
	}
	toolFailureRate := 0.0
	if totalRuns > 0 {
		toolFailureRate = float64(failedRuns) / float64(totalRuns)
	}
	alerts := make([]string, 0)
	if avgLag > float64(maxInt(60, intFromEnv("AUTOMATION_ALERT_QUEUE_LAG_SECONDS", 300))) {
		alerts = append(alerts, "queue lag exceeded threshold")
	}
	if retryRate > floatFromEnv("AUTOMATION_ALERT_RETRY_RATE", 0.35) {
		alerts = append(alerts, "retry rate exceeded threshold")
	}
	if dlq > maxInt(0, intFromEnv("AUTOMATION_ALERT_DLQ_COUNT", 5)) {
		alerts = append(alerts, "dead-letter queue size exceeded threshold")
	}
	if toolFailureRate > floatFromEnv("AUTOMATION_ALERT_TOOL_FAILURE_RATE", 0.25) {
		alerts = append(alerts, "tool failure rate exceeded threshold")
	}
	avgOutcomeScore := 0.0
	if outcomeScoreSamples > 0 {
		avgOutcomeScore = outcomeScoreTotal / float64(outcomeScoreSamples)
	}
	if avgOutcomeScore > 0 && avgOutcomeScore < floatFromEnv("AUTOMATION_ALERT_AUTONOMY_OUTCOME_SCORE", 0.45) {
		alerts = append(alerts, "autonomy outcome score dropped below threshold")
	}
	fallbackRecoveryRate := 0.0
	if fallbackRuns > 0 {
		fallbackRecoveryRate = float64(fallbackRecoveredRuns) / float64(fallbackRuns)
	}
	if fallbackRuns > 0 && fallbackRecoveryRate < floatFromEnv("AUTOMATION_ALERT_FALLBACK_RECOVERY_RATE", 0.5) {
		alerts = append(alerts, "autonomy fallback recovery rate below threshold")
	}
	killSwitchActive := boolFromEnv("AUTONOMY_GLOBAL_KILL_SWITCH", false)
	if killSwitchActive {
		alerts = append(alerts, "autonomy global kill switch is active")
	}
	extraMetrics := map[string]float64{
		"lagSamples":                   float64(lagCount),
		"agentRuns":                    float64(totalRuns),
		"autonomyOutcomeScore":         roundTo2(avgOutcomeScore),
		"autonomyFallbackRuns":         float64(fallbackRuns),
		"autonomyFallbackRecoveryRate": roundTo2(fallbackRecoveryRate),
		"autonomyKillSwitchActive": func() float64 {
			if killSwitchActive {
				return 1
			}
			return 0
		}(),
		"preReportTotal":                   float64(preReport.Total),
		"preReportVerified":                float64(preReport.Verified),
		"preReportSuppressed":              float64(preReport.Suppressed),
		"preReportDowngraded":              float64(preReport.Downgraded),
		"preReportPoCReplayed":             float64(preReport.PoCReplayed),
		"preReportPoCSucceeded":            float64(preReport.PoCSucceeded),
		"preReportVerifiedRate":            roundTo2(preReport.VerifiedRate),
		"preReportSuppressedRate":          roundTo2(preReport.SuppressedRate),
		"preReportPoCSuccessRate":          roundTo2(preReport.PoCSuccessRate),
		"preReportAverageConfidence":       roundTo2(preReport.AverageConfidence),
		"clusterTotalIn":                   float64(clusterMetrics.TotalIn),
		"clusterTotalOut":                  float64(clusterMetrics.TotalOut),
		"clusterClustered":                 float64(clusterMetrics.Clustered),
		"clusterRatio":                     roundTo2(clusterMetrics.Ratio),
		"differentialTotal":                float64(diffMetrics.Total),
		"differentialConfirmed":            float64(diffMetrics.Confirmed),
		"differentialFPStripped":           float64(diffMetrics.FPStripped),
		"differentialFPBenign":             float64(diffMetrics.FPBenign),
		"differentialExecErrors":           float64(diffMetrics.ExecErrors),
		"differentialConfirmedRate":        roundTo2(diffMetrics.ConfirmedRate),
		"surfaceTotal":                     float64(surfaceMetrics.InventoryTotal),
		"surfaceProbed":                    float64(surfaceMetrics.ProbedUnique),
		"surfaceCoverageRatio":             roundTo2(surfaceMetrics.CoverageRatio),
		"surfaceGapUnprobed":               float64(surfaceMetrics.GapUnprobed),
		"surfaceGapParamMissing":           float64(surfaceMetrics.GapParamMissing),
		"surfaceGapMethodMissing":          float64(surfaceMetrics.GapMethodMissing),
		"paramDiscoveryCandidates":         float64(paramMetrics.Candidates),
		"paramDiscoveryConfirmed":          float64(paramMetrics.Confirmed),
		"evidenceValid":                    float64(evidenceMetrics.Valid),
		"evidenceIncomplete":               float64(evidenceMetrics.Incomplete),
		"evidenceValidRatio":               roundTo2(evidenceMetrics.ValidRatio),
		"evidenceMissingUrl":               float64(evidenceMetrics.MissingByField["url"]),
		"evidenceMissingMethod":            float64(evidenceMetrics.MissingByField["method"]),
		"evidenceMissingParam":             float64(evidenceMetrics.MissingByField["param"]),
		"evidenceMissingPayloadClass":      float64(evidenceMetrics.MissingByField["payloadClass"]),
		"evidenceMissingReflectionContext": float64(evidenceMetrics.MissingByField["reflectionContext"]),
		"evidenceMissingResponseShape":     float64(evidenceMetrics.MissingByField["responseShape"]),
		"evidenceMissingOracleName":        float64(evidenceMetrics.MissingByField["oracleName"]),
		"calibrationApplied":               float64(calibrationMetrics.Applied),
		"calibrationSkipped":               float64(calibrationMetrics.Skipped),
		"calibrationPromoted":              float64(calibrationMetrics.Promoted),
		"calibrationDemoted":               float64(calibrationMetrics.Demoted),
		"calibrationMeanPosterior":         roundTo2(calibrationMetrics.MeanPosterior),
	}
	sanitizeMetricName := func(in string) string {
		s := strings.TrimSpace(strings.ToLower(in))
		if s == "" {
			return "unknown"
		}
		var b strings.Builder
		b.Grow(len(s))
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
				continue
			}
			b.WriteRune('_')
		}
		out := b.String()
		out = strings.Trim(out, "_")
		if out == "" {
			return "unknown"
		}
		return out
	}
	for name, agg := range preReport.ByProbe {
		key := sanitizeMetricName(name)
		extraMetrics["preReportProbeTotal."+key] = float64(agg.Total)
		extraMetrics["preReportProbeVerified."+key] = float64(agg.Verified)
		extraMetrics["preReportProbeSuppressed."+key] = float64(agg.Suppressed)
		extraMetrics["preReportProbeDowngraded."+key] = float64(agg.Downgraded)
		if agg.Total > 0 {
			extraMetrics["preReportProbeVerifiedRate."+key] = roundTo2(float64(agg.Verified) / float64(agg.Total))
			extraMetrics["preReportProbeSuppressedRate."+key] = roundTo2(float64(agg.Suppressed) / float64(agg.Total))
			extraMetrics["preReportProbeDowngradedRate."+key] = roundTo2(float64(agg.Downgraded) / float64(agg.Total))
		}
		if agg.PoCReplayed > 0 {
			extraMetrics["preReportProbePoCSuccessRate."+key] = roundTo2(float64(agg.PoCSucceeded) / float64(agg.PoCReplayed))
		}
	}
	for name, agg := range preReport.ByCategory {
		key := sanitizeMetricName(name)
		extraMetrics["preReportCategoryTotal."+key] = float64(agg.Total)
		extraMetrics["preReportCategoryVerified."+key] = float64(agg.Verified)
		extraMetrics["preReportCategorySuppressed."+key] = float64(agg.Suppressed)
	}
	writeJSON(w, http.StatusOK, model.AutomationMetrics{
		GeneratedAt:           now,
		WorkspaceID:           workspaceID,
		QueueLagSeconds:       roundTo2(avgLag),
		MaxQueueLag:           roundTo2(maxLag),
		RetryRate:             roundTo2(retryRate),
		DLQCount:              dlq,
		ToolFailureRate:       roundTo2(toolFailureRate),
		ROIByStrategy:         strategyROI,
		StrategyRunCounts:     strategyCounts,
		Alerts:                alerts,
		CanaryPercentByPolicy: canaryByPolicy,
		RollbackEventsRecent:  rollbackEventsRecent,
		FalsePositiveRate: func() float64 {
			if verifiedSampled == 0 {
				return 0
			}
			return roundTo2(float64(rejectedCount) / float64(verifiedSampled))
		}(),
		FalsePositiveRateByCategory: falsePositiveByCategory,
		VerifiedFindingsByCategory:  verifiedByCategory,
		ShadowAlignmentRate: func() float64 {
			if shadowSamples == 0 {
				return 0
			}
			return roundTo2(float64(shadowAligned) / float64(shadowSamples))
		}(),
		ShadowAlignmentByCategory:   shadowAlignmentByCategory,
		ShadowSamples:               shadowSamples,
		VerifiedFindingsSampled:     verifiedSampled,
		StrictReportingSuppressed:   strictSuppressed,
		StrictReportingScansSampled: strictScans,
		StrictReportingSuppressRate: func() float64 {
			if strictScans == 0 {
				return 0
			}
			return roundTo2(float64(strictSuppressed) / float64(strictScans))
		}(),
		Extra: extraMetrics,
	})
}

func autonomyOutcomeScore(job *model.ScanJob) float64 {
	if job == nil {
		return 0
	}
	completion := 0.0
	switch strings.ToLower(strings.TrimSpace(job.Status)) {
	case "completed":
		completion = 1
	case "cancelled":
		completion = 0.2
	}
	runSuccess := 0.0
	if len(job.AgentRuns) == 0 {
		if completion > 0 {
			runSuccess = completion
		}
	} else {
		success := 0
		for _, run := range job.AgentRuns {
			if strings.EqualFold(strings.TrimSpace(run.Status), "completed") && !run.TimedOut && strings.TrimSpace(run.Error) == "" {
				success++
			}
		}
		runSuccess = float64(success) / float64(len(job.AgentRuns))
	}
	highSignal := 0
	for _, finding := range job.Findings {
		if finding.Confidence >= 0.75 || finding.Severity == model.SeverityHigh {
			highSignal++
		}
	}
	signalQuality := 0.0
	if len(job.Findings) > 0 {
		signalQuality = float64(highSignal) / float64(len(job.Findings))
	}
	return clampFloat(completion*0.5+runSuccess*0.3+signalQuality*0.2, 0, 1)
}

func (s *Server) handleAutomationRebalance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !hasRole(r.Context(), model.APIKeyRoleAdmin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	var req struct {
		PolicyPack     string  `json:"policyPack"`
		CanaryPercent  int     `json:"canaryPercent"`
		Rollback       bool    `json:"rollback"`
		ExpectedMinROI float64 `json:"expectedMinRoiUsd"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	packName := normalizePolicyPackName(req.PolicyPack)
	pack, err := s.repo.GetAutomationPolicyPack(r.Context(), workspaceID, packName)
	if err != nil || pack == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy pack not found"})
		return
	}
	stage := strings.ToLower(strings.TrimSpace(os.Getenv("AUTOMATION_ENV_STAGE")))
	if stage == "" {
		stage = "dev"
	}
	if stage == "prod" &&
		pack.GovernanceProfile.EvaluationGate.PromoteToProdOnlyIfPass &&
		pack.GovernanceProfile.EvaluationGate.RequireReplayBenchmark {
		passed, delta, benchErr := s.runReplayBenchmark(r.Context(), workspaceID, pack.GovernanceProfile.EvaluationGate.MinKPIDeltaScore)
		if benchErr != nil {
			writeJSON(w, http.StatusPreconditionFailed, map[string]string{"error": "replay benchmark approval is required for production promotion"})
			return
		}
		if !passed {
			if pack.GovernanceProfile.RolloutControl.AutoRollbackOnKPIRegression && pack.CanaryPercent > 0 {
				beforeRaw, _ := json.Marshal(pack)
				next := *pack
				next.CanaryPercent = 0
				next.UpdatedBy = requesterFromRequest(r)
				next.UpdatedAt = time.Now().UTC()
				if err := s.repo.UpsertAutomationPolicyPack(r.Context(), next); err == nil {
					afterRaw, _ := json.Marshal(next)
					_ = s.repo.AppendAutomationPolicyAudit(r.Context(), model.AutomationPolicyAuditEvent{
						ID:              uuid.NewString(),
						WorkspaceID:     workspaceID,
						PolicyPack:      packName,
						StrategyVersion: next.StrategyVersion,
						Action:          "auto-rollback-kpi",
						ChangedBy:       requesterFromRequest(r),
						ChangedAt:       time.Now().UTC(),
						BeforeJSON:      string(beforeRaw),
						AfterJSON:       string(afterRaw),
					})
					writeJSON(w, http.StatusPreconditionFailed, map[string]any{
						"error":           "replay benchmark did not meet minimum KPI delta score",
						"delta":           fmt.Sprintf("%.3f", delta),
						"rollbackApplied": true,
						"canaryPercent":   0,
					})
					return
				}
			}
			writeJSON(w, http.StatusPreconditionFailed, map[string]string{
				"error": "replay benchmark did not meet minimum KPI delta score",
				"delta": fmt.Sprintf("%.3f", delta),
			})
			return
		}
	}
	beforeRaw, _ := json.Marshal(pack)
	next := *pack
	if req.Rollback {
		next.CanaryPercent = 0
	} else {
		next.StrategyVersion = maxInt(1, next.StrategyVersion+1)
		nextCanary := maxInt(0, minInt(100, req.CanaryPercent))
		if stageCanary, ok := next.GovernanceProfile.RolloutControl.CanaryPercentByStage[stage]; ok {
			nextCanary = minInt(nextCanary, maxInt(0, minInt(100, stageCanary)))
		}
		next.CanaryPercent = nextCanary
		if req.ExpectedMinROI > 0 {
			next.MinExpectedROIUSD = maxFloat(next.MinExpectedROIUSD, req.ExpectedMinROI)
		}
	}
	next.UpdatedBy = requesterFromRequest(r)
	next.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpsertAutomationPolicyPack(r.Context(), next); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update policy pack"})
		return
	}
	afterRaw, _ := json.Marshal(next)
	action := "rebalance"
	if req.Rollback {
		action = "rollback"
	}
	_ = s.repo.AppendAutomationPolicyAudit(r.Context(), model.AutomationPolicyAuditEvent{
		ID:              uuid.NewString(),
		WorkspaceID:     workspaceID,
		PolicyPack:      packName,
		StrategyVersion: next.StrategyVersion,
		Action:          action,
		ChangedBy:       requesterFromRequest(r),
		ChangedAt:       time.Now().UTC(),
		BeforeJSON:      string(beforeRaw),
		AfterJSON:       string(afterRaw),
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":          "updated",
		"policyPack":      packName,
		"strategyVersion": next.StrategyVersion,
		"canaryPercent":   next.CanaryPercent,
		"rollback":        req.Rollback,
	})
}

func (s *Server) runReplayBenchmark(ctx context.Context, workspaceID string, minDelta float64) (bool, float64, error) {
	jobs, err := s.repo.ListCompletedJobs(ctx, 500)
	if err != nil {
		return false, 0, err
	}
	total := 0.0
	count := 0
	for _, job := range jobs {
		if firstNonEmpty(job.WorkspaceID, "default") != firstNonEmpty(workspaceID, "default") {
			continue
		}
		runScore := 0.0
		runCount := 0
		for _, run := range job.AgentRuns {
			if run.Metadata == nil {
				continue
			}
			raw := strings.TrimSpace(run.Metadata["decision_quality_score"])
			if raw == "" {
				continue
			}
			parsed, parseErr := strconv.ParseFloat(raw, 64)
			if parseErr != nil {
				continue
			}
			runScore += clampFloat(parsed, 0, 1)
			runCount++
		}
		if runCount == 0 {
			continue
		}
		total += runScore / float64(runCount)
		count++
		if count >= 100 {
			break
		}
	}
	if count == 0 {
		return false, 0, fmt.Errorf("no replay data")
	}
	avg := total / float64(count)
	delta := avg - 0.5
	return delta >= minDelta, delta, nil
}

func (s *Server) evaluatePolicyGate(findings []model.Finding, policyPack string) model.PolicyGateResult {
	highBlock := s.gateHighBlock
	medBlock := s.gateMedBlock
	switch strings.ToLower(strings.TrimSpace(policyPack)) {
	case "regulated":
		highBlock = 0
		medBlock = 1
	case "bugbounty":
		highBlock = maxInt(1, s.gateHighBlock)
		medBlock = maxInt(2, s.gateMedBlock)
	}
	result := model.PolicyGateResult{
		Status:      "pass",
		GeneratedAt: time.Now().UTC(),
	}
	uncorroborated := 0
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityHigh:
			result.HighCount++
			result.BlockedFindings = append(result.BlockedFindings, f.Title)
			if !findingHasHighSeverityCorroboration(f) {
				uncorroborated++
				if result.UncorroboratedHighFindings == nil {
					result.UncorroboratedHighFindings = make([]string, 0, 1)
				}
				result.UncorroboratedHighFindings = append(result.UncorroboratedHighFindings, f.Title)
			}
		case model.SeverityMedium:
			result.MediumCount++
		}
	}
	thresholdExceeded := result.HighCount >= highBlock || result.MediumCount >= medBlock
	switch {
	case thresholdExceeded && uncorroborated > 0:
		result.Status = "blocked"
		result.Reason = fmt.Sprintf("policy_pack=%s high=%d medium=%d exceeded thresholds high>=%d or medium>=%d; %d high finding(s) lack multi-source corroboration or verified exploitability", strings.TrimSpace(policyPack), result.HighCount, result.MediumCount, highBlock, medBlock, uncorroborated)
	case thresholdExceeded:
		result.Status = "blocked"
		result.Reason = fmt.Sprintf("policy_pack=%s high=%d medium=%d exceeded thresholds high>=%d or medium>=%d", strings.TrimSpace(policyPack), result.HighCount, result.MediumCount, highBlock, medBlock)
	case uncorroborated > 0:
		result.Status = "blocked"
		result.Reason = fmt.Sprintf("policy_pack=%s %d high finding(s) lack multi-source corroboration or verified exploitability", strings.TrimSpace(policyPack), uncorroborated)
	default:
		result.Reason = fmt.Sprintf("policy_pack=%s thresholds satisfied", strings.TrimSpace(policyPack))
	}
	return result
}

// findingHasHighSeverityCorroboration returns true when a HIGH finding meets
// at least one of the corroboration requirements that gate publication:
//   - confirmed by ≥2 distinct agents/tools (Sources), or
//   - explicit reachable exploitability evidence, or
//   - operator-verified exploitability status (verified/confirmed).
//
// Findings emitted by the policy/governance subsystems themselves (e.g. the
// "policy-gate-blocked-release" sentinel) are exempt to avoid recursive
// blocking.
func findingHasHighSeverityCorroboration(f model.Finding) bool {
	if strings.EqualFold(strings.TrimSpace(f.Category), "governance") {
		return true
	}
	distinct := map[string]struct{}{}
	for _, src := range f.Sources {
		s := strings.ToLower(strings.TrimSpace(src))
		if s == "" {
			continue
		}
		distinct[s] = struct{}{}
	}
	if len(distinct) >= 2 {
		return true
	}
	if f.Exploitability != nil {
		if f.Exploitability.Reachable {
			return true
		}
		switch strings.ToLower(strings.TrimSpace(f.Exploitability.VerifiedStatus)) {
		case "verified", "confirmed":
			return true
		}
	}
	return false
}

func (s *Server) tuneScanOptions(ctx context.Context, target string, options model.ScanOptions, state *model.PersistentScanState, previous *model.ScanJob) model.ScanOptions {
	if previous != nil && previous.Dashboard != nil && previous.Dashboard.CoverageCompletenessScore < coverageLowThreshold {
		options.CrawlMaxPages = maxInt(options.CrawlMaxPages, coverageLowCrawlBoostPages)
	}
	if previous != nil && previous.Dashboard != nil {
		if previous.Dashboard.MeetsROIGate && previous.Dashboard.ExpectedROIUSD > s.defaultMinROI*highROIMultiplierForDeepScan {
			options.DeepScanOnHighSignal = true
			options.UseNucleiIntegration = true
			options.UseFFUFIntegration = true
		}
		if !previous.Dashboard.MeetsROIGate {
			options.UseSQLMapIntegration = false
			options.CrawlMaxPages = minInt(maxInt(options.CrawlMaxPages, lowROICrawlFloorPages), lowROICrawlCeilingPages)
		}
	}
	if state != nil && state.SessionInstability > 2 {
		options.UseNucleiIntegration = false
		options.UseSQLMapIntegration = false
		options.UseFFUFIntegration = false
	}

	// Gap 13: adaptive category budget.
	// Inspect the previous scan's probe records to identify categories that
	// produced exclusively no_signal outcomes (≥ noSignalMinProbes probes with
	// ≥ noSignalRateThreshold fraction of no_signal). Those categories are
	// appended to AutonomySuppressAgents as "skip-cat:<category>" entries so
	// that AdaptiveProbeAgent can forward them to the AI as a low-priority
	// advisory rather than wasting step budget on provably-clean attack surface.
	if previous != nil && previous.ID != "" {
		records, err := s.repo.ListProbeRecords(ctx, previous.ID)
		if err == nil && len(records) > 0 {
			type catStats struct{ total, noSignal int }
			stats := make(map[string]*catStats)
			for _, r := range records {
				if r.Category == "" {
					continue
				}
				if stats[r.Category] == nil {
					stats[r.Category] = &catStats{}
				}
				stats[r.Category].total++
				if r.Outcome == model.ProbeNoSignal {
					stats[r.Category].noSignal++
				}
			}
			for cat, cs := range stats {
				if cs.total >= noSignalMinProbes &&
					float64(cs.noSignal)/float64(cs.total) >= noSignalRateThreshold {
					options.AutonomySuppressAgents = append(
						options.AutonomySuppressAgents,
						"skip-cat:"+cat,
					)
				}
			}
		}
	}

	return options
}

func normalizeAutomationMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "safe", "aggressive", "autonomous", "canary":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "autonomous"
	}
}

func normalizeScheduleType(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "daily", "weekly", "cron":
		return strings.ToLower(strings.TrimSpace(kind))
	default:
		return "interval"
	}
}

func parseScheduleValueAndLocation(raw string) (string, *time.Location, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", time.UTC, nil
	}
	if !strings.Contains(value, "|") {
		return value, time.UTC, nil
	}
	parts := strings.SplitN(value, "|", 2)
	tz := strings.TrimSpace(parts[0])
	inner := strings.TrimSpace(parts[1])
	if tz == "" {
		return inner, time.UTC, nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return "", nil, fmt.Errorf("invalid schedule timezone")
	}
	return inner, loc, nil
}

func validateCampaignSchedule(scheduleType, scheduleValue, runWindow string, blackoutWindows []string) error {
	inner, _, err := parseScheduleValueAndLocation(scheduleValue)
	if err != nil {
		return err
	}
	if strings.TrimSpace(runWindow) != "" && !validWindowSpec(runWindow) {
		return fmt.Errorf("runWindow must use HH:MM-HH:MM format")
	}
	for _, win := range blackoutWindows {
		if strings.TrimSpace(win) != "" && !validWindowSpec(win) {
			return fmt.Errorf("blackoutWindows must use HH:MM-HH:MM format")
		}
	}
	switch normalizeScheduleType(scheduleType) {
	case "daily":
		if _, _, ok := parseClock(inner); !ok {
			return fmt.Errorf("daily scheduleValue must use HH:MM (optionally TZ|HH:MM)")
		}
	case "weekly":
		raw := strings.Split(inner, "@")
		if len(raw) != 2 {
			return fmt.Errorf("weekly scheduleValue must use weekday@HH:MM (optionally TZ|weekday@HH:MM)")
		}
		weekday := strings.ToLower(strings.TrimSpace(raw[0]))
		if weekday != "sun" && weekday != "mon" && weekday != "tue" && weekday != "wed" && weekday != "thu" && weekday != "fri" && weekday != "sat" {
			return fmt.Errorf("weekly scheduleValue must use sun|mon|tue|wed|thu|fri|sat")
		}
		if _, _, ok := parseClock(raw[1]); !ok {
			return fmt.Errorf("weekly scheduleValue must use weekday@HH:MM")
		}
	case "cron":
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		if _, err := parser.Parse(strings.TrimSpace(inner)); err != nil {
			return fmt.Errorf("cron scheduleValue must be a 5-field cron expression (optionally TZ|expr)")
		}
	}
	return nil
}

func validateCampaignAuthorization(req model.AutomationCampaignUpsertRequest, now time.Time) error {
	approval := req.AuthorizationApproval
	evidence := normalizeAuthorizationEvidence(req.AuthorizationEvidence)
	if !req.Active && strings.TrimSpace(approval.Signature) == "" && len(evidence) == 0 {
		return nil
	}
	if strings.TrimSpace(approval.ApprovedBy) == "" {
		return fmt.Errorf("authorizationApproval.approvedBy is required")
	}
	if strings.TrimSpace(approval.ApproverRole) == "" {
		return fmt.Errorf("authorizationApproval.approverRole is required")
	}
	if strings.TrimSpace(approval.Signature) == "" {
		return fmt.Errorf("authorizationApproval.signature is required")
	}
	if approval.ApprovedAt.IsZero() {
		return fmt.Errorf("authorizationApproval.approvedAt is required")
	}
	if approval.ApprovedAt.After(now.Add(campaignApprovalClockSkewTolerance)) {
		return fmt.Errorf("authorizationApproval.approvedAt cannot be more than %d minutes in the future", int(campaignApprovalClockSkewTolerance.Minutes()))
	}
	if len(evidence) == 0 {
		return fmt.Errorf("authorizationEvidence must include at least one record")
	}
	for i := range evidence {
		ev := evidence[i]
		if strings.TrimSpace(ev.Type) == "" {
			return fmt.Errorf("authorizationEvidence[%d].type is required", i)
		}
		if strings.TrimSpace(ev.Label) == "" {
			return fmt.Errorf("authorizationEvidence[%d].label is required", i)
		}
		if strings.TrimSpace(ev.URI) == "" && strings.TrimSpace(ev.SHA256) == "" {
			return fmt.Errorf("authorizationEvidence[%d] requires uri or sha256", i)
		}
		if sum := strings.TrimSpace(ev.SHA256); sum != "" && !isSHA256Hex(sum) {
			return fmt.Errorf("authorizationEvidence[%d].sha256 must be a 64-char hex digest", i)
		}
	}
	return nil
}

func normalizeAuthorizationEvidence(in []model.AuthorizationEvidence) []model.AuthorizationEvidence {
	if len(in) == 0 {
		return nil
	}
	out := make([]model.AuthorizationEvidence, 0, len(in))
	for _, ev := range in {
		ev.Type = strings.ToLower(strings.TrimSpace(ev.Type))
		ev.Label = strings.TrimSpace(ev.Label)
		ev.URI = strings.TrimSpace(ev.URI)
		ev.Description = strings.TrimSpace(ev.Description)
		ev.SHA256 = strings.ToLower(strings.TrimSpace(ev.SHA256))
		if ev.Type == "" && ev.Label == "" && ev.URI == "" && ev.SHA256 == "" && ev.Description == "" {
			continue
		}
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Label != out[j].Label {
			return out[i].Label < out[j].Label
		}
		if out[i].URI != out[j].URI {
			return out[i].URI < out[j].URI
		}
		return out[i].SHA256 < out[j].SHA256
	})
	return out
}

func campaignAuthorizationDigest(c model.AutomationCampaign) string {
	canonical := struct {
		CampaignID            string                        `json:"campaignId"`
		WorkspaceID           string                        `json:"workspaceId"`
		Target                string                        `json:"target"`
		PolicyPack            string                        `json:"policyPack"`
		PolicyVersion         int                           `json:"policyVersion"`
		AuthorizationApproval model.AuthorizationApproval   `json:"authorizationApproval"`
		AuthorizationEvidence []model.AuthorizationEvidence `json:"authorizationEvidence"`
	}{
		CampaignID:            strings.TrimSpace(c.ID),
		WorkspaceID:           strings.TrimSpace(c.WorkspaceID),
		Target:                strings.TrimSpace(c.Target),
		PolicyPack:            strings.TrimSpace(c.PolicyPack),
		PolicyVersion:         c.PolicyVersion,
		AuthorizationApproval: c.AuthorizationApproval,
		AuthorizationEvidence: normalizeAuthorizationEvidence(c.AuthorizationEvidence),
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		fallback := []byte(fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s",
			canonical.CampaignID,
			canonical.WorkspaceID,
			canonical.Target,
			canonical.PolicyPack,
			canonical.PolicyVersion,
			strings.TrimSpace(canonical.AuthorizationApproval.Signature),
			strings.TrimSpace(canonical.AuthorizationApproval.ApprovedBy),
		))
		sum := sha256.Sum256(fallback)
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func isSHA256Hex(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return false
	}
	return len(decoded) == sha256.Size
}

func validWindowSpec(spec string) bool {
	parts := strings.Split(strings.TrimSpace(spec), "-")
	if len(parts) != 2 {
		return false
	}
	_, _, okS := parseClock(parts[0])
	_, _, okE := parseClock(parts[1])
	return okS && okE
}

func (s *Server) effectiveMinROI(ctx context.Context, job *model.ScanJob) float64 {
	if job == nil {
		return s.defaultMinROI
	}
	options := job.Options
	minROI := s.defaultMinROI
	if options.MinExpectedROIUSD > 0 {
		minROI = options.MinExpectedROIUSD
	}
	if override, err := s.repo.GetProgramROIOverride(ctx, firstNonEmpty(job.WorkspaceID, "default"), strings.TrimSpace(job.ProgramName)); err == nil && override != nil {
		minROI = maxFloat(minROI, override.MinExpectedROIUSD)
	}
	switch normalizeAutomationMode(options.AutomationMode) {
	case "safe":
		minROI = maxFloat(minROI, s.defaultMinROI*1.5)
	case "aggressive":
		minROI = maxFloat(0, minROI*0.6)
	}
	return minROI
}

func (s *Server) applySafetyModePolicy(options model.ScanOptions) model.ScanOptions {
	stage := strings.ToLower(strings.TrimSpace(os.Getenv("AUTOMATION_ENV_STAGE")))
	isProductionLike := stage == "prod" || stage == "production" || stage == "staging"
	switch normalizeAutomationMode(options.AutomationMode) {
	case "safe":
		options.MaxExploitAttempts = 0
		options.MaxPerTargetConcurrency = minInt(maxInt(1, options.MaxPerTargetConcurrency), 1)
		options.MaxAutomationConcurrency = minInt(maxInt(1, options.MaxAutomationConcurrency), 1)
		options.RescanIntervalMinutes = maxInt(options.RescanIntervalMinutes, maxInt(60, options.MinRescanIntervalMinutes))
		options.AggressiveExploitation = false
	case "aggressive":
		options.MaxExploitAttempts = maxInt(options.MaxExploitAttempts, 5)
		options.MaxPerTargetConcurrency = maxInt(options.MaxPerTargetConcurrency, 3)
		options.MaxAutomationConcurrency = maxInt(options.MaxAutomationConcurrency, 4)
		options.RescanIntervalMinutes = maxInt(15, options.RescanIntervalMinutes)
	case "canary":
		options.MaxExploitAttempts = minInt(maxInt(options.MaxExploitAttempts, 1), 1)
		options.MaxPerTargetConcurrency = minInt(maxInt(1, options.MaxPerTargetConcurrency), 1)
		options.MaxAutomationConcurrency = minInt(maxInt(1, options.MaxAutomationConcurrency), 1)
		options.RescanIntervalMinutes = maxInt(options.RescanIntervalMinutes, maxInt(30, options.MinRescanIntervalMinutes))
		options.AggressiveExploitation = false
	default:
		options.MaxExploitAttempts = maxInt(options.MaxExploitAttempts, 1)
		options.MaxPerTargetConcurrency = maxInt(options.MaxPerTargetConcurrency, 2)
		options.MaxAutomationConcurrency = maxInt(options.MaxAutomationConcurrency, 2)
		options.RescanIntervalMinutes = maxInt(options.RescanIntervalMinutes, maxInt(30, options.MinRescanIntervalMinutes))
		if isProductionLike {
			options.MaxExploitAttempts = minInt(options.MaxExploitAttempts, 1)
			options.MaxPerTargetConcurrency = minInt(maxInt(1, options.MaxPerTargetConcurrency), 1)
			options.MaxAutomationConcurrency = minInt(maxInt(1, options.MaxAutomationConcurrency), 1)
		}
	}
	options.DailyScanLimit = maxInt(options.DailyScanLimit, s.defaultDailyScanLimit)
	options.DailyRuntimeLimitMinutes = maxInt(options.DailyRuntimeLimitMinutes, s.defaultDailyRuntimeMinutes)
	options.DailyProbeLimit = maxInt(options.DailyProbeLimit, s.defaultDailyProbeLimit)
	options.CrawlMaxPages = maxInt(options.CrawlMaxPages, 50)
	return options
}

func (s *Server) shouldDeferForDailyBudget(ctx context.Context, workspaceID string, options model.ScanOptions) (bool, string) {
	usage, err := s.repo.GetWorkspaceDailyUsage(ctx, firstNonEmpty(workspaceID, "default"), time.Now().UTC())
	if err != nil {
		return false, ""
	}
	if options.DailyScanLimit > 0 && usage.ScanCount >= options.DailyScanLimit {
		return true, fmt.Sprintf("daily scan budget exceeded (%d/%d)", usage.ScanCount, options.DailyScanLimit)
	}
	if options.DailyRuntimeLimitMinutes > 0 && usage.RuntimeMinutes >= options.DailyRuntimeLimitMinutes {
		return true, fmt.Sprintf("daily runtime budget exceeded (%d/%d minutes)", usage.RuntimeMinutes, options.DailyRuntimeLimitMinutes)
	}
	if options.DailyProbeLimit > 0 && usage.ProbeVolume >= options.DailyProbeLimit {
		return true, fmt.Sprintf("daily probe budget exceeded (%d/%d)", usage.ProbeVolume, options.DailyProbeLimit)
	}
	return false, ""
}

func roundTo2(v float64) float64 {
	return math.Round(v*100) / 100
}

func (s *Server) estimateExpectedROI(ctx context.Context, job *model.ScanJob) (float64, string) {
	if job == nil {
		return 0, "no-job"
	}
	feedback, err := s.repo.ListFeedback(ctx, 1000)
	if err != nil {
		feedback = nil
	}
	type feedbackAgg struct {
		total    int
		accepted int
		payout   float64
	}
	byKey := map[string]feedbackAgg{}
	globalAccepted := 0
	globalPayout := 0.0
	for _, item := range feedback {
		key := strings.ToLower(strings.TrimSpace(item.Category)) + "|" + strings.ToLower(strings.TrimSpace(item.Title))
		cur := byKey[key]
		cur.total++
		if strings.EqualFold(strings.TrimSpace(item.Outcome), "accepted") {
			cur.accepted++
			cur.payout += maxFloat(0, item.PayoutUSD)
			globalAccepted++
			globalPayout += maxFloat(0, item.PayoutUSD)
		}
		byKey[key] = cur
	}
	globalAvgPayout := 120.0
	if globalAccepted > 0 {
		globalAvgPayout = globalPayout / float64(globalAccepted)
	}
	expected := 0.0
	for _, f := range job.Findings {
		if f.Severity != model.SeverityHigh && f.Severity != model.SeverityMedium && f.Severity != model.SeverityLow {
			continue
		}
		severityImpact := 20.0
		switch f.Severity {
		case model.SeverityHigh:
			severityImpact = 550
		case model.SeverityMedium:
			severityImpact = 220
		case model.SeverityLow:
			severityImpact = 60
		}
		conf := f.Confidence
		if conf <= 0 {
			conf = 0.6
		}
		key := strings.ToLower(strings.TrimSpace(f.Category)) + "|" + strings.ToLower(strings.TrimSpace(f.Title))
		agg := byKey[key]
		hitRate := 0.35
		avgPayout := globalAvgPayout
		if agg.total > 0 {
			hitRate = float64(agg.accepted+1) / float64(agg.total+2)
		}
		if agg.accepted > 0 {
			avgPayout = agg.payout / float64(agg.accepted)
		}
		expected += (severityImpact*0.25 + avgPayout*0.75) * conf * hitRate
	}
	return maxFloat(0, roundTo2(expected)), "severity+confidence+historical-payout"
}

func (s *Server) applyAutoSuppressionHeuristics(ctx context.Context, findings []model.Finding) []model.Finding {
	feedback, err := s.repo.ListFeedback(ctx, 1000)
	if err != nil || len(feedback) == 0 || len(findings) == 0 {
		return findings
	}
	type agg struct {
		total    int
		accepted int
		payout   float64
	}
	signals := map[string]agg{}
	for _, item := range feedback {
		key := strings.ToLower(strings.TrimSpace(item.Category)) + "|" + strings.ToLower(strings.TrimSpace(item.Title))
		cur := signals[key]
		cur.total++
		if strings.EqualFold(strings.TrimSpace(item.Outcome), "accepted") {
			cur.accepted++
			cur.payout += maxFloat(0, item.PayoutUSD)
		}
		signals[key] = cur
	}
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity == model.SeverityHigh || f.Severity == model.SeverityMedium {
			out = append(out, f)
			continue
		}
		// Oracle-confirmed active-probe findings (e.g. reflected payload,
		// SQL error, timing differential) are never auto-suppressed regardless
		// of feedback history — a human pentester would always report a
		// demonstrated exploit primitive.
		if vt := strings.TrimSpace(f.EvidenceFields["validationType"]); vt == "active-probe" || vt == "oast-confirmed" {
			out = append(out, f)
			continue
		}
		key := strings.ToLower(strings.TrimSpace(f.Category)) + "|" + strings.ToLower(strings.TrimSpace(f.Title))
		agg := signals[key]
		// Require at least 5 feedback samples before auto-suppression kicks in.
		// With only 3 samples a single test-environment run with all-rejections
		// would incorrectly suppress a real finding in production.
		if agg.total < 5 {
			out = append(out, f)
			continue
		}
		acceptRate := float64(agg.accepted) / float64(agg.total)
		avgPayout := 0.0
		if agg.accepted > 0 {
			avgPayout = agg.payout / float64(agg.accepted)
		}
		if acceptRate < 0.15 && avgPayout < 20 && f.Confidence < 0.85 {
			continue
		}
		out = append(out, f)
	}
	return out
}

func (s *Server) runCampaignScheduler() {
	if s.repo == nil || s.campaignPoll <= 0 {
		return
	}
	ticker := time.NewTicker(s.campaignPoll)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().UTC()
		_, _ = s.repo.ReclaimStaleAutomationCampaignLeases(context.Background(), now.Add(-4*s.campaignPoll), 100)
		campaigns, err := s.repo.ListDueAutomationCampaigns(context.Background(), now, 25)
		if err != nil || len(campaigns) == 0 {
			continue
		}
		for _, c := range campaigns {
			if strings.TrimSpace(c.RunWindow) != "" && !inCampaignWindow(now, c) {
				nextRun := computeNextCampaignRun(now.Add(15*time.Minute), model.AutomationCampaignUpsertRequest{
					IntervalMin:     c.IntervalMin,
					ScheduleType:    c.ScheduleType,
					ScheduleValue:   c.ScheduleValue,
					RunWindow:       c.RunWindow,
					BlackoutWindows: c.BlackoutWindows,
				})
				_ = s.repo.UpdateAutomationCampaignRun(context.Background(), c.ID, now, nextRun)
				continue
			}
			if inCampaignBlackout(now, c) {
				nextRun := now.Add(30 * time.Minute)
				_ = s.repo.UpdateAutomationCampaignRun(context.Background(), c.ID, now, nextRun)
				continue
			}
			leaseUntil := now.Add(2 * s.campaignPoll)
			ok, err := s.repo.TryLeaseAutomationCampaign(context.Background(), c.ID, leaseUntil)
			if err != nil || !ok {
				continue
			}
			c.Options.AutomationMode = normalizeAutomationMode(c.Options.AutomationMode)
			c.Options = s.applySafetyModePolicy(c.Options)
			c.PolicyPack = normalizePolicyPackName(c.PolicyPack)
			c.Options, c.PolicyVersion = s.applyAutomationPolicyPack(context.Background(), firstNonEmpty(c.WorkspaceID, "default"), c.PolicyPack, c.Options)
			c.Options.MinExpectedROIUSD = maxFloat(c.Options.MinExpectedROIUSD, s.defaultMinROI)
			if blocked, reason := s.shouldDeferForDailyBudget(context.Background(), firstNonEmpty(c.WorkspaceID, "default"), c.Options); blocked {
				backoff := 30 * time.Minute
				_ = s.repo.MarkAutomationCampaignDispatchFailure(context.Background(), c.ID, reason, now, backoff)
				continue
			}
			runDueAt := c.NextRunAt
			if c.NextRetryAt != nil && !c.NextRetryAt.IsZero() {
				runDueAt = *c.NextRetryAt
			}
			runKey := strings.Join([]string{
				"campaign",
				strings.TrimSpace(c.ID),
				runDueAt.UTC().Format(time.RFC3339Nano),
			}, ":")
			idempotencyTarget := strings.Join([]string{
				firstNonEmpty(c.WorkspaceID, "default"),
				strings.TrimSpace(c.Target),
				strings.TrimSpace(c.ID),
			}, "::")
			if existing, err := s.repo.GetRecentJobByIdempotencyKey(context.Background(), runKey, idempotencyTarget, now.Add(-7*24*time.Hour)); err == nil && existing != nil {
				nextRun := resolveCampaignNextRunAfterDispatch(now, c)
				_ = s.repo.UpdateAutomationCampaignRun(context.Background(), c.ID, now, nextRun)
				continue
			}
			jobID := uuid.NewString()
			job := &model.ScanJob{
				ID:                 jobID,
				Target:             c.Target,
				WorkspaceID:        firstNonEmpty(c.WorkspaceID, "default"),
				RequestedBy:        c.RequestedBy,
				PolicyPack:         c.PolicyPack,
				Status:             "queued",
				StartedAt:          now,
				AuthProfileSummary: model.SummarizeAuthProfile(c.AuthProfile),
				Options:            c.Options,
				Scope:              c.Scope,
				ProgramName:        strings.TrimSpace(c.ProgramName),
				ProgramPolicyVersion: fmt.Sprintf(
					"%d",
					maxInt(1, c.PolicyVersion),
				),
			}
			if err := s.repo.CreateJob(context.Background(), job); err != nil {
				backoff := campaignRetryBackoff(c.RetryCount)
				_ = s.repo.MarkAutomationCampaignDispatchFailure(context.Background(), c.ID, err.Error(), now, backoff)
				continue
			}
			_ = s.repo.SaveIdempotencyRecord(context.Background(), runKey, idempotencyTarget, jobID, now)
			hbNow := now
			_ = s.repo.UpdateAutomationCampaignQueueState(context.Background(), c.ID, "running", runKey, &hbNow)
			s.appendAuditEvent(jobID, "automation-campaign", fmt.Sprintf("Campaign scheduled run: %s", c.ID))
			go func(campaign model.AutomationCampaign, scanJobID string, idempotencyKey string) {
				stopHB := make(chan struct{})
				go func() {
					beatTicker := time.NewTicker(maxDuration(5*time.Second, s.campaignPoll/2))
					defer beatTicker.Stop()
					for {
						select {
						case <-stopHB:
							return
						case beat := <-beatTicker.C:
							leaseUntil := beat.Add(2 * s.campaignPoll)
							ok, _ := s.repo.HeartbeatAutomationCampaignLease(context.Background(), campaign.ID, beat, leaseUntil)
							if !ok {
								return
							}
						}
					}
				}()
				s.runJob(scanJobID, campaign.Target, campaign.AuthProfile, nil, campaign.Options, campaign.Scope)
				close(stopHB)
				nextRun := resolveCampaignNextRunAfterDispatch(time.Now().UTC(), campaign)
				_ = s.repo.UpdateAutomationCampaignRun(context.Background(), campaign.ID, time.Now().UTC(), nextRun)
				_ = s.repo.UpdateAutomationCampaignQueueState(context.Background(), campaign.ID, "queued", idempotencyKey, nil)
			}(c, jobID, runKey)
		}
	}
}

func (s *Server) syncAutomationTickets(ctx context.Context, target string, findings []model.Finding) (int, int) {
	now := time.Now().UTC()
	currentFingerprints := make([]string, 0)
	open := 0
	for _, f := range findings {
		if f.Severity != model.SeverityHigh && f.Severity != model.SeverityMedium {
			continue
		}
		drift := strings.ToLower(strings.TrimSpace(f.DriftStatus))
		if drift == "resolved" {
			continue
		}
		fp := strings.ToLower(strings.TrimSpace(f.Category)) + "|" + strings.ToLower(strings.TrimSpace(f.Title))
		if fp == "" {
			continue
		}
		currentFingerprints = append(currentFingerprints, fp)
		sla := now.Add(72 * time.Hour)
		if f.Severity == model.SeverityHigh {
			sla = now.Add(24 * time.Hour)
		}
		if drift == "new" {
			if f.Severity == model.SeverityHigh {
				sla = now.Add(12 * time.Hour)
			} else {
				sla = now.Add(48 * time.Hour)
			}
		}
		status := "open"
		if drift == "changed" && f.Severity == model.SeverityHigh {
			status = "escalated"
		}
		ticket := model.AutomationTicket{
			ID:          uuid.NewString(),
			Target:      target,
			Fingerprint: fp,
			Title:       f.Title,
			Severity:    f.Severity,
			Status:      status,
			FirstSeenAt: now,
			LastSeenAt:  now,
			SLADueAt:    &sla,
		}
		if err := s.repo.UpsertAutomationTicket(ctx, ticket); err == nil {
			open++
		}
	}
	resolved, _ := s.repo.ResolveAutomationTicketsMissingFingerprints(ctx, target, currentFingerprints, now)
	return open, int(resolved)
}

func buildDeltaFindings(previousFindings, currentFindings []model.Finding) (int, int, int, []model.Finding) {
	prevByKey := map[string]model.Finding{}
	for _, f := range previousFindings {
		prevByKey[fingerprintFindingBase(f)] = f
	}
	currByKey := map[string]model.Finding{}
	for _, f := range currentFindings {
		currByKey[fingerprintFindingBase(f)] = f
	}

	newItems := make([]string, 0)
	changedItems := make([]string, 0)
	resolvedItems := make([]string, 0)
	for _, current := range currentFindings {
		key := fingerprintFindingBase(current)
		prev, ok := prevByKey[key]
		if !ok {
			newItems = append(newItems, fmt.Sprintf("[%s] %s", current.Severity, current.Title))
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(prev.Evidence), strings.TrimSpace(current.Evidence)) || prev.Severity != current.Severity {
			changedItems = append(changedItems, fmt.Sprintf("[%s] %s", current.Severity, current.Title))
		}
	}
	for _, prev := range previousFindings {
		if _, ok := currByKey[fingerprintFindingBase(prev)]; !ok {
			resolvedItems = append(resolvedItems, fmt.Sprintf("[%s] %s", prev.Severity, prev.Title))
		}
	}

	sort.Strings(newItems)
	sort.Strings(changedItems)
	sort.Strings(resolvedItems)
	delta := make([]model.Finding, 0, 3)
	if len(newItems) > 0 {
		delta = append(delta, model.Finding{
			ID:             "monitoring-new-attack-surface",
			Category:       "monitoring",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("New attack surface detected since last completed scan (%d new findings)", len(newItems)),
			Description:    "This scan surfaced findings not present in the previous completed scan for the same target.",
			Evidence:       strings.Join(limitStrings(newItems, 6), "; "),
			Recommendation: "Prioritize triage of these newly introduced findings and consider enabling scheduled rescans for continuous monitoring.",
			DriftStatus:    "new",
			Confidence:     0.95,
			Sources:        []string{"monitoring"},
		})
	}
	if len(changedItems) > 0 {
		delta = append(delta, model.Finding{
			ID:             "monitoring-changed-findings",
			Category:       "monitoring",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("Finding behavior changed since last scan (%d changed)", len(changedItems)),
			Description:    "Previously observed findings changed severity or evidence details.",
			Evidence:       strings.Join(limitStrings(changedItems, 6), "; "),
			Recommendation: "Re-validate exploitability and update remediation priority for changed findings.",
			DriftStatus:    "changed",
			Confidence:     0.9,
			Sources:        []string{"monitoring"},
		})
	}
	if len(resolvedItems) > 0 {
		delta = append(delta, model.Finding{
			ID:             "monitoring-resolved-findings",
			Category:       "monitoring",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("Previously detected findings no longer observed (%d resolved)", len(resolvedItems)),
			Description:    "Findings from the previous completed scan were not reproduced in this run.",
			Evidence:       strings.Join(limitStrings(resolvedItems, 6), "; "),
			Recommendation: "Confirm remediation durability with a follow-up verification run.",
			DriftStatus:    "resolved",
			Confidence:     0.86,
			Sources:        []string{"monitoring"},
		})
	}
	return len(newItems), len(changedItems), len(resolvedItems), delta
}

func normalizedFindingKey(f model.Finding) string {
	category := normalizeDedupToken(f.Category)
	title := normalizeDedupToken(f.Title)
	evidence := normalizeDedupToken(f.Evidence)
	if len(evidence) > 160 {
		evidence = evidence[:160]
	}
	param := normalizeDedupToken(f.AffectedParameter)
	host := normalizeDedupToken(hostFromTarget(strings.TrimSpace(f.AffectedURL)))
	id := normalizeDedupToken(f.ID)
	cwe := normalizeDedupToken(f.CWE)
	return strings.Join([]string{category, title, evidence, param, host, id, cwe}, "|")
}

func normalizeDedupToken(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	var b strings.Builder
	lastSpace := false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastSpace = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastSpace = false
		default:
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func deduplicateFindingsCrossAgent(findings []model.Finding) ([]model.Finding, int) {
	if len(findings) <= 1 {
		return findings, 0
	}
	type cluster struct {
		rep   model.Finding
		count int
	}
	clusters := map[string]cluster{}
	order := make([]string, 0, len(findings))
	for _, f := range findings {
		key := normalizedFindingKey(f)
		cur, ok := clusters[key]
		if !ok {
			clusters[key] = cluster{rep: f, count: 1}
			order = append(order, key)
			continue
		}
		cur.count++
		if severityWeight(f.Severity) > severityWeight(cur.rep.Severity) ||
			(severityWeight(f.Severity) == severityWeight(cur.rep.Severity) && f.Confidence > cur.rep.Confidence) {
			cur.rep = f
		}
		cur.rep.Sources = dedupeStrings(append(cur.rep.Sources, f.Sources...))
		clusters[key] = cur
	}
	out := make([]model.Finding, 0, len(clusters))
	for _, key := range order {
		cur := clusters[key]
		if cur.count > 1 {
			if cur.rep.EvidenceFields == nil {
				cur.rep.EvidenceFields = map[string]string{}
			}
			cur.rep.EvidenceFields["duplicateClusterSize"] = fmt.Sprintf("%d", cur.count)
		}
		out = append(out, cur.rep)
	}

	// Second-pass semantic deduplication: merge findings that share the same
	// (category, affected-URL-host, affected-parameter) tuple even when their
	// title, evidence text, or agent-assigned IDs differ. This collapses
	// independent agents that independently detected the same vulnerability
	// instance with slightly different wording.
	type semanticKey struct {
		category string
		host     string
		param    string
	}
	semClusters := map[semanticKey]int{} // maps semKey → index in out
	semOrder := make([]model.Finding, 0, len(out))
	for _, f := range out {
		sk := semanticKey{
			category: strings.ToLower(strings.TrimSpace(f.Category)),
			host:     normalizeDedupToken(hostFromTarget(strings.TrimSpace(f.AffectedURL))),
			param:    normalizeDedupToken(f.AffectedParameter),
		}
		// Only collapse when all three fields are non-empty to avoid
		// over-aggressive merging of host-level or category-level findings.
		if sk.category == "" || sk.host == "" || sk.param == "" {
			semOrder = append(semOrder, f)
			continue
		}
		idx, exists := semClusters[sk]
		if !exists {
			semClusters[sk] = len(semOrder)
			semOrder = append(semOrder, f)
			continue
		}
		rep := semOrder[idx]
		// Keep the highest-confidence, highest-severity representative.
		if severityWeight(f.Severity) > severityWeight(rep.Severity) ||
			(severityWeight(f.Severity) == severityWeight(rep.Severity) && f.Confidence > rep.Confidence) {
			rep = f
		}
		rep.Sources = dedupeStrings(append(rep.Sources, f.Sources...))
		if rep.EvidenceFields == nil {
			rep.EvidenceFields = map[string]string{}
		}
		rep.EvidenceFields["semanticDuplicateMerged"] = "true"
		semOrder[idx] = rep
	}
	removed := len(findings) - len(semOrder)
	return semOrder, removed
}

func applyEvidenceQualityTiers(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		tier := inferEvidenceQualityTier(f)
		f.EvidenceQualityTier = tier
		if f.EvidenceFields == nil {
			f.EvidenceFields = map[string]string{}
		}
		f.EvidenceFields["evidenceQualityTier"] = tier
		conf := f.Confidence
		if conf <= 0 {
			conf = defaultConfidenceForSeverity(f.Severity)
		}
		switch tier {
		case "strong":
			conf = maxFloat(conf, 0.8)
			conf = minFloat(0.99, conf+0.08)
		case "moderate":
			conf = minFloat(0.99, conf+0.02)
		case "weak":
			conf = minFloat(0.7, conf)
			conf = maxFloat(0.05, conf-0.08)
		}
		f.Confidence = conf
		out = append(out, f)
	}
	return out
}

func inferEvidenceQualityTier(f model.Finding) string {
	score := 0
	if len(f.ReproductionSteps) >= 2 {
		score++
	}
	if strings.TrimSpace(f.PoC) != "" {
		score++
	}
	if f.Exploitability != nil && strings.EqualFold(strings.TrimSpace(f.Exploitability.VerifiedStatus), "verified") {
		score++
	}
	if len(strings.TrimSpace(f.Evidence)) >= 120 || len(f.EvidenceFields) > 1 {
		score++
	}
	if strings.TrimSpace(f.AffectedURL) != "" || strings.TrimSpace(f.AffectedParameter) != "" {
		score++
	}
	if len(f.References) > 0 {
		score++
	}
	switch {
	case score >= 4:
		return "strong"
	case score >= 2:
		return "moderate"
	default:
		return "weak"
	}
}

func severityWeight(severity model.Severity) int {
	switch severity {
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	default:
		return 1
	}
}

func dedupeStrings(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

// fingerprintFindingBase returns a deduplication key that distinguishes the
// same vulnerability class on different endpoints. Including the normalised
// URL host+path and parameter means "SQL Injection on /api/users?id=" and
// "SQL Injection on /api/posts?id=" are tracked as separate findings — the
// same way a human pentester would report them — instead of being collapsed
// into a single entry that hides new attack surface.
func fingerprintFindingBase(f model.Finding) string {
	return strings.ToLower(strings.TrimSpace(f.Category)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Title)) + "|" +
		fingerprintURLHostPath(f.AffectedURL) + "|" +
		strings.ToLower(strings.TrimSpace(f.AffectedParameter))
}

// fingerprintURLHostPath returns "host/path" (lowercased, query/fragment
// stripped) for use in dedup keys. Empty input returns an empty string.
func fingerprintURLHostPath(rawURL string) string {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return ""
	}
	// Strip scheme.
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	// Strip query and fragment.
	for _, sep := range []string{"?", "#"} {
		if idx := strings.Index(u, sep); idx >= 0 {
			u = u[:idx]
		}
	}
	return strings.ToLower(strings.TrimRight(u, "/"))
}

func hasAuthorizationProfile(profile model.ScanAuthProfile) bool {
	return len(profile.Headers) > 0 ||
		len(profile.Cookies) > 0 ||
		strings.TrimSpace(profile.BasicAuthUsername) != "" ||
		strings.TrimSpace(profile.BasicAuthPassword) != "" ||
		(strings.TrimSpace(profile.Username) != "" && strings.TrimSpace(profile.Password) != "")
}

func validateAuthProfile(profile model.ScanAuthProfile) error {
	hasUsername := strings.TrimSpace(profile.Username) != ""
	hasPassword := strings.TrimSpace(profile.Password) != ""
	if hasUsername != hasPassword {
		return errors.New("authProfile username and password must both be provided for standard application authentication")
	}
	if strings.TrimSpace(profile.LoginURL) != "" && !hasUsername {
		return errors.New("authProfile loginUrl requires username and password")
	}
	if len(profile.LoginSteps) > 0 && !hasUsername {
		return errors.New("authProfile loginSteps require username and password")
	}
	for idx, step := range profile.LoginSteps {
		action := strings.ToLower(strings.TrimSpace(step.Action))
		switch action {
		case "fill":
			if strings.TrimSpace(step.Selector) == "" {
				return fmt.Errorf("authProfile loginSteps[%d] fill requires selector", idx)
			}
			if strings.TrimSpace(step.Value) == "" {
				return fmt.Errorf("authProfile loginSteps[%d] fill requires value", idx)
			}
		case "click":
			if strings.TrimSpace(step.Selector) == "" {
				return fmt.Errorf("authProfile loginSteps[%d] click requires selector", idx)
			}
		case "wait":
			if step.WaitMillis <= 0 {
				return fmt.Errorf("authProfile loginSteps[%d] wait requires waitMillis > 0", idx)
			}
		default:
			return fmt.Errorf("authProfile loginSteps[%d] has unsupported action %q", idx, step.Action)
		}
	}
	return nil
}

func applyProgramScope(scanScope model.ScanScope, profile model.ProgramScopeProfile) model.ScanScope {
	if len(profile.IncludeHosts) > 0 {
		scanScope.IncludeHosts = append(scanScope.IncludeHosts, profile.IncludeHosts...)
	}
	if len(profile.ExcludeHosts) > 0 {
		scanScope.ExcludeHosts = append(scanScope.ExcludeHosts, profile.ExcludeHosts...)
	}
	if len(profile.ExcludePaths) > 0 {
		scanScope.ExcludePaths = append(scanScope.ExcludePaths, profile.ExcludePaths...)
	}
	if len(profile.ProgramRules) > 0 {
		scanScope.ProgramRules = append(scanScope.ProgramRules, profile.ProgramRules...)
	}
	return scanScope
}

func enforceDisallowedTests(options model.ScanOptions, disallowed []string, programRules []string) model.ScanOptions {
	set := map[string]struct{}{}
	for _, item := range disallowed {
		key := strings.ToLower(strings.TrimSpace(item))
		if key != "" {
			set[key] = struct{}{}
		}
	}
	for _, rule := range programRules {
		if strings.Contains(strings.ToLower(rule), "no destructive") {
			set["sqlmap"] = struct{}{}
			set["nikto"] = struct{}{}
			set["ffuf"] = struct{}{}
			set["gobuster"] = struct{}{}
			set["kiterunner"] = struct{}{}
		}
	}
	disable := func(tool string) bool {
		_, ok := set[tool]
		return ok
	}
	if disable("nuclei") {
		options.UseNucleiIntegration = false
	}
	if disable("zap") || disable("zap_baseline") {
		options.UseZAPBaselineIntegration = false
	}
	if disable("sqlmap") {
		options.UseSQLMapIntegration = false
	}
	if disable("nikto") {
		options.UseNiktoIntegration = false
	}
	if disable("ffuf") {
		options.UseFFUFIntegration = false
	}
	if disable("gobuster") {
		options.UseGobusterIntegration = false
	}
	if disable("kiterunner") {
		options.UseKiterunnerIntegration = false
	}
	if disable("gau") {
		options.UseGauIntegration = false
	}
	if disable("arjun") {
		options.UseArjunIntegration = false
	}
	if disable("commix") {
		options.UseCommixIntegration = false
	}
	if disable("linkfinder") {
		options.UseLinkFinderIntegration = false
	}
	if disable("retire") {
		options.UseRetireJSIntegration = false
	}
	if disable("trufflehog") {
		options.UseTruffleHogIntegration = false
	}
	if disable("uncover") {
		options.UseUncoverIntegration = false
	}
	if disable("wpscan") {
		options.UseWPScanIntegration = false
	}
	return options
}
