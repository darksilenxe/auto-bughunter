package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/model"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type MemoryStore struct {
	mu sync.RWMutex

	jobs                map[string]model.ScanJob
	assetsByScanID      map[string][]model.ScanAsset
	auditByScanID       map[string][]model.ScanAuditEvent
	feedback            []model.ReportFeedback
	verifications       map[string][]model.FindingVerification
	suppressions        []model.SuppressionRule
	scanStates          map[string]model.PersistentScanState
	idempotency         map[string]memoryIdempotencyRecord
	tickets             map[string]model.AutomationTicket
	ticketByFingerprint map[string]string
	campaigns           map[string]model.AutomationCampaign
	roiOverrides        map[string]model.ProgramROIOverride
	policyPacks         map[string]model.AutomationPolicyPack
	policyAudit         []model.AutomationPolicyAuditEvent
	apiKeys             map[string]memoryAPIKey
	annotations         map[string][]model.ScanAnnotation
	shadowDecisions     []model.ShadowDecision
}

type memoryIdempotencyRecord struct {
	Key       string
	Target    string
	ScanID    string
	CreatedAt time.Time
}

type memoryAPIKey struct {
	Record model.APIKeyRecord
	Hash   string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		jobs:                map[string]model.ScanJob{},
		assetsByScanID:      map[string][]model.ScanAsset{},
		auditByScanID:       map[string][]model.ScanAuditEvent{},
		feedback:            []model.ReportFeedback{},
		verifications:       map[string][]model.FindingVerification{},
		scanStates:          map[string]model.PersistentScanState{},
		idempotency:         map[string]memoryIdempotencyRecord{},
		tickets:             map[string]model.AutomationTicket{},
		ticketByFingerprint: map[string]string{},
		campaigns:           map[string]model.AutomationCampaign{},
		roiOverrides:        map[string]model.ProgramROIOverride{},
		policyPacks:         map[string]model.AutomationPolicyPack{},
		policyAudit:         []model.AutomationPolicyAuditEvent{},
		apiKeys:             map[string]memoryAPIKey{},
		annotations:         map[string][]model.ScanAnnotation{},
		shadowDecisions:     []model.ShadowDecision{},
	}
}

func (s *MemoryStore) CreateJob(ctx context.Context, job *model.ScanJob) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if job == nil {
		return errors.New("scan job is required")
	}
	copyJob := cloneValue(*job)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[copyJob.ID] = copyJob
	if copyJob.Assets != nil {
		s.assetsByScanID[copyJob.ID] = cloneValue(copyJob.Assets)
	}
	if copyJob.AuditTrail != nil {
		s.auditByScanID[copyJob.ID] = cloneValue(copyJob.AuditTrail)
	}
	return nil
}

func (s *MemoryStore) UpdateJob(ctx context.Context, job *model.ScanJob) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if job == nil {
		return errors.New("scan job is required")
	}
	copyJob := cloneValue(*job)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[copyJob.ID] = copyJob
	s.assetsByScanID[copyJob.ID] = cloneValue(copyJob.Assets)
	s.auditByScanID[copyJob.ID] = cloneValue(copyJob.AuditTrail)
	return nil
}

func (s *MemoryStore) GetJob(ctx context.Context, id string) (*model.ScanJob, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[strings.TrimSpace(id)]
	if !ok {
		return nil, sql.ErrNoRows
	}
	out := s.withRelatedLocked(job)
	return &out, nil
}

func (s *MemoryStore) GetLatestCompletedJobByTarget(ctx context.Context, target, excludeID string) (*model.ScanJob, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	target = strings.TrimSpace(target)
	excludeID = strings.TrimSpace(excludeID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *model.ScanJob
	for _, job := range s.jobs {
		if job.Status != "completed" || job.Target != target || job.ID == excludeID {
			continue
		}
		candidate := s.withRelatedLocked(job)
		if best == nil || compareCompletedJobs(candidate, *best) < 0 {
			copied := candidate
			best = &copied
		}
	}
	if best == nil {
		return nil, nil
	}
	return best, nil
}

func (s *MemoryStore) SaveAssets(ctx context.Context, scanID string, assets []model.ScanAsset) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	id := strings.TrimSpace(scanID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assetsByScanID[id] = cloneValue(assets)
	if job, ok := s.jobs[id]; ok {
		job.Assets = cloneValue(assets)
		s.jobs[id] = job
	}
	return nil
}

func (s *MemoryStore) GetAssetsByScanID(ctx context.Context, scanID string) ([]model.ScanAsset, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneValue(s.assetsByScanID[strings.TrimSpace(scanID)]), nil
}

func (s *MemoryStore) AppendAuditEvent(ctx context.Context, scanID string, event model.ScanAuditEvent) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	id := strings.TrimSpace(scanID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditByScanID[id] = append(s.auditByScanID[id], cloneValue(event))
	if job, ok := s.jobs[id]; ok {
		job.AuditTrail = cloneValue(s.auditByScanID[id])
		s.jobs[id] = job
	}
	return nil
}

func (s *MemoryStore) ListAuditEvents(ctx context.Context, scanID string) ([]model.ScanAuditEvent, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneValue(s.auditByScanID[strings.TrimSpace(scanID)]), nil
}

func (s *MemoryStore) ListCompletedJobs(ctx context.Context, limit int) ([]*model.ScanJob, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.ScanJob, 0)
	for _, job := range s.jobs {
		if job.Status == "completed" {
			out = append(out, s.withRelatedLocked(job))
		}
	}
	sort.Slice(out, func(i, j int) bool { return compareCompletedJobs(out[i], out[j]) < 0 })
	if len(out) > limit {
		out = out[:limit]
	}
	result := make([]*model.ScanJob, 0, len(out))
	for _, job := range out {
		copyJob := job
		result = append(result, &copyJob)
	}
	return result, nil
}

func (s *MemoryStore) SaveFeedback(ctx context.Context, feedback model.ReportFeedback) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.feedback = append(s.feedback, cloneValue(feedback))
	return nil
}

func (s *MemoryStore) ListFeedback(ctx context.Context, limit int) ([]model.ReportFeedback, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 500
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := cloneValue(s.feedback)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) SaveFindingVerification(ctx context.Context, verification model.FindingVerification) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	key := strings.TrimSpace(verification.ScanID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifications[key] = append(s.verifications[key], cloneValue(verification))
	return nil
}

func (s *MemoryStore) GetLatestFindingVerifications(ctx context.Context, scanID string) (map[string]model.FindingVerification, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := cloneValue(s.verifications[strings.TrimSpace(scanID)])
	sort.Slice(entries, func(i, j int) bool { return entries[i].CreatedAt.After(entries[j].CreatedAt) })
	out := map[string]model.FindingVerification{}
	for _, item := range entries {
		if _, exists := out[item.FindingID]; !exists {
			out[item.FindingID] = item
		}
	}
	return out, nil
}

func (s *MemoryStore) SaveSuppressionRule(ctx context.Context, rule model.SuppressionRule) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suppressions = append(s.suppressions, cloneValue(rule))
	return nil
}

func (s *MemoryStore) ListActiveSuppressionRules(ctx context.Context, target string, now time.Time) ([]model.SuppressionRule, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	target = strings.TrimSpace(target)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.SuppressionRule, 0)
	for _, rule := range s.suppressions {
		if rule.Target != "" && rule.Target != target {
			continue
		}
		if rule.ExpiresAt != nil && !rule.ExpiresAt.After(now) {
			continue
		}
		out = append(out, cloneValue(rule))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) GetScanState(ctx context.Context, target string) (*model.PersistentScanState, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	target = strings.TrimSpace(target)
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.scanStates[target]
	if !ok {
		return nil, nil
	}
	copyState := cloneValue(state)
	return &copyState, nil
}

func (s *MemoryStore) UpsertScanState(ctx context.Context, state model.PersistentScanState) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanStates[strings.TrimSpace(state.Target)] = cloneValue(state)
	return nil
}

func (s *MemoryStore) GetRecentJobByIdempotencyKey(ctx context.Context, key, target string, since time.Time) (*model.ScanJob, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.idempotency[idempotencyKey(key, target)]
	if !ok || record.CreatedAt.Before(since) {
		return nil, nil
	}
	job, ok := s.jobs[record.ScanID]
	if !ok {
		return nil, nil
	}
	out := s.withRelatedLocked(job)
	return &out, nil
}

func (s *MemoryStore) SaveIdempotencyRecord(ctx context.Context, key, target, scanID string, createdAt time.Time) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idempotency[idempotencyKey(key, target)] = memoryIdempotencyRecord{
		Key:       strings.TrimSpace(key),
		Target:    strings.TrimSpace(target),
		ScanID:    strings.TrimSpace(scanID),
		CreatedAt: createdAt,
	}
	return nil
}

func (s *MemoryStore) UpsertAutomationTicket(ctx context.Context, ticket model.AutomationTicket) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	lookup := automationTicketKey(ticket.Target, ticket.Fingerprint)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existingID, ok := s.ticketByFingerprint[lookup]; ok {
		existing := s.tickets[existingID]
		ticket.ID = existing.ID
		ticket.FirstSeenAt = existing.FirstSeenAt
	}
	copyTicket := cloneValue(ticket)
	s.tickets[copyTicket.ID] = copyTicket
	s.ticketByFingerprint[lookup] = copyTicket.ID
	return nil
}

func (s *MemoryStore) ResolveAutomationTicketsMissingFingerprints(ctx context.Context, target string, fingerprints []string, resolvedAt time.Time) (int64, error) {
	if err := checkContext(ctx); err != nil {
		return 0, err
	}
	allowed := map[string]struct{}{}
	for _, fp := range fingerprints {
		allowed[strings.TrimSpace(fp)] = struct{}{}
	}
	var resolved int64
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ticket := range s.tickets {
		if ticket.Target != target || ticket.Status == "resolved" {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[ticket.Fingerprint]; ok {
				continue
			}
		}
		ticket.Status = "resolved"
		ticket.ResolvedAt = cloneTimePtr(resolvedAt)
		s.tickets[id] = ticket
		resolved++
	}
	return resolved, nil
}

func (s *MemoryStore) ListOpenAutomationTickets(ctx context.Context, target string, limit int) ([]model.AutomationTicket, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	target = strings.TrimSpace(target)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.AutomationTicket, 0)
	for _, ticket := range s.tickets {
		if ticket.Status == "resolved" {
			continue
		}
		if target != "" && ticket.Target != target {
			continue
		}
		out = append(out, cloneValue(ticket))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) UpsertAutomationCampaign(ctx context.Context, campaign model.AutomationCampaign) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	campaign.WorkspaceID = defaultWorkspace(campaign.WorkspaceID)
	if campaign.CreatedAt.IsZero() {
		campaign.CreatedAt = time.Now().UTC()
	}
	if campaign.UpdatedAt.IsZero() {
		campaign.UpdatedAt = campaign.CreatedAt
	}
	if strings.TrimSpace(campaign.QueueState) == "" {
		campaign.QueueState = "queued"
	}
	if strings.TrimSpace(campaign.PolicyPack) == "" {
		campaign.PolicyPack = "internal"
	}
	if campaign.PolicyVersion <= 0 {
		campaign.PolicyVersion = 1
	}
	if campaign.ID == "" {
		campaign.ID = uuid.NewString()
	}
	copyCampaign := cloneValue(campaign)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.campaigns[copyCampaign.ID] = copyCampaign
	return nil
}

func (s *MemoryStore) ListAutomationCampaigns(ctx context.Context, workspaceID string, activeOnly bool, limit int) ([]model.AutomationCampaign, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	workspaceID = defaultWorkspace(workspaceID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.AutomationCampaign, 0)
	for _, campaign := range s.campaigns {
		if campaign.WorkspaceID != workspaceID {
			continue
		}
		if activeOnly && !campaign.Active {
			continue
		}
		out = append(out, cloneValue(campaign))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) ListDueAutomationCampaigns(ctx context.Context, now time.Time, limit int) ([]model.AutomationCampaign, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.AutomationCampaign, 0)
	for _, campaign := range s.campaigns {
		if !campaign.Active || campaign.DeadLetter || strings.EqualFold(campaign.QueueState, "running") {
			continue
		}
		if campaign.LeaseUntil != nil && !campaign.LeaseUntil.Before(now) {
			continue
		}
		dueAt, ok := campaignDueAt(campaign)
		if !ok || dueAt.After(now) {
			continue
		}
		out = append(out, cloneValue(campaign))
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := campaignDueAt(out[i])
		right, _ := campaignDueAt(out[j])
		return left.Before(right)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) UpdateAutomationCampaignRun(ctx context.Context, id string, lastRunAt, nextRunAt time.Time) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	campaign, ok := s.campaigns[strings.TrimSpace(id)]
	if !ok {
		return nil
	}
	campaign.LastRunAt = cloneTimePtr(lastRunAt)
	campaign.NextRunAt = nextRunAt
	campaign.NextRetryAt = nil
	campaign.RetryCount = 0
	campaign.LastError = ""
	campaign.QueueState = "queued"
	campaign.LeaseUntil = nil
	campaign.HeartbeatAt = nil
	campaign.RunIdempotency = ""
	campaign.UpdatedAt = time.Now().UTC()
	s.campaigns[campaign.ID] = campaign
	return nil
}

func (s *MemoryStore) DeleteAutomationCampaign(ctx context.Context, id, workspaceID string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	workspaceID = strings.TrimSpace(workspaceID)
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if campaign, ok := s.campaigns[id]; ok && campaign.WorkspaceID == workspaceID {
		delete(s.campaigns, id)
	}
	return nil
}

func (s *MemoryStore) TryLeaseAutomationCampaign(ctx context.Context, id string, leaseUntil time.Time) (bool, error) {
	if err := checkContext(ctx); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	campaign, ok := s.campaigns[strings.TrimSpace(id)]
	if !ok || campaign.DeadLetter {
		return false, nil
	}
	now := time.Now().UTC()
	if campaign.LeaseUntil != nil && !campaign.LeaseUntil.Before(now) {
		return false, nil
	}
	campaign.LeaseUntil = cloneTimePtr(leaseUntil)
	campaign.QueueState = "running"
	campaign.HeartbeatAt = cloneTimePtr(now)
	campaign.UpdatedAt = now
	s.campaigns[campaign.ID] = campaign
	return true, nil
}

func (s *MemoryStore) MarkAutomationCampaignDispatchFailure(ctx context.Context, id, lastError string, now time.Time, backoff time.Duration) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	campaign, ok := s.campaigns[strings.TrimSpace(id)]
	if !ok {
		return nil
	}
	campaign.RetryCount++
	nextRetry := now.Add(backoff)
	campaign.NextRetryAt = cloneTimePtr(nextRetry)
	campaign.LastError = strings.TrimSpace(lastError)
	if campaign.RetryCount >= campaign.MaxAttempts && campaign.MaxAttempts > 0 {
		campaign.QueueState = "dead-letter"
		campaign.DeadLetter = true
	} else {
		campaign.QueueState = "queued"
	}
	campaign.LeaseUntil = nil
	campaign.HeartbeatAt = nil
	campaign.UpdatedAt = now
	s.campaigns[campaign.ID] = campaign
	return nil
}

func (s *MemoryStore) HeartbeatAutomationCampaignLease(ctx context.Context, id string, heartbeatAt, leaseUntil time.Time) (bool, error) {
	if err := checkContext(ctx); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	campaign, ok := s.campaigns[strings.TrimSpace(id)]
	if !ok || campaign.DeadLetter || !strings.EqualFold(campaign.QueueState, "running") || campaign.LeaseUntil == nil || campaign.LeaseUntil.Before(time.Now().UTC()) {
		return false, nil
	}
	campaign.HeartbeatAt = cloneTimePtr(heartbeatAt)
	campaign.LeaseUntil = cloneTimePtr(leaseUntil)
	campaign.UpdatedAt = time.Now().UTC()
	s.campaigns[campaign.ID] = campaign
	return true, nil
}

func (s *MemoryStore) ReclaimStaleAutomationCampaignLeases(ctx context.Context, staleBefore time.Time, limit int) (int64, error) {
	if err := checkContext(ctx); err != nil {
		return 0, err
	}
	if limit <= 0 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0)
	for id, campaign := range s.campaigns {
		if campaign.DeadLetter || !strings.EqualFold(campaign.QueueState, "running") {
			continue
		}
		if campaign.HeartbeatAt == nil || campaign.HeartbeatAt.Before(staleBefore) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return s.campaigns[ids[i]].UpdatedAt.Before(s.campaigns[ids[j]].UpdatedAt) })
	if len(ids) > limit {
		ids = ids[:limit]
	}
	now := time.Now().UTC()
	for _, id := range ids {
		campaign := s.campaigns[id]
		campaign.QueueState = "queued"
		campaign.LeaseUntil = nil
		campaign.HeartbeatAt = nil
		if strings.TrimSpace(campaign.LastError) == "" {
			campaign.LastError = "stale lease reclaimed for replay"
		}
		campaign.UpdatedAt = now
		s.campaigns[id] = campaign
	}
	return int64(len(ids)), nil
}

func (s *MemoryStore) UpdateAutomationCampaignQueueState(ctx context.Context, id, queueState, runIdempotencyKey string, heartbeatAt *time.Time) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	queueState = strings.ToLower(strings.TrimSpace(queueState))
	if queueState == "" {
		queueState = "queued"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	campaign, ok := s.campaigns[strings.TrimSpace(id)]
	if !ok {
		return nil
	}
	campaign.QueueState = queueState
	campaign.RunIdempotency = strings.TrimSpace(runIdempotencyKey)
	campaign.HeartbeatAt = cloneOptionalTimePtr(heartbeatAt)
	campaign.UpdatedAt = time.Now().UTC()
	s.campaigns[campaign.ID] = campaign
	return nil
}

func (s *MemoryStore) GetProgramROIOverride(ctx context.Context, workspaceID, programName string) (*model.ProgramROIOverride, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	workspaceID = defaultWorkspace(workspaceID)
	programName = strings.TrimSpace(programName)
	if programName == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.roiOverrides[roiOverrideKey(workspaceID, programName)]
	if !ok {
		return nil, nil
	}
	copyItem := cloneValue(item)
	return &copyItem, nil
}

func (s *MemoryStore) UpsertProgramROIOverride(ctx context.Context, item model.ProgramROIOverride) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	item.WorkspaceID = defaultWorkspace(item.WorkspaceID)
	item.ProgramName = strings.TrimSpace(item.ProgramName)
	if item.ProgramName == "" {
		return fmt.Errorf("program name is required")
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roiOverrides[roiOverrideKey(item.WorkspaceID, item.ProgramName)] = cloneValue(item)
	return nil
}

func (s *MemoryStore) ListProgramROIOverrides(ctx context.Context, workspaceID string, limit int) ([]model.ProgramROIOverride, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	workspaceID = defaultWorkspace(workspaceID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.ProgramROIOverride, 0)
	for _, item := range s.roiOverrides {
		if item.WorkspaceID == workspaceID {
			out = append(out, cloneValue(item))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) GetWorkspaceDailyUsage(ctx context.Context, workspaceID string, day time.Time) (model.WorkspaceDailyUsage, error) {
	if err := checkContext(ctx); err != nil {
		return model.WorkspaceDailyUsage{}, err
	}
	workspaceID = defaultWorkspace(workspaceID)
	start := day.UTC().Truncate(24 * time.Hour)
	end := start.Add(24 * time.Hour)
	usage := model.WorkspaceDailyUsage{WorkspaceID: workspaceID, Day: start}
	var runtimeMinutes float64
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, job := range s.jobs {
		if defaultWorkspace(job.WorkspaceID) != workspaceID {
			continue
		}
		if job.StartedAt.Before(start) || !job.StartedAt.Before(end) {
			continue
		}
		usage.ScanCount++
		if job.CompletedAt != nil {
			runtimeMinutes += math.Max(job.CompletedAt.Sub(job.StartedAt).Minutes(), 0)
		}
		usage.ProbeVolume += len(job.Findings)
	}
	usage.RuntimeMinutes = int(math.Round(runtimeMinutes))
	return usage, nil
}

func (s *MemoryStore) GetAutomationPolicyPack(ctx context.Context, workspaceID, name string) (*model.AutomationPolicyPack, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	workspaceID = defaultWorkspace(workspaceID)
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.policyPacks[policyPackKey(workspaceID, name)]
	if !ok {
		return nil, nil
	}
	copyItem := cloneValue(item)
	return &copyItem, nil
}

func (s *MemoryStore) UpsertAutomationPolicyPack(ctx context.Context, item model.AutomationPolicyPack) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	item.WorkspaceID = defaultWorkspace(item.WorkspaceID)
	item.Name = strings.TrimSpace(item.Name)
	if item.Name == "" {
		return fmt.Errorf("policy pack name is required")
	}
	if item.StrategyVersion <= 0 {
		item.StrategyVersion = 1
	}
	if item.CanaryPercent < 0 {
		item.CanaryPercent = 0
	}
	if item.CanaryPercent > 100 {
		item.CanaryPercent = 100
	}
	if item.MinExpectedROIUSD < 0 {
		item.MinExpectedROIUSD = 0
	}
	if item.MaxAutomationConcurrency < 0 {
		item.MaxAutomationConcurrency = 0
	}
	if item.MaxPerTargetConcurrency < 0 {
		item.MaxPerTargetConcurrency = 0
	}
	if item.MaxExploitAttempts < 0 {
		item.MaxExploitAttempts = 0
	}
	if item.DailyScanLimit < 0 {
		item.DailyScanLimit = 0
	}
	if item.DailyRuntimeLimitMinutes < 0 {
		item.DailyRuntimeLimitMinutes = 0
	}
	if item.DailyProbeLimit < 0 {
		item.DailyProbeLimit = 0
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyPacks[policyPackKey(item.WorkspaceID, item.Name)] = cloneValue(item)
	return nil
}

func (s *MemoryStore) ListAutomationPolicyPacks(ctx context.Context, workspaceID string, limit int) ([]model.AutomationPolicyPack, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	workspaceID = defaultWorkspace(workspaceID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.AutomationPolicyPack, 0)
	for _, item := range s.policyPacks {
		if item.WorkspaceID == workspaceID {
			out = append(out, cloneValue(item))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) AppendAutomationPolicyAudit(ctx context.Context, event model.AutomationPolicyAuditEvent) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	event.ID = strings.TrimSpace(event.ID)
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	event.WorkspaceID = defaultWorkspace(event.WorkspaceID)
	event.PolicyPack = strings.TrimSpace(event.PolicyPack)
	if event.ChangedAt.IsZero() {
		event.ChangedAt = time.Now().UTC()
	}
	if event.StrategyVersion <= 0 {
		event.StrategyVersion = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyAudit = append(s.policyAudit, cloneValue(event))
	return nil
}

func (s *MemoryStore) ListAutomationPolicyAudit(ctx context.Context, workspaceID, policyPack string, limit int) ([]model.AutomationPolicyAuditEvent, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 200
	}
	workspaceID = defaultWorkspace(workspaceID)
	policyPack = strings.TrimSpace(policyPack)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.AutomationPolicyAuditEvent, 0)
	for _, item := range s.policyAudit {
		if item.WorkspaceID != workspaceID {
			continue
		}
		if policyPack != "" && !strings.EqualFold(item.PolicyPack, policyPack) {
			continue
		}
		out = append(out, cloneValue(item))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChangedAt.After(out[j].ChangedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) CreateAPIKey(ctx context.Context, workspaceID, name string, role model.APIKeyRole) (*model.APIKeyRecord, string, error) {
	if err := checkContext(ctx); err != nil {
		return nil, "", err
	}
	workspaceID = defaultWorkspace(workspaceID)
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unnamed"
	}
	role = normalizeAPIKeyRole(role)
	raw, err := generateRawAPIKey()
	if err != nil {
		return nil, "", err
	}
	hashed, err := hashAPIKey(raw)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	rec := model.APIKeyRecord{
		ID:          uuid.NewString(),
		WorkspaceID: workspaceID,
		Name:        name,
		Role:        role,
		KeyPrefix:   apiKeyPrefix(raw),
		CreatedAt:   now,
		Active:      true,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys[rec.ID] = memoryAPIKey{Record: cloneValue(rec), Hash: hashed}
	copyRec := cloneValue(rec)
	return &copyRec, raw, nil
}

func (s *MemoryStore) ListAPIKeys(ctx context.Context, workspaceID string) ([]model.APIKeyRecord, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	workspaceID = strings.TrimSpace(workspaceID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.APIKeyRecord, 0)
	for _, key := range s.apiKeys {
		if key.Record.WorkspaceID == workspaceID {
			out = append(out, cloneValue(key.Record))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) RotateAPIKey(ctx context.Context, id string) (*model.APIKeyRecord, string, error) {
	if err := checkContext(ctx); err != nil {
		return nil, "", err
	}
	raw, err := generateRawAPIKey()
	if err != nil {
		return nil, "", err
	}
	hashed, err := hashAPIKey(raw)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.apiKeys[strings.TrimSpace(id)]
	if !ok {
		return nil, "", sql.ErrNoRows
	}
	state.Record.KeyPrefix = apiKeyPrefix(raw)
	state.Record.RotatedAt = cloneTimePtr(now)
	state.Record.RevokedAt = nil
	state.Record.Active = true
	state.Hash = hashed
	s.apiKeys[state.Record.ID] = state
	copyRec := cloneValue(state.Record)
	return &copyRec, raw, nil
}

func (s *MemoryStore) RevokeAPIKey(ctx context.Context, id string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.apiKeys[strings.TrimSpace(id)]
	if !ok {
		return sql.ErrNoRows
	}
	state.Record.Active = false
	state.Record.RevokedAt = cloneTimePtr(now)
	s.apiKeys[state.Record.ID] = state
	return nil
}

func (s *MemoryStore) AuthenticateAPIKey(ctx context.Context, rawKey string) (*model.APIKeyRecord, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	candidate := strings.TrimSpace(rawKey)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, key := range s.apiKeys {
		if !key.Record.Active {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(key.Hash), []byte(candidate)) == nil {
			copyRec := cloneValue(key.Record)
			return &copyRec, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (s *MemoryStore) SaveScanAnnotation(ctx context.Context, annotation model.ScanAnnotation) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	key := strings.TrimSpace(annotation.ScanID)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.annotations[key] {
		if existing.ID == annotation.ID {
			return nil
		}
	}
	s.annotations[key] = append(s.annotations[key], cloneValue(annotation))
	return nil
}

func (s *MemoryStore) ListScanAnnotations(ctx context.Context, scanID string) ([]model.ScanAnnotation, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := cloneValue(s.annotations[strings.TrimSpace(scanID)])
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// SaveProbeRecord persists a probe outcome in memory (no-op retention policy).
func (s *MemoryStore) SaveProbeRecord(_ context.Context, _ string, _ model.ProbeResult) error {
	return nil
}

// ListProbeRecords returns an empty slice; the in-memory store does not retain probe records.
func (s *MemoryStore) ListProbeRecords(_ context.Context, _ string) ([]model.ProbeRecord, error) {
	return nil, nil
}

// ListProbeRecordsByOutcome returns an empty slice; the in-memory store does not retain probe records.
func (s *MemoryStore) ListProbeRecordsByOutcome(_ context.Context, _ model.ProbeOutcome, _ time.Time, _ int) ([]model.ProbeRecord, error) {
	return nil, nil
}

// ListProbeRecordsByCategory returns an empty slice; the in-memory store does not retain probe records.
func (s *MemoryStore) ListProbeRecordsByCategory(_ context.Context, _ string, _ time.Time, _ int) ([]model.ProbeRecord, error) {
	return nil, nil
}

func (s *MemoryStore) SaveShadowDecision(ctx context.Context, decision model.ShadowDecision) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shadowDecisions = append(s.shadowDecisions, cloneValue(decision))
	return nil
}

func (s *MemoryStore) ListShadowDecisions(ctx context.Context, since time.Time, limit int) ([]model.ShadowDecision, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 1000
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.ShadowDecision, 0, len(s.shadowDecisions))
	for _, item := range s.shadowDecisions {
		if !item.CreatedAt.Before(since) {
			out = append(out, cloneValue(item))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) withRelatedLocked(job model.ScanJob) model.ScanJob {
	out := cloneValue(job)
	out.Assets = cloneValue(s.assetsByScanID[job.ID])
	out.AuditTrail = cloneValue(s.auditByScanID[job.ID])
	return out
}

func compareCompletedJobs(left, right model.ScanJob) int {
	leftCompleted := time.Time{}
	rightCompleted := time.Time{}
	if left.CompletedAt != nil {
		leftCompleted = *left.CompletedAt
	}
	if right.CompletedAt != nil {
		rightCompleted = *right.CompletedAt
	}
	switch {
	case leftCompleted.After(rightCompleted):
		return -1
	case leftCompleted.Before(rightCompleted):
		return 1
	case left.StartedAt.After(right.StartedAt):
		return -1
	case left.StartedAt.Before(right.StartedAt):
		return 1
	default:
		return strings.Compare(left.ID, right.ID)
	}
}

func campaignDueAt(campaign model.AutomationCampaign) (time.Time, bool) {
	if campaign.NextRetryAt != nil && !campaign.NextRetryAt.IsZero() {
		return *campaign.NextRetryAt, true
	}
	if !campaign.NextRunAt.IsZero() {
		return campaign.NextRunAt, true
	}
	return time.Time{}, false
}

func cloneTimePtr(t time.Time) *time.Time {
	copyTime := t
	return &copyTime
}

func cloneOptionalTimePtr(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	copyTime := *t
	return &copyTime
}

func defaultWorkspace(workspaceID string) string {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return "default"
	}
	return workspaceID
}

func idempotencyKey(key, target string) string {
	return strings.TrimSpace(key) + "::" + strings.TrimSpace(target)
}

func automationTicketKey(target, fingerprint string) string {
	return strings.TrimSpace(target) + "::" + strings.TrimSpace(fingerprint)
}

func roiOverrideKey(workspaceID, programName string) string {
	return defaultWorkspace(workspaceID) + "::" + strings.ToLower(strings.TrimSpace(programName))
}

func policyPackKey(workspaceID, name string) string {
	return defaultWorkspace(workspaceID) + "::" + strings.ToLower(strings.TrimSpace(name))
}

func normalizeAPIKeyRole(role model.APIKeyRole) model.APIKeyRole {
	role = model.APIKeyRole(strings.ToLower(strings.TrimSpace(string(role))))
	if role == "" {
		return model.APIKeyRoleViewer
	}
	return role
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func cloneValue[T any](value T) T {
	var out T
	data, err := json.Marshal(value)
	if err != nil {
		return value
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return value
	}
	return out
}
