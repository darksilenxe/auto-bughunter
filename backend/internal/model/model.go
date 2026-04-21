package model

import "time"

type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Finding struct {
	ID                string            `json:"id"`
	Category          string            `json:"category"`
	Severity          Severity          `json:"severity"`
	Title             string            `json:"title"`
	Description       string            `json:"description"`
	Evidence          string            `json:"evidence"`
	Recommendation    string            `json:"recommendation"`
	Confidence        float64           `json:"confidence,omitempty"`
	Sources           []string          `json:"sources,omitempty"`
	DriftStatus       string            `json:"driftStatus,omitempty"`
	EvidenceFields    map[string]string `json:"evidenceFields,omitempty"`
	BusinessTags      []string          `json:"businessTags,omitempty"`
	Exploitability    *Exploitability   `json:"exploitability,omitempty"`
	CVSSVector        string            `json:"cvssVector,omitempty"`
	CVSSScore         float64           `json:"cvssScore,omitempty"`
	CWE               string            `json:"cwe,omitempty"`
	OWASPCategory     string            `json:"owaspCategory,omitempty"`
	AffectedURL       string            `json:"affectedUrl,omitempty"`
	AffectedParameter string            `json:"affectedParameter,omitempty"`
	ReproductionSteps []string          `json:"reproductionSteps,omitempty"`
	Impact            string            `json:"impact,omitempty"`
	References        []string          `json:"references,omitempty"`
	PoC               string            `json:"poc,omitempty"`
	// MITRETechniques is a deterministic list of MITRE ATT&CK technique IDs
	// (e.g. "T1190", "T1059.007") associated with this finding. Populated
	// from the finding's category/CWE by mitre.AnnotateFinding so the field
	// behaves like a sibling of CWE/OWASPCategory.
	MITRETechniques []string `json:"mitreTechniques,omitempty"`
}

// ReportTemplateOptions allows callers to customize the cover/branding sections
// of generated reports. All fields are optional; sensible defaults are used
// when a value is empty.
type ReportTemplateOptions struct {
	CompanyName    string `json:"companyName,omitempty"`
	LogoPath       string `json:"logoPath,omitempty"`
	Classification string `json:"classification,omitempty"`
	Contact        string `json:"contact,omitempty"`
	ProgramHandle  string `json:"programHandle,omitempty"`
	ReportType     string `json:"reportType,omitempty"`
}

// BugBountySubmission is the canonical structure for a single-finding report
// suitable for submission to bug-bounty platforms (HackerOne, Bugcrowd, etc.).
type BugBountySubmission struct {
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	CVSSVector  string   `json:"cvssVector,omitempty"`
	CVSSScore   float64  `json:"cvssScore,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Asset       string   `json:"asset,omitempty"`
	Summary     string   `json:"summary"`
	Steps       []string `json:"steps,omitempty"`
	Impact      string   `json:"impact,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
	Attachments []string `json:"attachments,omitempty"`
}

type Exploitability struct {
	Reachable       bool     `json:"reachable"`
	RequiredRole    string   `json:"requiredRole,omitempty"`
	Prerequisites   []string `json:"prerequisites,omitempty"`
	AttackPathHints []string `json:"attackPathHints,omitempty"`
	VerifiedStatus  string   `json:"verifiedStatus,omitempty"`
	VerifiedNotes   string   `json:"verifiedNotes,omitempty"`
}

type ScanRequest struct {
	Target               string              `json:"target"`
	WorkspaceID          string              `json:"workspaceId,omitempty"`
	IdempotencyKey       string              `json:"idempotencyKey,omitempty"`
	AuthProfile          ScanAuthProfile     `json:"authProfile,omitempty"`
	AuthProfiles         []RoleAuthProfile   `json:"authProfiles,omitempty"`
	Options              ScanOptions         `json:"options,omitempty"`
	Scope                ScanScope           `json:"scope,omitempty"`
	ProgramScopeProfile  ProgramScopeProfile `json:"programScopeProfile,omitempty"`
	DisallowedTestTypes  []string            `json:"disallowedTestTypes,omitempty"`
	EventDrivenRescanOn  []string            `json:"eventDrivenRescanOn,omitempty"`
	ProgramName          string              `json:"programName,omitempty"`
	ProgramPolicyVersion string              `json:"programPolicyVersion,omitempty"`
}

type ScanAuthProfile struct {
	Headers           map[string]string `json:"headers,omitempty"`
	Cookies           map[string]string `json:"cookies,omitempty"`
	UserAgent         string            `json:"userAgent,omitempty"`
	BasicAuthUsername string            `json:"basicAuthUsername,omitempty"`
	BasicAuthPassword string            `json:"basicAuthPassword,omitempty"`
	LoginURL          string            `json:"loginUrl,omitempty"`
	Username          string            `json:"username,omitempty"`
	Password          string            `json:"password,omitempty"`
}

type RoleAuthProfile struct {
	RoleName     string          `json:"roleName"`
	AuthProfile  ScanAuthProfile `json:"authProfile,omitempty"`
	Priority     int             `json:"priority,omitempty"`
	RefreshAfter int             `json:"refreshAfterSeconds,omitempty"`
}

type ProgramScopeProfile struct {
	IncludeHosts []string `json:"includeHosts,omitempty"`
	ExcludeHosts []string `json:"excludeHosts,omitempty"`
	ExcludePaths []string `json:"excludePaths,omitempty"`
	ProgramRules []string `json:"programRules,omitempty"`
}

type ScanAuthProfileSummary struct {
	HeaderKeys      []string `json:"headerKeys,omitempty"`
	CookieNames     []string `json:"cookieNames,omitempty"`
	HasBasicAuth    bool     `json:"hasBasicAuth,omitempty"`
	HasStandardAuth bool     `json:"hasStandardAuth,omitempty"`
	UserAgent       string   `json:"userAgent,omitempty"`
	LoginURL        string   `json:"loginUrl,omitempty"`
}

type ScanOptions struct {
	UseNucleiIntegration      bool     `json:"useNucleiIntegration,omitempty"`
	UseZAPBaselineIntegration bool     `json:"useZapBaselineIntegration,omitempty"`
	UseSubfinderIntegration   bool     `json:"useSubfinderIntegration,omitempty"`
	UseHttpxIntegration       bool     `json:"useHttpxIntegration,omitempty"`
	UseNaabuIntegration       bool     `json:"useNaabuIntegration,omitempty"`
	UseDnsxIntegration        bool     `json:"useDnsxIntegration,omitempty"`
	UseShuffleDNSIntegration  bool     `json:"useShuffleDnsIntegration,omitempty"`
	UseCertTransparency       bool     `json:"useCertificateTransparencyIntegration,omitempty"`
	UseAmassIntegration       bool     `json:"useAmassIntegration,omitempty"`
	UseKatanaIntegration      bool     `json:"useKatanaIntegration,omitempty"`
	UseTlsxIntegration        bool     `json:"useTlsxIntegration,omitempty"`
	UseCdncheckIntegration    bool     `json:"useCdncheckIntegration,omitempty"`
	UseAsnmapIntegration      bool     `json:"useAsnmapIntegration,omitempty"`
	UseWPScanIntegration      bool     `json:"useWpScanIntegration,omitempty"`
	UseNiktoIntegration       bool     `json:"useNiktoIntegration,omitempty"`
	UseSQLMapIntegration      bool     `json:"useSqlMapIntegration,omitempty"`
	UseFFUFIntegration        bool     `json:"useFfufIntegration,omitempty"`
	UseGobusterIntegration    bool     `json:"useGobusterIntegration,omitempty"`
	RescanIntervalMinutes     int      `json:"rescanIntervalMinutes,omitempty"`
	Priority                  int      `json:"priority,omitempty"`
	MaxRetries                int      `json:"maxRetries,omitempty"`
	BackoffMillis             int      `json:"backoffMillis,omitempty"`
	RequestDelayMillis        int      `json:"requestDelayMillis,omitempty"`
	MaxPerTargetConcurrency   int      `json:"maxPerTargetConcurrency,omitempty"`
	TargetRateLimitPerMinute  int      `json:"targetRateLimitPerMinute,omitempty"`
	GlobalScanBudget          int      `json:"globalScanBudget,omitempty"`
	AutomationMode            string   `json:"automationMode,omitempty"`
	MinExpectedROIUSD         float64  `json:"minExpectedRoiUsd,omitempty"`
	DeepScanOnHighSignal      bool     `json:"deepScanOnHighSignal,omitempty"`
	CrawlMaxPages             int      `json:"crawlMaxPages,omitempty"`
	SeedRuntimeEndpoints      []string `json:"seedRuntimeEndpoints,omitempty"`
	// ML agent per-scan toggles
	UseMLTriageAgent       bool `json:"useMLTriageAgent,omitempty"`
	UseAttackPathAgent     bool `json:"useAttackPathAgent,omitempty"`
	UseFalsePositiveReview bool `json:"useFalsePositiveReview,omitempty"`
	UseRemediationPlanner  bool `json:"useRemediationPlanner,omitempty"`
	// PassiveOnly enables "responsible-disclosure mode": all active
	// vulnerability probes (XSS, SQLi, OAST SSRF, subdomain takeover,
	// IDOR role-diff, open-redirect, CORS, SSTI, GraphQL introspection)
	// are skipped. Passive observations (security headers, cookie flags,
	// TLS configuration, runtime endpoint discovery, secrets-in-JS) still
	// run. Useful when assessing assets where written authorisation has
	// not yet been confirmed.
	PassiveOnly bool `json:"passiveOnly,omitempty"`
	// WAFBypass enables polymorphic payload variants in the active XSS,
	// SQLi and SSTI probes. When a Web Application Firewall blocks the
	// canonical payload the probe will retry with a small set of mutated
	// equivalents (case randomisation, whitespace alternatives, alternate
	// tags/event-handlers, double URL-encoding, comment-decorated
	// arithmetic etc.). Variants are still bounded by the per-probe
	// maxAttempts budget and gated by scope.IsURLInScope, so enabling
	// this does not expand attack surface — only expressiveness.
	WAFBypass bool `json:"wafBypass,omitempty"`
	// AggressiveExploitation enables deeper exploit-validation paths by
	// prioritizing exploitation-focused agents (Metasploit/Burp follow-ups)
	// earlier in orchestration.
	AggressiveExploitation bool `json:"aggressiveExploitation,omitempty"`
	// Daily unattended automation limits (workspace-scoped).
	DailyScanLimit           int `json:"dailyScanLimit,omitempty"`
	DailyRuntimeLimitMinutes int `json:"dailyRuntimeLimitMinutes,omitempty"`
	DailyProbeLimit          int `json:"dailyProbeLimit,omitempty"`
	// Safety caps applied by automation mode.
	MaxExploitAttempts       int `json:"maxExploitAttempts,omitempty"`
	MaxAutomationConcurrency int `json:"maxAutomationConcurrency,omitempty"`
	MinRescanIntervalMinutes int `json:"minRescanIntervalMinutes,omitempty"`
	// Autonomy governance controls.
	AutonomyMaxNoNoveltyRounds       int      `json:"autonomyMaxNoNoveltyRounds,omitempty"`
	AutonomyMaxConsecutiveFailRounds int      `json:"autonomyMaxConsecutiveFailRounds,omitempty"`
	AutonomyForceRunAgents           []string `json:"autonomyForceRunAgents,omitempty"`
	AutonomySuppressAgents           []string `json:"autonomySuppressAgents,omitempty"`
	AutonomyPlannerLock              string   `json:"autonomyPlannerLock,omitempty"`
	AutonomyEmergencyStop            bool     `json:"autonomyEmergencyStop,omitempty"`
	AutonomyFallbackRerun            bool     `json:"autonomyFallbackRerun,omitempty"`
	AutonomyMinMarginalScore         float64  `json:"autonomyMinMarginalScore,omitempty"`
	AutonomyExplorationBudgetPercent int      `json:"autonomyExplorationBudgetPercent,omitempty"`
	AutonomyMemoryRetentionDays      int      `json:"autonomyMemoryRetentionDays,omitempty"`
}

// ScanScope contains per-scan program scope rules.
// Host patterns support exact values (example.com) and wildcards (*.example.com).
type ScanScope struct {
	IncludeHosts []string `json:"includeHosts,omitempty"`
	ExcludeHosts []string `json:"excludeHosts,omitempty"`
	ExcludePaths []string `json:"excludePaths,omitempty"`
	ProgramRules []string `json:"programRules,omitempty"`
}

type ScanJob struct {
	ID                   string                  `json:"id"`
	Target               string                  `json:"target"`
	WorkspaceID          string                  `json:"workspaceId,omitempty"`
	RequestedBy          string                  `json:"requestedBy,omitempty"`
	PolicyPack           string                  `json:"policyPack,omitempty"`
	Status               string                  `json:"status"`
	StartedAt            time.Time               `json:"startedAt"`
	CompletedAt          *time.Time              `json:"completedAt,omitempty"`
	Findings             []Finding               `json:"findings,omitempty"`
	AISummary            string                  `json:"aiSummary,omitempty"`
	ModelRecommendations *ModelRecommendations   `json:"modelRecommendations,omitempty"`
	Error                string                  `json:"error,omitempty"`
	AuthProfileSummary   *ScanAuthProfileSummary `json:"authProfileSummary,omitempty"`
	Options              ScanOptions             `json:"options,omitempty"`
	Scope                ScanScope               `json:"scope,omitempty"`
	Assets               []ScanAsset             `json:"assets,omitempty"`
	AssetLinks           []ScanAssetLink         `json:"assetLinks,omitempty"`
	AuditTrail           []ScanAuditEvent        `json:"auditTrail,omitempty"`
	AgentRuns            []AgentRunTelemetry     `json:"agentRuns,omitempty"`
	Dashboard            *DecisionDashboard      `json:"dashboard,omitempty"`
	AttackGraph          *AttackGraphData        `json:"attackGraph,omitempty"`
	NextActions          []string                `json:"nextActions,omitempty"`
	AutomatedReport      string                  `json:"automatedReport,omitempty"`
	ProgramName          string                  `json:"programName,omitempty"`
	ProgramPolicyVersion string                  `json:"programPolicyVersion,omitempty"`
	DisallowedTestTypes  []string                `json:"disallowedTestTypes,omitempty"`
}

type APIKeyRole string

const (
	APIKeyRoleAdmin   APIKeyRole = "admin"
	APIKeyRoleTriager APIKeyRole = "triager"
	APIKeyRoleAnalyst APIKeyRole = "analyst"
	APIKeyRoleViewer  APIKeyRole = "viewer"
)

type APIKeyRecord struct {
	ID          string     `json:"id"`
	WorkspaceID string     `json:"workspaceId"`
	Name        string     `json:"name"`
	Role        APIKeyRole `json:"role"`
	KeyPrefix   string     `json:"keyPrefix"`
	CreatedAt   time.Time  `json:"createdAt"`
	RotatedAt   *time.Time `json:"rotatedAt,omitempty"`
	RevokedAt   *time.Time `json:"revokedAt,omitempty"`
	Active      bool       `json:"active"`
}

type AttackGraphData struct {
	Source string            `json:"source,omitempty"`
	Nodes  []AttackGraphNode `json:"nodes,omitempty"`
	Edges  []AttackGraphEdge `json:"edges,omitempty"`
}

type AttackGraphNode struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Label    string `json:"label,omitempty"`
	Sublabel string `json:"sublabel,omitempty"`
	Severity string `json:"severity,omitempty"`
	TS       int64  `json:"ts,omitempty"`
}

type AttackGraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type ReportFeedback struct {
	ID          string    `json:"id"`
	ScanID      string    `json:"scanId"`
	FindingID   string    `json:"findingId"`
	Category    string    `json:"category,omitempty"`
	Title       string    `json:"title,omitempty"`
	ProgramName string    `json:"programName,omitempty"`
	Outcome     string    `json:"outcome"`
	PayoutUSD   float64   `json:"payoutUsd,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

type FindingVerification struct {
	ID         string    `json:"id"`
	ScanID     string    `json:"scanId"`
	FindingID  string    `json:"findingId"`
	Status     string    `json:"status"`
	Notes      string    `json:"notes,omitempty"`
	VerifiedBy string    `json:"verifiedBy,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

type SuppressionRule struct {
	ID        string     `json:"id"`
	Target    string     `json:"target,omitempty"`
	FindingID string     `json:"findingId,omitempty"`
	Category  string     `json:"category,omitempty"`
	Title     string     `json:"title,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	CreatedBy string     `json:"createdBy,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

type PolicyGateResult struct {
	Status          string    `json:"status"`
	Reason          string    `json:"reason,omitempty"`
	BlockedFindings []string  `json:"blockedFindings,omitempty"`
	HighCount       int       `json:"highCount"`
	MediumCount     int       `json:"mediumCount"`
	GeneratedAt     time.Time `json:"generatedAt"`
}

type AutomationTicket struct {
	ID          string     `json:"id"`
	Target      string     `json:"target"`
	Fingerprint string     `json:"fingerprint"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	Status      string     `json:"status"`
	Owner       string     `json:"owner,omitempty"`
	SLADueAt    *time.Time `json:"slaDueAt,omitempty"`
	FirstSeenAt time.Time  `json:"firstSeenAt"`
	LastSeenAt  time.Time  `json:"lastSeenAt"`
	ResolvedAt  *time.Time `json:"resolvedAt,omitempty"`
}

type AutomationEventRequest struct {
	Type        string          `json:"type"`
	Target      string          `json:"target"`
	ProgramName string          `json:"programName,omitempty"`
	AuthProfile ScanAuthProfile `json:"authProfile,omitempty"`
	Options     ScanOptions     `json:"options,omitempty"`
	Scope       ScanScope       `json:"scope,omitempty"`
	Assets      []string        `json:"assets,omitempty"`
}

type AutomationCampaign struct {
	ID              string          `json:"id"`
	Target          string          `json:"target"`
	WorkspaceID     string          `json:"workspaceId,omitempty"`
	RequestedBy     string          `json:"requestedBy,omitempty"`
	PolicyPack      string          `json:"policyPack,omitempty"`
	PolicyVersion   int             `json:"policyVersion,omitempty"`
	Name            string          `json:"name,omitempty"`
	ProgramName     string          `json:"programName,omitempty"`
	IntervalMin     int             `json:"intervalMin"`
	ScheduleType    string          `json:"scheduleType,omitempty"`
	ScheduleValue   string          `json:"scheduleValue,omitempty"`
	RunWindow       string          `json:"runWindow,omitempty"`
	BlackoutWindows []string        `json:"blackoutWindows,omitempty"`
	NextRunAt       time.Time       `json:"nextRunAt"`
	LastRunAt       *time.Time      `json:"lastRunAt,omitempty"`
	RetryCount      int             `json:"retryCount,omitempty"`
	MaxAttempts     int             `json:"maxAttempts,omitempty"`
	NextRetryAt     *time.Time      `json:"nextRetryAt,omitempty"`
	LastError       string          `json:"lastError,omitempty"`
	DeadLetter      bool            `json:"deadLetter,omitempty"`
	QueueState      string          `json:"queueState,omitempty"`
	LeaseUntil      *time.Time      `json:"leaseUntil,omitempty"`
	HeartbeatAt     *time.Time      `json:"heartbeatAt,omitempty"`
	RunIdempotency  string          `json:"runIdempotencyKey,omitempty"`
	Active          bool            `json:"active"`
	AuthProfile     ScanAuthProfile `json:"authProfile,omitempty"`
	Options         ScanOptions     `json:"options,omitempty"`
	Scope           ScanScope       `json:"scope,omitempty"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
}

type AutomationCampaignUpsertRequest struct {
	ID              string          `json:"id,omitempty"`
	Target          string          `json:"target"`
	PolicyPack      string          `json:"policyPack,omitempty"`
	Name            string          `json:"name,omitempty"`
	ProgramName     string          `json:"programName,omitempty"`
	IntervalMin     int             `json:"intervalMin"`
	ScheduleType    string          `json:"scheduleType,omitempty"`
	ScheduleValue   string          `json:"scheduleValue,omitempty"`
	RunWindow       string          `json:"runWindow,omitempty"`
	BlackoutWindows []string        `json:"blackoutWindows,omitempty"`
	MaxAttempts     int             `json:"maxAttempts,omitempty"`
	Active          bool            `json:"active"`
	AuthProfile     ScanAuthProfile `json:"authProfile,omitempty"`
	Options         ScanOptions     `json:"options,omitempty"`
	Scope           ScanScope       `json:"scope,omitempty"`
}

type AutomationPolicyPack struct {
	WorkspaceID              string                    `json:"workspaceId"`
	Name                     string                    `json:"name"`
	StrategyVersion          int                       `json:"strategyVersion"`
	CanaryPercent            int                       `json:"canaryPercent,omitempty"`
	AutomationMode           string                    `json:"automationMode,omitempty"`
	MinExpectedROIUSD        float64                   `json:"minExpectedRoiUsd,omitempty"`
	MaxAutomationConcurrency int                       `json:"maxAutomationConcurrency,omitempty"`
	MaxPerTargetConcurrency  int                       `json:"maxPerTargetConcurrency,omitempty"`
	MaxExploitAttempts       int                       `json:"maxExploitAttempts,omitempty"`
	DailyScanLimit           int                       `json:"dailyScanLimit,omitempty"`
	DailyRuntimeLimitMinutes int                       `json:"dailyRuntimeLimitMinutes,omitempty"`
	DailyProbeLimit          int                       `json:"dailyProbeLimit,omitempty"`
	EscalateOnNewHigh        bool                      `json:"escalateOnNewHigh,omitempty"`
	EscalateOnChangedHigh    bool                      `json:"escalateOnChangedHigh,omitempty"`
	GovernanceProfile        AutonomyGovernanceProfile `json:"governanceProfile,omitempty"`
	UpdatedBy                string                    `json:"updatedBy,omitempty"`
	UpdatedAt                time.Time                 `json:"updatedAt"`
}

type AutonomyGovernanceProfile struct {
	SuccessCriteria   map[string]AutonomySuccessCriteria `json:"successCriteria,omitempty"`
	RiskMatrix        AutonomyRiskMatrix                 `json:"riskMatrix,omitempty"`
	FailureHandling   AutonomyFailureHandlingPolicy      `json:"failureHandling,omitempty"`
	MemoryPolicy      AutonomyMemoryPolicy               `json:"memoryPolicy,omitempty"`
	EvaluationGate    AutonomyEvaluationGate             `json:"evaluationGate,omitempty"`
	RolloutControl    AutonomyRolloutControl             `json:"rolloutControl,omitempty"`
	OperatorOverride  AutonomyOperatorOverridePolicy     `json:"operatorOverride,omitempty"`
	GovernanceCadence AutonomyGovernanceCadence          `json:"governanceCadence,omitempty"`
}

type AutonomySuccessCriteria struct {
	NovelFindingsRateMin        float64 `json:"novelFindingsRateMin,omitempty"`
	FalsePositiveRateMax        float64 `json:"falsePositiveRateMax,omitempty"`
	DuplicateSuppressionRateMin float64 `json:"duplicateSuppressionRateMin,omitempty"`
	FailureRecoveryRateMin      float64 `json:"failureRecoveryRateMin,omitempty"`
	ScanDurationCapMinutes      int     `json:"scanDurationCapMinutes,omitempty"`
}

type AutonomyRiskMatrix struct {
	AlwaysAllowedActions         []string `json:"alwaysAllowedActions,omitempty"`
	ConditionalActions           []string `json:"conditionalActions,omitempty"`
	HumanApprovalRequiredActions []string `json:"humanApprovalRequiredActions,omitempty"`
	HighRiskModules              []string `json:"highRiskModules,omitempty"`
	RetryLimit                   int      `json:"retryLimit,omitempty"`
	EscalationRule               string   `json:"escalationRule,omitempty"`
}

type AutonomyFailureHandlingPolicy struct {
	BackoffMillis                 int    `json:"backoffMillis,omitempty"`
	FallbackPlanner               string `json:"fallbackPlanner,omitempty"`
	SuppressionCooldownRounds     int    `json:"suppressionCooldownRounds,omitempty"`
	MaxNoNoveltyRounds            int    `json:"maxNoNoveltyRounds,omitempty"`
	MaxConsecutiveFailureRounds   int    `json:"maxConsecutiveFailureRounds,omitempty"`
	AutoRetryOnFailure            bool   `json:"autoRetryOnFailure,omitempty"`
	PauseForOperatorAfterFailures int    `json:"pauseForOperatorAfterFailures,omitempty"`
}

type AutonomyMemoryPolicy struct {
	RetentionDays int      `json:"retentionDays,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	ResetTriggers []string `json:"resetTriggers,omitempty"`
}

type AutonomyEvaluationGate struct {
	RequireReplayBenchmark  bool    `json:"requireReplayBenchmark,omitempty"`
	MinKPIDeltaScore        float64 `json:"minKpiDeltaScore,omitempty"`
	PromoteToProdOnlyIfPass bool    `json:"promoteToProdOnlyIfPass,omitempty"`
}

type AutonomyRolloutControl struct {
	CanaryPercentByStage          map[string]int `json:"canaryPercentByStage,omitempty"`
	PromotionStages               []string       `json:"promotionStages,omitempty"`
	AutoRollbackOnErrorSpike      bool           `json:"autoRollbackOnErrorSpike,omitempty"`
	AutoRollbackOnSafetyViolation bool           `json:"autoRollbackOnSafetyViolation,omitempty"`
	AutoRollbackOnKPIRegression   bool           `json:"autoRollbackOnKpiRegression,omitempty"`
}

type AutonomyOperatorOverridePolicy struct {
	AllowForceRun       bool `json:"allowForceRun,omitempty"`
	AllowSuppress       bool `json:"allowSuppress,omitempty"`
	AllowPlannerLock    bool `json:"allowPlannerLock,omitempty"`
	AllowEmergencyStop  bool `json:"allowEmergencyStop,omitempty"`
	AllowFallbackRerun  bool `json:"allowFallbackRerun,omitempty"`
	RequireAuditLogging bool `json:"requireAuditLogging,omitempty"`
}

type AutonomyGovernanceCadence struct {
	WeeklyReviewEnabled     bool `json:"weeklyReviewEnabled,omitempty"`
	MonthlyRebalanceEnabled bool `json:"monthlyRebalanceEnabled,omitempty"`
}

type AutomationPolicyAuditEvent struct {
	ID              string    `json:"id"`
	WorkspaceID     string    `json:"workspaceId"`
	PolicyPack      string    `json:"policyPack"`
	StrategyVersion int       `json:"strategyVersion"`
	Action          string    `json:"action"`
	ChangedBy       string    `json:"changedBy"`
	ChangedAt       time.Time `json:"changedAt"`
	BeforeJSON      string    `json:"beforeJson,omitempty"`
	AfterJSON       string    `json:"afterJson,omitempty"`
}

type AutomationMetrics struct {
	GeneratedAt       time.Time          `json:"generatedAt"`
	WorkspaceID       string             `json:"workspaceId"`
	QueueLagSeconds   float64            `json:"queueLagSeconds"`
	MaxQueueLag       float64            `json:"maxQueueLagSeconds"`
	RetryRate         float64            `json:"retryRate"`
	DLQCount          int                `json:"dlqCount"`
	ToolFailureRate   float64            `json:"toolFailureRate"`
	ROIByStrategy     map[string]float64 `json:"roiByStrategy,omitempty"`
	StrategyRunCounts map[string]int     `json:"strategyRunCounts,omitempty"`
	Alerts            []string           `json:"alerts,omitempty"`
	Extra             map[string]float64 `json:"extra,omitempty"`
}

type ProgramROIOverride struct {
	WorkspaceID       string    `json:"workspaceId"`
	ProgramName       string    `json:"programName"`
	MinExpectedROIUSD float64   `json:"minExpectedRoiUsd"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type WorkspaceDailyUsage struct {
	WorkspaceID    string    `json:"workspaceId"`
	Day            time.Time `json:"day"`
	ScanCount      int       `json:"scanCount"`
	RuntimeMinutes int       `json:"runtimeMinutes"`
	ProbeVolume    int       `json:"probeVolume"`
}

type ExecutiveReport struct {
	GeneratedAt                 time.Time          `json:"generatedAt"`
	TotalCompletedScans         int                `json:"totalCompletedScans"`
	NewFindings                 int                `json:"newFindings"`
	ChangedFindings             int                `json:"changedFindings"`
	ResolvedFindings            int                `json:"resolvedFindings"`
	HighOrMediumFindings        int                `json:"highOrMediumFindings"`
	AcceptedFeedback            int                `json:"acceptedFeedback"`
	RejectedFeedback            int                `json:"rejectedFeedback"`
	DuplicateFeedback           int                `json:"duplicateFeedback"`
	FalsePositiveRate           float64            `json:"falsePositiveRate"`
	MeanTimeToResolveHours      float64            `json:"meanTimeToResolveHours"`
	AverageExpectedROIUSD       float64            `json:"averageExpectedRoiUsd"`
	HighROICompletedScans       int                `json:"highRoiCompletedScans"`
	AcceptedPayoutPerScanUSD    float64            `json:"acceptedPayoutPerScanUsd"`
	OpenAutomationTickets       int                `json:"openAutomationTickets"`
	RecentlyResolvedTicketCount int                `json:"recentlyResolvedTicketCount"`
	AgentAcceptedRate           map[string]float64 `json:"agentAcceptedRate,omitempty"`
	AgentPayoutPerScanHour      map[string]float64 `json:"agentPayoutPerScanHour,omitempty"`
	AgentFalsePositiveRate      map[string]float64 `json:"agentFalsePositiveRate,omitempty"`
	ROISparkline                []float64          `json:"roiSparkline,omitempty"`
}

type PersistentScanState struct {
	Target                string         `json:"target"`
	LastUpdatedAt         time.Time      `json:"lastUpdatedAt"`
	SessionInstability    int            `json:"sessionInstability"`
	KnownRuntimeEndpoints []string       `json:"knownRuntimeEndpoints,omitempty"`
	AutonomyMemory        AutonomyMemory `json:"autonomyMemory,omitempty"`
}

type AutonomyMemory struct {
	PreferredAgents    []string                     `json:"preferredAgents,omitempty"`
	SuppressedAgents   []string                     `json:"suppressedAgents,omitempty"`
	LastAgentSequence  []string                     `json:"lastAgentSequence,omitempty"`
	AgentStats         map[string]AutonomyAgentStat `json:"agentStats,omitempty"`
	LastRunAt          time.Time                    `json:"lastRunAt,omitempty"`
	RetentionAppliedAt time.Time                    `json:"retentionAppliedAt,omitempty"`
}

type AutonomyAgentStat struct {
	Runs                   int     `json:"runs,omitempty"`
	Errors                 int     `json:"errors,omitempty"`
	Timeouts               int     `json:"timeouts,omitempty"`
	Findings               int     `json:"findings,omitempty"`
	HighConfidenceFindings int     `json:"highConfidenceFindings,omitempty"`
	YieldPerMinute         float64 `json:"yieldPerMinute,omitempty"`
	DecisionQualitySum     float64 `json:"decisionQualitySum,omitempty"`
	DecisionQualitySamples int     `json:"decisionQualitySamples,omitempty"`
	OperatorApprovals      int     `json:"operatorApprovals,omitempty"`
	OperatorRejections     int     `json:"operatorRejections,omitempty"`
}

type ModelRecommendations struct {
	ToolSelection       []ToolRecommendation        `json:"toolSelection,omitempty"`
	PrioritizedFindings []PrioritizedFinding        `json:"prioritizedFindings,omitempty"`
	Copilot             EngagementCopilotSuggestion `json:"copilot"`
	ModelMode           string                      `json:"modelMode,omitempty"`
	SecurityKnowledge   *SecurityKnowledgeContext   `json:"securityKnowledge,omitempty"`
}

type SecurityKnowledgeContext struct {
	Query            string               `json:"query,omitempty"`
	Stage            string               `json:"stage,omitempty"`
	CurationMode     string               `json:"curationMode,omitempty"`
	LicenseNotice    string               `json:"licenseNotice,omitempty"`
	SuggestedActions []string             `json:"suggestedActions,omitempty"`
	References       []KnowledgeReference `json:"references,omitempty"`
}

type KnowledgeReference struct {
	ID                 string  `json:"id,omitempty"`
	Title              string  `json:"title,omitempty"`
	URL                string  `json:"url,omitempty"`
	SourceType         string  `json:"sourceType,omitempty"`
	License            string  `json:"license,omitempty"`
	Topic              string  `json:"topic,omitempty"`
	VulnerabilityClass string  `json:"vulnerabilityClass,omitempty"`
	Technique          string  `json:"technique,omitempty"`
	Passage            string  `json:"passage,omitempty"`
	Score              float64 `json:"score,omitempty"`
}

type ToolRecommendation struct {
	Tool       string  `json:"tool"`
	Score      float64 `json:"score"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}

type PrioritizedFinding struct {
	FindingID string   `json:"findingId"`
	Title     string   `json:"title"`
	Severity  Severity `json:"severity"`
	Score     float64  `json:"score"`
	Reason    string   `json:"reason"`
}

type EngagementCopilotSuggestion struct {
	Summary          string   `json:"summary"`
	SuggestedActions []string `json:"suggestedActions,omitempty"`
	Confidence       float64  `json:"confidence"`
}

type ScanAsset struct {
	AssetType    string    `json:"assetType"`
	AssetKey     string    `json:"assetKey"`
	AssetValue   string    `json:"assetValue,omitempty"`
	DiscoveredAt time.Time `json:"discoveredAt"`
}

type ScanAssetLink struct {
	FromType string `json:"fromType"`
	FromKey  string `json:"fromKey"`
	ToType   string `json:"toType"`
	ToKey    string `json:"toKey"`
	Relation string `json:"relation"`
}

type ScanAuditEvent struct {
	Stage     string            `json:"stage"`
	Message   string            `json:"message"`
	Timestamp time.Time         `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type AgentRunTelemetry struct {
	AgentName        string            `json:"agentName"`
	Status           string            `json:"status"`
	StartedAt        time.Time         `json:"startedAt"`
	CompletedAt      time.Time         `json:"completedAt"`
	DurationMs       int64             `json:"durationMs"`
	TargetsAttempted int               `json:"targetsAttempted,omitempty"`
	TargetsSkipped   int               `json:"targetsSkipped,omitempty"`
	SkippedReasons   []string          `json:"skippedReasons,omitempty"`
	Error            string            `json:"error,omitempty"`
	TimedOut         bool              `json:"timedOut,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type DecisionDashboard struct {
	CoverageCompletenessScore int      `json:"coverageCompletenessScore"`
	AuthenticatedCoverageRate float64  `json:"authenticatedCoverageRate"`
	NewFindings               int      `json:"newFindings"`
	ChangedFindings           int      `json:"changedFindings"`
	ResolvedFindings          int      `json:"resolvedFindings"`
	TopAttackPaths            []string `json:"topAttackPaths,omitempty"`
	UntestedReasons           []string `json:"untestedReasons,omitempty"`
	ActionableFindings        int      `json:"actionableFindings"`
	ExpectedROIUSD            float64  `json:"expectedRoiUsd,omitempty"`
	ExpectedROIBasis          string   `json:"expectedRoiBasis,omitempty"`
	MeetsROIGate              bool     `json:"meetsRoiGate,omitempty"`
	// MITREHeatmap is a deterministic count of findings per MITRE ATT&CK
	// technique ID, used by the dashboard UI to render a heatmap. Empty
	// when no findings carry MITRE annotations.
	MITREHeatmap map[string]int `json:"mitreHeatmap,omitempty"`
}

func SummarizeAuthProfile(profile ScanAuthProfile) *ScanAuthProfileSummary {
	if len(profile.Headers) == 0 &&
		len(profile.Cookies) == 0 &&
		profile.UserAgent == "" &&
		profile.BasicAuthUsername == "" &&
		profile.BasicAuthPassword == "" &&
		profile.LoginURL == "" &&
		profile.Username == "" &&
		profile.Password == "" {
		return nil
	}

	summary := &ScanAuthProfileSummary{
		HeaderKeys:      make([]string, 0, len(profile.Headers)),
		CookieNames:     make([]string, 0, len(profile.Cookies)),
		HasBasicAuth:    profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "",
		HasStandardAuth: profile.Username != "" || profile.Password != "",
		UserAgent:       profile.UserAgent,
		LoginURL:        profile.LoginURL,
	}

	for key := range profile.Headers {
		summary.HeaderKeys = append(summary.HeaderKeys, key)
	}
	for name := range profile.Cookies {
		summary.CookieNames = append(summary.CookieNames, name)
	}

	return summary
}

// ProxyRequest represents a single HTTP request/response pair captured by the
// intercepting proxy. Request and response headers are stored as flat maps.
type ProxyRequest struct {
	ID              string            `json:"id"`
	CapturedAt      time.Time         `json:"capturedAt"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"requestHeaders"`
	RequestBody     string            `json:"requestBody"`
	ResponseStatus  int               `json:"responseStatus"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	ResponseBody    string            `json:"responseBody"`
	Notes           string            `json:"notes,omitempty"`
}

// ProxyReplayRequest is the payload for the POST /api/proxy/replay endpoint.
// OverrideHeaders replaces/adds headers on top of the original request headers.
// OverrideBody, when non-empty, replaces the original request body entirely.
type ProxyReplayRequest struct {
	RequestID       string            `json:"requestId"`
	OverrideHeaders map[string]string `json:"overrideHeaders,omitempty"`
	OverrideBody    string            `json:"overrideBody,omitempty"`
	Scope           *ScanScope        `json:"scope,omitempty"`
}
