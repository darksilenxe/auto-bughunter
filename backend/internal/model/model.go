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
	ID             string   `json:"id"`
	Category       string   `json:"category"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Evidence       string   `json:"evidence"`
	Recommendation string   `json:"recommendation"`
}

type ScanRequest struct {
	Target      string          `json:"target"`
	AuthProfile ScanAuthProfile `json:"authProfile,omitempty"`
	Options     ScanOptions     `json:"options,omitempty"`
	Scope       ScanScope       `json:"scope,omitempty"`
}

type ScanAuthProfile struct {
	Headers           map[string]string `json:"headers,omitempty"`
	Cookies           map[string]string `json:"cookies,omitempty"`
	UserAgent         string            `json:"userAgent,omitempty"`
	BasicAuthUsername string            `json:"basicAuthUsername,omitempty"`
	BasicAuthPassword string            `json:"basicAuthPassword,omitempty"`
}

type ScanAuthProfileSummary struct {
	HeaderKeys   []string `json:"headerKeys,omitempty"`
	CookieNames  []string `json:"cookieNames,omitempty"`
	HasBasicAuth bool     `json:"hasBasicAuth,omitempty"`
	UserAgent    string   `json:"userAgent,omitempty"`
}

type ScanOptions struct {
	UseNucleiIntegration      bool `json:"useNucleiIntegration,omitempty"`
	UseZAPBaselineIntegration bool `json:"useZapBaselineIntegration,omitempty"`
	UseSubfinderIntegration   bool `json:"useSubfinderIntegration,omitempty"`
	UseHttpxIntegration       bool `json:"useHttpxIntegration,omitempty"`
	UseNaabuIntegration       bool `json:"useNaabuIntegration,omitempty"`
	UseDnsxIntegration        bool `json:"useDnsxIntegration,omitempty"`
	UseShuffleDNSIntegration  bool `json:"useShuffleDnsIntegration,omitempty"`
	UseCertTransparency       bool `json:"useCertificateTransparencyIntegration,omitempty"`
	UseAmassIntegration       bool `json:"useAmassIntegration,omitempty"`
	UseKatanaIntegration      bool `json:"useKatanaIntegration,omitempty"`
	UseTlsxIntegration        bool `json:"useTlsxIntegration,omitempty"`
	UseCdncheckIntegration    bool `json:"useCdncheckIntegration,omitempty"`
	UseAsnmapIntegration      bool `json:"useAsnmapIntegration,omitempty"`
	UseWPScanIntegration      bool `json:"useWpScanIntegration,omitempty"`
	UseNiktoIntegration       bool `json:"useNiktoIntegration,omitempty"`
	UseSQLMapIntegration      bool `json:"useSqlMapIntegration,omitempty"`
	RescanIntervalMinutes     int  `json:"rescanIntervalMinutes,omitempty"`
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
	ID                 string                  `json:"id"`
	Target             string                  `json:"target"`
	Status             string                  `json:"status"`
	StartedAt          time.Time               `json:"startedAt"`
	CompletedAt        *time.Time              `json:"completedAt,omitempty"`
	Findings           []Finding               `json:"findings,omitempty"`
	AISummary          string                  `json:"aiSummary,omitempty"`
	Error              string                  `json:"error,omitempty"`
	AuthProfileSummary *ScanAuthProfileSummary `json:"authProfileSummary,omitempty"`
	Options            ScanOptions             `json:"options,omitempty"`
	Scope              ScanScope               `json:"scope,omitempty"`
	Assets             []ScanAsset             `json:"assets,omitempty"`
	AuditTrail         []ScanAuditEvent        `json:"auditTrail,omitempty"`
}

type ScanAsset struct {
	AssetType    string    `json:"assetType"`
	AssetKey     string    `json:"assetKey"`
	AssetValue   string    `json:"assetValue,omitempty"`
	DiscoveredAt time.Time `json:"discoveredAt"`
}

type ScanAuditEvent struct {
	Stage     string    `json:"stage"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

func SummarizeAuthProfile(profile ScanAuthProfile) *ScanAuthProfileSummary {
	if len(profile.Headers) == 0 && len(profile.Cookies) == 0 && profile.UserAgent == "" && profile.BasicAuthUsername == "" && profile.BasicAuthPassword == "" {
		return nil
	}

	summary := &ScanAuthProfileSummary{
		HeaderKeys:   make([]string, 0, len(profile.Headers)),
		CookieNames:  make([]string, 0, len(profile.Cookies)),
		HasBasicAuth: profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "",
		UserAgent:    profile.UserAgent,
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
