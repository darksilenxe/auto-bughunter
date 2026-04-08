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
	UseKatanaIntegration      bool `json:"useKatanaIntegration,omitempty"`
	UseTlsxIntegration        bool `json:"useTlsxIntegration,omitempty"`
	UseCdncheckIntegration    bool `json:"useCdncheckIntegration,omitempty"`
	UseAsnmapIntegration      bool `json:"useAsnmapIntegration,omitempty"`
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
