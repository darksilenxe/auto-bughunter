package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/metrics"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/oast"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

type Service struct {
	httpClient     *http.Client
	cfg            Config
	oast           *oast.Service
	proxyStore     proxy.Store
	scannerProxy   ProxyConfig
	proxyTransport http.RoundTripper
	// bundledProxyPort is the port the in-process intercepting proxy
	// listens on (PROXY_PORT). Used to decide whether RecordingTransport
	// should be skipped (when scanner traffic already flows through the
	// bundled proxy) so the same request isn't captured twice.
	bundledProxyPort string
}

const supplementalResourceFetchMaxURLs = 8
const supplementalResourceFetchMaxReadBytes int64 = 128 * 1024
const supplementalResourceFetchTextExcerptMaxChars = 220

var (
	htmlScriptStyleRe = regexp.MustCompile(`(?is)<(script|style)[^>]*>.*?</(script|style)>`)
	htmlTagRe         = regexp.MustCompile(`(?s)<[^>]+>`)
	htmlWhitespaceRe  = regexp.MustCompile(`\s+`)
)

// SetOAST attaches an OAST service. Safe to call with nil to disable.
func (s *Service) SetOAST(o *oast.Service) { s.oast = o }

// OAST returns the attached OAST service or nil.
func (s *Service) OAST() *oast.Service { return s.oast }

// SetProxyStore attaches a proxy store so that all outbound HTTP requests made
// by the scanner are recorded and visible in the Network Graph UI. Safe to
// call with nil to disable recording.
func (s *Service) SetProxyStore(store proxy.Store) { s.proxyStore = store }

// SetScannerProxy configures an optional upstream HTTP(S) proxy that all
// scanner-initiated traffic will be routed through. bundledProxyPort is the
// port the in-process intercepting proxy listens on so we can avoid
// double-capturing the same request via RecordingTransport when the upstream
// proxy IS the bundled one. Safe to call with cfg.Enabled=false to disable.
//
// Returns the error from buildTransport when the configuration is malformed
// so the caller can log it; the service falls back to direct connections in
// that case (matching previous behaviour).
func (s *Service) SetScannerProxy(cfg ProxyConfig, bundledProxyPort string) error {
	s.scannerProxy = cfg
	s.bundledProxyPort = strings.TrimSpace(bundledProxyPort)
	if !cfg.Enabled {
		s.proxyTransport = nil
		s.httpClient = &http.Client{Timeout: 15 * time.Second}
		return nil
	}
	rt, err := buildTransport(cfg)
	if err != nil {
		// Disable proxying on error so callers get direct connections
		// rather than a broken transport.
		s.scannerProxy = ProxyConfig{}
		s.proxyTransport = nil
		s.httpClient = &http.Client{Timeout: 15 * time.Second}
		return err
	}
	s.proxyTransport = rt
	s.httpClient = &http.Client{Timeout: 15 * time.Second, Transport: rt}
	return nil
}

type Config struct {
	EnableSubfinder   bool
	EnableHttpx       bool
	EnableCloudlist   bool
	EnableVulnx       bool
	EnableNaabu       bool
	EnableDnsx        bool
	EnableShuffleDNS  bool
	EnableCertTrans   bool
	EnableAmass       bool
	EnableKatana      bool
	EnableTlsx        bool
	EnableCdncheck    bool
	EnableAsnmap      bool
	EnableWPScan      bool
	EnableNikto       bool
	EnableSQLMap      bool
	EnableFFUF        bool
	EnableGobuster    bool
	EnableKiterunner  bool
	EnableGau         bool
	EnableArjun       bool
	EnableCommix      bool
	EnableLinkFinder  bool
	EnableRetireJS    bool
	EnableTruffleHog  bool
	EnableUncover     bool
	EnableSemgrep        bool
	EnableUISimulation   bool
	AllowDestructive     bool
	NucleiBinary      string
	ZAPBaselineBinary string
	XSSMapBinary      string
	SubfinderBinary   string
	HttpxBinary       string
	CloudlistBinary   string
	VulnxBinary       string
	NaabuBinary       string
	DnsxBinary        string
	ShuffleDNSBinary  string
	KatanaBinary      string
	TlsxBinary        string
	CdncheckBinary    string
	AsnmapBinary      string
	FFUFBinary        string
	GobusterBinary    string
	KiterunnerBinary  string
	GauBinary         string
	ArjunBinary       string
	CommixBinary      string
	LinkFinderBinary  string
	RetireJSBinary    string
	TruffleHogBinary  string
	UncoverBinary     string

	IntegrationTimeout time.Duration
	DefaultMaxRetries  int
	DefaultBackoff     time.Duration
}

type RunInput struct {
	Target      string
	AuthProfile model.ScanAuthProfile
	Options     model.ScanOptions
	Scope       model.ScanScope
	// Emit publishes live events to the per-scan event bus. It is nil-safe.
	Emit func(model.ScanEvent)
	// Session is a per-scan stateful HTTP context that persists cookies, CSRF
	// tokens, and XHR-discovered endpoints across all probes. When nil, Run
	// creates one automatically; callers may pre-create a session to share
	// state across multiple Run calls or external probe invocations.
	Session *ScanSession
	// DetectedTech holds the technology stack fingerprinted from the baseline
	// HTTP response. Probes use it to prioritize the most-likely payload
	// variants (e.g. Jinja2 payloads first for Python backends, SpEL first
	// for Java, etc.) so the fixed probe budget is used more efficiently.
	// Populated automatically by Run(); callers may pre-set it to override.
	DetectedTech TechStack
	// WAFFingerprint is the result of the pre-scan WAF canary probe. It is
	// populated automatically by Run() before any active probes launch so
	// all probes can consult it without re-issuing the canary request.
	WAFFingerprint WAFFingerprint
}

func NewService(cfg Config) *Service {
	if cfg.IntegrationTimeout <= 0 {
		cfg.IntegrationTimeout = 90 * time.Second
	}
	if cfg.DefaultMaxRetries < 0 {
		cfg.DefaultMaxRetries = 0
	}
	if cfg.DefaultBackoff <= 0 {
		cfg.DefaultBackoff = 400 * time.Millisecond
	}
	if strings.TrimSpace(cfg.NucleiBinary) == "" {
		cfg.NucleiBinary = "nuclei"
	}
	if strings.TrimSpace(cfg.ZAPBaselineBinary) == "" {
		cfg.ZAPBaselineBinary = "zap-baseline.py"
	}
	if strings.TrimSpace(cfg.XSSMapBinary) == "" {
		cfg.XSSMapBinary = "xssmap"
	}
	if strings.TrimSpace(cfg.SubfinderBinary) == "" {
		cfg.SubfinderBinary = "subfinder"
	}
	if strings.TrimSpace(cfg.HttpxBinary) == "" {
		cfg.HttpxBinary = "httpx"
	}
	if strings.TrimSpace(cfg.CloudlistBinary) == "" {
		cfg.CloudlistBinary = "cloudlist"
	}
	if strings.TrimSpace(cfg.VulnxBinary) == "" {
		cfg.VulnxBinary = "vulnx"
	}
	if strings.TrimSpace(cfg.NaabuBinary) == "" {
		cfg.NaabuBinary = "naabu"
	}
	if strings.TrimSpace(cfg.DnsxBinary) == "" {
		cfg.DnsxBinary = "dnsx"
	}
	if strings.TrimSpace(cfg.ShuffleDNSBinary) == "" {
		cfg.ShuffleDNSBinary = "shuffledns"
	}
	if strings.TrimSpace(cfg.KatanaBinary) == "" {
		cfg.KatanaBinary = "katana"
	}
	if strings.TrimSpace(cfg.TlsxBinary) == "" {
		cfg.TlsxBinary = "tlsx"
	}
	if strings.TrimSpace(cfg.CdncheckBinary) == "" {
		cfg.CdncheckBinary = "cdncheck"
	}
	if strings.TrimSpace(cfg.AsnmapBinary) == "" {
		cfg.AsnmapBinary = "asnmap"
	}
	if strings.TrimSpace(cfg.FFUFBinary) == "" {
		cfg.FFUFBinary = "ffuf"
	}
	if strings.TrimSpace(cfg.GobusterBinary) == "" {
		cfg.GobusterBinary = "gobuster"
	}
	if strings.TrimSpace(cfg.KiterunnerBinary) == "" {
		cfg.KiterunnerBinary = "kr"
	}
	if strings.TrimSpace(cfg.GauBinary) == "" {
		cfg.GauBinary = "gau"
	}
	if strings.TrimSpace(cfg.ArjunBinary) == "" {
		cfg.ArjunBinary = "arjun"
	}
	if strings.TrimSpace(cfg.CommixBinary) == "" {
		cfg.CommixBinary = "commix"
	}
	if strings.TrimSpace(cfg.LinkFinderBinary) == "" {
		cfg.LinkFinderBinary = "linkfinder"
	}
	if strings.TrimSpace(cfg.RetireJSBinary) == "" {
		cfg.RetireJSBinary = "retire"
	}
	if strings.TrimSpace(cfg.TruffleHogBinary) == "" {
		cfg.TruffleHogBinary = "trufflehog"
	}
	if strings.TrimSpace(cfg.UncoverBinary) == "" {
		cfg.UncoverBinary = "uncover"
	}

	return &Service{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cfg:        cfg,
	}
}

func (s *Service) Run(ctx context.Context, input RunInput) ([]model.Finding, error) {
	u, err := url.Parse(input.Target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme")
	}
	if err := safety.ValidateOutboundURL(input.Target); err != nil {
		return nil, fmt.Errorf("target blocked by ssrf policy: %w", err)
	}
	if !scope.IsURLInScope(input.Target, input.Scope) {
		return nil, fmt.Errorf("target is outside configured scan scope")
	}

	// Ensure a session exists for the lifetime of this scan.
	if input.Session == nil {
		input.Session = NewScanSessionWithTransport(s.proxyTransport)
	}

	if input.Options.RequestDelayMillis > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(input.Options.RequestDelayMillis) * time.Millisecond):
		}
	}

	var findings []model.Finding
	if hasStandardLoginCredentials(input.AuthProfile) {
		resolvedProfile, authFindings := bootstrapStandardAuthProfile(ctx, input.Target, input.AuthProfile, input.Scope, input.Emit)
		input.AuthProfile = resolvedProfile
		findings = append(findings, authFindings...)
		// Seed the session cookie jar with any cookies obtained during login
		// so all subsequent probes send them automatically.
		input.Session.SeedCookies(input.Target, resolvedProfile.Cookies)
	}

	emitCmd := func(cmd, msg string) {
		if input.Emit != nil {
			input.Emit(model.ScanEvent{
				Type:    model.ScanEventCommand,
				Command: cmd,
				Message: msg,
			})
		}
	}

	// Fingerprint the WAF (if any) before launching active probes so every
	// probe in this run can consult input.WAFFingerprint without re-issuing
	// the canary request. The fingerprint is only captured once per scan;
	// passive-only scans skip the canary to avoid triggering WAF alerts.
	if !input.Options.PassiveOnly {
		input.WAFFingerprint = s.CaptureWAFFingerprint(ctx, input.Target, input.AuthProfile, input.Options)
	}

	safeTargetURL, err := rebuildRequestURL(input.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, safeTargetURL, nil)
	ApplyAuthProfile(req, input.AuthProfile)
	emitCmd(fmt.Sprintf("GET %s", safeTargetURL), "Probing target for security headers, cookies, and TLS")
	resp, err := s.doRequestWithSession(ctx, req, input.Options, input.Session)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	findings = append(findings, checkSecurityHeaders(resp.Header)...)
	findings = append(findings, checkCookies(resp)...)
	findings = append(findings, s.runSecurityHeadersProbe(input, resp.Header, resp)...)
	if u.Scheme == "https" {
		emitCmd(fmt.Sprintf("tlscheck %s", u.Host), "Checking TLS configuration")
		findings = append(findings, checkTLS(u.Host)...)
		findings = append(findings, s.runTLSConfigProbe(ctx, input)...)
	}
	emitCmd(fmt.Sprintf("dns-san %s", u.Hostname()), "Evaluating DNS records and certificate SANs")
	findings = append(findings, s.runDNSSANProbe(ctx, input)...)

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	bodyText := string(bodyBytes)
	// Harvest any tokens present in the baseline response body.
	input.Session.HarvestFromResponse(resp, bodyBytes)

	// Fingerprint the tech stack from the baseline response so all subsequent
	// probes can prioritize payloads toward the detected engine family.
	// Only override when the caller hasn't pre-populated DetectedTech.
	if len(input.DetectedTech.Labels()) == 0 {
		input.DetectedTech = detectTechStack(resp.Header, bodyBytes)
	}

	findings = append(findings, s.runReverseTabnabbingProbe(input, bodyText)...)
	findings = append(findings, s.runClickjackingProbe(input, resp.Header)...)
	findings = append(findings, s.runCSPAnalysisProbe(input, resp.Header, bodyText)...)
	findings = append(findings, s.runSupplementalResourceFetch(ctx, input)...)
	findings = append(findings, discoverRuntimeSurface(input.Target, bodyText, input.Scope)...)
	findings = append(findings, runContextualParamProbes(ctx, input.Target, bodyText, input.AuthProfile, input.Options, input.Scope, s)...)
	findings = append(findings, s.runOASTHeaderSSRFProbe(ctx, input)...)
	findings = append(findings, s.runActiveXSSProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActiveSQLiProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runOASTBodySSRFProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runSubdomainTakeoverProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActiveOpenRedirectProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActiveCORSProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActiveSSTIProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActiveGraphQLIntrospectionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runGraphQLAbuseProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runSecretsInJSProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActiveNoSQLiProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActivePathTraversalProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActiveXXEProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runSensitiveFileProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runCRLFInjectionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runForbiddenBypassProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runCachePoisoningProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runParamPollutionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runVhostDiscoveryProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runRequestSmugglingProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActiveLDAPInjectionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActiveXPathInjectionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runFormulaInjectionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActivePrototypePollutionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runDanglingMarkupProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runMassAssignmentProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runAccountEnumerationProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runWebSocketProbe(ctx, input, bodyText)...)
	findings = append(findings, s.RunSAMLProbe(ctx, input.Target, input.Scope, input.Options, input.AuthProfile, input.Emit)...)
	findings = append(findings, s.runHTTPMethodsProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runVerboseErrorProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runFileUploadProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runCommandInjectionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runSSIInjectionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runCrossDomainPolicyProbe(ctx, input)...)
	findings = append(findings, s.runXSSIJSONPProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runSMTPInjectionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runCloudStorageProbe(ctx, input, bodyText)...)

	// AI/LLM agent vulnerability probes.
	// Run detection first; it marks DetectedTech["ai-agent"] so all subsequent
	// probes can gate themselves without re-probing the endpoint.
	findings = append(findings, s.runAIAgentDetectProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runActivePromptInjectionProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runAIOutputHandlingProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runAIDisclosureProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runAIToolAbuseProbe(ctx, input, bodyText)...)
	findings = append(findings, s.runAIDOSProbe(ctx, input, bodyText)...)

	emitCmd(fmt.Sprintf("chromedp navigate %s", input.Target), "Running headless browser crawl and capturing screenshot")
	browserFindings, browserEndpoints, err := headlessChecks(ctx, input.Target, input.AuthProfile, input.Options, input.Scope, input.Emit)
	if err != nil {
		findings = append(findings, model.Finding{
			ID:             "browser-error",
			Category:       "scanner",
			Severity:       model.SeverityLow,
			Title:          "Headless browser check failed",
			Description:    "The headless browser module could not complete on this target.",
			Evidence:       err.Error(),
			Recommendation: "Validate target accessibility and Chromium dependencies in the runner.",
		})
	} else {
		findings = append(findings, browserFindings...)
	}
	// Record endpoints discovered by the SPA XHR interceptor and feed them
	// back into the scan so all subsequent probes see the real API surface.
	for _, ep := range browserEndpoints {
		input.Session.AddDiscoveredEndpoint(ep)
	}
	if discovered := input.Session.DiscoveredURLs(); len(discovered) > 0 {
		for _, du := range discovered {
			alreadySeeded := false
			for _, existing := range input.Options.SeedRuntimeEndpoints {
				if existing == du {
					alreadySeeded = true
					break
				}
			}
			if !alreadySeeded {
				input.Options.SeedRuntimeEndpoints = append(input.Options.SeedRuntimeEndpoints, du)
			}
		}
	}

	// Stateful probes that require a live session (cookies/tokens already harvested).
	if !input.Options.PassiveOnly {
		findings = append(findings, s.runStoredXSSProbe(ctx, input)...)
		findings = append(findings, s.runJWTProbe(ctx, input)...)
		findings = append(findings, s.runCSRFProbe(ctx, input)...)
		findings = append(findings, s.runPasswordResetProbe(ctx, input)...)
		findings = append(findings, s.runCacheDeceptionProbe(ctx, input)...)
		findings = append(findings, s.runMFABypassProbe(ctx, input)...)
	}

	integrationFindings := s.runOptionalIntegrations(ctx, input)
	findings = append(findings, integrationFindings...)

	return findings, nil
}

func discoverRuntimeSurface(target, body string, scanScope model.ScanScope) []model.Finding {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	endpoints := extractRuntimeEndpoints(target, body, scanScope, 18)
	if len(endpoints) == 0 {
		return nil
	}

	findings := []model.Finding{
		{
			ID:             "runtime-surface-endpoints",
			Category:       "discovery",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("Runtime endpoint expansion discovered %d candidate endpoints", len(endpoints)),
			Description:    "Response content analysis discovered additional API/documentation endpoints from runtime hints (JS/OpenAPI/GraphQL-style markers).",
			Evidence:       strings.Join(endpoints, ", "),
			Recommendation: "Prioritize these discovered endpoints for authenticated authorization and input-validation testing.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      "Parse response body for endpoint markers and validate in-scope URLs",
			},
		},
	}

	lower := strings.ToLower(strings.Join(endpoints, ","))
	if strings.Contains(lower, "graphql") {
		findings = append(findings, model.Finding{
			ID:             "runtime-graphql-surface",
			Category:       "api",
			Severity:       model.SeverityInfo,
			Title:          "GraphQL surface hint detected",
			Description:    "Runtime analysis indicates GraphQL-related routes that may require schema-level auth and introspection hardening checks.",
			Evidence:       strings.Join(filterContains(endpoints, "graphql", 6), ", "),
			Recommendation: "Verify introspection policy, field-level authorization, and resolver input validation.",
		})
	}
	if strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger") || strings.Contains(lower, "api-docs") {
		findings = append(findings, model.Finding{
			ID:             "runtime-openapi-surface",
			Category:       "api",
			Severity:       model.SeverityInfo,
			Title:          "API documentation endpoint hint detected",
			Description:    "Runtime analysis indicates OpenAPI/Swagger documentation endpoints that can expand attack-surface coverage.",
			Evidence:       strings.Join(filterAnyContains(endpoints, []string{"openapi", "swagger", "api-docs"}, 6), ", "),
			Recommendation: "Enumerate documented routes and test authorization consistency across endpoints.",
		})
	}
	return findings
}

func runContextualParamProbes(ctx context.Context, target, body string, auth model.ScanAuthProfile, options model.ScanOptions, scanScope model.ScanScope, service *Service) []model.Finding {
	if options.PassiveOnly {
		return nil
	}
	candidates := extractRuntimeEndpoints(target, body, scanScope, 10)
	if len(options.SeedRuntimeEndpoints) > 0 {
		candidates = append(candidates, options.SeedRuntimeEndpoints...)
	}
	if len(candidates) == 0 {
		candidates = []string{target}
	}

	params := []string{"id", "user", "account", "q", "search", "next", "redirect", "url", "file", "path"}
	marker := "ABH_REFLECT_PROBE_7f9e2"
	reflections := make([]string, 0)
	serverErrors := make([]string, 0)

	maxAttempts := 12
	if options.GlobalScanBudget > 0 && options.GlobalScanBudget < maxAttempts {
		maxAttempts = options.GlobalScanBudget
	}
	attempts := 0
	for _, raw := range candidates {
		if attempts >= maxAttempts {
			break
		}
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		for _, p := range params {
			if attempts >= maxAttempts {
				break
			}
			probe := *u
			q := probe.Query()
			q.Set(p, marker)
			probe.RawQuery = q.Encode()
			// Rebuild the request URL from parsed fields before validating or
			// issuing the request so the safety property stays explicit at the
			// sink and remains recognisable to static taint analysis.
			safeProbeURL, err := rebuildRequestURL(probe.String())
			if err != nil {
				continue
			}
			if !scope.IsURLInScope(safeProbeURL, scanScope) {
				continue
			}
			if err := safety.ValidateOutboundURL(safeProbeURL); err != nil {
				continue
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, safeProbeURL, nil)
			ApplyAuthProfile(req, auth)
			resp, err := service.doRequestWithRetry(ctx, req, options)
			if err != nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			_ = resp.Body.Close()
			attempts++
			bodyLower := strings.ToLower(string(respBody))
			if strings.Contains(bodyLower, strings.ToLower(marker)) {
				reflections = append(reflections, probe.String())
			}
			if resp.StatusCode >= 500 {
				serverErrors = append(serverErrors, fmt.Sprintf("%s status=%d", probe.String(), resp.StatusCode))
			}
		}
	}

	findings := make([]model.Finding, 0, 2)
	if len(reflections) > 0 {
		findings = append(findings, model.Finding{
			ID:             "contextual-param-reflection",
			Category:       "input-validation",
			Severity:       model.SeverityMedium,
			Title:          "Context-aware probe found reflected parameter input",
			Description:    "Safe parameter probing observed direct reflection of probe values in responses, which can indicate weak output encoding or input handling paths.",
			Evidence:       strings.Join(limitStrings(reflections, 6), ", "),
			Recommendation: "Validate context-aware output encoding and add targeted injection testing for these reflected parameters.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      "Replay listed URL with marker payload and inspect reflected output",
			},
		})
	}
	if len(serverErrors) > 0 {
		findings = append(findings, model.Finding{
			ID:             "contextual-param-error-signal",
			Category:       "input-validation",
			Severity:       model.SeverityLow,
			Title:          "Context-aware probe triggered server error paths",
			Description:    "Safe parameter probing produced server-side errors that may indicate fragile parser/query handling in specific parameters.",
			Evidence:       strings.Join(limitStrings(serverErrors, 6), "; "),
			Recommendation: "Inspect these endpoints for robust validation and add targeted non-destructive input tests.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      "Replay listed URLs and inspect server logs/trace IDs for parsing exceptions",
			},
		})
	}
	return findings
}

func extractRuntimeEndpoints(target, body string, scanScope model.ScanScope, max int) []string {
	if max <= 0 {
		max = 12
	}
	seen := map[string]struct{}{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		resolved := resolveEndpoint(target, value)
		if resolved == "" || !scope.IsURLInScope(resolved, scanScope) {
			return
		}
		if err := safety.ValidateOutboundURL(resolved); err != nil {
			return
		}
		seen[resolved] = struct{}{}
	}

	scriptSrc := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	for _, m := range scriptSrc.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	quotedPath := regexp.MustCompile(`["'](\/(?:api|graphql|openapi|swagger|api-docs)[^"'\s]*)["']`)
	for _, m := range quotedPath.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	for _, staticPath := range []string{"/openapi.json", "/swagger.json", "/api-docs", "/graphql"} {
		add(staticPath)
	}

	out := make([]string, 0, len(seen))
	for endpoint := range seen {
		out = append(out, endpoint)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func resolveEndpoint(baseTarget, endpoint string) string {
	base, err := url.Parse(baseTarget)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	if parsed.Scheme != "" && parsed.Host != "" {
		return parsed.String()
	}
	return base.ResolveReference(parsed).String()
}

func (s *Service) runSupplementalResourceFetch(ctx context.Context, input RunInput) []model.Finding {
	urls := collectSupplementalResourceURLs(input.Target, input.Options.SupplementalResourceURLs, input.Scope, supplementalResourceFetchMaxURLs)
	if len(urls) == 0 {
		return nil
	}
	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: "supplemental-resource-fetch",
			Message: fmt.Sprintf("Fetching %d operator-specified supplemental resource(s)", len(urls)),
		})
	}

	targetHost := hostFromURL(input.Target)
	evidence := make([]string, 0, len(urls))
	skippedAuthHosts := 0

	for _, rawURL := range urls {
		// Rebuild and re-validate each URL at the request site so outbound
		// safety remains explicit even though the candidate list was already
		// filtered upstream.
		safeRawURL, err := rebuildRequestURL(rawURL)
		if err != nil {
			continue
		}
		if !scope.IsURLInScope(safeRawURL, input.Scope) {
			continue
		}
		if err := safety.ValidateOutboundURL(safeRawURL); err != nil {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, safeRawURL, nil)
		if err != nil {
			continue
		}
		rawHost := hostFromURL(safeRawURL)
		if strings.EqualFold(rawHost, targetHost) {
			ApplyAuthProfile(req, input.AuthProfile)
		} else {
			skippedAuthHosts++
		}

		resp, err := s.doRequestWithRetry(ctx, req, input.Options)
		if err != nil {
			evidence = append(evidence, fmt.Sprintf("%s error=%s", safeRawURL, strings.TrimSpace(err.Error())))
			continue
		}
		contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
		if idx := strings.Index(contentType, ";"); idx >= 0 {
			contentType = strings.TrimSpace(contentType[:idx])
		}
		if contentType == "" {
			contentType = "unknown"
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, supplementalResourceFetchMaxReadBytes))
		_ = resp.Body.Close()
		if strings.Contains(strings.ToLower(contentType), "text/html") {
			if excerpt := extractPlainTextExcerptFromHTML(string(body), supplementalResourceFetchTextExcerptMaxChars); excerpt != "" {
				evidence = append(evidence, fmt.Sprintf("%s status=%d type=%s text=%q", safeRawURL, resp.StatusCode, contentType, excerpt))
				continue
			}
		}
		evidence = append(evidence, fmt.Sprintf("%s status=%d type=%s bytes=%d", safeRawURL, resp.StatusCode, contentType, len(body)))
	}

	if len(evidence) == 0 {
		return nil
	}
	recommendation := "Keep supplemental fetch URLs constrained to assets you are explicitly authorized to assess and keep their hosts in scan scope."
	if skippedAuthHosts > 0 {
		recommendation += " Credentials were intentionally not forwarded to cross-host supplemental requests."
	}
	return []model.Finding{{
		ID:             "supplemental-resource-fetch",
		Category:       "discovery",
		Severity:       model.SeverityInfo,
		Title:          fmt.Sprintf("Fetched %d supplemental web resource(s)", len(evidence)),
		Description:    "Operator-specified supplemental resources were fetched during this scan; HTML responses are normalized into plain-text excerpts for training context.",
		Evidence:       strings.Join(limitStrings(evidence, supplementalResourceFetchMaxURLs), "; "),
		Recommendation: recommendation,
		EvidenceFields: map[string]string{
			"validationType": "safe-observation",
			"reproStep":      "Issue GET requests to each supplementalResourceUrls entry and record status/content type",
		},
	}}
}

func extractPlainTextExcerptFromHTML(html string, max int) string {
	if max <= 0 {
		max = supplementalResourceFetchTextExcerptMaxChars
	}
	text := strings.TrimSpace(html)
	if text == "" {
		return ""
	}
	text = htmlScriptStyleRe.ReplaceAllString(text, " ")
	text = htmlTagRe.ReplaceAllString(text, " ")
	text = htmlWhitespaceRe.ReplaceAllString(text, " ")
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	runes := []rune(text)
	if len(runes) > max {
		return strings.TrimSpace(string(runes[:max])) + "…"
	}
	return text
}

func collectSupplementalResourceURLs(target string, candidates []string, scanScope model.ScanScope, max int) []string {
	if max <= 0 {
		max = supplementalResourceFetchMaxURLs
	}
	if len(candidates) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		resolved := resolveEndpoint(target, candidate)
		if resolved == "" {
			continue
		}
		if !scope.IsURLInScope(resolved, scanScope) {
			continue
		}
		if err := safety.ValidateOutboundURL(resolved); err != nil {
			continue
		}
		if _, exists := seen[resolved]; exists {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func rebuildRequestURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid request url")
	}
	safe := url.URL{
		Scheme:   strings.ToLower(parsed.Scheme),
		User:     parsed.User,
		Host:     parsed.Host,
		Path:     parsed.Path,
		RawPath:  parsed.RawPath,
		RawQuery: parsed.RawQuery,
	}
	return safe.String(), nil
}

func filterContains(items []string, keyword string, max int) []string {
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item), keyword) {
			out = append(out, item)
		}
	}
	if len(out) > max {
		return out[:max]
	}
	return out
}

func filterAnyContains(items []string, keywords []string, max int) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		lower := strings.ToLower(item)
		for _, keyword := range keywords {
			if strings.Contains(lower, strings.ToLower(strings.TrimSpace(keyword))) {
				out = append(out, item)
				break
			}
		}
	}
	if len(out) > max {
		return out[:max]
	}
	return out
}

// resolveProxyForOptions returns the proxy configuration in effect for the
// given per-scan options. When ScanOptions overrides the service-level
// proxy, the second return value is a one-shot transport built from the
// override (callers must wrap their client with it). It returns nil when
// the override matches the service-level configuration, so the existing
// session.client / s.httpClient transport (already proxy-aware) is reused.
func (s *Service) resolveProxyForOptions(opts model.ScanOptions) (ProxyConfig, http.RoundTripper) {
	// Compute the desired configuration: per-scan UseProxy/ProxyURL win
	// over service-level defaults when provided.
	desired := s.scannerProxy
	if opts.UseProxy != nil {
		desired.Enabled = *opts.UseProxy
	}
	if strings.TrimSpace(opts.ProxyURL) != "" {
		desired.URL = strings.TrimSpace(opts.ProxyURL)
	}
	// Did anything actually change vs the service default?
	if desired.Enabled == s.scannerProxy.Enabled &&
		desired.URL == s.scannerProxy.URL &&
		desired.CAFile == s.scannerProxy.CAFile &&
		desired.InsecureSkipVerify == s.scannerProxy.InsecureSkipVerify {
		return desired, nil
	}
	// Build a one-shot override transport. On error we silently fall back
	// to the service-level transport so a bad per-scan URL can't break the
	// scan; callers can observe the malformed URL via standard logs.
	rt, err := buildTransport(desired)
	if err != nil {
		return s.scannerProxy, nil
	}
	return desired, rt
}

// doRequestWithSession executes req with retry logic, using the session's
// HTTP client and token-injection when sess is non-nil. It falls back to
// s.httpClient when sess is nil, preserving backward compatibility with all
// existing callers of doRequestWithRetry.
func (s *Service) doRequestWithSession(ctx context.Context, req *http.Request, options model.ScanOptions, sess *ScanSession) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	client := s.httpClient
	if sess != nil {
		client = sess.Client()
	}
	// Determine the effective scanner-proxy configuration for this request.
	// Per-scan options may override the service-level defaults.
	effectiveProxy, perScanTransport := s.resolveProxyForOptions(options)
	// When a per-scan override changes the upstream proxy, wrap the client
	// with a one-shot transport so the override is honoured without
	// mutating the shared session/service client.
	if perScanTransport != nil {
		wrapped := *client // shallow copy — shares the cookie Jar
		wrapped.Transport = perScanTransport
		client = &wrapped
	}
	// Wrap the client with a recording transport when a proxy store is
	// configured so that all scanner-initiated requests appear in the
	// Network Graph UI (GET /api/proxy/requests). Skip the wrap when the
	// effective upstream proxy IS the bundled in-process proxy, because in
	// that case the same request would be captured twice (once here and
	// once when the proxy itself records the proxied roundtrip).
	if s.proxyStore != nil && !effectiveProxy.IsBundledLocal(s.bundledProxyPort) {
		wrapped := *client // shallow copy — shares the cookie Jar
		base := wrapped.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		wrapped.Transport = &proxy.RecordingTransport{Wrapped: base, Store: s.proxyStore}
		client = &wrapped
	}
	maxRetries := s.cfg.DefaultMaxRetries
	if options.MaxRetries > 0 {
		maxRetries = options.MaxRetries
	}
	backoff := s.cfg.DefaultBackoff
	if options.BackoffMillis > 0 {
		backoff = time.Duration(options.BackoffMillis) * time.Millisecond
	}

	// Buffer the request body once so each retry can rewind it. Without
	// this, req.Clone() shares the original body reader, which is drained
	// after the first attempt and produces empty-body POSTs on retries.
	var bodyBytes []byte
	if req.Body != nil && req.GetBody == nil {
		b, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		bodyBytes = b
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		req.ContentLength = int64(len(bodyBytes))
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		cloned := req.Clone(ctx)
		// Refresh the cloned body so retried POST/PUT requests send the
		// full payload instead of the already-drained reader from the
		// previous attempt.
		if req.GetBody != nil {
			if body, err := req.GetBody(); err == nil {
				cloned.Body = body
			}
		}
		// Inject CSRF/bearer tokens harvested earlier in this scan. The
		// session cookie jar handles Cookie headers automatically.
		if sess != nil {
			sess.InjectIntoRequest(cloned)
		}
		metrics.OutboundProbeRequests.Inc()
		resp, err := client.Do(cloned)
		if err == nil && !isRetriableStatus(resp.StatusCode) {
			// Harvest any authentication tokens present in response headers.
			if sess != nil {
				sess.HarvestFromResponse(resp, nil)
			}
			return resp, nil
		}
		var retryAfter time.Duration
		if err == nil && resp != nil {
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("retriable response status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if attempt == maxRetries {
			break
		}
		wait := backoff * time.Duration(attempt+1)
		if retryAfter > wait {
			if retryAfter > 30*time.Second {
				retryAfter = 30 * time.Second
			}
			wait = retryAfter
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, lastErr
}

func (s *Service) doRequestWithRetry(ctx context.Context, req *http.Request, options model.ScanOptions) (*http.Response, error) {
	return s.doRequestWithSession(ctx, req, options, nil)
}

// parseRetryAfter parses the value of an HTTP Retry-After header. RFC 9110
// allows two forms: "delay-seconds" (e.g. `Retry-After: 120`) and an
// HTTP-date (e.g. `Retry-After: Fri, 31 Dec 2027 23:59:59 GMT`). Returns
// zero when the value is empty or unparseable.
func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}

func isRetriableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusBadGateway || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}

func ApplyAuthProfile(req *http.Request, profile model.ScanAuthProfile) {
	if req == nil {
		return
	}
	for key, value := range profile.Headers {
		if strings.TrimSpace(key) != "" {
			req.Header.Set(key, value)
		}
	}
	if profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}
	if profile.BasicAuthUsername != "" || profile.BasicAuthPassword != "" {
		req.SetBasicAuth(profile.BasicAuthUsername, profile.BasicAuthPassword)
	}
	if len(profile.Cookies) > 0 {
		names := make([]string, 0, len(profile.Cookies))
		for name := range profile.Cookies {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, name+"="+profile.Cookies[name])
		}
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
}

func checkSecurityHeaders(h http.Header) []model.Finding {
	required := map[string]string{
		"Content-Security-Policy": "Define a strict CSP to reduce script injection risk.",
		"X-Frame-Options":         "Set DENY or SAMEORIGIN to prevent clickjacking.",
		"X-Content-Type-Options":  "Set nosniff to prevent MIME sniffing.",
		"Referrer-Policy":         "Set a restrictive referrer policy.",
	}

	findings := make([]model.Finding, 0, len(required))
	for header, rec := range required {
		if strings.TrimSpace(h.Get(header)) == "" {
			findings = append(findings, model.Finding{
				ID:             "missing-header-" + strings.ToLower(strings.ReplaceAll(header, "-", "_")),
				Category:       "headers",
				Severity:       model.SeverityMedium,
				Title:          "Missing security header: " + header,
				Description:    "The response is missing a commonly recommended security header.",
				Evidence:       header + " not present",
				Recommendation: rec,
				EvidenceFields: map[string]string{
					"validationType": "safe-observation",
					"reproStep":      "GET / and inspect response headers",
				},
			})
		}
	}
	return findings
}

func checkCookies(resp *http.Response) []model.Finding {
	findings := []model.Finding{}
	for _, c := range resp.Cookies() {
		if !c.HttpOnly {
			findings = append(findings, model.Finding{
				ID:             "cookie-httponly-" + c.Name,
				Category:       "cookies",
				Severity:       model.SeverityMedium,
				Title:          "Cookie missing HttpOnly",
				Description:    "A cookie was observed without HttpOnly.",
				Evidence:       c.Name,
				Recommendation: "Set HttpOnly for session/auth cookies.",
				EvidenceFields: map[string]string{
					"validationType": "safe-observation",
					"reproStep":      "GET / and inspect Set-Cookie attributes",
				},
			})
		}
		if !c.Secure && resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme == "https" {
			findings = append(findings, model.Finding{
				ID:             "cookie-secure-" + c.Name,
				Category:       "cookies",
				Severity:       model.SeverityMedium,
				Title:          "Cookie missing Secure",
				Description:    "A cookie was observed without Secure on an HTTPS target.",
				Evidence:       c.Name,
				Recommendation: "Set Secure for sensitive cookies.",
				EvidenceFields: map[string]string{
					"validationType": "safe-observation",
					"reproStep":      "GET HTTPS endpoint and inspect Set-Cookie attributes",
				},
			})
		}
	}
	return findings
}

func checkTLS(host string) []model.Finding {
	findings := []model.Finding{}
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":443"
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12})
	if err != nil {
		findings = append(findings, model.Finding{
			ID:             "tls-connectivity",
			Category:       "tls",
			Severity:       model.SeverityMedium,
			Title:          "TLS handshake issue",
			Description:    "Could not complete TLS handshake with minimum TLS 1.2.",
			Evidence:       err.Error(),
			Recommendation: "Ensure valid certificates and modern TLS configuration.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      "openssl s_client -connect " + addr + " -tls1_2",
			},
		})
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, model.Finding{
			ID:             "tls-legacy-version",
			Category:       "tls",
			Severity:       model.SeverityHigh,
			Title:          "Legacy TLS version negotiated",
			Description:    "The endpoint negotiated an outdated TLS version.",
			Evidence:       fmt.Sprintf("tlsVersion=%x", state.Version),
			Recommendation: "Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      "Check negotiated TLS version against policy",
			},
		})
	}

	if len(state.PeerCertificates) > 0 {
		notAfter := state.PeerCertificates[0].NotAfter
		if time.Until(notAfter) < (14 * 24 * time.Hour) {
			findings = append(findings, model.Finding{
				ID:             "tls-cert-expiring",
				Category:       "tls",
				Severity:       model.SeverityLow,
				Title:          "Certificate expiring soon",
				Description:    "Leaf certificate is close to expiration.",
				Evidence:       notAfter.UTC().Format(time.RFC3339),
				Recommendation: "Rotate certificate before expiration to avoid outages.",
				EvidenceFields: map[string]string{
					"validationType":  "safe-observation",
					"reproStep":       "Inspect leaf certificate NotAfter",
					"daysUntilExpiry": strconv.Itoa(int(time.Until(notAfter).Hours() / 24)),
				},
			})
		}
	}

	return findings
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
