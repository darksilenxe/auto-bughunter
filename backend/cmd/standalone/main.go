package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/api"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/storage"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "abh:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	quiet, args := consumeQuietFlag(args)
	if len(args) == 0 || normalizeHelpArg(args[0]) == "help" {
		printMainUsage(stdout)
		return nil
	}
	switch normalizeHelpArg(args[0]) {
	case "scan", "tools":
	default:
		printMainUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}

	srv, restoreEnv, err := startStandaloneServer(stderr, quiet)
	if err != nil {
		return err
	}
	defer restoreEnv()
	defer srv.close()

	cfg := defaultEmbeddedClientConfig(srv.baseURL, srv.apiKey)
	return runCommand(args, cfg, stdout, stderr)
}

type standaloneServer struct {
	baseURL    string
	apiKey     string
	httpServer *http.Server
}

func startStandaloneServer(stderr io.Writer, quiet bool) (*standaloneServer, func(), error) {
	listener, baseURL, err := openStandaloneListener()
	if err != nil {
		return nil, func() {}, err
	}

	key, err := generateEphemeralAPIKey()
	if err != nil {
		_ = listener.Close()
		return nil, func() {}, err
	}
	restoreEnv := setEnvForLifetime("BOOTSTRAP_ADMIN_API_KEY", key)

	repo := storage.NewMemoryStore()
	proxyStore := proxy.NewMemStore()
	scanService := scanner.NewService(scanner.Config{
		EnableSubfinder:    getbool("ENABLE_SUBFINDER_INTEGRATION", false),
		EnableHttpx:        getbool("ENABLE_HTTPX_INTEGRATION", false),
		EnableCloudlist:    getbool("ENABLE_CLOUDLIST_INTEGRATION", false),
		EnableVulnx:        getbool("ENABLE_VULNX_INTEGRATION", false),
		EnableNaabu:        getbool("ENABLE_NAABU_INTEGRATION", false),
		EnableDnsx:         getbool("ENABLE_DNSX_INTEGRATION", false),
		EnableShuffleDNS:   getbool("ENABLE_SHUFFLEDNS_INTEGRATION", false),
		EnableCertTrans:    getbool("ENABLE_CERTIFICATE_TRANSPARENCY_INTEGRATION", false),
		EnableAmass:        getbool("ENABLE_AMASS_INTEGRATION", false),
		EnableKatana:       getbool("ENABLE_KATANA_INTEGRATION", false),
		EnableTlsx:         getbool("ENABLE_TLSX_INTEGRATION", false),
		EnableCdncheck:     getbool("ENABLE_CDNCHECK_INTEGRATION", false),
		EnableAsnmap:       getbool("ENABLE_ASNMAP_INTEGRATION", false),
		EnableNikto:        getbool("ENABLE_NIKTO_INTEGRATION", false),
		EnableWPScan:       getbool("ENABLE_WPSCAN_INTEGRATION", false),
		EnableSQLMap:       getbool("ENABLE_SQLMAP_INTEGRATION", false),
		EnableFFUF:         getbool("ENABLE_FFUF_INTEGRATION", false),
		EnableGobuster:     getbool("ENABLE_GOBUSTER_INTEGRATION", false),
		AllowDestructive:   getbool("ALLOW_DESTRUCTIVE_CHECKS", false),
		NucleiBinary:       getenv("NUCLEI_BINARY", "nuclei"),
		ZAPBaselineBinary:  getenv("ZAP_BASELINE_BINARY", "zap-baseline.py"),
		XSSMapBinary:       getenv("XSSMAP_BINARY", "xssmap"),
		SubfinderBinary:    getenv("SUBFINDER_BINARY", "subfinder"),
		HttpxBinary:        getenv("HTTPX_BINARY", "httpx"),
		CloudlistBinary:    getenv("CLOUDLIST_BINARY", "cloudlist"),
		VulnxBinary:        getenv("VULNX_BINARY", "vulnx"),
		NaabuBinary:        getenv("NAABU_BINARY", "naabu"),
		DnsxBinary:         getenv("DNSX_BINARY", "dnsx"),
		ShuffleDNSBinary:   getenv("SHUFFLEDNS_BINARY", "shuffledns"),
		KatanaBinary:       getenv("KATANA_BINARY", "katana"),
		TlsxBinary:         getenv("TLSX_BINARY", "tlsx"),
		CdncheckBinary:     getenv("CDNCHECK_BINARY", "cdncheck"),
		AsnmapBinary:       getenv("ASNMAP_BINARY", "asnmap"),
		FFUFBinary:         getenv("FFUF_BINARY", "ffuf"),
		GobusterBinary:     getenv("GOBUSTER_BINARY", "gobuster"),
		IntegrationTimeout: time.Duration(getint("INTEGRATION_TIMEOUT_SECONDS", 90)) * time.Second,
		DefaultMaxRetries:  getint("DEFAULT_MAX_RETRIES", 1),
		DefaultBackoff:     time.Duration(getint("DEFAULT_BACKOFF_MILLIS", 400)) * time.Millisecond,
	})
	server := api.NewServer(
		scanService,
		nil,
		nil,
		nil,
		nil,
		repo,
		proxyStore,
		getint("MAX_PER_TARGET_CONCURRENCY", 3),
		getint("GLOBAL_SCAN_BUDGET", 5),
		api.AgentConfig{},
		time.Duration(getint("SCAN_TIMEOUT_SECONDS", 600))*time.Second,
	)

	httpServer := &http.Server{
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = httpServer.Serve(listener)
	}()

	if err := waitForHealth(baseURL, key); err != nil {
		restoreEnv()
		_ = httpServer.Shutdown(context.Background())
		_ = listener.Close()
		return nil, func() {}, err
	}
	if !quiet {
		fmt.Fprintf(stderr, "embedded backend: %s\n", baseURL)
	}
	return &standaloneServer{
		baseURL:    baseURL,
		apiKey:     key,
		httpServer: httpServer,
	}, restoreEnv, nil
}

func (s *standaloneServer) close() {
	if s == nil || s.httpServer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.httpServer.Shutdown(ctx)
}

func openStandaloneListener() (net.Listener, string, error) {
	port := strings.TrimSpace(os.Getenv("STANDALONE_PORT"))
	addr := "127.0.0.1:0"
	if port != "" {
		addr = "127.0.0.1:" + port
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}
	return listener, "http://" + listener.Addr().String(), nil
}

// generateEphemeralAPIKey returns an in-process bootstrap token in the same
// abh_<48 hex chars> format used elsewhere in the backend, giving 24 bytes of
// randomness for the temporary embedded server lifetime.
func generateEphemeralAPIKey() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "abh_" + hex.EncodeToString(buf), nil
}

func setEnvForLifetime(key, value string) func() {
	old, had := os.LookupEnv(key)
	_ = os.Setenv(key, value)
	return func() {
		if had {
			_ = os.Setenv(key, old)
			return
		}
		_ = os.Unsetenv(key)
	}
}

func waitForHealth(baseURL, apiKey string) error {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, reqErr := http.NewRequest(http.MethodGet, baseURL+"/api/health", nil)
		if reqErr != nil {
			return reqErr
		}
		if strings.TrimSpace(apiKey) != "" {
			req.Header.Set("X-API-Key", apiKey)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("wait for embedded backend: %w", err)
			}
			return fmt.Errorf("wait for embedded backend: health returned non-2xx")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type clientConfig struct {
	baseURL     string
	apiKey      string
	workspaceID string
	timeout     time.Duration
}

type httpClient struct {
	baseURL     string
	apiKey      string
	workspaceID string
	client      *http.Client
}

type httpError struct {
	StatusCode int
	Message    string
	Body       []byte
}

func (e *httpError) Error() string {
	if e == nil {
		return ""
	}
	if e.StatusCode <= 0 {
		return e.Message
	}
	if strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("request failed with HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("request failed with HTTP %d", e.StatusCode)
}

func newHTTPClient(cfg clientConfig) *httpClient {
	timeout := cfg.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &httpClient{
		baseURL:     strings.TrimRight(strings.TrimSpace(cfg.baseURL), "/"),
		apiKey:      strings.TrimSpace(cfg.apiKey),
		workspaceID: strings.TrimSpace(cfg.workspaceID),
		client:      &http.Client{Timeout: timeout},
	}
}

func (c *httpClient) get(ctx context.Context, path string, query map[string]string) ([]byte, error) {
	u, err := c.buildURL(path, query)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *httpClient) postJSON(ctx context.Context, path string, body []byte) ([]byte, error) {
	u, err := c.buildURL(path, nil)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *httpClient) buildURL(path string, query map[string]string) (string, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL %q: %w", c.baseURL, err)
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("invalid path %q: %w", path, err)
	}
	finalURL := base.ResolveReference(rel)
	values := finalURL.Query()
	for key, value := range query {
		values.Set(key, value)
	}
	finalURL.RawQuery = values.Encode()
	return finalURL.String(), nil
}

func (c *httpClient) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.workspaceID != "" {
		req.Header.Set("X-Workspace-ID", c.workspaceID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, &httpError{StatusCode: resp.StatusCode, Message: responseMessage(body), Body: body}
	}
	return body, nil
}

func responseMessage(body []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"error", "detail", "message"} {
			if value := strings.TrimSpace(fmt.Sprint(payload[key])); value != "" && value != "<nil>" {
				return value
			}
		}
	}
	return strings.TrimSpace(string(body))
}

func runCommand(args []string, cfg clientConfig, stdout, stderr io.Writer) error {
	switch normalizeHelpArg(args[0]) {
	case "scan":
		return runScan(args[1:], cfg, stdout, stderr)
	case "tools":
		return runTools(args[1:], cfg, stdout, stderr)
	default:
		printMainUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runTools(args []string, cfg clientConfig, stdout, stderr io.Writer) error {
	if len(args) == 0 || normalizeHelpArg(args[0]) == "help" {
		printToolsUsage(stderr)
		return nil
	}
	switch args[0] {
	case "health":
		return runToolsHealth(args[1:], cfg, stdout, stderr)
	case "updates":
		return runToolsUpdates(args[1:], cfg, stdout, stderr)
	default:
		printToolsUsage(stderr)
		return fmt.Errorf("unknown tools command %q", args[0])
	}
}

func runToolsHealth(args []string, cfg clientConfig, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tools health", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "json", "output format: json|text")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := newHTTPClient(cfg).get(context.Background(), "/api/tools/health", nil)
	if err != nil {
		return err
	}
	return writeCommandOutput(stdout, *format, body, writeToolsHealthText)
}

func runToolsUpdates(args []string, cfg clientConfig, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tools updates", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "json", "output format: json|text")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := newHTTPClient(cfg).get(context.Background(), "/api/tools/updates", nil)
	if err != nil {
		return err
	}
	return writeCommandOutput(stdout, *format, body, writeToolsUpdatesText)
}

func runScan(args []string, cfg clientConfig, stdout, stderr io.Writer) error {
	if len(args) == 0 || normalizeHelpArg(args[0]) == "help" {
		printScanUsage(stderr)
		return nil
	}
	switch args[0] {
	case "start":
		return runScanStart(args[1:], cfg, stdout, stderr)
	case "get":
		return runScanGet(args[1:], cfg, stdout, stderr)
	case "run":
		return runScanRun(args[1:], cfg, stdout, stderr)
	default:
		printScanUsage(stderr)
		return fmt.Errorf("unknown scan command %q", args[0])
	}
}

func runScanStart(args []string, cfg clientConfig, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "json", "output format: json|text")
	inputPath := fs.String("input", "", "JSON file containing a scan request (use '-' for stdin)")
	target := fs.String("target", "", "target URL to scan")
	idempotencyKey := fs.String("idempotency-key", "", "optional idempotency key")
	automationMode := fs.String("automation-mode", "", "optional automation mode override")
	passiveOnly := fs.Bool("passive-only", false, "enable passive-only scan mode")
	aggressive := fs.Bool("aggressive-exploitation", false, "enable aggressive exploitation mode")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := buildScanRequestBody(*inputPath, *target, *idempotencyKey, *automationMode, *passiveOnly, *aggressive)
	if err != nil {
		return err
	}
	resp, err := newHTTPClient(cfg).postJSON(context.Background(), "/api/scan", body)
	if err != nil {
		return err
	}
	return writeCommandOutput(stdout, *format, resp, writeScanCreateText)
}

func runScanGet(args []string, cfg clientConfig, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan get", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "json", "output format: json|text")
	id := fs.String("id", "", "scan ID")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return fmt.Errorf("-id is required")
	}
	resp, err := newHTTPClient(cfg).get(context.Background(), "/api/scan/"+url.PathEscape(strings.TrimSpace(*id)), nil)
	if err != nil {
		return err
	}
	return writeCommandOutput(stdout, *format, resp, writeScanJobText)
}

func runScanRun(args []string, cfg clientConfig, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "json", "output format: json|text")
	inputPath := fs.String("input", "", "JSON file containing a scan request (use '-' for stdin)")
	target := fs.String("target", "", "target URL to scan")
	idempotencyKey := fs.String("idempotency-key", "", "optional idempotency key")
	automationMode := fs.String("automation-mode", "", "optional automation mode override")
	passiveOnly := fs.Bool("passive-only", false, "enable passive-only scan mode")
	aggressive := fs.Bool("aggressive-exploitation", false, "enable aggressive exploitation mode")
	pollInterval := fs.Duration("poll-interval", 5*time.Second, "poll interval while waiting for completion")
	waitTimeout := fs.Duration("wait-timeout", 30*time.Minute, "maximum time to wait for scan completion")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := buildScanRequestBody(*inputPath, *target, *idempotencyKey, *automationMode, *passiveOnly, *aggressive)
	if err != nil {
		return err
	}
	client := newHTTPClient(cfg)
	startResp, err := client.postJSON(context.Background(), "/api/scan", body)
	if err != nil {
		return err
	}
	started, err := parseScanCreateResponse(startResp)
	if err != nil {
		return err
	}
	finalResp, err := waitForScanCompletion(context.Background(), client, started.ID, *pollInterval, *waitTimeout)
	if err != nil {
		return err
	}
	if err := writeCommandOutput(stdout, *format, finalResp, writeScanJobText); err != nil {
		return err
	}
	finalJob, err := parseScanJobResponse(finalResp)
	if err != nil {
		return err
	}
	switch finalJob.Status {
	case "completed":
		return nil
	case "failed", "cancelled":
		if strings.TrimSpace(finalJob.Error) != "" {
			return fmt.Errorf("scan %s %s: %s", finalJob.ID, finalJob.Status, finalJob.Error)
		}
		return fmt.Errorf("scan %s %s", finalJob.ID, finalJob.Status)
	default:
		return fmt.Errorf("scan %s ended in unexpected status %q", finalJob.ID, finalJob.Status)
	}
}

func buildScanRequestBody(inputPath, target, idempotencyKey, automationMode string, passiveOnly, aggressive bool) ([]byte, error) {
	var req model.ScanRequest
	if strings.TrimSpace(inputPath) != "" {
		input, err := readInput(inputPath)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(input, &req); err != nil {
			return nil, fmt.Errorf("invalid scan request JSON: %w", err)
		}
	}
	if trimmed := strings.TrimSpace(target); trimmed != "" {
		req.Target = trimmed
	}
	if trimmed := strings.TrimSpace(idempotencyKey); trimmed != "" {
		req.IdempotencyKey = trimmed
	}
	if trimmed := strings.TrimSpace(automationMode); trimmed != "" {
		req.Options.AutomationMode = trimmed
	}
	if passiveOnly {
		req.Options.PassiveOnly = true
	}
	if aggressive {
		req.Options.AggressiveExploitation = true
	}
	if strings.TrimSpace(req.Target) == "" {
		return nil, fmt.Errorf("scan target is required (set -target or provide target in -input)")
	}
	return json.Marshal(req)
}

func waitForScanCompletion(ctx context.Context, client *httpClient, scanID string, pollInterval, waitTimeout time.Duration) ([]byte, error) {
	if strings.TrimSpace(scanID) == "" {
		return nil, fmt.Errorf("scan ID is required")
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	deadline := time.Time{}
	if waitTimeout > 0 {
		deadline = time.Now().Add(waitTimeout)
	}
	for {
		resp, err := client.get(ctx, "/api/scan/"+url.PathEscape(strings.TrimSpace(scanID)), nil)
		if err != nil {
			return nil, err
		}
		job, err := parseScanJobResponse(resp)
		if err != nil {
			return nil, err
		}
		if isTerminalScanStatus(job.Status) {
			return resp, nil
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, fmt.Errorf("timed out waiting for scan %s after %s", scanID, waitTimeout)
		}
		sleepFor := pollInterval
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, fmt.Errorf("timed out waiting for scan %s after %s", scanID, waitTimeout)
			}
			if sleepFor > remaining {
				sleepFor = remaining
			}
		}
		timer := time.NewTimer(sleepFor)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func isTerminalScanStatus(status string) bool {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "completed", "failed", "cancelled":
		return true
	default:
		return false
	}
}

type toolsHealthResponse struct {
	CheckedAt string           `json:"checkedAt"`
	Tools     []toolHealthItem `json:"tools"`
}

type toolHealthItem struct {
	Name      string `json:"name"`
	Binary    string `json:"binary"`
	Installed bool   `json:"installed"`
	Category  string `json:"category"`
}

type scanCreateResponse struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Deduplicated string `json:"deduplicated,omitempty"`
}

type scanJobResponse struct {
	ID          string        `json:"id"`
	Target      string        `json:"target"`
	Status      string        `json:"status"`
	Error       string        `json:"error,omitempty"`
	Findings    []scanFinding `json:"findings,omitempty"`
	CompletedAt string        `json:"completedAt,omitempty"`
}

type scanFinding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Title    string `json:"title"`
}

func writeToolsHealthText(w io.Writer, raw []byte) error {
	var resp toolsHealthResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	installed := 0
	for _, tool := range resp.Tools {
		if tool.Installed {
			installed++
		}
	}
	fmt.Fprintf(w, "Tool health at %s: %d/%d installed\n", strings.TrimSpace(resp.CheckedAt), installed, len(resp.Tools))
	for _, tool := range resp.Tools {
		status := "missing"
		if tool.Installed {
			status = "installed"
		}
		fmt.Fprintf(w, "- %s [%s] %s (%s)\n", tool.Name, tool.Category, status, tool.Binary)
	}
	return nil
}

func writeToolsUpdatesText(w io.Writer, raw []byte) error {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	fmt.Fprintf(w, "Tool updates report generated at %s\n", strings.TrimSpace(fmt.Sprint(payload["generatedAt"])))
	if summary, ok := payload["summary"].(map[string]any); ok && len(summary) > 0 {
		fmt.Fprintln(w, "Summary:")
		for _, key := range []string{"current", "outdated", "failed"} {
			if value, ok := summary[key]; ok {
				fmt.Fprintf(w, "- %s: %v\n", key, value)
			}
		}
	}
	if tools, ok := payload["tools"].([]any); ok && len(tools) > 0 {
		fmt.Fprintln(w, "Tools:")
		for _, entry := range tools {
			tool, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			line := fmt.Sprintf("- %s: %v", strings.TrimSpace(fmt.Sprint(tool["name"])), tool["status"])
			if current := strings.TrimSpace(fmt.Sprint(tool["currentVersion"])); current != "" && current != "<nil>" {
				line += fmt.Sprintf(" current=%s", current)
			}
			if latest := strings.TrimSpace(fmt.Sprint(tool["latestVersion"])); latest != "" && latest != "<nil>" {
				line += fmt.Sprintf(" latest=%s", latest)
			}
			fmt.Fprintln(w, line)
		}
	}
	return nil
}

func writeScanCreateText(w io.Writer, raw []byte) error {
	resp, err := parseScanCreateResponse(raw)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("Queued scan %s (status=%s)", strings.TrimSpace(resp.ID), strings.TrimSpace(resp.Status))
	if strings.EqualFold(strings.TrimSpace(resp.Deduplicated), "true") {
		line += " [deduplicated]"
	}
	_, err = fmt.Fprintln(w, line)
	return err
}

func writeScanJobText(w io.Writer, raw []byte) error {
	resp, err := parseScanJobResponse(raw)
	if err != nil {
		return err
	}
	counts := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
	for _, finding := range resp.Findings {
		counts[strings.ToLower(strings.TrimSpace(finding.Severity))]++
	}
	if _, err := fmt.Fprintf(w, "Scan %s for %s: %s\n", strings.TrimSpace(resp.ID), strings.TrimSpace(resp.Target), strings.TrimSpace(resp.Status)); err != nil {
		return err
	}
	if strings.TrimSpace(resp.CompletedAt) != "" {
		if _, err := fmt.Fprintf(w, "Completed: %s\n", strings.TrimSpace(resp.CompletedAt)); err != nil {
			return err
		}
	}
	if strings.TrimSpace(resp.Error) != "" {
		if _, err := fmt.Fprintf(w, "Error: %s\n", strings.TrimSpace(resp.Error)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "Findings: %d (high=%d medium=%d low=%d info=%d)\n", len(resp.Findings), counts["high"], counts["medium"], counts["low"], counts["info"]); err != nil {
		return err
	}
	for idx, finding := range resp.Findings {
		if _, err := fmt.Fprintf(w, "%d. [%s] %s - %s\n", idx+1, strings.TrimSpace(finding.Severity), strings.TrimSpace(finding.Category), strings.TrimSpace(finding.Title)); err != nil {
			return err
		}
	}
	return nil
}

func parseScanCreateResponse(raw []byte) (scanCreateResponse, error) {
	var resp scanCreateResponse
	return resp, json.Unmarshal(raw, &resp)
}

func parseScanJobResponse(raw []byte) (scanJobResponse, error) {
	var resp scanJobResponse
	return resp, json.Unmarshal(raw, &resp)
}

func writeCommandOutput(stdout io.Writer, format string, raw []byte, textWriter func(io.Writer, []byte) error) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return writePrettyJSON(stdout, raw)
	case "text":
		return textWriter(stdout, raw)
	default:
		return fmt.Errorf("unsupported format %q (expected json or text)", format)
	}
}

func writePrettyJSON(stdout io.Writer, raw []byte) error {
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return fmt.Errorf("response was not valid JSON: %w", err)
	}
	out.WriteByte('\n')
	_, err := stdout.Write(out.Bytes())
	return err
}

func readInput(path string) ([]byte, error) {
	switch strings.TrimSpace(path) {
	case "":
		return nil, fmt.Errorf("input path is required")
	case "-":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return nil, fmt.Errorf("stdin was empty")
		}
		return data, nil
	default:
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return nil, fmt.Errorf("%s was empty", path)
		}
		return data, nil
	}
}

func defaultEmbeddedClientConfig(baseURL, apiKey string) clientConfig {
	return clientConfig{
		baseURL:     baseURL,
		apiKey:      apiKey,
		workspaceID: strings.TrimSpace(os.Getenv("AUTOBUGHUNTER_WORKSPACE_ID")),
		timeout:     30 * time.Second,
	}
}

func consumeQuietFlag(args []string) (bool, []string) {
	if len(args) == 0 {
		return false, args
	}
	switch strings.TrimSpace(strings.ToLower(args[0])) {
	case "-quiet", "--quiet":
		return true, args[1:]
	default:
		return false, args
	}
}

func normalizeHelpArg(arg string) string {
	switch strings.TrimSpace(strings.ToLower(arg)) {
	case "-h", "--help", "help":
		return "help"
	default:
		return strings.TrimSpace(strings.ToLower(arg))
	}
}

func printMainUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  abh [-quiet] scan <start|get|run> [flags]
  abh [-quiet] tools <health|updates> [flags]

Environment:
  STANDALONE_PORT                Optional fixed local port for the embedded backend
  AUTOBUGHUNTER_WORKSPACE_ID     Optional backend workspace ID header`)
}

func printToolsUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  abh tools health [flags]
  abh tools updates [flags]

Flags:
  -format <json|text>            Output format
  -timeout <duration>            Request timeout`)
}

func printScanUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  abh scan start -target <url> [flags]
  abh scan start -input <request.json|-> [flags]
  abh scan get -id <scan-id> [flags]
  abh scan run -target <url> [flags]
  abh scan run -input <request.json|-> [flags]

Flags:
  -input <file|->                Full scan request JSON
  -target <url>                  Target URL override
  -idempotency-key <key>         Optional idempotency key
  -automation-mode <mode>        Optional automation mode override
  -passive-only                  Enable passive-only scan mode
  -aggressive-exploitation       Enable deeper exploitation paths
  -format <json|text>            Output format
  -timeout <duration>            Request timeout

scan run flags:
  -poll-interval <duration>      Poll interval while waiting (default 5s)
  -wait-timeout <duration>       Max wait time (default 30m)`)
}

func getenv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func getbool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func getint(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return parsed
}
