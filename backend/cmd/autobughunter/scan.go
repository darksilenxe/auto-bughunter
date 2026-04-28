package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

func runScan(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || normalizeHelpArg(args[0]) == "help" {
		printScanUsage(stderr)
		return nil
	}
	switch args[0] {
	case "start":
		return runScanStart(args[1:], stdout, stderr)
	case "get":
		return runScanGet(args[1:], stdout, stderr)
	case "run":
		return runScanRun(args[1:], stdout, stderr)
	default:
		printScanUsage(stderr)
		return fmt.Errorf("unknown scan command %q", args[0])
	}
}

func runScanStart(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan start", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := defaultBackendClientConfig()
	format := fs.String("format", "json", "output format: json|text")
	inputPath := fs.String("input", "", "JSON file containing a scan request (use '-' for stdin)")
	target := fs.String("target", "", "target URL to scan")
	idempotencyKey := fs.String("idempotency-key", "", "optional idempotency key")
	automationMode := fs.String("automation-mode", "", "optional automation mode override")
	passiveOnly := fs.Bool("passive-only", false, "enable passive-only scan mode")
	aggressive := fs.Bool("aggressive-exploitation", false, "enable aggressive exploitation mode")
	addBackendFlags(fs, &cfg)
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

func runScanGet(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan get", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := defaultBackendClientConfig()
	format := fs.String("format", "json", "output format: json|text")
	id := fs.String("id", "", "scan ID")
	addBackendFlags(fs, &cfg)
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

func runScanRun(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan run", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := defaultBackendClientConfig()
	format := fs.String("format", "json", "output format: json|text")
	inputPath := fs.String("input", "", "JSON file containing a scan request (use '-' for stdin)")
	target := fs.String("target", "", "target URL to scan")
	idempotencyKey := fs.String("idempotency-key", "", "optional idempotency key")
	automationMode := fs.String("automation-mode", "", "optional automation mode override")
	passiveOnly := fs.Bool("passive-only", false, "enable passive-only scan mode")
	aggressive := fs.Bool("aggressive-exploitation", false, "enable aggressive exploitation mode")
	pollInterval := fs.Duration("poll-interval", 5*time.Second, "poll interval while waiting for completion")
	waitTimeout := fs.Duration("wait-timeout", 30*time.Minute, "maximum time to wait for scan completion")
	addBackendFlags(fs, &cfg)
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

func printScanUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  autobughunter scan start -target <url> [flags]
  autobughunter scan start -input <request.json|-> [flags]
  autobughunter scan get -id <scan-id> [flags]
  autobughunter scan run -target <url> [flags]
  autobughunter scan run -input <request.json|-> [flags]

Common scan flags:
  -backend-base <url>         Backend API base URL
  -api-key <key>              Backend API key
  -workspace-id <id>          Backend workspace ID header
  -input <file|->             Full scan request JSON
  -target <url>               Target URL override
  -idempotency-key <key>      Optional idempotency key
  -automation-mode <mode>     Optional automation mode override
  -passive-only               Enable passive-only scan mode
  -aggressive-exploitation    Enable deeper exploitation paths
  -format <json|text>         Output format

scan run flags:
  -poll-interval <duration>   Poll interval while waiting (default 5s)
  -wait-timeout <duration>    Max wait time (default 30m)`)
}
