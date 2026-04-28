package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "autobughunter:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printMainUsage(stderr)
		return nil
	}

	switch normalizeHelpArg(args[0]) {
	case "help":
		printMainUsage(stdout)
		return nil
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "tools":
		return runTools(args[1:], stdout, stderr)
	case "ml":
		return runML(args[1:], stdout, stderr)
	default:
		printMainUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runTools(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || normalizeHelpArg(args[0]) == "help" {
		printToolsUsage(stderr)
		return nil
	}
	switch args[0] {
	case "health":
		return runToolsHealth(args[1:], stdout, stderr)
	case "updates":
		return runToolsUpdates(args[1:], stdout, stderr)
	default:
		printToolsUsage(stderr)
		return fmt.Errorf("unknown tools command %q", args[0])
	}
}

func runML(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || normalizeHelpArg(args[0]) == "help" {
		printMLUsage(stderr)
		return nil
	}
	switch args[0] {
	case "dataset":
		return runMLDataset(args[1:], stdout, stderr)
	case "score-findings":
		return runMLInference(args[0], "/v1/score-findings", args[1:], stdout, stderr)
	case "attack-paths":
		return runMLInference(args[0], "/v1/attack-paths", args[1:], stdout, stderr)
	case "remediation-plan":
		return runMLInference(args[0], "/v1/remediation-plan", args[1:], stdout, stderr)
	case "false-positive-candidates":
		return runMLInference(args[0], "/v1/false-positive-candidates", args[1:], stdout, stderr)
	default:
		printMLUsage(stderr)
		return fmt.Errorf("unknown ml command %q", args[0])
	}
}

func runToolsHealth(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tools health", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := defaultBackendClientConfig()
	format := fs.String("format", "json", "output format: json|text")
	addBackendFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return err
	}

	body, err := newHTTPClient(cfg).get(context.Background(), "/api/tools/health", nil)
	if err != nil {
		return err
	}
	return writeCommandOutput(stdout, *format, body, writeToolsHealthText)
}

func runToolsUpdates(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tools updates", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := defaultBackendClientConfig()
	format := fs.String("format", "json", "output format: json|text")
	addBackendFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return err
	}

	body, err := newHTTPClient(cfg).get(context.Background(), "/api/tools/updates", nil)
	if err != nil {
		return err
	}
	return writeCommandOutput(stdout, *format, body, writeToolsUpdatesText)
}

func runMLDataset(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || normalizeHelpArg(args[0]) == "help" {
		printMLDatasetUsage(stderr)
		return nil
	}
	if args[0] != "export" {
		printMLDatasetUsage(stderr)
		return fmt.Errorf("unknown ml dataset command %q", args[0])
	}

	fs := flag.NewFlagSet("ml dataset export", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := defaultBackendClientConfig()
	format := fs.String("format", "json", "output format: json|text")
	limit := fs.Int("limit", 100, "maximum completed engagements to export")
	addBackendFlags(fs, &cfg)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	query := map[string]string{"limit": fmt.Sprintf("%d", *limit)}
	body, err := newHTTPClient(cfg).get(context.Background(), "/api/ml/engagements", query)
	if err != nil {
		return err
	}
	return writeCommandOutput(stdout, *format, body, writeMLDatasetText)
}

func runMLInference(command, path string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ml "+command, flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := defaultMLClientConfig()
	format := fs.String("format", "json", "output format: json|text")
	inputPath := fs.String("input", "", "JSON file to read (use '-' for stdin)")
	limit := fs.Int("limit", -1, "remediation-plan only: override the response item limit")
	addMLFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*inputPath) == "" {
		return fmt.Errorf("-input is required (use '-' for stdin)")
	}

	input, err := readInput(*inputPath)
	if err != nil {
		return err
	}
	body, err := normalizeMLRequest(command, input, *limit)
	if err != nil {
		return err
	}

	resp, err := newHTTPClient(cfg).postJSON(context.Background(), path, body)
	if err != nil {
		return err
	}

	renderText := writeMLScoreText
	switch command {
	case "attack-paths":
		renderText = writeMLListText("Attack paths", "attackPaths")
	case "remediation-plan":
		renderText = writeMLListText("Remediation plan", "remediationPlan")
	case "false-positive-candidates":
		renderText = writeMLCandidatesText
	}
	return writeCommandOutput(stdout, *format, resp, renderText)
}

func printMainUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  autobughunter scan <start|get|run> [flags]
  autobughunter tools <health|updates> [flags]
  autobughunter ml dataset export [flags]
  autobughunter ml <score-findings|attack-paths|remediation-plan|false-positive-candidates> [flags]

Environment:
  AUTOBUGHUNTER_BACKEND_URL       Backend API base URL (default: http://localhost:8080)
  AUTOBUGHUNTER_ML_URL            ML service base URL (falls back to ML_SERVICE_URL, then http://localhost:8090)
  AUTOBUGHUNTER_API_KEY           Backend API key (falls back to BOOTSTRAP_ADMIN_API_KEY)
  AUTOBUGHUNTER_WORKSPACE_ID      Backend workspace ID header
  AUTOBUGHUNTER_SIDECAR_AUTH_TOKEN ML service bearer token (falls back to SIDECAR_AUTH_TOKEN)`)
}

func printToolsUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  autobughunter tools health [flags]
  autobughunter tools updates [flags]`)
}

func printMLUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  autobughunter ml dataset export [flags]
  autobughunter ml score-findings -input <file|-> [flags]
  autobughunter ml attack-paths -input <file|-> [flags]
  autobughunter ml remediation-plan -input <file|-> [flags]
  autobughunter ml false-positive-candidates -input <file|-> [flags]`)
}

func printMLDatasetUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  autobughunter ml dataset export [flags]`)
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

func normalizeHelpArg(arg string) string {
	switch strings.TrimSpace(strings.ToLower(arg)) {
	case "-h", "--help", "help":
		return "help"
	default:
		return strings.TrimSpace(strings.ToLower(arg))
	}
}

func addBackendFlags(fs *flag.FlagSet, cfg *clientConfig) {
	fs.StringVar(&cfg.baseURL, "backend-base", cfg.baseURL, "backend API base URL")
	fs.StringVar(&cfg.apiKey, "api-key", cfg.apiKey, "backend API key")
	fs.StringVar(&cfg.workspaceID, "workspace-id", cfg.workspaceID, "backend workspace ID")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "request timeout")
}

func addMLFlags(fs *flag.FlagSet, cfg *clientConfig) {
	fs.StringVar(&cfg.baseURL, "ml-base", cfg.baseURL, "ML service base URL")
	fs.StringVar(&cfg.bearerToken, "sidecar-token", cfg.bearerToken, "ML service bearer token")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "request timeout")
}

func defaultBackendClientConfig() clientConfig {
	return clientConfig{
		baseURL:     firstNonEmpty(os.Getenv("AUTOBUGHUNTER_BACKEND_URL"), "http://localhost:8080"),
		apiKey:      firstNonEmpty(os.Getenv("AUTOBUGHUNTER_API_KEY"), os.Getenv("BOOTSTRAP_ADMIN_API_KEY")),
		workspaceID: strings.TrimSpace(os.Getenv("AUTOBUGHUNTER_WORKSPACE_ID")),
		timeout:     30 * time.Second,
	}
}

func defaultMLClientConfig() clientConfig {
	return clientConfig{
		baseURL:     firstNonEmpty(os.Getenv("AUTOBUGHUNTER_ML_URL"), os.Getenv("ML_SERVICE_URL"), "http://localhost:8090"),
		bearerToken: firstNonEmpty(os.Getenv("AUTOBUGHUNTER_SIDECAR_AUTH_TOKEN"), os.Getenv("SIDECAR_AUTH_TOKEN")),
		timeout:     30 * time.Second,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
