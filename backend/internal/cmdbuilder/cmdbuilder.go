// Package cmdbuilder provides safe dynamic command generation, validation,
// and execution for autonomous pen testing agents.
//
// Agents use the Generator to propose tool invocations tailored to their
// current findings, the Validator enforces a strict safety policy, and the
// Runner executes approved commands and captures their output.
package cmdbuilder

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// ────────────────────────────────────────────────────────────────────────────
// Command spec
// ────────────────────────────────────────────────────────────────────────────

// CommandSpec describes a shell command that an agent wants to run.
type CommandSpec struct {
	// Binary is the executable name (no path).
	Binary string
	// Args are the command-line arguments.
	Args []string
	// Rationale explains why the command was chosen.
	Rationale string
	// GeneratedBy is the agent that generated this command.
	GeneratedBy string
	// Timeout overrides the default execution timeout.
	Timeout time.Duration
}

// String returns a human-readable representation of the command.
func (c CommandSpec) String() string {
	parts := append([]string{c.Binary}, c.Args...)
	return strings.Join(parts, " ")
}

// ────────────────────────────────────────────────────────────────────────────
// Safety validator
// ────────────────────────────────────────────────────────────────────────────

// allowedBinaries is the strict allow-list of binaries that agents may invoke.
// Every binary here is a recognised, safe pen testing tool.
var allowedBinaries = map[string]bool{
	"nuclei":          true,
	"subfinder":       true,
	"httpx":           true,
	"naabu":           true,
	"dnsx":            true,
	"katana":          true,
	"tlsx":            true,
	"ffuf":            true,
	"gobuster":        true,
	"nikto":           true,
	"wpscan":          true,
	"sqlmap":          true,
	"curl":            true,
	"wget":            true,
	"nmap":            true,
	"whatweb":         true,
	"wafw00f":         true,
	"arjun":           true,
	"dalfox":          true,
	"gf":              true,
	"anew":            true,
	"qsreplace":       true,
	"python3":         true,
	"python":          true,
}

// blockedArgPatterns are argument substrings that are never permitted regardless
// of the binary, e.g. those that would allow command injection or filesystem writes
// outside safe scratch space.
var blockedArgPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\$\(`),         // command substitution $(...)
	regexp.MustCompile("`"),             // backtick substitution
	regexp.MustCompile(`&&`),           // shell AND chaining
	regexp.MustCompile(`\|\|`),         // shell OR chaining
	regexp.MustCompile(`;\s*\w`),       // semicolon command chaining
	regexp.MustCompile(`>\s*/[a-z]`),         // redirecting to non-tmp absolute path
	regexp.MustCompile(`rm\s+-`),       // rm flags
	regexp.MustCompile(`chmod\s+[0-7]*7`), // chmod world-writable
	regexp.MustCompile(`/etc/`),        // /etc access
	regexp.MustCompile(`/proc/`),       // /proc access
	regexp.MustCompile(`/sys/`),        // /sys access
	regexp.MustCompile(`/root/`),       // /root access
	regexp.MustCompile(`~`),            // home directory reference
}

// Validate checks that a CommandSpec is safe to execute.
// It returns a non-nil error if the command violates the safety policy.
func Validate(spec CommandSpec, target string) error {
	bin := strings.TrimSpace(spec.Binary)
	if bin == "" {
		return fmt.Errorf("empty binary")
	}
	binLower := strings.ToLower(bin)
	if !allowedBinaries[binLower] {
		return fmt.Errorf("binary %q is not on the approved tool list", bin)
	}
	if (binLower == "python3" || binLower == "python") && !isSafePythonInvocation(spec.Args) {
		return fmt.Errorf("python commands must execute a script under /tmp/auto-bughunter/tools without interpreter flags")
	}

	for _, arg := range spec.Args {
		for _, pat := range blockedArgPatterns {
			if pat.MatchString(arg) {
				return fmt.Errorf("argument %q contains a blocked pattern (%s)", arg, pat.String())
			}
		}
	}

	// Ensure the target hostname appears in at least one argument when the
	// command is expected to make network requests.
	if isNetworkTool(binLower) && target != "" {
		tHost := extractHost(target)
		found := false
		for _, arg := range spec.Args {
			if tHost != "" && strings.Contains(arg, tHost) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("no argument references the scan target %q; commands must target the authorised host", tHost)
		}
	}

	return nil
}

func isNetworkTool(bin string) bool {
	switch strings.ToLower(bin) {
	case "python3", "python", "gf", "anew", "qsreplace":
		return false
	}
	return true
}

func isSafePythonInvocation(args []string) bool {
	if len(args) == 0 {
		return false
	}
	script := strings.TrimSpace(args[0])
	if script == "" || strings.HasPrefix(script, "-") {
		return false
	}
	script = filepath.Clean(script)
	if !strings.HasPrefix(script, "/tmp/auto-bughunter/tools/") {
		return false
	}
	for _, arg := range args[1:] {
		if strings.TrimSpace(arg) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(arg), "-") {
			return false
		}
	}
	return true
}

func extractHost(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return target
	}
	return u.Hostname()
}

// ────────────────────────────────────────────────────────────────────────────
// Runner
// ────────────────────────────────────────────────────────────────────────────

const (
	defaultTimeout = 60 * time.Second
	maxTimeout     = 5 * time.Minute
	maxOutputBytes = 2 * 1024 * 1024 // 2 MB
)

// RunResult holds the output of an executed command.
type RunResult struct {
	Spec     CommandSpec
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	Error    error
}

// Run validates and executes a CommandSpec.  It emits a command event before
// running, and respects the context deadline in addition to spec.Timeout.
func Run(ctx context.Context, spec CommandSpec, target string, emit func(model.ScanEvent)) RunResult {
	result := RunResult{Spec: spec}

	if err := Validate(spec, target); err != nil {
		result.Error = fmt.Errorf("safety validation failed: %w", err)
		return result
	}

	// Emit the command event so the UI can show what's running.
	if emit != nil {
		emit(model.ScanEvent{
			Type:        model.ScanEventCommand,
			AgentName:   spec.GeneratedBy,
			Command:     spec.String(),
			Message:     spec.Rationale,
			Timestamp:   time.Now().UTC(),
		})
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, spec.Binary, spec.Args...) //nolint:gosec // binary is allowlisted
	cmd.Env = safeEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	result.Duration = time.Since(start)

	// Truncate output to avoid memory bloat.
	out := stdout.String()
	if len(out) > maxOutputBytes {
		out = out[:maxOutputBytes] + "\n[output truncated]"
	}
	result.Stdout = out
	result.Stderr = stderr.String()
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil && cmdCtx.Err() == context.DeadlineExceeded {
		result.Error = fmt.Errorf("command timed out after %s", timeout)
	} else {
		result.Error = err
	}

	return result
}

// safeEnv returns a minimal environment for subprocess execution that strips
// sensitive variables (tokens, keys, database URLs) while keeping enough for
// the tools to function.
func safeEnv() []string {
	keep := []string{"PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "TERM"}
	env := os.Environ()
	out := make([]string, 0, len(keep))
	for _, e := range env {
		k := strings.SplitN(e, "=", 2)[0]
		for _, allowed := range keep {
			if strings.EqualFold(k, allowed) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// ────────────────────────────────────────────────────────────────────────────
// Heuristic command generator
// ────────────────────────────────────────────────────────────────────────────

// Generator creates CommandSpec slices from findings context.  It uses
// heuristics so that agents can compose tool invocations tailored to
// what they have discovered, without requiring a running LLM.
type Generator struct{}

// Generate returns a list of CommandSpecs appropriate for the current findings
// and target.  Commands are ordered by expected value (highest first).
func (g *Generator) Generate(agentName, target string, findings []model.Finding) []CommandSpec {
	cmds := make([]CommandSpec, 0, 4)

	paramURLs := extractParamURLs(findings, target)
	hasSQLi := hasCategory(findings, "injection") || hasTitle(findings, "sql")
	hasXSS := hasTitle(findings, "xss") || hasTitle(findings, "cross-site")
	hasWordPress := hasEvidence(findings, "wordpress") || hasEvidence(findings, "wp-content")
	hasJWT := hasEvidence(findings, "jwt") || hasTitle(findings, "jwt")
	hasGraphQL := hasEvidence(findings, "graphql") || hasTitle(findings, "graphql")
	hasOpenRedirect := hasTitle(findings, "redirect") && hasCategory(findings, "cors_redirect")
	hasAdminPanel := hasEvidence(findings, "admin") || hasTitle(findings, "admin panel")
	hasForms := hasTitle(findings, "form") || hasEvidence(findings, "forms=")

	// SQL injection probe
	if hasSQLi && len(paramURLs) > 0 {
		cmds = append(cmds, CommandSpec{
			Binary:      "sqlmap",
			Args:        []string{"-u", paramURLs[0], "--batch", "--level=2", "--risk=1", "--output-dir=/tmp/auto-bughunter/sqlmap"},
			Rationale:   "SQL injection indicators found; probing with sqlmap at safe risk level",
			GeneratedBy: agentName,
			Timeout:     3 * time.Minute,
		})
	}

	// XSS probe with dalfox
	if hasXSS && len(paramURLs) > 0 {
		cmds = append(cmds, CommandSpec{
			Binary:      "dalfox",
			Args:        []string{"url", paramURLs[0], "--silence", "--no-color"},
			Rationale:   "XSS indicators found; probing reflected XSS with dalfox",
			GeneratedBy: agentName,
			Timeout:     2 * time.Minute,
		})
	}

	// WordPress-specific enumeration
	if hasWordPress {
		cmds = append(cmds, CommandSpec{
			Binary:      "wpscan",
			Args:        []string{"--url", target, "--enumerate", "vp,vt,u", "--no-banner"},
			Rationale:   "WordPress detected; enumerating plugins, themes, users",
			GeneratedBy: agentName,
			Timeout:     2 * time.Minute,
		})
	}

	// JWT secret probe (custom Python tool - will be built by ToolBuilderAgent)
	if hasJWT {
		cmds = append(cmds, CommandSpec{
			Binary:      "python3",
			Args:        []string{"/tmp/auto-bughunter/tools/jwt_probe.py", target},
			Rationale:   "JWT tokens detected; probing for weak secrets and algorithm confusion",
			GeneratedBy: agentName,
			Timeout:     30 * time.Second,
		})
	}

	// GraphQL introspection
	if hasGraphQL {
		cmds = append(cmds, CommandSpec{
			Binary:      "python3",
			Args:        []string{"/tmp/auto-bughunter/tools/graphql_probe.py", target},
			Rationale:   "GraphQL endpoint detected; running introspection and query enumeration",
			GeneratedBy: agentName,
			Timeout:     45 * time.Second,
		})
	}

	// Parameter fuzzing with ffuf
	if hasForms && !hasSQLi {
		host := extractHost(target)
		cmds = append(cmds, CommandSpec{
			Binary:      "ffuf",
			Args:        []string{"-u", target + "/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "20", "-mc", "200,204,301,302,307,401,403", "-H", "Host: " + host, "-s"},
			Rationale:   "Forms discovered; fuzzing for additional endpoints with ffuf",
			GeneratedBy: agentName,
			Timeout:     90 * time.Second,
		})
	}

	// Admin panel deep-dive
	if hasAdminPanel {
		host := extractHost(target)
		cmds = append(cmds, CommandSpec{
			Binary:      "gobuster",
			Args:        []string{"dir", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "20", "-q", "-H", "Host: " + host},
			Rationale:   "Admin panel indicators found; running gobuster dir scan for hidden admin paths",
			GeneratedBy: agentName,
			Timeout:     2 * time.Minute,
		})
	}

	// Open redirect chain check
	if hasOpenRedirect {
		cmds = append(cmds, CommandSpec{
			Binary:      "python3",
			Args:        []string{"/tmp/auto-bughunter/tools/redirect_probe.py", target},
			Rationale:   "Open redirect indicators; probing redirect chain for token leakage",
			GeneratedBy: agentName,
			Timeout:     30 * time.Second,
		})
	}

	// Wafw00f WAF detection (always useful for adaptation)
	if len(cmds) == 0 {
		cmds = append(cmds, CommandSpec{
			Binary:      "wafw00f",
			Args:        []string{target, "--no-colors"},
			Rationale:   "Detecting WAF presence to adapt attack strategy",
			GeneratedBy: agentName,
			Timeout:     30 * time.Second,
		})
	}

	return cmds
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

func hasCategory(findings []model.Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Category), substr) {
			return true
		}
	}
	return false
}

func hasTitle(findings []model.Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), substr) {
			return true
		}
	}
	return false
}

func hasEvidence(findings []model.Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Evidence), substr) {
			return true
		}
	}
	return false
}

func extractParamURLs(findings []model.Finding, target string) []string {
	urls := make([]string, 0)
	seen := map[string]bool{}
	for _, f := range findings {
		// Look for evidence that contains a URL with query parameters.
		for _, part := range strings.Fields(f.Evidence) {
			if strings.HasPrefix(part, "http") && strings.Contains(part, "?") && !seen[part] {
				if strings.Contains(part, extractHost(target)) {
					seen[part] = true
					urls = append(urls, part)
				}
			}
		}
	}
	if len(urls) == 0 {
		return []string{target + "?id=1"}
	}
	return urls
}
