package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// BurpParsedConfig holds the scan-relevant data extracted from a Burp Suite
// project configuration file. It is returned by POST /api/burp/parse so the
// frontend can pre-populate the scan form with target URL, scope rules, and
// any authentication headers or cookies found in match-replace rules.
type BurpParsedConfig struct {
	Target       string            `json:"target,omitempty"`
	IncludeHosts []string          `json:"includeHosts"`
	ExcludeHosts []string          `json:"excludeHosts"`
	ExcludePaths []string          `json:"excludePaths"`
	Headers      map[string]string `json:"headers"`
	Cookies      map[string]string `json:"cookies"`
	Notes        []string          `json:"notes"`
}

// ── Burp JSON types (unexported) ─────────────────────────────────────────────

type burpScopeEntry struct {
	Enabled  bool   `json:"enabled"`
	File     string `json:"file"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type burpMatchReplaceRule struct {
	Comment       string `json:"comment"`
	Enabled       bool   `json:"enabled"`
	MatchType     string `json:"match_type"`
	ReplaceString string `json:"replace_string"`
	RuleType      string `json:"rule_type"`
}

type burpProjectConfig struct {
	Target struct {
		Scope struct {
			AdvancedMode bool             `json:"advanced_mode"`
			Include      []burpScopeEntry `json:"include"`
			Exclude      []burpScopeEntry `json:"exclude"`
		} `json:"scope"`
	} `json:"target"`
	Proxy struct {
		MatchReplaceRules []burpMatchReplaceRule `json:"match_replace_rules"`
	} `json:"proxy"`
	// Some Burp exports nest the target scope under "project_options"
	ProjectOptions struct {
		Target struct {
			Scope struct {
				AdvancedMode bool             `json:"advanced_mode"`
				Include      []burpScopeEntry `json:"include"`
				Exclude      []burpScopeEntry `json:"exclude"`
			} `json:"scope"`
		} `json:"target"`
	} `json:"project_options"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleBurpParse accepts a multipart/form-data file upload (field "file")
// containing a Burp Suite project configuration export (.json) or a Burp
// project file (.burp, which is a ZIP archive). It parses the file and
// returns a BurpParsedConfig JSON object suitable for pre-populating the
// scan form on the frontend.
func (s *Server) handleBurpParse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Limit upload to 32 MB — project config files are tiny; full .burp
	// project files can be larger, but we only need the JSON fragments inside.
	const maxSize = 32 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)
	if err := r.ParseMultipartForm(maxSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file too large or malformed multipart request"})
		return
	}

	f, hdr, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing 'file' field in form"})
		return
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read uploaded file"})
		return
	}

	var cfg BurpParsedConfig
	name := strings.ToLower(hdr.Filename)
	if strings.HasSuffix(name, ".burp") || isZIPData(data) {
		cfg, err = parseBurpZIP(data)
	} else {
		cfg, err = parseBurpJSON(data)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to parse Burp configuration: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, cfg)
}

// ── Parsers ───────────────────────────────────────────────────────────────────

// isZIPData returns true when data begins with the ZIP magic bytes PK\x03\x04.
func isZIPData(data []byte) bool {
	return len(data) >= 4 &&
		data[0] == 'P' && data[1] == 'K' &&
		data[2] == 0x03 && data[3] == 0x04
}

// parseBurpZIP extracts scan configuration from a .burp project file.
// Burp project files are ZIP archives; we scan for any JSON entry that
// contains recognisable scope configuration.
func parseBurpZIP(data []byte) (BurpParsedConfig, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return BurpParsedConfig{}, err
	}
	for _, f := range zr.File {
		n := strings.ToLower(f.Name)
		if !strings.HasSuffix(n, ".json") &&
			!strings.Contains(n, "config") &&
			!strings.Contains(n, "option") {
			continue
		}
		rc, openErr := f.Open()
		if openErr != nil {
			continue
		}
		jsonData, readErr := io.ReadAll(rc)
		rc.Close()
		if readErr != nil {
			continue
		}
		cfg, parseErr := parseBurpJSON(jsonData)
		if parseErr == nil && (len(cfg.IncludeHosts) > 0 || cfg.Target != "") {
			return cfg, nil
		}
	}
	return BurpParsedConfig{
		IncludeHosts: []string{},
		ExcludeHosts: []string{},
		ExcludePaths: []string{},
		Headers:      map[string]string{},
		Cookies:      map[string]string{},
		Notes:        []string{"No recognisable scope configuration found in the Burp project file."},
	}, nil
}

// parseBurpJSON parses a Burp Suite project options JSON export and extracts
// target URL, scope rules, and any authentication material found in
// match-replace rules.
func parseBurpJSON(data []byte) (BurpParsedConfig, error) {
	var raw burpProjectConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return BurpParsedConfig{}, err
	}

	cfg := BurpParsedConfig{
		IncludeHosts: make([]string, 0),
		ExcludeHosts: make([]string, 0),
		ExcludePaths: make([]string, 0),
		Headers:      make(map[string]string),
		Cookies:      make(map[string]string),
		Notes:        make([]string, 0),
	}

	// Support both top-level "target.scope" and "project_options.target.scope".
	inclEntries := raw.Target.Scope.Include
	exclEntries := raw.Target.Scope.Exclude
	matchRules := raw.Proxy.MatchReplaceRules
	if len(inclEntries) == 0 {
		inclEntries = raw.ProjectOptions.Target.Scope.Include
		exclEntries = raw.ProjectOptions.Target.Scope.Exclude
	}

	// ── Include scope → includeHosts + derive target URL ─────────────────
	for _, entry := range inclEntries {
		if !entry.Enabled {
			continue
		}
		host := cleanBurpRegexHost(entry.Host)
		if host == "" {
			continue
		}
		cfg.IncludeHosts = append(cfg.IncludeHosts, host)

		// Build the primary target URL from the first non-wildcard include entry.
		if cfg.Target == "" && !strings.Contains(host, "*") {
			proto := entry.Protocol
			if proto == "" || proto == "any" {
				proto = "https"
			}
			portSuffix := ""
			if entry.Port != "" && entry.Port != "443" && entry.Port != "80" {
				portSuffix = ":" + entry.Port
			}
			path := strings.TrimRight(entry.File, ".*$")
			if path == "" {
				path = "/"
			}
			cfg.Target = proto + "://" + host + portSuffix + path
		}
	}

	// ── Exclude scope → excludeHosts / excludePaths ───────────────────────
	for _, entry := range exclEntries {
		if !entry.Enabled {
			continue
		}
		host := cleanBurpRegexHost(entry.Host)
		if host == "" {
			continue
		}
		path := strings.TrimRight(entry.File, ".*$")
		if path != "" && path != "/" {
			cfg.ExcludePaths = append(cfg.ExcludePaths, path)
		} else {
			cfg.ExcludeHosts = append(cfg.ExcludeHosts, host)
		}
	}

	// ── Auth extraction from match-replace rules ──────────────────────────
	for _, rule := range matchRules {
		if !rule.Enabled {
			continue
		}
		val := strings.TrimSpace(rule.ReplaceString)
		if val == "" {
			continue
		}

		switch strings.ToLower(rule.MatchType) {
		case "request_header", "request_header_name", "request_header_value":
			if idx := strings.Index(val, ":"); idx > 0 {
				name := strings.TrimSpace(val[:idx])
				value := strings.TrimSpace(val[idx+1:])
				if strings.EqualFold(name, "cookie") {
					parseBurpCookieHeader(value, cfg.Cookies)
				} else if name != "" && value != "" {
					cfg.Headers[name] = value
				}
			}
		case "request_cookie", "cookie_name", "cookie_value":
			if idx := strings.Index(val, "="); idx > 0 {
				cfg.Cookies[strings.TrimSpace(val[:idx])] = strings.TrimSpace(val[idx+1:])
			}
		}
	}

	if len(cfg.IncludeHosts) == 0 && cfg.Target == "" {
		cfg.Notes = append(cfg.Notes,
			"No scope configuration found. Make sure the file is a Burp Suite "+
				"project options export (Project menu → Save project options).")
	}

	return cfg, nil
}

// cleanBurpRegexHost converts a Burp-style host regex to a plain hostname or
// glob pattern. Burp stores hosts as Java regexes, e.g.:
//
//	"example\\.com"       → "example.com"
//	".*\\.example\\.com"  → "*.example.com"
func cleanBurpRegexHost(raw string) string {
	s := strings.TrimSuffix(strings.TrimSuffix(raw, "$"), "^")
	wildcardPrefix := strings.HasPrefix(s, ".*\\.")
	if wildcardPrefix {
		s = strings.TrimPrefix(s, ".*\\.")
	}
	s = strings.ReplaceAll(s, "\\.", ".")
	if wildcardPrefix {
		s = "*." + s
	}
	return s
}

// parseBurpCookieHeader parses a "name=value; name2=value2" cookie string and
// populates out with the extracted key-value pairs.
func parseBurpCookieHeader(header string, out map[string]string) {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx > 0 {
			name := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+1:])
			if name != "" {
				out[name] = value
			}
		}
	}
}
