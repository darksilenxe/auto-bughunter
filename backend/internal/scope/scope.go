package scope

import (
	"net/url"
	"strings"

	"auto-bughunter/backend/internal/model"
)

func Normalize(targetURL string, in model.ScanScope) model.ScanScope {
	out := model.ScanScope{
		IncludeHosts: normalizePatterns(in.IncludeHosts),
		ExcludeHosts: normalizePatterns(in.ExcludeHosts),
		ExcludePaths: normalizePaths(in.ExcludePaths),
		ProgramRules: normalizeRules(in.ProgramRules),
	}

	if len(out.IncludeHosts) == 0 {
		if u, err := url.Parse(targetURL); err == nil && u.Hostname() != "" {
			out.IncludeHosts = []string{strings.ToLower(u.Hostname())}
		}
	}

	return out
}

func IsURLInScope(raw string, s model.ScanScope) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return IsHostInScope(u.Hostname(), s) && !IsPathExcluded(u.Path, s)
}

func IsHostInScope(host string, s model.ScanScope) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}

	if len(s.IncludeHosts) > 0 && !matchesAny(host, s.IncludeHosts) {
		return false
	}
	if matchesAny(host, s.ExcludeHosts) {
		return false
	}
	return true
}

func IsPathExcluded(path string, s model.ScanScope) bool {
	path = normalizePath(path)
	for _, excluded := range s.ExcludePaths {
		if strings.HasPrefix(path, excluded) {
			return true
		}
	}
	return false
}

func FilterTargets(rawTargets []string, s model.ScanScope) []string {
	out := make([]string, 0, len(rawTargets))
	seen := map[string]struct{}{}
	for _, raw := range rawTargets {
		if !IsURLInScope(raw, s) {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

func matchesAny(host string, patterns []string) bool {
	for _, p := range patterns {
		if matchHostPattern(host, p) {
			return true
		}
	}
	return false
}

func matchHostPattern(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if host == "" || pattern == "" {
		return false
	}

	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return host == pattern
}

func normalizePatterns(values []string) []string {
	return dedupeNormalized(values, func(v string) string { return strings.ToLower(strings.TrimSpace(v)) })
}

func normalizeRules(values []string) []string {
	return dedupeNormalized(values, strings.TrimSpace)
}

func normalizePaths(values []string) []string {
	return dedupeNormalized(values, normalizePath)
}

func normalizePath(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return v
}

func dedupeNormalized(values []string, norm func(string) string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, v := range values {
		n := norm(v)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
