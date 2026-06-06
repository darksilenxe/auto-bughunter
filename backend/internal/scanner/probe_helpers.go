package scanner

import "strings"

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func matchAnyLower(body string, signatures []string) string {
	lower := strings.ToLower(body)
	for _, signature := range signatures {
		sig := strings.ToLower(strings.TrimSpace(signature))
		if sig != "" && strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}
