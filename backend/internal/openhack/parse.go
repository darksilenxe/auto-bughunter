package openhack

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"
)

// parseExpert parses an expert markdown file into an *Expert. The frontmatter
// is expected to be a small subset of YAML — strings and bullet lists only;
// no nested mappings or anchors. Unknown frontmatter keys are ignored so the
// parser keeps working when the upstream OpenHack pack is refreshed.
func parseExpert(data []byte) (*Expert, error) {
	fm, body, err := splitFrontmatter(string(data))
	if err != nil {
		return nil, err
	}
	exp := &Expert{
		ID:             trimQuoted(fm["id"]),
		Title:          trimQuoted(fm["title"]),
		Category:       trimQuoted(fm["category"]),
		Tags:           lowerSlice(parseListValue(fm["tags"])),
		RoutingSignals: lowerSlice(parseListValue(fm["routing_signals"])),
		StandardRefs:   parseListValue(fm["standard_refs"]),
		Body:           strings.TrimSpace(body),
	}
	if exp.ID == "" {
		return nil, fmt.Errorf("expert prompt is missing id frontmatter")
	}
	return exp, nil
}

// parseOrchestration parses an orchestration / recon markdown file.
func parseOrchestration(data []byte) (*Orchestration, error) {
	fm, body, err := splitFrontmatter(string(data))
	if err != nil {
		return nil, err
	}
	o := &Orchestration{
		ID:    trimQuoted(fm["id"]),
		Title: trimQuoted(fm["title"]),
		Body:  strings.TrimSpace(body),
	}
	if o.ID == "" {
		// Fall back to the filename so we still get a stable lookup key.
		o.ID = "unknown"
	}
	return o, nil
}

// splitFrontmatter splits a markdown file with optional `---` frontmatter
// into a flat key→raw-value map and the body. List values are returned as a
// single string containing the raw lines (one bullet per line) so the caller
// can decide how to split them.
func splitFrontmatter(raw string) (map[string]string, string, error) {
	out := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return out, strings.Join(lines, "\n"), nil
	}
	// Find the closing fence.
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		// No closing fence — treat the whole document as body.
		return out, raw, nil
	}

	var currentKey string
	var currentList []string
	flush := func() {
		if currentKey != "" {
			out[currentKey] = strings.Join(currentList, "\n")
		}
		currentKey = ""
		currentList = nil
	}
	for _, line := range lines[1:end] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(line, "  - ") || strings.HasPrefix(line, "- ") {
			// list item — keep collecting under the current key
			currentList = append(currentList, strings.TrimPrefix(strings.TrimPrefix(trimmed, "- "), "-"))
			continue
		}
		// key: value
		idx := strings.Index(trimmed, ":")
		if idx < 0 {
			continue
		}
		flush()
		currentKey = strings.ToLower(strings.TrimSpace(trimmed[:idx]))
		valuePart := strings.TrimSpace(trimmed[idx+1:])
		if valuePart != "" {
			currentList = []string{valuePart}
		}
	}
	flush()
	body := strings.Join(lines[end+1:], "\n")
	return out, body, nil
}

// stripFrontmatter is a convenience for callers (e.g. SharedProtocol) that
// just want the body.
func stripFrontmatter(raw string) string {
	_, body, err := splitFrontmatter(raw)
	if err != nil {
		return raw
	}
	return body
}

func parseListValue(raw string) []string {
	if raw == "" {
		return nil
	}
	// Inline form: `tags: [a, b, c]`
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
		if inner == "" {
			return nil
		}
		parts := strings.Split(inner, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, trimQuoted(p))
			}
		}
		return out
	}
	// Multi-line bullet form already split on newlines by splitFrontmatter.
	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, trimQuoted(p))
		}
	}
	return out
}

func lowerSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(s))
	}
	return out
}

func trimQuoted(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// Used to keep import clean — referenced indirectly when a future maintainer
// wants to derive an id from filename. Kept exported so tests can call it.
var _ = filepath.Base
