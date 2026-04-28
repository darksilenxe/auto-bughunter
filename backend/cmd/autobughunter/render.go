package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

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

type mlDatasetResponse struct {
	Records []json.RawMessage `json:"records"`
}

type scoredFindingsResponse struct {
	ScoredFindings []scoredFinding `json:"scoredFindings"`
}

type falsePositiveCandidatesResponse struct {
	Candidates []scoredFinding `json:"candidates"`
}

type scoredFinding struct {
	Finding struct {
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Category string `json:"category"`
	} `json:"finding"`
	Score          float64 `json:"score"`
	Confidence     float64 `json:"confidence"`
	Exploitability string  `json:"exploitability"`
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

func writeMLDatasetText(w io.Writer, raw []byte) error {
	var resp mlDatasetResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	fmt.Fprintf(w, "Exported %d engagement records\n", len(resp.Records))
	return nil
}

func writeMLScoreText(w io.Writer, raw []byte) error {
	var resp scoredFindingsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	fmt.Fprintf(w, "Scored %d findings\n", len(resp.ScoredFindings))
	for idx, item := range resp.ScoredFindings {
		fmt.Fprintf(
			w,
			"%d. %s [%s/%s] score=%.2f confidence=%.2f exploitability=%s\n",
			idx+1,
			strings.TrimSpace(item.Finding.Title),
			strings.TrimSpace(item.Finding.Severity),
			strings.TrimSpace(item.Finding.Category),
			item.Score,
			item.Confidence,
			strings.TrimSpace(item.Exploitability),
		)
	}
	return nil
}

func writeMLCandidatesText(w io.Writer, raw []byte) error {
	var resp falsePositiveCandidatesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	fmt.Fprintf(w, "Found %d low-confidence candidates\n", len(resp.Candidates))
	for idx, item := range resp.Candidates {
		fmt.Fprintf(
			w,
			"%d. %s [%s/%s] score=%.2f confidence=%.2f exploitability=%s\n",
			idx+1,
			strings.TrimSpace(item.Finding.Title),
			strings.TrimSpace(item.Finding.Severity),
			strings.TrimSpace(item.Finding.Category),
			item.Score,
			item.Confidence,
			strings.TrimSpace(item.Exploitability),
		)
	}
	return nil
}

func writeMLListText(title, key string) func(io.Writer, []byte) error {
	return func(w io.Writer, raw []byte) error {
		var payload map[string][]string
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		items := payload[key]
		fmt.Fprintf(w, "%s (%d)\n", title, len(items))
		for idx, item := range items {
			fmt.Fprintf(w, "%d. %s\n", idx+1, item)
		}
		return nil
	}
}
