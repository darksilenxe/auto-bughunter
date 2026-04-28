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
	counts := map[string]int{
		"high":   0,
		"medium": 0,
		"low":    0,
		"info":   0,
	}
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

func parseScanCreateResponse(raw []byte) (scanCreateResponse, error) {
	var resp scanCreateResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return scanCreateResponse{}, err
	}
	return resp, nil
}

func parseScanJobResponse(raw []byte) (scanJobResponse, error) {
	var resp scanJobResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return scanJobResponse{}, err
	}
	return resp, nil
}
