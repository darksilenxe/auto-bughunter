package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// SubmissionAdapterResult is the normalized response from a platform adapter.
type SubmissionAdapterResult struct {
	Reference   string `json:"reference,omitempty"`
	RawResponse string `json:"rawResponse,omitempty"`
}

// SubmitBugBountyFinding submits a finding payload to a supported platform API.
func SubmitBugBountyFinding(ctx context.Context, platform, apiKey string, sub model.BugBountySubmission) (SubmissionAdapterResult, error) {
	p := strings.ToLower(strings.TrimSpace(platform))
	if p != "hackerone" && p != "bugcrowd" {
		return SubmissionAdapterResult{}, fmt.Errorf("unsupported submission platform: %s", platform)
	}
	if strings.TrimSpace(apiKey) == "" {
		return SubmissionAdapterResult{}, fmt.Errorf("missing submission API key")
	}
	baseURL := platformBaseURL(p)
	if baseURL == "" {
		return SubmissionAdapterResult{}, fmt.Errorf("missing platform base URL")
	}
	body, err := platformPayload(p, sub)
	if err != nil {
		return SubmissionAdapterResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(body))
	if err != nil {
		return SubmissionAdapterResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return SubmissionAdapterResult{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SubmissionAdapterResult{}, fmt.Errorf("%s submission failed: HTTP %d: %s", p, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	ref := extractSubmissionReference(raw)
	return SubmissionAdapterResult{
		Reference:   ref,
		RawResponse: strings.TrimSpace(string(raw)),
	}, nil
}

func platformBaseURL(platform string) string {
	switch platform {
	case "hackerone":
		if v := strings.TrimSpace(os.Getenv("ABH_SUBMIT_HACKERONE_URL")); v != "" {
			return v
		}
	case "bugcrowd":
		if v := strings.TrimSpace(os.Getenv("ABH_SUBMIT_BUGCROWD_URL")); v != "" {
			return v
		}
	}
	return ""
}

func platformPayload(platform string, sub model.BugBountySubmission) ([]byte, error) {
	switch platform {
	case "hackerone":
		return json.Marshal(map[string]any{
			"title":                sub.Title,
			"weakness_description": sub.Summary,
			"impact":               sub.Impact,
			"severity_rating":      strings.ToLower(string(sub.Severity)),
			"vulnerability_information": map[string]any{
				"cvss_score":  sub.CVSSScore,
				"cvss_vector": sub.CVSSVector,
				"cwe":         sub.CWE,
				"asset":       sub.Asset,
			},
			"steps_to_reproduce": strings.Join(sub.Steps, "\n"),
			"suggested_fix":      sub.Remediation,
			"references":         sub.References,
		})
	case "bugcrowd":
		return json.Marshal(map[string]any{
			"title":        sub.Title,
			"summary":      sub.Summary,
			"severity":     strings.ToLower(string(sub.Severity)),
			"target":       sub.Asset,
			"impact":       sub.Impact,
			"reproduction": strings.Join(sub.Steps, "\n"),
			"remediation":  sub.Remediation,
			"cwe":          sub.CWE,
			"cvss_score":   sub.CVSSScore,
			"cvss_vector":  sub.CVSSVector,
			"references":   sub.References,
		})
	default:
		return nil, fmt.Errorf("unsupported submission platform: %s", platform)
	}
}

func extractSubmissionReference(raw []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	for _, k := range []string{"id", "reference", "submission_id", "report_id"} {
		if v := strings.TrimSpace(fmt.Sprintf("%v", payload[k])); v != "" && v != "<nil>" {
			return v
		}
	}
	return ""
}
