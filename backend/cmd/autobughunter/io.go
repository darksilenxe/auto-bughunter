package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

func readInput(path string) ([]byte, error) {
	switch strings.TrimSpace(path) {
	case "":
		return nil, fmt.Errorf("input path is required")
	case "-":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return nil, fmt.Errorf("stdin was empty")
		}
		return data, nil
	default:
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return nil, fmt.Errorf("%s was empty", path)
		}
		return data, nil
	}
}

func normalizeMLRequest(command string, input []byte, limit int) ([]byte, error) {
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("input JSON was empty")
	}

	switch trimmed[0] {
	case '[':
		return wrapFindingsArray(command, json.RawMessage(trimmed), limit)
	case '{':
		return normalizeMLObject(command, trimmed, limit)
	default:
		return nil, fmt.Errorf("input must be a JSON object or array")
	}
}

func wrapFindingsArray(command string, findings json.RawMessage, limit int) ([]byte, error) {
	payload := map[string]any{
		"findings": findings,
	}
	if command == "remediation-plan" {
		payload["limit"] = remediationLimit(limit)
	}
	return json.Marshal(payload)
}

func normalizeMLObject(command string, input []byte, limit int) ([]byte, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(input, &payload); err != nil {
		return nil, fmt.Errorf("invalid JSON object: %w", err)
	}
	if _, ok := payload["findings"]; !ok {
		if looksLikeFinding(payload) {
			single, err := json.Marshal([]json.RawMessage{json.RawMessage(input)})
			if err != nil {
				return nil, err
			}
			return wrapFindingsArray(command, single, limit)
		}
		return nil, fmt.Errorf("object input must contain a findings field")
	}
	if command == "remediation-plan" && limit >= 0 {
		limitBytes, err := json.Marshal(remediationLimit(limit))
		if err != nil {
			return nil, err
		}
		payload["limit"] = limitBytes
	}
	return json.Marshal(payload)
}

func looksLikeFinding(payload map[string]json.RawMessage) bool {
	for _, key := range []string{"id", "category", "severity", "title", "description", "evidence", "recommendation"} {
		if _, ok := payload[key]; ok {
			return true
		}
	}
	return false
}

func remediationLimit(limit int) int {
	if limit <= 0 {
		return 5
	}
	return limit
}
