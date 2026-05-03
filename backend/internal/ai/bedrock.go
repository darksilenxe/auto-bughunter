package ai

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// bedrockProvider implements Provider for AWS Bedrock Runtime.
// Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html
//
// Authentication uses AWS Signature Version 4.  Credentials are read from the
// standard AWS environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
// AWS_SESSION_TOKEN) so any standard AWS credential chain (env, IAM role,
// instance profile) works without an SDK dependency.
//
// Request format targets Anthropic Claude models (anthropic.claude-*) which
// are the primary Claude models available on Bedrock.  The request body
// mirrors the Anthropic Messages API with an extra "anthropic_version" field
// required by Bedrock.
type bedrockProvider struct {
	// region is the AWS region string, e.g. "us-east-1".
	region string
	http   *http.Client
}

const (
	bedrockService        = "bedrock"
	bedrockMaxTokens      = 4096
	bedrockAnthropicVer   = "bedrock-2023-05-31"
	awsSigV4Algorithm     = "AWS4-HMAC-SHA256"
)

func (p *bedrockProvider) Complete(ctx context.Context, model string, messages []Message, temperature float64, jsonMode bool) (string, error) {
	accessKey := strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
	secretKey := strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY"))
	sessionToken := strings.TrimSpace(os.Getenv("AWS_SESSION_TOKEN"))
	if accessKey == "" || secretKey == "" {
		return "", fmt.Errorf("bedrock: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not set")
	}

	// Separate system and conversation messages.
	var systemContent string
	userMessages := make([]map[string]string, 0, len(messages))
	for _, m := range messages {
		if m.Role == "system" {
			if systemContent != "" {
				systemContent += "\n"
			}
			systemContent += m.Content
			continue
		}
		userMessages = append(userMessages, map[string]string{
			"role":    m.Role,
			"content": m.Content,
		})
	}
	if jsonMode && len(userMessages) > 0 {
		last := userMessages[len(userMessages)-1]
		if !strings.Contains(strings.ToLower(last["content"]), "json") {
			last["content"] += "\n\nReply with strict JSON only."
			userMessages[len(userMessages)-1] = last
		}
	}

	payload := map[string]any{
		"anthropic_version": bedrockAnthropicVer,
		"max_tokens":        bedrockMaxTokens,
		"temperature":       temperature,
		"messages":          userMessages,
	}
	if systemContent != "" {
		payload["system"] = systemContent
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("bedrock: marshal: %w", err)
	}

	host := fmt.Sprintf("bedrock-runtime.%s.amazonaws.com", p.region)
	path := fmt.Sprintf("/model/%s/invoke", model)
	endpoint := "https://" + host + path

	now := time.Now().UTC()
	dateTime := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	// Build the canonical request.
	payloadHash := sha256Hex(bodyBytes)
	canonicalHeaders := "content-type:application/json\nhost:" + host + "\nx-amz-date:" + dateTime + "\n"
	if sessionToken != "" {
		canonicalHeaders += "x-amz-security-token:" + sessionToken + "\n"
	}
	signedHeaders := "content-type;host;x-amz-date"
	if sessionToken != "" {
		signedHeaders += ";x-amz-security-token"
	}
	canonicalRequest := strings.Join([]string{
		"POST",
		path,
		"", // no query string
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// Build the string-to-sign.
	credentialScope := strings.Join([]string{date, p.region, bedrockService, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		awsSigV4Algorithm,
		dateTime,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Derive the signing key.
	signingKey := hmacSHA256(
		hmacSHA256(
			hmacSHA256(
				hmacSHA256([]byte("AWS4"+secretKey), []byte(date)),
				[]byte(p.region),
			),
			[]byte(bedrockService),
		),
		[]byte("aws4_request"),
	)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authHeader := fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		awsSigV4Algorithm, accessKey, credentialScope, signedHeaders, signature,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("bedrock: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Amz-Date", dateTime)
	req.Header.Set("Authorization", authHeader)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("bedrock: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("bedrock: status %d", resp.StatusCode)
	}

	// Bedrock wraps the model response in the same body that the model would
	// return natively.  For Anthropic Claude models this is the Anthropic
	// Messages API response shape.
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("bedrock: decode: %w", err)
	}
	for _, block := range out.Content {
		if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
			return strings.TrimSpace(block.Text), nil
		}
	}
	return "", fmt.Errorf("bedrock: no text block in response")
}

// sha256Hex returns the lowercase hex SHA-256 digest of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// hmacSHA256 returns the HMAC-SHA256 of data with key.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
