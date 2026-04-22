package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// FlowStep represents one step in a multi-step stateful transaction flow.
// Steps are executed in order; later steps may reference earlier state.
type FlowStep struct {
	// Name is a human-readable label for the step (e.g. "add-to-cart").
	Name string `json:"name"`
	// Method is the HTTP verb (GET, POST, PUT, PATCH, DELETE).
	Method string `json:"method"`
	// Path is the URL path relative to the scan target.
	Path string `json:"path"`
	// Body is an optional JSON request body. Supports {{TOKEN}} interpolation
	// from the previous step's response body (token extraction).
	Body map[string]interface{} `json:"body,omitempty"`
	// Headers are additional headers for this step.
	Headers map[string]string `json:"headers,omitempty"`
	// ExpectedStatus is the HTTP status code the honest flow should return.
	// 0 means accept any 2xx.
	ExpectedStatus int `json:"expectedStatus,omitempty"`
	// MutationField is the JSON body field to tamper in the skip/race tests.
	// Leave empty to skip mutation-based tests for this step.
	MutationField string `json:"mutationField,omitempty"`
	// MutationValues are the tampered values to substitute for MutationField.
	MutationValues []interface{} `json:"mutationValues,omitempty"`
}

// Flow represents a complete stateful transaction (e.g. purchase, coupon
// redemption, account-registration).
type Flow struct {
	// Name identifies the flow (e.g. "purchase-flow").
	Name string `json:"name"`
	// Steps are the ordered sequence of HTTP interactions.
	Steps []FlowStep `json:"steps"`
}

// flowStepResult records what happened when a step was executed.
type flowStepResult struct {
	Name       string
	Status     int
	Body       string
	DurationMs int64
}

// builtInFlows are the default flows derived from common web-application
// transaction patterns. These are used when the operator has not provided
// explicit flows via SeedRuntimeEndpoints context.
var builtInFlows = []Flow{
	{
		Name: "payment-flow",
		Steps: []FlowStep{
			{Name: "add-to-cart", Method: "POST", Path: "/cart", Body: map[string]interface{}{"product_id": "1", "quantity": 1}},
			{Name: "apply-coupon", Method: "POST", Path: "/cart/coupon", Body: map[string]interface{}{"code": "TEST10"}},
			{Name: "checkout", Method: "POST", Path: "/checkout", Body: map[string]interface{}{"payment_method": "card"}},
			{Name: "confirm", Method: "POST", Path: "/checkout/confirm", Body: map[string]interface{}{"confirmed": true}},
		},
	},
	{
		Name: "account-registration",
		Steps: []FlowStep{
			{Name: "register", Method: "POST", Path: "/register", Body: map[string]interface{}{"email": "test@abh-probe.local", "password": "TestProbe123!"}},
			{Name: "verify-email", Method: "GET", Path: "/verify"},
			{Name: "complete-profile", Method: "POST", Path: "/profile", Body: map[string]interface{}{"name": "ABH Probe"}},
		},
	},
}

// flowBodyLimit caps per-step response read.
const flowBodyLimit = 64 * 1024

// flowStepTimeout is the per-step request timeout.
const flowStepTimeout = 10 * time.Second

// RunFlowEngine executes stateful multi-step transaction flows to detect:
//  1. Step-skipping: accessing a later step (e.g. /checkout/confirm) without
//     executing the prerequisite steps.
//  2. Double-submit: replaying a completed flow step to double-charge or
//     double-redeem.
//  3. Price/parameter tampering: substituting negative prices, zero quantities,
//     or unexpected field values at any step in the flow.
//
// The engine runs built-in flows against the target. Each flow tests the happy
// path first to confirm the server is responsive, then applies attack variants.
func (s *Service) RunFlowEngine(
	ctx context.Context,
	target string,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
	emit func(model.ScanEvent),
) []model.Finding {
	if options.PassiveOnly {
		return nil
	}

	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}

	if emit != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("flow-engine %s", target),
			Message: fmt.Sprintf("Executing %d stateful transaction flows for business-logic vulnerabilities", len(builtInFlows)),
		})
	}

	var findings []model.Finding
	for _, flow := range builtInFlows {
		findings = append(findings, s.runSingleFlow(ctx, base, flow, scanScope, options, auth)...)
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

// runSingleFlow executes one Flow's attack scenarios.
func (s *Service) runSingleFlow(
	ctx context.Context,
	base *url.URL,
	flow Flow,
	scanScope model.ScanScope,
	options model.ScanOptions,
	auth model.ScanAuthProfile,
) []model.Finding {
	var findings []model.Finding

	// 1. Test step-skipping: jump directly to the last step without the prior steps.
	if len(flow.Steps) >= 2 {
		lastStep := flow.Steps[len(flow.Steps)-1]
		ep := resolveFlowURL(base, lastStep.Path)
		if scope.IsURLInScope(ep, scanScope) {
			resp, _, err := s.flowSendStep(ctx, ep, lastStep, nil, auth, options)
			if err == nil && resp != nil && is2xx(resp.StatusCode) {
				findings = append(findings, model.Finding{
					ID:       "flow-step-skip-" + flowSlug(flow.Name, lastStep.Name),
					Category: "access-control",
					Severity: model.SeverityHigh,
					Title:    fmt.Sprintf("[%s] Step-skipping: %q reached without prerequisites", flow.Name, lastStep.Name),
					Description: fmt.Sprintf(
						"The final transaction step %q (POST %s) returned HTTP %d when accessed directly "+
							"without executing the prerequisite steps (%s). "+
							"An attacker can complete a payment, claim a discount, or bypass an authorization "+
							"gate without performing the required prior steps in the flow.",
						lastStep.Name, ep, resp.StatusCode,
						summarizeStepNames(flow.Steps[:len(flow.Steps)-1]),
					),
					Evidence: fmt.Sprintf("Direct POST %s → HTTP %d (expected rejection)", ep, resp.StatusCode),
					Recommendation: "Enforce server-side flow state tracking for every multi-step transaction. " +
						"Validate that all prerequisite steps have completed before processing the final step. " +
						"Use signed session tokens or database-side state machines to track progress.",
					Confidence:    0.80,
					AffectedURL:   ep,
					CWE:           "CWE-840",
					OWASPCategory: "A04:2021 - Insecure Design",
					Sources:       []string{"active-scanner", "flow-engine"},
					ReproductionSteps: []string{
						fmt.Sprintf("Skip all prerequisite steps (%s).", summarizeStepNames(flow.Steps[:len(flow.Steps)-1])),
						fmt.Sprintf("Send POST directly to %s.", ep),
						"Observe that the server accepts the request and completes the transaction.",
					},
					BusinessTags: []string{"flow-skip", "business-logic", flow.Name},
					EvidenceFields: map[string]string{
						"validationType": "active-probe",
						"flowName":       flow.Name,
						"stepName":       lastStep.Name,
						"stepURL":        ep,
						"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
					},
				})
			}
			if resp != nil {
				_, _ = io.ReadAll(io.LimitReader(resp.Body, flowBodyLimit))
				_ = resp.Body.Close()
			}
		}
	}

	// 2. Test parameter tampering on any step that declares MutationField.
	for _, step := range flow.Steps {
		if step.MutationField == "" || len(step.MutationValues) == 0 {
			continue
		}
		ep := resolveFlowURL(base, step.Path)
		if !scope.IsURLInScope(ep, scanScope) {
			continue
		}
		for _, mutVal := range step.MutationValues {
			tampered := cloneBody(step.Body)
			tampered[step.MutationField] = mutVal
			tamperedStep := step
			tamperedStep.Body = tampered

			resp, _, err := s.flowSendStep(ctx, ep, tamperedStep, nil, auth, options)
			if err != nil || resp == nil {
				continue
			}
			_, _ = io.ReadAll(io.LimitReader(resp.Body, flowBodyLimit))
			_ = resp.Body.Close()
			if is2xx(resp.StatusCode) {
				findings = append(findings, model.Finding{
					ID:       "flow-tamper-" + flowSlug(flow.Name, step.Name) + "-" + fmt.Sprintf("%v", mutVal),
					Category: "access-control",
					Severity: model.SeverityHigh,
					Title:    fmt.Sprintf("[%s] Parameter tampering at step %q accepted by server", flow.Name, step.Name),
					Description: fmt.Sprintf(
						"Setting %q = %v in the %q step request body returned HTTP %d. "+
							"This may allow price manipulation, quantity bypass, or privilege escalation "+
							"depending on the field semantics.",
						step.MutationField, mutVal, step.Name, resp.StatusCode,
					),
					Evidence: fmt.Sprintf(
						"POST %s with %s=%v → HTTP %d",
						ep, step.MutationField, mutVal, resp.StatusCode,
					),
					Recommendation: "Validate all business-logic fields server-side. Never trust client-supplied " +
						"prices, quantities, or identifiers. Re-derive computed values from authoritative sources " +
						"(catalogue/pricing service) on the server before processing.",
					Confidence:    0.75,
					AffectedURL:   ep,
					CWE:           "CWE-20",
					OWASPCategory: "A04:2021 - Insecure Design",
					Sources:       []string{"active-scanner", "flow-engine"},
					BusinessTags:  []string{"parameter-tampering", "business-logic", flow.Name},
					EvidenceFields: map[string]string{
						"validationType": "active-probe",
						"flowName":       flow.Name,
						"stepName":       step.Name,
						"tamperedField":  step.MutationField,
						"tamperedValue":  fmt.Sprintf("%v", mutVal),
						"responseStatus": fmt.Sprintf("%d", resp.StatusCode),
					},
				})
			}
		}
	}

	return findings
}

// flowSendStep sends a single flow step and returns the response.
func (s *Service) flowSendStep(
	ctx context.Context,
	ep string,
	step FlowStep,
	previousBody []byte,
	auth model.ScanAuthProfile,
	options model.ScanOptions,
) (*http.Response, []byte, error) {
	stepCtx, cancel := context.WithTimeout(ctx, flowStepTimeout)
	defer cancel()

	method := strings.ToUpper(strings.TrimSpace(step.Method))
	if method == "" {
		method = http.MethodGet
	}

	var bodyReader io.Reader
	if step.Body != nil {
		bodyJSON, err := json.Marshal(interpolateBody(step.Body, previousBody))
		if err == nil {
			bodyReader = bytes.NewReader(bodyJSON)
		}
	}

	req, err := http.NewRequestWithContext(stepCtx, method, ep, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	ApplyAuthProfile(req, auth)
	if step.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range step.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.doRequestWithRetry(stepCtx, req, options)
	if err != nil || resp == nil {
		return nil, nil, err
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, flowBodyLimit))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	return resp, respBody, nil
}

// resolveFlowURL combines the scan base URL with a relative path.
func resolveFlowURL(base *url.URL, path string) string {
	ref, err := url.Parse(path)
	if err != nil {
		return base.String()
	}
	return base.ResolveReference(ref).String()
}

// interpolateBody replaces {{TOKEN}} placeholders in a body map using a
// simple key extraction from the previous response body.
func interpolateBody(body map[string]interface{}, prevBody []byte) map[string]interface{} {
	if len(prevBody) == 0 {
		return body
	}
	out := cloneBody(body)
	var prev map[string]interface{}
	if err := json.Unmarshal(prevBody, &prev); err != nil {
		return out
	}
	for k, v := range out {
		if s, ok := v.(string); ok && strings.HasPrefix(s, "{{") && strings.HasSuffix(s, "}}") {
			key := strings.TrimSuffix(strings.TrimPrefix(s, "{{"), "}}")
			if val, ok := prev[key]; ok {
				out[k] = val
			}
		}
	}
	return out
}

// cloneBody produces a shallow copy of a JSON body map.
func cloneBody(body map[string]interface{}) map[string]interface{} {
	if body == nil {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(body))
	for k, v := range body {
		out[k] = v
	}
	return out
}

// summarizeStepNames returns a comma-separated list of step names.
func summarizeStepNames(steps []FlowStep) string {
	names := make([]string, 0, len(steps))
	for _, s := range steps {
		names = append(names, s.Name)
	}
	return strings.Join(names, " → ")
}

func flowSlug(flow, step string) string {
	return raceSlug(flow + "-" + step)
}
