package model

// ProbeOutcome classifies what a scanner hypothesis probe observed at the
// HTTP level. It is set even when no vulnerability is confirmed so the AI
// can distinguish between "the target is not vulnerable" and "the probe was
// actively suppressed or produced an anomalous signal worth investigating".
type ProbeOutcome string

const (
	// ProbeConfirmed means the probe returned a deterministic oracle signal
	// and a finding was produced (e.g. SQL error string in body, unescaped
	// XSS payload reflected, credentialed CORS response).
	ProbeConfirmed ProbeOutcome = "confirmed"

	// ProbeWAFBlocked means the server returned HTTP 403, 406, or 429, or
	// the body contained a known WAF interception signature, indicating the
	// payload was filtered before reaching the application logic. The
	// vulnerability may still be present; an evasion-variant payload is
	// warranted.
	ProbeWAFBlocked ProbeOutcome = "waf_blocked"

	// ProbeNearMiss means the probe received a response that contains
	// partial signals consistent with vulnerability (e.g. the body has
	// SQL-like error text but not an exact confirmed error string, or the
	// payload appears in the body but inside a JavaScript string context
	// rather than raw HTML). A refined payload targeting the specific
	// context may confirm the finding.
	ProbeNearMiss ProbeOutcome = "near_miss"

	// ProbeServerError means the server returned HTTP 5xx. A 500 on an
	// injection probe is itself a potential signal (unhandled exception
	// from malformed input). The AI should consider a follow-up probe.
	ProbeServerError ProbeOutcome = "server_error"

	// ProbeNoSignal means the probe returned a normal response with no
	// observable anomalies. The target appears not vulnerable on this
	// endpoint/parameter/payload combination.
	ProbeNoSignal ProbeOutcome = "no_signal"

	// ProbeError means the probe could not be completed due to a network
	// error, context cancellation, or invalid URL.
	ProbeError ProbeOutcome = "error"
)

// ProbeResult captures the full outcome of a single hypothesis probe. Unlike
// the binary confirmed / not-confirmed result of RunHypothesisVerification,
// ProbeResult preserves every HTTP-level signal so that the AI's Reflect step
// can reason about WHY a probe failed and adapt its strategy accordingly.
//
// Fields are intentionally plain types so the struct can be serialised to JSON
// and included verbatim in the AI reflection prompt.
type ProbeResult struct {
	// Category is the vulnerability class that was probed (e.g. "xss", "sqli").
	Category string `json:"category"`

	// Endpoint is the target URL.
	Endpoint string `json:"endpoint"`

	// ParamName is the HTTP parameter that received the payload.
	ParamName string `json:"paramName,omitempty"`

	// Payload is the exact string sent as the parameter value.
	Payload string `json:"payload"`

	// Outcome classifies what the probe observed at the HTTP level.
	Outcome ProbeOutcome `json:"outcome"`

	// StatusCode is the HTTP status code returned by the server.
	StatusCode int `json:"statusCode"`

	// Observation is a one- or two-sentence plain-English description of
	// what the probe observed. This is written for the AI: it describes
	// the response in terms a penetration tester would understand and
	// includes the most relevant diagnostic detail (e.g. "Server returned
	// 403 with Cloudflare interception page — WAF is active on this
	// endpoint. Try a URL-encoded or case-variant payload.").
	Observation string `json:"observation"`

	// Confirmed is true when the probe produced a verified finding.
	Confirmed bool `json:"confirmed"`

	// Finding is non-nil when Confirmed is true.
	Finding *Finding `json:"finding,omitempty"`
}
