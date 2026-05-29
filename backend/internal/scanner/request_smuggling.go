package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scope"
)

// smugglingDialTimeout bounds the TCP/TLS handshake for the raw-socket probe.
const smugglingDialTimeout = 8 * time.Second

// smugglingReadTimeout bounds how long the probe waits for a response. The
// detection relies on a vulnerable back-end exceeding this while waiting for
// bytes that never arrive (a self-inflicted timeout that does NOT poison other
// users' connections).
const smugglingReadTimeout = 6 * time.Second

// smugglingMinDelta is the minimum extra latency (probe minus baseline) that is
// treated as a desync signal when the probe does not fully time out.
const smugglingMinDelta = 4 * time.Second

// runRequestSmugglingProbe performs a conservative, timing-based HTTP request
// smuggling (desync) detection. It uses the standard CL.TE / TE.CL "self
// timeout" technique: a crafted request that causes a vulnerable back-end to
// block waiting for additional bytes, delaying *this* connection's response
// without leaving a dangling partial request that could affect other users.
//
// It is deliberately detection-only — it never sends a complete smuggled
// follow-up request — and runs only in active (non-passive) mode against an
// in-scope, SSRF-validated target.
func (s *Service) runRequestSmugglingProbe(ctx context.Context, input RunInput, _ string) []model.Finding {
	if input.Options.PassiveOnly {
		return nil
	}

	u, err := url.Parse(strings.TrimSpace(input.Target))
	if err != nil || u.Host == "" {
		return nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	if !scope.IsURLInScope(input.Target, input.Scope) || safety.ValidateOutboundURL(input.Target) != nil {
		return nil
	}

	if input.Emit != nil {
		input.Emit(model.ScanEvent{
			Type:    model.ScanEventCommand,
			Command: fmt.Sprintf("request-smuggling %s", input.Target),
			Message: "Probing for HTTP request smuggling (CL.TE/TE.CL desync) via timing differential",
		})
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	hostHeader := u.Host

	// Establish a fast baseline: a well-formed request should return promptly.
	baseline, ok := s.smugglingRequest(ctx, u, smugglingBaselineRequest(path, hostHeader))
	if !ok || baseline.timedOut {
		// If even a normal request is slow/unreachable, timing analysis is
		// unreliable — abort rather than risk a false positive.
		return nil
	}

	variants := []struct {
		name    string
		variant string
		payload string
	}{
		{"CL.TE", "clte", smugglingCLTERequest(path, hostHeader)},
		{"TE.CL", "tecl", smugglingTECLRequest(path, hostHeader)},
	}

	for _, v := range variants {
		probe, ok := s.smugglingRequest(ctx, u, v.payload)
		if !ok {
			continue
		}
		if !classifySmuggling(baseline.elapsed, probe.elapsed, probe.timedOut) {
			continue
		}
		// Confirm with a second probe to reduce flakiness from transient
		// network jitter.
		confirm, ok := s.smugglingRequest(ctx, u, v.payload)
		if !ok || !classifySmuggling(baseline.elapsed, confirm.elapsed, confirm.timedOut) {
			continue
		}

		return []model.Finding{{
			ID:       "request-smuggling-" + v.variant,
			Category: "injection",
			Severity: model.SeverityHigh,
			Title:    fmt.Sprintf("Potential HTTP request smuggling (%s desync)", v.name),
			Description: fmt.Sprintf("A %s-style request caused the server to block waiting for additional request bytes while a well-formed "+
				"request returned promptly. This timing differential is the classic signature of a front-end/back-end disagreement on request "+
				"boundaries (HTTP request smuggling), which can be escalated to bypass front-end access controls, poison the shared connection, "+
				"and hijack other users' requests.", v.name),
			Evidence: fmt.Sprintf("Baseline response in %s; %s probe took %s (timed out: %t), repeated to confirm.",
				baseline.elapsed.Round(time.Millisecond), v.name, probe.elapsed.Round(time.Millisecond), probe.timedOut),
			Recommendation: "Normalise request parsing across the front-end and back-end: reject requests that contain both Content-Length and " +
				"Transfer-Encoding, disable downgraded HTTP/1.1 keep-alive reuse to back-ends where possible, and prefer HTTP/2 end-to-end. " +
				"Manually confirm with a controlled differential-response test before reporting externally.",
			Confidence:    0.5,
			AffectedURL:   input.Target,
			CWE:           "CWE-444",
			OWASPCategory: "A03:2021 - Injection",
			Sources:       []string{"active-scanner", "request-smuggling"},
			ReproductionSteps: []string{
				"Manually replay the timing test with a tool such as Burp Repeater / Turbo Intruder.",
				fmt.Sprintf("Send a well-formed request to %s and note the fast response.", input.Target),
				fmt.Sprintf("Send the %s-crafted request and observe the delayed response, confirming the parser disagreement.", v.name),
				"Validate impact with a controlled differential-response payload before any external disclosure.",
			},
			EvidenceFields: map[string]string{
				"validationType":  "active-probe-timing",
				"desyncType":      v.variant,
				"baselineMillis":  fmt.Sprintf("%d", baseline.elapsed.Milliseconds()),
				"probeMillis":     fmt.Sprintf("%d", probe.elapsed.Milliseconds()),
				"probeTimedOut":   fmt.Sprintf("%t", probe.timedOut),
				"requiresManualX": "true",
			},
		}}
	}

	return nil
}

// smugglingResult captures the timing outcome of a single raw request.
type smugglingResult struct {
	elapsed  time.Duration
	timedOut bool
}

// smugglingRequest opens a raw TCP/TLS connection to the target, writes the
// provided raw HTTP/1.1 request bytes, and measures how long the server takes
// to send the first response bytes. A read deadline bounds the wait.
func (s *Service) smugglingRequest(ctx context.Context, u *url.URL, raw string) (smugglingResult, bool) {
	addr := smugglingAddr(u)
	dialer := &net.Dialer{Timeout: smugglingDialTimeout}

	dctx, cancel := context.WithTimeout(ctx, smugglingDialTimeout)
	defer cancel()

	var conn net.Conn
	var err error
	if u.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: u.Hostname()})
	} else {
		conn, err = dialer.DialContext(dctx, "tcp", addr)
	}
	if err != nil || conn == nil {
		return smugglingResult{}, false
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(smugglingDialTimeout))
	start := time.Now()
	if _, err := conn.Write([]byte(raw)); err != nil {
		return smugglingResult{}, false
	}

	_ = conn.SetReadDeadline(time.Now().Add(smugglingReadTimeout))
	reader := bufio.NewReader(conn)
	_, err = reader.ReadByte()
	elapsed := time.Since(start)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return smugglingResult{elapsed: elapsed, timedOut: true}, true
		}
		// Connection reset / EOF: treat as a completed (non-timeout) exchange.
		return smugglingResult{elapsed: elapsed, timedOut: false}, true
	}
	return smugglingResult{elapsed: elapsed, timedOut: false}, true
}

// smugglingAddr returns host:port for the URL, defaulting the port by scheme.
func smugglingAddr(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}

// classifySmuggling reports whether the probe timing indicates a desync: either
// the probe fully timed out while the baseline was fast, or the probe took
// substantially longer than the baseline.
func classifySmuggling(baseline, probe time.Duration, probeTimedOut bool) bool {
	// Only trust the signal when the baseline itself was fast.
	if baseline >= smugglingReadTimeout-time.Second {
		return false
	}
	if probeTimedOut {
		return true
	}
	return probe-baseline >= smugglingMinDelta
}

// smugglingBaselineRequest builds a well-formed HTTP/1.1 GET request.
func smugglingBaselineRequest(path, host string) string {
	return strings.Join([]string{
		"GET " + path + " HTTP/1.1",
		"Host: " + host,
		"Connection: close",
		"User-Agent: auto-bughunter-smuggle-probe",
		"", "",
	}, "\r\n")
}

// smugglingCLTERequest builds a CL.TE timing payload. A back-end honouring
// Transfer-Encoding reads the first chunk and blocks waiting for the next
// chunk that the front-end (honouring Content-Length) never forwards.
func smugglingCLTERequest(path, host string) string {
	body := "1\r\nA\r\nX\r\n"
	return strings.Join([]string{
		"POST " + path + " HTTP/1.1",
		"Host: " + host,
		"Content-Length: 6",
		"Transfer-Encoding: chunked",
		"Connection: close",
		"",
		body,
	}, "\r\n")
}

// smugglingTECLRequest builds a TE.CL timing payload. A back-end honouring
// Content-Length blocks waiting for bytes after the front-end (honouring
// Transfer-Encoding) has already considered the request complete.
func smugglingTECLRequest(path, host string) string {
	body := "0\r\n\r\nX"
	return strings.Join([]string{
		"POST " + path + " HTTP/1.1",
		"Host: " + host,
		"Content-Length: 6",
		"Transfer-Encoding: chunked",
		"Connection: close",
		"",
		body,
	}, "\r\n")
}
