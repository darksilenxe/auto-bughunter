package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// An AI advisor may reorder or skip entries based on scan context.
var reconnaissanceChecks = []string{
	"dns_info",
	"http_version",
	"service_info",
}

type ReconnaissanceAgent struct {
	enabled bool
}

func NewReconnaissanceAgent(enabled bool) *ReconnaissanceAgent {
	return &ReconnaissanceAgent{enabled: enabled}
}

func (a *ReconnaissanceAgent) Name() string {
	return "reconnaissance"
}

func (a *ReconnaissanceAgent) Enabled() bool {
	return a.enabled
}

func (a *ReconnaissanceAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	host := extractHost(input.Target)
	if host == "" {
		return output, fmt.Errorf("invalid target URL")
	}

	// If an AgentAdvisor pre-run hook wrote advice to the blackboard, use it
	// to reorder or skip checks. Default order is preserved when no advice is
	// present.
	advice := ParseAdviceNote(input.SharedScanContext.GetNote(a.Name()))
	ordered := OrderChecks(advice, reconnaissanceChecks)

	type checkFn func()
	checkMap := map[string]checkFn{
		"dns_info":     func() { gatherDNSInfo(ctx, host, &output) },
		"http_version": func() { gatherHTTPVersion(ctx, input.Target, &output) },
		"service_info": func() { gatherServiceInfo(ctx, host, &output) },
	}

	for _, check := range ordered {
		if ctx.Err() != nil {
			break
		}
		if fn, ok := checkMap[check]; ok {
			fn()
		}
	}

	if input.SharedScanContext != nil {
		if server := strings.TrimSpace(output.Metadata["server_header"]); server != "" {
			input.SharedScanContext.SetTechStack([]string{server})
			input.SharedScanContext.AddDiscovery(DiscoveryEvent{
				Kind:        DiscoveryTechStack,
				Value:       server,
				SourceAgent: a.Name(),
				Confidence:  0.9,
			}, input.Emit)
		} else if proto := strings.TrimSpace(output.Metadata["http_version"]); proto != "" {
			input.SharedScanContext.SetTechStack([]string{proto})
			input.SharedScanContext.AddDiscovery(DiscoveryEvent{
				Kind:        DiscoveryTechStack,
				Value:       proto,
				SourceAgent: a.Name(),
				Confidence:  0.6,
			}, input.Emit)
		}
		if ips := strings.TrimSpace(output.Metadata["resolved_ips"]); ips != "" {
			input.SharedScanContext.AddDiscovery(DiscoveryEvent{
				Kind:        DiscoveryGeneric,
				Value:       "resolved_ips=" + ips,
				SourceAgent: a.Name(),
				Confidence:  1.0,
			}, input.Emit)
		}
	}

	output.DebugNotes = fmt.Sprintf("Reconnaissance completed for %s. Checked: %s. Discovered %d services/endpoints.", host, strings.Join(ordered, ", "), len(output.Findings))
	return output, nil
}

func gatherDNSInfo(ctx context.Context, host string, output *AgentOutput) {
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err == nil && len(ips) > 0 {
		ipStrs := make([]string, 0, len(ips))
		for _, ip := range ips {
			ipStrs = append(ipStrs, ip.String())
		}
		output.Metadata["resolved_ips"] = strings.Join(ipStrs, ";")

		if len(ips) > 1 {
			output.Findings = append(output.Findings, model.Finding{
				ID:             "recon-multiple-ips",
				Category:       "reconnaissance",
				Severity:       model.SeverityInfo,
				Title:          "Multiple IP addresses resolved",
				Description:    fmt.Sprintf("The target domain resolves to %d IP addresses (load balancing/failover detected).", len(ips)),
				Evidence:       strings.Join(ipStrs, ", "),
				Recommendation: "Verify all IPs are under the same security policy; scan each if necessary.",
			})
		}
	}

	mxRecords, err := resolver.LookupMX(ctx, host)
	if err == nil && len(mxRecords) > 0 {
		output.Metadata["mx_records"] = fmt.Sprintf("%d", len(mxRecords))
	}
}

func gatherHTTPVersion(ctx context.Context, target string, output *AgentOutput) {
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		defer resp.Body.Close()
		output.Metadata["http_version"] = resp.Proto
		output.Metadata["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
		if server := strings.TrimSpace(resp.Header.Get("Server")); server != "" {
			output.Metadata["server_header"] = server
		}

		if strings.Contains(resp.Proto, "1.0") {
			output.Findings = append(output.Findings, model.Finding{
				ID:             "recon-http10",
				Category:       "reconnaissance",
				Severity:       model.SeverityLow,
				Title:          "HTTP 1.0 detected",
				Description:    "Target is using HTTP 1.0, which lacks modern security features.",
				Evidence:       resp.Proto,
				Recommendation: "Upgrade to HTTP/1.1 or HTTP/2 to enable Keep-Alive and other security headers.",
			})
		}
	}
}

func gatherServiceInfo(ctx context.Context, host string, output *AgentOutput) {
	commonPorts := []int{25, 53, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 27017}
	openCount := 0

	for _, port := range commonPorts {
		select {
		case <-ctx.Done():
			return
		default:
		}

		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			openCount++
		}
	}

	if openCount > 0 {
		output.Findings = append(output.Findings, model.Finding{
			ID:             "recon-open-services",
			Category:       "reconnaissance",
			Severity:       model.SeverityInfo,
			Title:          "Open network services detected",
			Description:    fmt.Sprintf("%d additional network services are accessible on common ports.", openCount),
			Evidence:       fmt.Sprintf("open_count=%d", openCount),
			Recommendation: "Document which services are intentional; close unnecessary ones.",
		})
	}
}

func extractHost(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
