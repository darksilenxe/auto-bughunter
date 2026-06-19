package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

// runDNSSANProbe performs passive DNS reconnaissance and certificate SAN
// evaluation against the target hostname.
//
// DNS checks (WSTG-INFO-02 / WSTG-CONF-10):
//   - A and AAAA records (forward resolution)
//   - PTR / reverse-DNS records for each resolved IP
//   - CNAME chain unwinding
//   - NS records (nameserver enumeration)
//   - MX records (mail server exposure)
//   - TXT records (SPF, DMARC, DKIM, verification tokens)
//   - Wildcard DNS detection (*.hostname resolves)
//   - Missing forward DNS (unresolvable target)
//
// Certificate SAN checks (WSTG-CRYP-01):
//   - Complete SAN list (DNSNames, IPs, URIs)
//   - Hostname ↔ SAN mismatch detection
//   - CN-only certificate (deprecated — no SANs)
//   - Overly broad wildcard SANs (e.g., *.tld)
//   - IP address SANs that may widen attack surface
//   - Additional hostnames discovered via SANs (potential extra targets)
//
// All checks are read-only observations; nothing modifies server state.
func (s *Service) runDNSSANProbe(ctx context.Context, input RunInput) []model.Finding {
	u, err := url.Parse(input.Target)
	if err != nil || u.Host == "" {
		return nil
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil
	}

	var findings []model.Finding

	// ── DNS evaluation ────────────────────────────────────────────────────────
	findings = append(findings, checkDNSRecords(ctx, hostname, input.Target)...)

	// ── Certificate SAN evaluation (HTTPS only) ───────────────────────────────
	if u.Scheme == "https" {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		findings = append(findings, checkCertSANs(hostname, net.JoinHostPort(hostname, port), input.Target)...)
	}

	return findings
}

// ---------------------------------------------------------------------------
// DNS checks
// ---------------------------------------------------------------------------

func checkDNSRecords(ctx context.Context, hostname, target string) []model.Finding {
	resolver := &net.Resolver{}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var findings []model.Finding

	// ── 1. Forward A / AAAA lookup ─────────────────────────────────────────
	addrs, err := resolver.LookupHost(dialCtx, hostname)
	if err != nil || len(addrs) == 0 {
		findings = append(findings, model.Finding{
			ID:       "dns-no-resolution",
			Category: "dns",
			Severity: model.SeverityMedium,
			Title:    "Target hostname does not resolve",
			Description: fmt.Sprintf(
				"The hostname %q could not be resolved to any IP address. "+
					"This may indicate a dangling DNS entry (potential subdomain takeover), "+
					"a misconfiguration, or a decommissioned service.",
				hostname,
			),
			Evidence:       fmt.Sprintf("hostname=%s lookupError=%v", hostname, err),
			Recommendation: "Verify the DNS record is intentional. Remove any dangling CNAME or A records pointing to decommissioned infrastructure.",
			AffectedURL:    target,
			CWE:            "CWE-350",
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"hostname":       hostname,
				"error":          fmt.Sprintf("%v", err),
			},
		})
		return findings // no point checking further without an IP
	}

	ipv4s := filterIPs(addrs, false)
	ipv6s := filterIPs(addrs, true)
	allIPs := append(ipv4s, ipv6s...)

	findings = append(findings, model.Finding{
		ID:       "dns-forward-resolution",
		Category: "dns",
		Severity: model.SeverityInfo,
		Title:    fmt.Sprintf("DNS resolved %q to %d address(es)", hostname, len(allIPs)),
		Description: "Forward DNS lookup completed successfully. The resolved IP addresses are " +
			"recorded for cross-referencing against certificate SANs and reverse-DNS entries.",
		Evidence: fmt.Sprintf("hostname=%s A=%s AAAA=%s",
			hostname, strings.Join(ipv4s, ","), strings.Join(ipv6s, ",")),
		Recommendation: "Verify all resolved IPs are expected. Unexpected IPs may indicate DNS hijacking or unauthorised delegation.",
		AffectedURL:    target,
		Sources:        []string{"passive-scanner", "dns-san"},
		EvidenceFields: map[string]string{
			"validationType": "safe-observation",
			"hostname":       hostname,
			"ipv4":           strings.Join(ipv4s, ","),
			"ipv6":           strings.Join(ipv6s, ","),
		},
	})

	// ── 2. Reverse PTR lookup for each resolved IP ─────────────────────────
	ptrMismatches := []string{}
	for _, ip := range allIPs {
		ptrCtx, ptrCancel := context.WithTimeout(ctx, 5*time.Second)
		ptrs, ptrErr := resolver.LookupAddr(ptrCtx, ip)
		ptrCancel()
		if ptrErr != nil || len(ptrs) == 0 {
			ptrMismatches = append(ptrMismatches, fmt.Sprintf("%s→(no PTR)", ip))
			continue
		}
		// Normalise: strip trailing dot
		for i, p := range ptrs {
			ptrs[i] = strings.TrimSuffix(p, ".")
		}
		// Check if PTR matches the forward hostname
		matched := false
		for _, ptr := range ptrs {
			if strings.EqualFold(ptr, hostname) || strings.HasSuffix(strings.ToLower(ptr), "."+strings.ToLower(hostname)) {
				matched = true
				break
			}
		}
		if !matched {
			ptrMismatches = append(ptrMismatches, fmt.Sprintf("%s→[%s]", ip, strings.Join(ptrs, ",")))
		}
	}
	if len(ptrMismatches) > 0 {
		findings = append(findings, model.Finding{
			ID:       "dns-ptr-mismatch",
			Category: "dns",
			Severity: model.SeverityInfo,
			Title:    "Reverse DNS (PTR) does not match forward hostname",
			Description: "The PTR record for one or more resolved IPs does not match the forward hostname. " +
				"This is common for shared hosting and CDNs, but may also indicate the IP is shared " +
				"infrastructure that could affect security boundary assumptions.",
			Evidence:       strings.Join(ptrMismatches, "; "),
			Recommendation: "If this is dedicated infrastructure, align forward and reverse DNS for operational clarity and email deliverability.",
			AffectedURL:    target,
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"mismatches":     strings.Join(ptrMismatches, "; "),
			},
		})
	}

	// ── 3. CNAME chain ─────────────────────────────────────────────────────
	cnameCtx, cnameCancel := context.WithTimeout(ctx, 5*time.Second)
	cname, cnameErr := resolver.LookupCNAME(cnameCtx, hostname)
	cnameCancel()
	cname = strings.TrimSuffix(cname, ".")
	if cnameErr == nil && !strings.EqualFold(cname, hostname) {
		// CNAME points somewhere else — note it for visibility
		findings = append(findings, model.Finding{
			ID:       "dns-cname-target",
			Category: "dns",
			Severity: model.SeverityInfo,
			Title:    fmt.Sprintf("DNS CNAME delegation to %q", cname),
			Description: fmt.Sprintf(
				"The hostname %q is a CNAME pointing to %q. "+
					"Security controls (WAF, rate-limiting, TLS termination) may be applied at the "+
					"CNAME target rather than the visible hostname, affecting the attack surface.",
				hostname, cname,
			),
			Evidence:       fmt.Sprintf("CNAME %s → %s", hostname, cname),
			Recommendation: "Ensure security controls are enforced at the CNAME target. If the CNAME points to third-party infrastructure, verify the provider account cannot be claimed (subdomain takeover).",
			AffectedURL:    target,
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"cname":          cname,
			},
		})
	}

	// ── 4. NS records (nameserver enumeration) ─────────────────────────────
	// Look up the registrable domain (strip one label from the hostname)
	nsCtx, nsCancel := context.WithTimeout(ctx, 5*time.Second)
	nss, nsErr := resolver.LookupNS(nsCtx, registrableDomain(hostname))
	nsCancel()
	if nsErr == nil && len(nss) > 0 {
		nsNames := make([]string, 0, len(nss))
		for _, ns := range nss {
			nsNames = append(nsNames, strings.TrimSuffix(ns.Host, "."))
		}
		sort.Strings(nsNames)
		findings = append(findings, model.Finding{
			ID:       "dns-ns-records",
			Category: "dns",
			Severity: model.SeverityInfo,
			Title:    fmt.Sprintf("Nameserver records: %s", strings.Join(nsNames, ", ")),
			Description: "Nameserver records reveal the DNS provider and can help identify shared " +
				"infrastructure, third-party DNS hosting, or authoritative servers that may " +
				"be a target for DNS cache poisoning or zone transfer attacks.",
			Evidence:       fmt.Sprintf("NS %s → [%s]", registrableDomain(hostname), strings.Join(nsNames, ", ")),
			Recommendation: "Ensure DNS provider enforces DNSSEC and disables zone transfers (AXFR) to unauthorised sources.",
			AffectedURL:    target,
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"nameservers":    strings.Join(nsNames, ","),
			},
		})
	}

	// ── 5. MX records ──────────────────────────────────────────────────────
	mxCtx, mxCancel := context.WithTimeout(ctx, 5*time.Second)
	mxs, mxErr := resolver.LookupMX(mxCtx, registrableDomain(hostname))
	mxCancel()
	if mxErr == nil && len(mxs) > 0 {
		mxHosts := make([]string, 0, len(mxs))
		for _, mx := range mxs {
			mxHosts = append(mxHosts, strings.TrimSuffix(mx.Host, "."))
		}
		findings = append(findings, model.Finding{
			ID:       "dns-mx-records",
			Category: "dns",
			Severity: model.SeverityInfo,
			Title:    fmt.Sprintf("Mail exchanger (MX) records: %s", strings.Join(mxHosts, ", ")),
			Description: "MX records identify mail exchange infrastructure. Mail servers are frequent " +
				"targets for phishing, relay abuse, and email-based injection attacks.",
			Evidence:       fmt.Sprintf("MX %s → [%s]", registrableDomain(hostname), strings.Join(mxHosts, ", ")),
			Recommendation: "Ensure SPF, DKIM, and DMARC are properly configured to prevent email spoofing.",
			AffectedURL:    target,
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"mxHosts":        strings.Join(mxHosts, ","),
			},
		})
	}

	// ── 6. TXT records (SPF / DMARC / DKIM / verification tokens) ──────────
	txtCtx, txtCancel := context.WithTimeout(ctx, 5*time.Second)
	txts, txtErr := resolver.LookupTXT(txtCtx, registrableDomain(hostname))
	txtCancel()
	if txtErr == nil && len(txts) > 0 {
		spfFound := false
		dmarcFound := false
		sensitiveTokens := []string{}
		for _, txt := range txts {
			lower := strings.ToLower(txt)
			if strings.HasPrefix(lower, "v=spf1") {
				spfFound = true
			}
			if strings.HasPrefix(lower, "v=dmarc1") {
				dmarcFound = true
			}
			// Flag potentially sensitive verification tokens (site-verify, domain-confirm, etc.)
			if containsAny(lower, "verification=", "verify=", "token=", "secret=", "key=", "api-key=") {
				sensitiveTokens = append(sensitiveTokens, txt)
			}
		}

		if !spfFound {
			findings = append(findings, model.Finding{
				ID:       "dns-no-spf",
				Category: "dns",
				Severity: model.SeverityMedium,
				Title:    "No SPF record found",
				Description: fmt.Sprintf(
					"No Sender Policy Framework (SPF) TXT record was found for %s. "+
						"Without SPF, anyone can send email claiming to be from this domain, "+
						"enabling phishing and social-engineering attacks.",
					registrableDomain(hostname),
				),
				Evidence:       fmt.Sprintf("TXT lookup for %s returned no v=spf1 record", registrableDomain(hostname)),
				Recommendation: "Publish a valid SPF TXT record, e.g.: v=spf1 include:_spf.google.com ~all",
				AffectedURL:    target,
				CWE:            "CWE-346",
				Sources:        []string{"passive-scanner", "dns-san"},
				EvidenceFields: map[string]string{
					"validationType": "safe-observation",
					"domain":         registrableDomain(hostname),
				},
			})
		}

		dmarcCtx, dmarcCancel := context.WithTimeout(ctx, 5*time.Second)
		dmarcTxts, dmarcErr := resolver.LookupTXT(dmarcCtx, "_dmarc."+registrableDomain(hostname))
		dmarcCancel()
		if dmarcErr != nil || len(dmarcTxts) == 0 {
			dmarcFound = false
		} else {
			for _, t := range dmarcTxts {
				if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
					dmarcFound = true
					break
				}
			}
		}
		if !dmarcFound {
			findings = append(findings, model.Finding{
				ID:       "dns-no-dmarc",
				Category: "dns",
				Severity: model.SeverityMedium,
				Title:    "No DMARC record found",
				Description: fmt.Sprintf(
					"No DMARC policy (_dmarc.%s TXT) was found. "+
						"Without DMARC, mail receivers cannot enforce SPF/DKIM alignment, "+
						"leaving the domain open to impersonation in phishing campaigns.",
					registrableDomain(hostname),
				),
				Evidence:       fmt.Sprintf("TXT lookup for _dmarc.%s returned no v=DMARC1 record", registrableDomain(hostname)),
				Recommendation: "Publish a DMARC TXT record at _dmarc." + registrableDomain(hostname) + " — start with p=none for monitoring, then enforce with p=quarantine or p=reject.",
				AffectedURL:    target,
				CWE:            "CWE-346",
				Sources:        []string{"passive-scanner", "dns-san"},
				EvidenceFields: map[string]string{
					"validationType": "safe-observation",
					"domain":         "_dmarc." + registrableDomain(hostname),
				},
			})
		}

		if len(sensitiveTokens) > 0 {
			findings = append(findings, model.Finding{
				ID:       "dns-txt-sensitive-tokens",
				Category: "dns",
				Severity: model.SeverityLow,
				Title:    "TXT records contain potentially sensitive verification tokens",
				Description: "TXT records containing key=, token=, or similar patterns may expose " +
					"service verification tokens, API keys, or secrets publicly in DNS.",
				Evidence:       strings.Join(sensitiveTokens, " | "),
				Recommendation: "Review each TXT record. Remove verification tokens once ownership is confirmed; never store permanent secrets in DNS.",
				AffectedURL:    target,
				CWE:            "CWE-312",
				Sources:        []string{"passive-scanner", "dns-san"},
				EvidenceFields: map[string]string{
					"validationType": "safe-observation",
					"tokens":         strings.Join(sensitiveTokens, " | "),
				},
			})
		}
	}

	// ── 7. Wildcard DNS detection ────────────────────────────────────────────
	wildcardLabel := fmt.Sprintf("nonexistent-abh-%d.%s", time.Now().Unix(), hostname)
	wcCtx, wcCancel := context.WithTimeout(ctx, 5*time.Second)
	wcAddrs, wcErr := resolver.LookupHost(wcCtx, wildcardLabel)
	wcCancel()
	if wcErr == nil && len(wcAddrs) > 0 {
		findings = append(findings, model.Finding{
			ID:       "dns-wildcard-detected",
			Category: "dns",
			Severity: model.SeverityMedium,
			Title:    "Wildcard DNS record detected",
			Description: fmt.Sprintf(
				"A random subdomain (%s) resolved to %s, indicating a wildcard DNS record (*.%s). "+
					"Wildcard DNS can mask subdomain takeover vulnerabilities because even dangling "+
					"CNAMEs appear to resolve, preventing standard takeover detection.",
				wildcardLabel, strings.Join(wcAddrs, ","), hostname,
			),
			Evidence:       fmt.Sprintf("probe=%s resolved=%s", wildcardLabel, strings.Join(wcAddrs, ",")),
			Recommendation: "Evaluate whether wildcard DNS is intentional. If so, audit all subdomains for dangling CNAME records that may be claimable by third parties.",
			AffectedURL:    target,
			CWE:            "CWE-350",
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"wildcardDomain": "*." + hostname,
				"resolvedIPs":    strings.Join(wcAddrs, ","),
			},
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Certificate SAN checks
// ---------------------------------------------------------------------------

func checkCertSANs(hostname, addr, target string) []model.Finding {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional: we parse cert data regardless of trust
		ServerName:         hostname,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return nil // TLS probe covers connectivity failures
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	leaf := state.PeerCertificates[0]
	var findings []model.Finding

	// Collect all SANs
	dnsNames := leaf.DNSNames
	ipSANs := leaf.IPAddresses
	uriSANs := leaf.URIs
	emailSANs := leaf.EmailAddresses
	cn := leaf.Subject.CommonName

	// ── 1. CN-only certificate (no SANs) ──────────────────────────────────
	if len(dnsNames) == 0 && len(ipSANs) == 0 {
		findings = append(findings, model.Finding{
			ID:       "cert-san-missing",
			Category: "tls",
			Severity: model.SeverityHigh,
			Title:    "Certificate has no Subject Alternative Names (CN-only, deprecated)",
			Description: fmt.Sprintf(
				"The leaf certificate for %s has no Subject Alternative Name extension. "+
					"RFC 2818 (superseded by RFC 6125) deprecated the use of CN for hostname matching. "+
					"Modern browsers (Chrome 58+, Firefox 48+) reject certificates without SANs, "+
					"causing hard connection failures for end users.",
				hostname,
			),
			Evidence:       fmt.Sprintf("CN=%s dnsSANs=0 ipSANs=0", cn),
			Recommendation: "Reissue the certificate with at least one DNS SAN matching the intended hostname.",
			AffectedURL:    target,
			CWE:            "CWE-297",
			OWASPCategory:  "A02:2021 - Cryptographic Failures",
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"cn":             cn,
			},
		})
	}

	// ── 2. Hostname ↔ SAN mismatch ─────────────────────────────────────────
	if len(dnsNames) > 0 && !leaf.VerifyHostname(hostname) == false {
		// VerifyHostname returns nil on match; check the actual error
		if verifyErr := leaf.VerifyHostname(hostname); verifyErr != nil {
			findings = append(findings, model.Finding{
				ID:       "cert-san-hostname-mismatch",
				Category: "tls",
				Severity: model.SeverityHigh,
				Title:    fmt.Sprintf("Certificate SAN does not match hostname %q", hostname),
				Description: fmt.Sprintf(
					"The certificate presented by %s does not include the request hostname "+
						"in its Subject Alternative Names (SANs=%v). "+
						"Browsers will display a certificate error, which may train users to "+
						"accept certificate warnings and masks MITM attacks.",
					hostname, dnsNames,
				),
				Evidence:       fmt.Sprintf("hostname=%s SANs=%v error=%v", hostname, dnsNames, verifyErr),
				Recommendation: "Reissue the certificate with the correct hostname in the SAN extension.",
				AffectedURL:    target,
				CWE:            "CWE-297",
				OWASPCategory:  "A02:2021 - Cryptographic Failures",
				Sources:        []string{"passive-scanner", "dns-san"},
				EvidenceFields: map[string]string{
					"validationType": "safe-observation",
					"hostname":       hostname,
					"sans":           strings.Join(dnsNames, ","),
					"error":          verifyErr.Error(),
				},
			})
		}
	}

	// ── 3. SAN inventory summary ──────────────────────────────────────────
	if len(dnsNames) > 0 {
		extraHosts := []string{}
		for _, san := range dnsNames {
			if !strings.EqualFold(san, hostname) && !strings.HasPrefix(san, "*.") {
				extraHosts = append(extraHosts, san)
			}
		}
		sort.Strings(dnsNames)
		evidenceParts := []string{fmt.Sprintf("dnsSANs=[%s]", strings.Join(dnsNames, ","))}
		if len(ipSANs) > 0 {
			ipStrs := make([]string, len(ipSANs))
			for i, ip := range ipSANs {
				ipStrs[i] = ip.String()
			}
			evidenceParts = append(evidenceParts, fmt.Sprintf("ipSANs=[%s]", strings.Join(ipStrs, ",")))
		}
		if len(uriSANs) > 0 {
			uriStrs := make([]string, len(uriSANs))
			for i, u := range uriSANs {
				uriStrs[i] = u.String()
			}
			evidenceParts = append(evidenceParts, fmt.Sprintf("uriSANs=[%s]", strings.Join(uriStrs, ",")))
		}
		if len(emailSANs) > 0 {
			evidenceParts = append(evidenceParts, fmt.Sprintf("emailSANs=[%s]", strings.Join(emailSANs, ",")))
		}

		rec := "Review the complete SAN list to ensure all covered hostnames are still in use."
		if len(extraHosts) > 0 {
			rec += fmt.Sprintf(" The following non-wildcard SANs represent additional in-scope hostnames: %s", strings.Join(extraHosts, ", "))
		}

		findings = append(findings, model.Finding{
			ID:       "cert-san-inventory",
			Category: "tls",
			Severity: model.SeverityInfo,
			Title:    fmt.Sprintf("Certificate covers %d DNS SAN(s)", len(dnsNames)),
			Description: "The certificate Subject Alternative Names define the complete set of " +
				"hostnames and IP addresses the certificate is valid for. " +
				"Additional SANs may represent wider attack surface.",
			Evidence:       strings.Join(evidenceParts, " "),
			Recommendation: rec,
			AffectedURL:    target,
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"dnsSANs":        strings.Join(dnsNames, ","),
				"cn":             cn,
			},
		})
	}

	// ── 4. Overly broad wildcard SANs ──────────────────────────────────────
	broadWildcards := []string{}
	for _, san := range dnsNames {
		if !strings.HasPrefix(san, "*.") {
			continue
		}
		// Strip wildcard prefix and check if the remainder is a TLD or near-TLD
		base := strings.TrimPrefix(san, "*.")
		parts := strings.Split(base, ".")
		if len(parts) <= 1 {
			// *.tld — covers an entire TLD
			broadWildcards = append(broadWildcards, san)
		} else if len(parts) == 2 {
			// *.example.com is normal; flag only if the second-level is 2-3 chars (country-code SLD like *.co.uk)
			if len(parts[0]) <= 3 {
				broadWildcards = append(broadWildcards, san)
			}
		}
	}
	if len(broadWildcards) > 0 {
		findings = append(findings, model.Finding{
			ID:       "cert-san-broad-wildcard",
			Category: "tls",
			Severity: model.SeverityMedium,
			Title:    "Certificate contains overly broad wildcard SAN(s)",
			Description: fmt.Sprintf(
				"The certificate contains wildcard SANs (%s) that cover a very wide hostname space. "+
					"A single compromised certificate grants a man-in-the-middle attacker the ability "+
					"to impersonate any subdomain covered by the wildcard.",
				strings.Join(broadWildcards, ", "),
			),
			Evidence:       fmt.Sprintf("broadWildcards=%s", strings.Join(broadWildcards, ",")),
			Recommendation: "Limit wildcard certificates to the minimum necessary hostname scope. " +
				"Prefer per-hostname or single-subdomain-level wildcards (e.g., *.example.com rather than *.com).",
			AffectedURL:    target,
			CWE:            "CWE-295",
			OWASPCategory:  "A02:2021 - Cryptographic Failures",
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType":  "safe-observation",
				"broadWildcards":  strings.Join(broadWildcards, ","),
			},
		})
	}

	// ── 5. IP address SANs ────────────────────────────────────────────────
	if len(ipSANs) > 0 {
		ipStrs := make([]string, len(ipSANs))
		for i, ip := range ipSANs {
			ipStrs[i] = ip.String()
		}
		findings = append(findings, model.Finding{
			ID:       "cert-san-ip-addresses",
			Category: "tls",
			Severity: model.SeverityInfo,
			Title:    fmt.Sprintf("Certificate contains %d IP address SAN(s): %s", len(ipSANs), strings.Join(ipStrs, ", ")),
			Description: "IP address SANs in the certificate reveal server IP addresses that may " +
				"bypass DNS-based access controls or geo-restrictions when accessed directly.",
			Evidence:       fmt.Sprintf("ipSANs=%s", strings.Join(ipStrs, ",")),
			Recommendation: "Ensure direct IP access is restricted or returns identical security controls as the hostname-based endpoint.",
			AffectedURL:    target,
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"ipSANs":         strings.Join(ipStrs, ","),
			},
		})
	}

	// ── 6. Expired or soon-to-expire certificate ───────────────────────────
	// (complements checkTLS — that uses TLS 1.2 min, this uses InsecureSkipVerify
	// so we still capture expiry even when the chain is already untrusted)
	notAfter := leaf.NotAfter
	daysLeft := int(time.Until(notAfter).Hours() / 24)
	if daysLeft < 0 {
		findings = append(findings, model.Finding{
			ID:       "cert-san-expired",
			Category: "tls",
			Severity: model.SeverityHigh,
			Title:    "Certificate is expired",
			Description: fmt.Sprintf(
				"The TLS certificate for %s expired %d day(s) ago (NotAfter: %s). "+
					"Expired certificates cause hard browser failures and erode user trust.",
				hostname, -daysLeft, notAfter.UTC().Format(time.RFC3339),
			),
			Evidence:       fmt.Sprintf("notAfter=%s daysLeft=%d", notAfter.UTC().Format(time.RFC3339), daysLeft),
			Recommendation: "Renew the certificate immediately. Consider automated renewal with ACME / Let's Encrypt.",
			AffectedURL:    target,
			CWE:            "CWE-298",
			OWASPCategory:  "A02:2021 - Cryptographic Failures",
			Sources:        []string{"passive-scanner", "dns-san"},
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"notAfter":       notAfter.UTC().Format(time.RFC3339),
				"daysLeft":       fmt.Sprintf("%d", daysLeft),
			},
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// filterIPs splits a mixed list of IPv4/IPv6 addresses.
func filterIPs(addrs []string, wantIPv6 bool) []string {
	var result []string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		isIPv6 := ip.To4() == nil
		if isIPv6 == wantIPv6 {
			result = append(result, addr)
		}
	}
	return result
}

// registrableDomain returns the last two dot-separated labels of hostname,
// which is a best-effort approximation of the registrable domain.
// e.g. "sub.example.com" → "example.com", "example.com" → "example.com"
func registrableDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// containsAny reports whether s contains any of the given substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
