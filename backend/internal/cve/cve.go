// Package cve provides CVE-identifier detection and a small offline
// knowledge base used by the cve_reverse_engineer agent to seed AI-driven
// root-cause analysis and PoC generation with known CVSS/CWE/reference data
// before falling back to a live NVD lookup (when configured) or the AI
// provider's own knowledge.
package cve

import (
	"regexp"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// idPattern matches CVE identifiers such as "CVE-2021-44228" case-insensitively.
var idPattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

// Record is a small, structured summary of a known CVE, sourced either from
// the bundled offline knowledge base or from a live lookup client.
type Record struct {
	ID         string
	Summary    string
	CWE        string
	CVSSVector string
	CVSSScore  float64
	References []string
	// Source describes where this record came from (e.g. "offline", "nvd").
	Source string
}

// offlineDB is a small curated set of high-value web-facing CVEs that the
// platform's native probes (see agent.MetasploitAgent) already fingerprint.
// It is intentionally not exhaustive: it exists to give the AI reverse-
// engineering agent a grounded starting point when it encounters one of
// these well-known identifiers, and to produce a useful write-up even when
// no AI provider or live CVE database is configured.
var offlineDB = map[string]Record{
	"CVE-2021-44228": {
		ID:         "CVE-2021-44228",
		Summary:    "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP/RMI lookups, allowing remote code execution when a crafted string is logged (\"Log4Shell\").",
		CWE:        "CWE-502",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		CVSSScore:  10.0,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"},
		Source:     "offline",
	},
	"CVE-2022-22965": {
		ID:         "CVE-2022-22965",
		Summary:    "Spring Framework allows remote code execution via data binding on JDK 9+ when running as a WAR deployment (\"Spring4Shell\").",
		CWE:        "CWE-94",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22965"},
		Source:     "offline",
	},
	"CVE-2014-6271": {
		ID:         "CVE-2014-6271",
		Summary:    "GNU Bash processes trailing commands in function definitions passed via environment variables, allowing remote command execution through CGI (\"Shellshock\").",
		CWE:        "CWE-78",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-6271"},
		Source:     "offline",
	},
	"CVE-2017-5638": {
		ID:         "CVE-2017-5638",
		Summary:    "Apache Struts 2 Jakarta Multipart parser mishandles the Content-Type header, allowing OGNL expression injection and remote code execution (S2-045/S2-057 family).",
		CWE:        "CWE-94",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  10.0,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-5638"},
		Source:     "offline",
	},
	"CVE-2021-41773": {
		ID:         "CVE-2021-41773",
		Summary:    "Apache HTTP Server path normalization flaw allows path traversal and, when CGI is enabled, remote code execution.",
		CWE:        "CWE-22",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
		Source:     "offline",
	},
	"CVE-2018-7600": {
		ID:         "CVE-2018-7600",
		Summary:    "Drupal core does not sufficiently sanitize form API render arrays, allowing unauthenticated remote code execution (\"Drupalgeddon2\").",
		CWE:        "CWE-20",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
		Source:     "offline",
	},
	"CVE-2021-26084": {
		ID:         "CVE-2021-26084",
		Summary:    "Confluence Server and Data Center OGNL injection allows an unauthenticated attacker to execute arbitrary code.",
		CWE:        "CWE-917",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-26084"},
		Source:     "offline",
	},
	"CVE-2019-19781": {
		ID:         "CVE-2019-19781",
		Summary:    "Citrix ADC and Gateway path traversal allows unauthenticated arbitrary code execution.",
		CWE:        "CWE-22",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-19781"},
		Source:     "offline",
	},
	"CVE-2021-26855": {
		ID:         "CVE-2021-26855",
		Summary:    "Microsoft Exchange Server SSRF (\"ProxyLogon\") allows an unauthenticated attacker to send arbitrary HTTP requests and authenticate as the Exchange server.",
		CWE:        "CWE-918",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-26855"},
		Source:     "offline",
	},
	"CVE-2019-16759": {
		ID:         "CVE-2019-16759",
		Summary:    "vBulletin widgetConfig template rendering allows unauthenticated remote code execution.",
		CWE:        "CWE-94",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-16759"},
		Source:     "offline",
	},
	"CVE-2020-5902": {
		ID:         "CVE-2020-5902",
		Summary:    "F5 BIG-IP TMUI path traversal allows unauthenticated remote code execution.",
		CWE:        "CWE-22",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:  9.8,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-5902"},
		Source:     "offline",
	},
	"CVE-2019-11510": {
		ID:         "CVE-2019-11510",
		Summary:    "Pulse Connect Secure arbitrary file read allows an unauthenticated attacker to retrieve sensitive files, including credentials.",
		CWE:        "CWE-22",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSSScore:  7.5,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-11510"},
		Source:     "offline",
	},
	"CVE-2020-3452": {
		ID:         "CVE-2020-3452",
		Summary:    "Cisco ASA/FTD web services path traversal allows unauthenticated arbitrary file read.",
		CWE:        "CWE-22",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSSScore:  7.5,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-3452"},
		Source:     "offline",
	},
	"CVE-2018-13379": {
		ID:         "CVE-2018-13379",
		Summary:    "Fortinet FortiOS SSL VPN path traversal allows unauthenticated arbitrary file read, including cleartext session credentials.",
		CWE:        "CWE-22",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CVSSScore:  7.5,
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-13379"},
		Source:     "offline",
	},
}

// Normalize upper-cases a CVE identifier and trims surrounding whitespace so
// lookups and de-duplication are consistent regardless of source casing.
func Normalize(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// Lookup returns the offline knowledge-base record for a CVE identifier, if
// known. The returned bool reports whether a record was found.
func Lookup(id string) (Record, bool) {
	rec, ok := offlineDB[Normalize(id)]
	return rec, ok
}

// DetectFindingCVEs scans a finding's textual fields for CVE identifiers and
// returns the de-duplicated, normalized set found (e.g. []string{"CVE-2021-44228"}).
// It looks at Title, Description, Evidence, Recommendation, Impact,
// References, Sources and every value in EvidenceFields so that CVE IDs
// surfaced by any probe or integration (retire.js Identifiers.CVE, nuclei
// template IDs, Metasploit probe titles, etc.) are recognized uniformly.
func DetectFindingCVEs(f model.Finding) []string {
	var sb strings.Builder
	sb.WriteString(f.Title)
	sb.WriteByte(' ')
	sb.WriteString(f.Description)
	sb.WriteByte(' ')
	sb.WriteString(f.Evidence)
	sb.WriteByte(' ')
	sb.WriteString(f.Recommendation)
	sb.WriteByte(' ')
	sb.WriteString(f.Impact)
	sb.WriteByte(' ')
	for _, r := range f.References {
		sb.WriteString(r)
		sb.WriteByte(' ')
	}
	for _, s := range f.Sources {
		sb.WriteString(s)
		sb.WriteByte(' ')
	}
	for _, v := range f.EvidenceFields {
		sb.WriteString(v)
		sb.WriteByte(' ')
	}

	matches := idPattern.FindAllString(sb.String(), -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		norm := Normalize(m)
		if seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	sort.Strings(out)
	return out
}
