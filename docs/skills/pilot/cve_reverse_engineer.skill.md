# SKILL: cve_reverse_engineer

- **Agent:** `cve_reverse_engineer`
- **Layer:** triage/review
- **Status:** pilot

## 1) Purpose

Reverse-engineer CVE-tagged findings into root-cause context and bounded reproduction guidance.

## 2) Owned decisions

- Detect and deduplicate CVE IDs across existing findings.
- Produce CVE-enriched findings using offline catalog data and optional AI analysis.
- Decide whether proposed PoC can execute under safety/scope gates.

## 3) Required inputs

- Existing findings with CVE hints.
- Target URL and scan scope/options.
- Optional AI client and offline CVE knowledge base.

## 4) Expected outputs

- CVE-enriched findings with CWE/CVSS/references and analysis notes.
- Metadata for analyzed CVEs and PoC proposed/executed/confirmed counts.

## 5) Hard constraints

- Respect CVE-per-run cap.
- Never fire PoC without safety URL validation and scope checks.
- Only execute PoC when CVE PoC execution is explicitly enabled.

## 6) Escalation / handoff

- Hand off enriched CVE findings to reporting/remediation planning.
- Leave unfired PoCs as reproduction guidance when execution is disallowed.

## 7) Non-goals (must not do)

- Must not discover brand-new vulnerabilities from raw traffic.
- Must not bypass scope or outbound safety controls.
