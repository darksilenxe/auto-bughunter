# SKILLS.md — Agent Skill Registry

This file is the complete, consolidated SKILL reference for every registered
agent in Auto Bughunter.  It extends the pilot set in
[`docs/skills/pilot/`](docs/skills/pilot/) to cover all agents listed in
[`backend/internal/agent/factory.go`](backend/internal/agent/factory.go).

For the canonical schema used by each entry see
[`docs/skills/SKILL_SPEC.md`](docs/skills/SKILL_SPEC.md).

---

## Ownership Layers

| Layer | Agents |
|---|---|
| **discovery/probing** | `reconnaissance`, `js_sast`, `scanning`, `advanced_coverage`, `input_validation`, `information_disclosure`, `access_control`, `api_security`, `cors_redirect`, `ssrf`, `auth_bypass`, `file_upload`, `wordlist`, `adaptive_probe` |
| **correlation/chain reasoning** | `exploit_chain`, `llm_chain_synthesis`, `hypothesis`, `pentest_loop`, `reasoning_iteration`, `attack_path` |
| **triage/review** | `analysis`, `ml_triage`, `false_positive_review`, `impact_verifier`, `cve_reverse_engineer`, `openhack_expert`, `openhack_triage` |
| **reporting/remediation** | `reporting`, `remediation_planner` |
| **tool/command generation** | `ai_tool_calling`, `tool_builder`, `hacktricks_techniques`, `dynamic_command`, `metasploit`, `burp` |

---

## Discovery / Probing Agents

---

### `reconnaissance`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Collect baseline host intelligence (DNS, HTTP version, service fingerprint) before
any active probing begins.

#### 2) Owned decisions

- Resolve the target hostname and enumerate IP addresses.
- Identify server software, HTTP version, and basic service metadata.
- Determine whether the host is reachable and worth scanning.

#### 3) Required inputs

- Target URL.
- Scan options (passive-only flag respected).

#### 4) Expected outputs

- Findings tagged `dns_info`, `http_version`, `service_info`.
- Metadata: resolved IPs, detected server/framework, HTTP version.

#### 5) Hard constraints

- Must not fire active injection probes; reconnaissance only.
- Must validate target host against scan scope before any request.

#### 6) Escalation / handoff

- Passes resolved host metadata to `scanning`, `wordlist`, and other probing agents.
- Surface newly found subdomains/IPs back to the orchestrator for scope expansion.

#### 7) Non-goals (must not do)

- Must not perform active vulnerability probing.
- Must not modify target state.

---

### `js_sast`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Capture in-scope JavaScript bundles and run a static analysis pass to flag
client-side weakness sinks, code defects, and extract SPA routes.

#### 2) Owned decisions

- Fetch and parse all in-scope JavaScript bundles.
- Classify sinks: DOM XSS, `eval`/`new Function`, insecure `postMessage`,
  client-side storage secrets, leftover `debugger` statements.
- Extract route references to seed subsequent wordlist and active-probe passes.

#### 3) Required inputs

- `scanService` with JS SAST probe configured.
- Target URL and scan options.

#### 4) Expected outputs

- Findings for each detected weakness or code defect.
- Metadata: extracted route list, weakness classes detected.

#### 5) Hard constraints

- Fetch only in-scope URLs (scope check before each JS bundle fetch).
- Must not execute any JavaScript in the target runtime.

#### 6) Escalation / handoff

- Discovered routes seed the `wordlist` agent's focused pass.
- Detected weakness classes inform which active probes `scanning` runs next.

#### 7) Non-goals (must not do)

- Must not perform runtime/headless-browser execution of analyzed scripts.
- Must not make write requests to the target.

---

### `scanning`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Execute the core security probe suite against the target via the scanner
service, covering headers, cookies, TLS, headless-browser checks, and all
configured active probes.

#### 2) Owned decisions

- Delegate the full probe pass to `scanner.Service`.
- Apply pre-run AI advisor focus context when available.

#### 3) Required inputs

- `scanService` (required; no findings produced when nil).
- Target URL, auth profile, scan options.

#### 4) Expected outputs

- Findings from all active probes (XSS, SQLi, SSTI, SSRF, CORS, CSRF, etc.).
- Metadata: scan duration, findings count.

#### 5) Hard constraints

- Respect `passiveOnly` flag — skip active probes when set.
- Destructive checks (SQLMap, commix, XSSMap) require `AllowDestructiveChecks=true`.
- All probe URLs must pass scope and `secureurl` validation.

#### 6) Escalation / handoff

- Passes finding set to `analysis`, `exploit_chain`, and triage agents.
- Feeds new endpoints discovered during crawl back to `wordlist`.

#### 7) Non-goals (must not do)

- Must not run ML/AI scoring on findings — that is owned by `ml_triage`.
- Must not generate executive summaries.

---

### `advanced_coverage`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Extend the attack surface beyond what `scanning` covers by running supplemental
probes (vhost discovery, hidden endpoint probing, surface diff, extended integrations).

#### 2) Owned decisions

- Run vhost discovery, hidden-endpoint probe, and surface-gap detection.
- Decide which supplemental integrations to activate based on scan options.

#### 3) Required inputs

- `scanService` configured with advanced probe modules.
- Target URL, scan options, prior recon findings.

#### 4) Expected outputs

- Findings from advanced probe modules.
- Metadata: new endpoints discovered, surface diff summary.

#### 5) Hard constraints

- Scope-check all discovered vhosts and endpoints before probing.
- Respect `passiveOnly` flag.

#### 6) Escalation / handoff

- Newly discovered endpoints feed back to `scanning` and `input_validation`.
- Surface diff results are passed to reporting.

#### 7) Non-goals (must not do)

- Must not duplicate checks owned by `scanning`.
- Must not run ML/AI scoring.

---

### `input_validation`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Run injection probes against discovered input fields and endpoints (SQLi, XSS,
path traversal, XXE, OS command injection).

#### 2) Owned decisions

- Select target parameters and payloads based on discovered surface.
- Run probes in priority order: `sqli`, `xss`, `path_traversal`, `xxe`, `cmd_injection`.

#### 3) Required inputs

- Target URL and discovered endpoints/parameters.
- Scan options (`AllowDestructiveChecks` for destructive variants).

#### 4) Expected outputs

- Findings for confirmed injection vulnerabilities with evidence.

#### 5) Hard constraints

- Destructive injection probes (SQLMap, commix) require `AllowDestructiveChecks=true`.
- Scope-check every request before sending.

#### 6) Escalation / handoff

- Confirmed injection findings are passed to `exploit_chain` and `ml_triage`.

#### 7) Non-goals (must not do)

- Must not perform business-logic or access-control checks.
- Must not modify production data beyond the intended probe payload.

---

### `information_disclosure`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Detect accidental exposure of sensitive data: verbose errors, backup files,
secrets in JS bundles, directory listings, and debug endpoints.

#### 2) Owned decisions

- Probe for sensitive file paths (`.git`, backups, config files, stack traces).
- Scan JS bundles for embedded secrets (API keys, credentials).

#### 3) Required inputs

- Target URL and scan options.

#### 4) Expected outputs

- Findings for each confirmed disclosure with evidence snippet.

#### 5) Hard constraints

- Must not attempt to exfiltrate real user data.
- Scope-check all discovery requests.

#### 6) Escalation / handoff

- Disclosed secrets or config files are flagged for `reporting` and `impact_verifier`.

#### 7) Non-goals (must not do)

- Must not store or transmit any discovered credentials outside the finding record.

---

### `access_control`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Detect broken access control: IDOR, privilege escalation, weak auth, default
credentials, and exposed admin panels.

#### 2) Owned decisions

- Probe resource endpoints with alternate user IDs (IDOR).
- Test for default or weak credentials on admin interfaces.
- Attempt privilege escalation via role-parameter manipulation.

#### 3) Required inputs

- Target URL, auth profile (for multi-role diff), scan options.

#### 4) Expected outputs

- Findings for IDOR, privilege escalation, default-credential hits, admin panels.

#### 5) Hard constraints

- Must not create or delete production data as a side effect.
- Scope-check all probed endpoints.

#### 6) Escalation / handoff

- IDOR and privilege-escalation findings are prioritized by `ml_triage` and
  `impact_verifier`.

#### 7) Non-goals (must not do)

- Must not run injection probes — owned by `input_validation`.

---

### `api_security`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Probe REST and GraphQL APIs for security misconfigurations (introspection
exposure, batching abuse, mass assignment, BOLA, rate-limit bypass).

#### 2) Owned decisions

- Test GraphQL introspection, batching, depth/field limits, and alias overloading.
- Probe REST endpoints for mass assignment and object-level authorization issues.

#### 3) Required inputs

- Target URL, discovered API endpoints, scan options.

#### 4) Expected outputs

- Findings for GraphQL and REST API vulnerabilities.

#### 5) Hard constraints

- Scope-check every API endpoint before probing.
- Do not attempt to exfiltrate real records beyond what confirms the vulnerability.

#### 6) Escalation / handoff

- GraphQL introspection results seed `wordlist` for field enumeration.
- Mass-assignment findings are correlated by `exploit_chain`.

#### 7) Non-goals (must not do)

- Must not run generic injection probes — owned by `input_validation`.

---

### `cors_redirect`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Detect CORS misconfigurations and open-redirect vulnerabilities.

#### 2) Owned decisions

- Test reflective/wildcard CORS headers across discovered endpoints.
- Probe redirect parameters for open-redirect payloads.

#### 3) Required inputs

- Target URL, discovered endpoints, scan options.

#### 4) Expected outputs

- Findings for exploitable CORS policies and open-redirect instances.

#### 5) Hard constraints

- Must not follow redirects to out-of-scope hosts during probing.
- Scope-check all probe requests.

#### 6) Escalation / handoff

- CORS + XSS chains are surfaced by `exploit_chain`.
- Open-redirect + OAuth chains are flagged for `exploit_chain`.

#### 7) Non-goals (must not do)

- Must not test CSRF — owned by `scanning`.

---

### `ssrf`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Detect Server-Side Request Forgery via both request-header injection and
body-parameter injection, using OAST callbacks for blind detection.

#### 2) Owned decisions

- Inject OAST callback URLs into header-based SSRF vectors
  (X-Forwarded-For, X-Original-URL, Host, etc.).
- Inject OAST callback URLs into body/form parameters that accept URLs.
- Poll the OAST endpoint for callback hits.

#### 3) Required inputs

- Target URL, OAST endpoint configuration, scan options.

#### 4) Expected outputs

- Findings for confirmed SSRF (header-based and body-based) with OAST evidence.

#### 5) Hard constraints

- OAST callbacks must use the configured `OAST_POLLING_ENDPOINT` — never
  hard-code external services.
- Scope-check the primary target; OAST callbacks are inherently out-of-scope
  infrastructure and are exempt.

#### 6) Escalation / handoff

- Confirmed SSRF findings are correlated by `exploit_chain` (SSRF → cloud
  metadata → credential theft chain).

#### 7) Non-goals (must not do)

- Must not attempt to reach internal services beyond confirming SSRF.
- Must not store or exfiltrate any data retrieved via SSRF.

---

### `auth_bypass`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Detect authentication bypass: JWT abuse (alg:none, weak HMAC), password-reset
poisoning, OAuth/OIDC flow abuse, and MFA bypass.

#### 2) Owned decisions

- Test JWT `alg:none` and weak-secret attacks.
- Probe password-reset flows for host-header/link poisoning.
- Test OAuth state fixation and redirect-URI manipulation.

#### 3) Required inputs

- Target URL, auth profile, scan options.

#### 4) Expected outputs

- Findings for each confirmed auth bypass vector.

#### 5) Hard constraints

- Must not consume or lock real user accounts.
- Scope-check all probed auth endpoints.

#### 6) Escalation / handoff

- Auth bypass findings are prioritized by `impact_verifier` and correlated by
  `exploit_chain`.

#### 7) Non-goals (must not do)

- Must not run brute-force credential attacks.
- Must not test for IDOR/access-control issues — owned by `access_control`.

---

### `file_upload`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Detect file-upload abuse: unrestricted file types, path traversal via filename,
zip-slip, and web-shell delivery.

#### 2) Owned decisions

- Test upload endpoints with polyglot and extension-bypass payloads.
- Detect whether uploaded files are served at a predictable path.

#### 3) Required inputs

- Target URL, discovered upload endpoints, scan options.

#### 4) Expected outputs

- Findings for exploitable upload vulnerabilities with evidence of reachable
  uploaded content.

#### 5) Hard constraints

- Must not upload payloads that persist beyond the test request (use benign
  content with a short TTL where possible).
- Scope-check all upload and retrieval requests.

#### 6) Escalation / handoff

- Web-shell delivery evidence is escalated immediately to `impact_verifier`.

#### 7) Non-goals (must not do)

- Must not attempt remote code execution via uploaded shells.

---

### `wordlist`

- **Layer:** discovery/probing
- **Status:** active

#### 1) Purpose

Enumerate directories, subdomains, and API endpoints using curated wordlists
and JS-SAST-extracted routes.

#### 2) Owned decisions

- Run directory, subdomain, and API endpoint fuzzing in priority order.
- Incorporate JS-SAST-extracted routes into the seed wordlist for a faster
  targeted pass.

#### 3) Required inputs

- Target URL, `WordlistScanner`, scan options.
- Optional: JS-SAST route list from the blackboard.

#### 4) Expected outputs

- Findings for discovered directories, active subdomains, and API endpoints.
- Metadata: discovered endpoint count, seed routes used.

#### 5) Hard constraints

- Respect concurrency limits to avoid overwhelming the target.
- Scope-check every probed path before sending.

#### 6) Escalation / handoff

- Newly discovered endpoints are fed back to `scanning` and `input_validation`
  for active probing.

#### 7) Non-goals (must not do)

- Must not run active injection probes on discovered paths — owned by
  `input_validation`.

---

### `adaptive_probe`

*(See [`docs/skills/pilot/adaptive_probe.skill.md`](docs/skills/pilot/adaptive_probe.skill.md) for the canonical entry.)*

- **Layer:** discovery/probing
- **Status:** pilot

Runs an evidence-driven one-probe-at-a-time loop that selects the next
highest-value probe from live observations and an AI planning model. Stops on
budget exhaustion, cancellation, or AI-decision failure. Must not perform
exploit-chain synthesis or final severity triage.

---

## Correlation / Chain Reasoning Agents

---

### `exploit_chain`

- **Layer:** correlation/chain reasoning
- **Status:** active

#### 1) Purpose

Correlate the cumulative finding set into deterministic multi-step attack chains
without making any HTTP requests.

#### 2) Owned decisions

- Identify known chain patterns (CORS+XSS, SSRF+metadata, SQLi+IDOR,
  auth bypass+high-severity, JWT confusion, subdomain takeover+XSS delivery,
  GraphQL+IDOR exfiltration, open redirect+OAuth).
- Emit escalated chain findings that demonstrate combined impact.

#### 3) Required inputs

- `AllFindings` from prior agents (read-only).

#### 4) Expected outputs

- Chain findings with escalated severity and a composite chain description.
- Metadata: chains detected count.

#### 5) Hard constraints

- Zero network requests — purely deterministic analysis.
- Must not invent evidence not present in the input finding set.

#### 6) Escalation / handoff

- Chain findings are passed to `ml_triage`, `impact_verifier`, and `reporting`.

#### 7) Non-goals (must not do)

- Must not generate novel chain hypotheses — owned by `llm_chain_synthesis`.
- Must not perform final triage/report gating.

---

### `llm_chain_synthesis`

- **Layer:** correlation/chain reasoning
- **Status:** active

#### 1) Purpose

Ask the AI to reason across the full finding set to identify novel multi-step
attack chains that are not covered by `exploit_chain`'s static rules.

#### 2) Owned decisions

- Construct an AI prompt from the finding set and impact goals.
- Filter AI-proposed chains by structural completeness and minimum confidence.

#### 3) Required inputs

- `AllFindings` and impact goals.
- Configured AI client (skipped when nil).

#### 4) Expected outputs

- Chain findings with AI-synthesized descriptions and confidence scores.
- Metadata: chains attempted/accepted.

#### 5) Hard constraints

- Must not surface chains with confidence below the configured threshold.
- Must not make any outbound probing requests.

#### 6) Escalation / handoff

- Synthesized chains are fed to `reporting` and `impact_verifier`.

#### 7) Non-goals (must not do)

- Must not replace deterministic `exploit_chain` analysis.
- Must not run probes to verify hypotheses — that belongs to `hypothesis`.

---

### `hypothesis`

- **Layer:** correlation/chain reasoning
- **Status:** active

#### 1) Purpose

Generate testable vulnerability hypotheses (LLM-proposes / scanner-verifies
loop) and confirm only those the deterministic scanner oracle validates.

#### 2) Owned decisions

- Generate hypotheses from findings, target surface, and optional episodic memory.
- Execute each hypothesis via the scanner service's deterministic probe
  infrastructure.
- Confirm only oracle-validated results.

#### 3) Required inputs

- `aiClient` (falls back to rule-based reasoner when nil).
- `scanService` for oracle verification.
- Existing findings, target, auth profile, scan options.
- Optional: `memory.Store` for cross-scan episodic context.

#### 4) Expected outputs

- Oracle-confirmed findings for each validated hypothesis.

#### 5) Hard constraints

- Must not surface findings that the scanner oracle did not confirm.
- Scope-check all verification requests.

#### 6) Escalation / handoff

- Verified findings are passed to triage/review agents.

#### 7) Non-goals (must not do)

- Must not report AI-generated findings without scanner confirmation.
- Must not perform final triage policy decisions.

---

### `pentest_loop`

*(See [`docs/skills/pilot/pentest_loop.skill.md`](docs/skills/pilot/pentest_loop.skill.md) for the canonical entry.)*

- **Layer:** correlation/chain reasoning
- **Status:** pilot

Runs iterative hypothesis → verify → exploit-chain rounds to deepen coverage.
Must not bypass scanner verification or make final triage policy decisions.

---

### `reasoning_iteration`

*(See [`docs/skills/pilot/reasoning_iteration.skill.md`](docs/skills/pilot/reasoning_iteration.skill.md) for the canonical entry.)*

- **Layer:** correlation/chain reasoning
- **Status:** pilot

Runs adaptive multi-round probing with explicit post-round reflection to pivot
strategy based on observed gaps. Must not skip deterministic verification or
finalize report acceptance decisions.

---

### `attack_path`

- **Layer:** correlation/chain reasoning
- **Status:** active

#### 1) Purpose

Use the ML service to correlate findings across categories and infer likely
multi-step attack paths.

#### 2) Owned decisions

- Call `ml.Service.AttackPaths` with the accumulated finding set.
- Translate ML-returned paths into ranked `model.Finding` entries.

#### 3) Required inputs

- `AllFindings`.
- Configured `ml.Service` (skipped when nil or `UseAttackPathAgent` is false).

#### 4) Expected outputs

- Attack-path findings with path description, steps, and confidence.
- Metadata: attack-path count.

#### 5) Hard constraints

- Must not make any direct HTTP calls to the scan target.
- Requires `UseAttackPathAgent=true` in scan options.

#### 6) Escalation / handoff

- Attack-path findings are passed to `reporting` and `remediation_planner`.

#### 7) Non-goals (must not do)

- Must not perform active probing to verify inferred paths.
- Must not replace deterministic `exploit_chain` analysis.

---

## Triage / Review Agents

---

### `analysis`

- **Layer:** triage/review
- **Status:** active

#### 1) Purpose

Deduplicate the accumulated finding set and rank findings by severity for
downstream consumption.

#### 2) Owned decisions

- Identify and merge duplicate findings (same category + URL + parameter).
- Sort findings by severity (critical → info) as the canonical ranked list.

#### 3) Required inputs

- `AllFindings` or `Previous.Findings`.

#### 4) Expected outputs

- Deduplicated, severity-ranked finding list.
- Metadata: original count, deduplicated count.

#### 5) Hard constraints

- Must not drop findings unless they are true structural duplicates.
- Must not change severity scores during deduplication.

#### 6) Escalation / handoff

- Passes the deduplicated list to `ml_triage`, `impact_verifier`, and `reporting`.

#### 7) Non-goals (must not do)

- Must not run active probes or make HTTP requests.
- Must not perform ML/AI-based confidence scoring.

---

### `ml_triage`

- **Layer:** triage/review
- **Status:** active

#### 1) Purpose

Apply deterministic ML risk scoring and confidence calibration to all findings
and surface the top-ranked items for operator review.

#### 2) Owned decisions

- Score all findings via `ml.Service.ScoreFindings`.
- Select the top N findings by composite risk score.
- Annotate each with risk score, confidence, and exploitability class.

#### 3) Required inputs

- `AllFindings`.
- Configured `ml.Service` (skipped when nil or `UseMLTriageAgent` is false).

#### 4) Expected outputs

- Top-N ML-prioritized findings with score/confidence annotations.
- Metadata: scored findings count.

#### 5) Hard constraints

- Requires `UseMLTriageAgent=true` in scan options.
- Must not make any HTTP calls to the scan target.

#### 6) Escalation / handoff

- Prioritized list is used by `reporting` and `remediation_planner`.

#### 7) Non-goals (must not do)

- Must not suppress findings from the full finding set — it only annotates.
- Must not perform active re-probing to validate scores.

---

### `false_positive_review`

- **Layer:** triage/review
- **Status:** active

#### 1) Purpose

Identify the findings most likely to be false positives using ML confidence
thresholds and surface them as a shortlist for analyst verification.

#### 2) Owned decisions

- Call `ml.Service.FalsePositiveCandidates` with the finding set.
- Emit a shortlist with FP probability and reason annotations.

#### 3) Required inputs

- `AllFindings`.
- Configured `ml.Service` and `UseFalsePositiveReviewAgent=true`.

#### 4) Expected outputs

- Shortlist of FP-candidate findings with probability scores.
- Metadata: candidates shortlisted count.

#### 5) Hard constraints

- Must not automatically suppress findings — the shortlist is advisory only.
- Must not make HTTP calls to the scan target.

#### 6) Escalation / handoff

- Shortlist is attached to the scan report for analyst override workflow.

#### 7) Non-goals (must not do)

- Must not make final suppression decisions — owned by `openhack_triage`.

---

### `impact_verifier`

- **Layer:** triage/review
- **Status:** active

#### 1) Purpose

Estimate exploitability and business impact for each finding by scoring against
operator-supplied impact goals and promoting the highest-risk items.

#### 2) Owned decisions

- Apply `impact.RankFindings` using configured impact goals.
- Promote findings that exceed the exploitability threshold to `high` or `critical`.
- Annotate each finding with an exploitability label and business-impact summary.

#### 3) Required inputs

- `AllFindings` and `ScanOptions` (impact goals, exploitability threshold).

#### 4) Expected outputs

- Promoted findings with updated severity and impact annotations.
- Metadata: promoted count.

#### 5) Hard constraints

- Must not demote findings that already have strong proof artifacts.
- Must not make HTTP calls to the scan target.

#### 6) Escalation / handoff

- Promoted findings are passed to `reporting` and `remediation_planner`.

#### 7) Non-goals (must not do)

- Must not perform active probing to re-verify exploitability.

---

### `cve_reverse_engineer`

*(See [`docs/skills/pilot/cve_reverse_engineer.skill.md`](docs/skills/pilot/cve_reverse_engineer.skill.md) for the canonical entry.)*

- **Layer:** triage/review
- **Status:** pilot

Reverse-engineers CVE-tagged findings into root-cause write-ups and bounded
PoC proposals. Must never fire a PoC without scope + safety checks, and PoC
execution requires `EnableCVEPoCExecution=true`.

---

### `openhack_expert`

*(See [`docs/skills/pilot/openhack_expert.skill.md`](docs/skills/pilot/openhack_expert.skill.md) for the canonical entry.)*

- **Layer:** triage/review
- **Status:** pilot

Routes each finding to the matching OpenHack expert prompt and enriches it
with expert-specific quality analysis. Must not create new findings or make
final suppression decisions.

---

### `openhack_triage`

*(See [`docs/skills/pilot/openhack_triage.skill.md`](docs/skills/pilot/openhack_triage.skill.md) for the canonical entry.)*

- **Layer:** triage/review
- **Status:** pilot

Applies OpenHack finding-triage outcomes (accepted/downgraded/rejected/duplicate/
needs_context) and suppresses ineligible findings. Must not run probes or invent
evidence.

---

## Reporting / Remediation Agents

---

### `reporting`

- **Layer:** reporting/remediation
- **Status:** active

#### 1) Purpose

Produce the scan's executive summary and identify the top-risk findings for
operator consumption.

#### 2) Owned decisions

- Rank findings by impact goals using `impact.RankFindings`.
- Build the executive summary text.
- Identify the top-N risk findings and attach their indices.

#### 3) Required inputs

- `AllFindings` or `Previous.Findings`.
- `ScanOptions` (impact goals).

#### 4) Expected outputs

- Metadata: `summary` (executive summary text), `top_risk_1`…`top_risk_N`,
  `impact_goals`.

#### 5) Hard constraints

- Must not make HTTP calls to the scan target.
- Must not modify or suppress findings — reporting only.

#### 6) Escalation / handoff

- Summary and top-risk indices are consumed by the scan-result API and frontend.

#### 7) Non-goals (must not do)

- Must not perform triage or scoring — those are upstream responsibilities.
- Must not generate remediation plans — owned by `remediation_planner`.

---

### `remediation_planner`

- **Layer:** reporting/remediation
- **Status:** active

#### 1) Purpose

Generate a prioritized remediation sequence for the finding set using the ML
service's remediation-plan logic.

#### 2) Owned decisions

- Call `ml.Service.RemediationPlan` with the finding set.
- Order remediation steps by risk and dependency.

#### 3) Required inputs

- `AllFindings`.
- Configured `ml.Service` and `UseRemediationPlannerAgent=true`.

#### 4) Expected outputs

- Remediation-plan findings/steps with recommended actions and priority.
- Metadata: steps generated count.

#### 5) Hard constraints

- Must not make HTTP calls to the scan target.
- Requires `UseRemediationPlannerAgent=true`.

#### 6) Escalation / handoff

- Remediation plan is attached to the final scan report.

#### 7) Non-goals (must not do)

- Must not perform active re-probing or re-scoring.

---

## Tool / Command Generation Agents

---

### `ai_tool_calling`

- **Layer:** tool/command generation
- **Status:** active

#### 1) Purpose

Let the planning model autonomously choose bounded tool actions (commands,
HackTricks technique templates, generated Python tools) and route all execution
through the guarded `cmdbuilder` and `toolbuilder` infrastructure.

#### 2) Owned decisions

- Call `PlanToolCall` to select the next action across multiple rounds.
- Execute chosen commands, adapted technique templates, or LLM-generated tools.
- Stop after `maxAIToolCallRounds` (4) or when the AI returns no action.

#### 3) Required inputs

- Configured AI client implementing `aiToolCaller`.
- Existing findings and target for context.

#### 4) Expected outputs

- Findings from executed tool actions.
- Metadata: rounds run, actions taken counts.

#### 5) Hard constraints

- All executions must pass `cmdbuilder` policy validation.
- Cap per-round action counts (max 2 commands, 2 HackTricks, 1 generated tool,
  2 technique templates).
- Must respect context cancellation.

#### 6) Escalation / handoff

- Findings from tool execution are passed to triage/review layers.

#### 7) Non-goals (must not do)

- Must not execute arbitrary commands that bypass `cmdbuilder` validation.
- Must not make direct HTTP calls to the scan target outside the tool infrastructure.

---

### `tool_builder`

- **Layer:** tool/command generation
- **Status:** active

#### 1) Purpose

Select built-in tool templates matching the current finding context and, when
an AI coding client is available, generate bespoke Python tools for findings
with no matching template.

#### 2) Owned decisions

- Match findings to built-in templates (JWT, GraphQL, etc.).
- Ask the AI coding model to generate bespoke tools for unmatched findings.
- Execute all generated tools under policy validation.

#### 3) Required inputs

- `AllFindings` for context-based template selection.
- Optional AI coding client (falls back to built-in catalog only when nil).
- `toolbuilder.Builder` for execution.

#### 4) Expected outputs

- Findings from tool execution.
- Metadata: templates used, AI-generated tool count.

#### 5) Hard constraints

- AI tool generation is capped at `maxAIGeneratedTools` (3) per run.
- All generated tools must pass policy validation before execution.

#### 6) Escalation / handoff

- Tool findings are forwarded to triage agents.

#### 7) Non-goals (must not do)

- Must not execute tools that were not validated by `toolbuilder.Builder`.

---

### `hacktricks_techniques`

- **Layer:** tool/command generation
- **Status:** active

#### 1) Purpose

Bridge the HackTricks technique template library to live execution by adapting
templates to the specific target and finding evidence and executing approved
commands.

#### 2) Owned decisions

- Look up matching HackTricks technique templates for each finding.
- Adapt templates to the real target (`{{TARGET}}`, `{{PARAM}}`, etc.) using
  the coding LLM (falls back to placeholder substitution when nil).
- Validate adapted commands via `cmdbuilder` and execute approved ones.

#### 3) Required inputs

- `AllFindings` to drive template selection.
- Optional AI coding client.

#### 4) Expected outputs

- Findings parsed from command output.
- Metadata: techniques matched, commands run/failed.

#### 5) Hard constraints

- Max `maxTechniquesPerFinding` (3) commands per finding.
- All commands must pass `cmdbuilder` safety policy.
- Respect context cancellation.

#### 6) Escalation / handoff

- Findings from technique execution are passed to triage/review layers.

#### 7) Non-goals (must not do)

- Must not execute unvalidated commands.
- Must not run generic wordlist/fuzzing — owned by `wordlist`.

---

### `dynamic_command`

*(See [`docs/skills/pilot/dynamic_commands.skill.md`](docs/skills/pilot/dynamic_commands.skill.md) for the canonical entry.)*

- **Layer:** tool/command generation
- **Status:** pilot

Generates and executes bounded external security-tool commands from findings via
`cmdbuilder` policy validation. Falls back to local heuristic generation when
the sidecar-proposal service is unavailable. Must not execute arbitrary
unvalidated commands.

---

### `metasploit`

- **Layer:** tool/command generation
- **Status:** active

#### 1) Purpose

Optionally invoke Metasploit RPC to run curated exploit modules against the
target when `MSF_RPC_URL` is configured.

#### 2) Owned decisions

- Select applicable Metasploit modules from the configured template list.
- Expand `{{RHOSTS}}`, `{{RPORT}}`, `{{SSL}}`, `{{TARGETURI}}` placeholders.
- Execute modules via Metasploit RPC and parse findings from output.

#### 3) Required inputs

- `MSF_RPC_URL` and `MSF_RPC_PASSWORD` environment variables.
- Module template file (default: `backend/templates/metasploit_rpc_modules.template.json`).
- Target URL and scan options.

#### 4) Expected outputs

- Findings from executed Metasploit module output.
- Metadata: modules run, execution status.

#### 5) Hard constraints

- Requires `AllowDestructiveChecks=true` for high-risk exploit modules.
- `MSF_RPC_ENABLE_LESS_SAFE_MODULES=true` needed for extra high-risk modules.
- Scope-check target before any module execution.

#### 6) Escalation / handoff

- Module-confirmed findings are tagged for `cve_reverse_engineer` CVE enrichment.

#### 7) Non-goals (must not do)

- Must not run modules against out-of-scope hosts.
- Must not persist any shells or backdoors on the target.

---

### `burp`

- **Layer:** tool/command generation
- **Status:** active

#### 1) Purpose

Optionally integrate with the Burp Suite Professional API to run Burp scans
and import findings when `BURP_API_URL` is configured.

#### 2) Owned decisions

- Submit the target to the Burp API for scanning.
- Poll for scan completion and retrieve issue findings.
- Translate Burp issues into `model.Finding` entries.

#### 3) Required inputs

- `BURP_API_URL` and optional API key.
- Target URL and scan options.

#### 4) Expected outputs

- Findings translated from Burp issue list.
- Metadata: Burp scan ID, issues retrieved count.

#### 5) Hard constraints

- Requires `BURP_API_URL` to be configured; skipped silently otherwise.
- Scope-check target before submission.
- `BURP_API_URL` must pass `secureurl` HTTPS validation.

#### 6) Escalation / handoff

- Burp findings join the main finding set for `analysis` and `ml_triage`.

#### 7) Non-goals (must not do)

- Must not modify Burp project configuration.
- Must not expose Burp API credentials in findings or logs.
