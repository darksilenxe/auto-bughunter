# Auto Bughunter Roadmap (Best-in-Class in Niche)

This roadmap turns the strategic plan into a concrete 3-wave execution plan with deliverables and acceptance criteria.

## North Star

Make Auto Bughunter the most trusted and effective platform for **authorized autonomous bug bounty and AppSec scanning** by maximizing:

- Signal quality (true positives, exploitability confidence)
- Operator trust (safety, governance, auditability)
- Time-to-action (scan-to-report and remediation workflows)

## Primary ICPs

- Solo bug bounty hunters
- Small pentest teams
- Internal AppSec teams

## Core Product KPIs

- True-positive rate
- Median time-to-actionable finding
- Scan-to-report time
- Exploit validation rate
- Analyst override rate
- Repeat-user retention

## Current Status Snapshot

The platform already has meaningful groundwork in place (automation policy packs/audit APIs, campaign scheduling with retries/queue state, confidence-driven triage, autonomous orchestration, and webhook/slack notifications).  
This roadmap now focuses on finishing the remaining productization and enterprise-hardening work.

## What’s Left to Finish (Cross-Wave)

- Product-level KPI instrumentation and dashboards exposed in-product.
- End-to-end proof-of-authorization UX with immutable export bundle.
- Complete finding lifecycle UX/workflows across verification, suppression/acceptance, and remediation ownership.
- Stronger high-severity validation gates (strict exploitability/corroboration requirements by default policy).
- Full explainability surfaces in UI/reporting for agent choice and ranking outcomes.
- Bug bounty submission acceleration (template packs, dedupe intelligence, payout learning loop).
- First-party work-management integrations beyond generic webhooks.
- Executive decision intelligence reporting and compliance evidence ownership flow.
- Public benchmark suite + CI regression gates + release scorecards as a continuous moat.
- Intercept proxy plugin platform groundwork, rollout, and governance (free plugin store + performance transparency + container/API contracts).

### Autonomous Agentic Platform Implementation Backlog

- [ ] Implement policy-aware runtime model/prompt tuning profiles with full audit traces.
- [ ] Implement per-target adaptive strategy using historical drift, ROI, and prior exploit success.
- [ ] Build autonomous campaign planner that continuously discovers targets, clusters by asset risk, and auto-schedules scans within policy budgets.
- [ ] Add autonomous retest loop that verifies remediations and reopens findings when regressions appear.
- [ ] Add exploit-validation sandbox with strict isolation for safe live PoC execution and replayable proof artifacts.
- [ ] Add automatic bounty-report submission adapters (HackerOne/Bugcrowd APIs), including program-specific formatting and duplicate pre-checks.
- [ ] Add auto-triage + auto-suppression governance with confidence thresholds, reviewer override flows, and drift alerts.
- [ ] Add outcome-learning loop from bounty responses (duplicate/N-A/accepted/payout) directly into ranking and probe planning.
- [ ] Implement Jira/Linear bidirectional sync with ownership SLAs and remediation state reconciliation.
- [ ] Ship decision dashboards for risk burn-down, MTTR, true-positive trend, exploitability trend, and payout ROI.
- [ ] Define and enforce orchestration/queueing SLOs with auto-scaling and backpressure controls.
- [ ] Complete proxy plugin platform: catalog lifecycle, signing/review pipeline, capability sandbox, compatibility gates, and perf-cost enforcement.
- [ ] Add benchmark-gated release quality: public benchmark suite, CI regression gates, and release scorecards.
- [ ] Add immutable evidence chain-of-custody for every autonomous decision/finding/report for audit and legal defensibility.
- [ ] Add autonomy guardrails that pause or de-escalate scans on scope ambiguity, legal-risk signals, or anomalous behavior.

---

## Wave 1 — Trust + Quality Foundations

Focus areas: governance, authorization proof, auditability, and false-positive reduction.

> **Phases in this wave:** [Phase A — Prove Exploitability](#phase-a--prove-exploitability) · [Phase B — Sharpen Signal-to-Noise](#phase-b--sharpen-signal-to-noise) · [Phase F — Safer Autonomous Operation](#phase-f--safer-autonomous-operation) (foundations)

### Deliverables

1. Policy guardrails by default
   - Enforce `safe`, `autonomous`, `aggressive` policy profiles with explicit runtime/probe/ROI budgets.
2. Proof-of-authorization workflow
   - Campaign-level authorization evidence and signed-approval metadata.
3. Finding lifecycle state model
   - Standardize states: `new -> verified -> suppressed|accepted -> remediated`.
4. Audit exports
   - Export policy decisions, agent decisions, tool evidence, and report hashes.
5. Quality gates for high severity
   - Require multi-signal corroboration and exploitability evidence before high-severity publication.
6. Strict-mode reporting
   - Add configurable confidence thresholds and strict output mode.

### Acceptance criteria

- Every automated run is attached to a policy profile and budget decision record.
- Authorization evidence is queryable and exportable per campaign.
- All findings have lifecycle state transitions and state-change audit entries.
- High-severity findings require explicit corroboration metadata.
- Strict mode can be enabled per workspace/program and measurably lowers noisy output.

### Remaining implementation checklist

- [x] Add signed approval capture + immutable authorization evidence export package.
- [x] Enforce explicit risk budgets per default profile in UI and API validation.
- [x] Complete lifecycle state machine and ownership transitions in operator UX.
- [x] Gate high-severity publication on corroboration + exploitability requirements by policy.
- [x] Add strict-reporting toggles with measurable false-positive reduction telemetry.

### Phase A — Prove Exploitability

*Goal: Every high/critical finding ships with a reproducible attack chain and concrete impact evidence.*

**Deliverables**

1. Safe PoC generation — auto-generate sandboxed, replay-safe, audit-logged PoCs per finding, gated on `AllowDestructiveChecks=false` safe mode.
2. Verification traces — capture full request/response proof bundles alongside each PoC.
3. Strengthened `proofpolicy` gates — require a minimum evidence coverage score before a finding is promoted to `verified`.
4. Exploit-validation sandbox — isolated container environment for live PoC replay with no exfiltration risk.
5. `exploit_chain` as first-class finding field — attach `exploit_chain` agent output to every high-severity finding.

**Acceptance criteria**

- ≥80% of high/critical findings include a machine-readable PoC + trace bundle.
- Exploit validation rate KPI is tracked in dashboards.
- Sandbox replay is available in UI with a one-click rerun action.

**Implementation checklist**

- [x] Add safe PoC generator to `exploit_chain` agent output with `AllowDestructiveChecks` gate.
- [x] Capture request/response proof bundle as a structured `VerificationTrace` field on `Finding`.
- [x] Raise `proofpolicy` minimum evidence coverage threshold for `high`/`critical` severity findings.
- [ ] Wire exploit-validation sandbox container (isolated, no exfiltration) and expose replay API.
- [ ] Surface PoC bundle and exploit chain in finding detail UI and export bundles.
- [x] Add exploit validation rate to Core Product KPI dashboard.

### Phase B — Sharpen Signal-to-Noise

*Goal: Continuous false-positive feedback loops and per-probe precision/recall tracking.*

**Deliverables**

1. Per-probe precision/recall ledger — record TP/FP/FN outcome labels from analyst triage.
2. Auto-throttle for noisy probes — suspend probes whose FP rate exceeds threshold (e.g., >30% FP over rolling 50 results).
3. Ledger UI surface — per-probe stats, category breakdowns, trending noisiest checks.
4. Feedback loop into ML agents — analyst overrides update `ml_triage` and `false_positive_review` ranking weights.
5. Noisy probe dashboard alert — alert when a probe degrades below precision floor.

**Acceptance criteria**

- Analyst override rate KPI falls measurably after throttle is active.
- Noisy probes are auto-throttled within one campaign cycle.
- Per-probe precision/recall stats are visible in the operator UI.

**Implementation checklist**

- [x] Add `ProbeOutcomeLedger` storage schema: probe key → rolling TP/FP/FN counts.
- [x] Instrument analyst triage actions (accept/reject/suppress) to write outcome labels.
- [x] Implement auto-throttle: skip probes above FP threshold and record throttle decision.
- [x] Expose ledger API endpoint and wire into UI as a "Probe Health" dashboard panel.
- [x] Feed ledger outcome weights into `ml_triage` and `false_positive_review` agent prompts.
- [x] Add "noisy probe" alert type to campaign notification system.

---

## Wave 2 — Orchestration Intelligence + Bug Bounty Specialization

Focus areas: adaptive automation, explainability, and bug bounty outcome performance.

> **Phases in this wave:** [Phase A — Prove Exploitability](#phase-a--prove-exploitability) (completion) · [Phase B — Sharpen Signal-to-Noise](#phase-b--sharpen-signal-to-noise) (completion) · [Phase C — Coverage Map](#phase-c--coverage-map) · [Phase D — Bug Bounty-Native Output](#phase-d--bug-bounty-native-output)

### Deliverables

1. Policy-aware runtime tuning
   - Runtime model/prompt tuning profiles selected by policy + target context.
2. Planner evaluation harness
   - Offline replay of historical scans to compare planning quality and outcomes.
3. Adaptive execution strategy
   - Per-target strategy using asset type, historical drift, prior findings, and ROI signals.
4. Explainability layer
   - “Why this agent ran” and “Why this finding ranked high” in UI and reports.
5. Bug bounty workflow acceleration
   - Platform-oriented submission templates, severity rationale helpers, reproducibility bundles.
6. Duplicate intelligence + payout learning
   - Similarity scoring against prior scans/submissions and feedback-driven prioritization updates.
7. Program profile packs
   - Vertical presets (fintech, healthcare, SaaS, API-first) with safer defaults.

### Acceptance criteria

- Planner replay can score and compare candidate strategies against baseline.
- Adaptive strategy is active and reflected in execution telemetry.
- Every prioritized finding includes machine-readable ranking rationale.
- Submission artifacts are generated with reproducibility evidence by default.
- Feedback loop changes prioritization behavior with measurable trend improvement.

### Remaining implementation checklist

- [x] Add runtime policy-aware model/prompt tuning profiles with audit traces.
- [x] Ship planner offline replay harness with baseline comparison output.
- [x] Add per-target adaptive strategy policy using historical drift and ROI signals.
- [x] Surface “why agent ran” and “why ranked high” in UI and report exports.
- [x] Add HackerOne/Bugcrowd-oriented submission bundles and severity rationale helpers.
- [x] Add duplicate detection against prior submissions/scans with similarity thresholds.
- [x] Close payout-feedback loop into prioritization scoring by program profile.
- [x] Define intercept-proxy plugin SDK contracts (hook surface + API schema + manifest format) and publish creator docs.
- [x] Add compatibility harness for plugin API versions and baseline no-plugin regression checks.

### Phase C — Coverage Map

*Goal: Build a structured map of app attack surface and use it to direct probe budget.*

**Deliverables**

1. Coverage map artifact — per-scan output listing auth states explored, roles tested, hidden APIs discovered, and JS runtime endpoints found.
2. Likelihood × impact scoring — score each surface area and expose as a ranked coverage heatmap.
3. Adaptive scheduling integration — wire adaptive probe agent to spend remaining budget on the highest-ROI uncovered surface areas.
4. Coverage delta tracking — alert when new attack surface appears across scans (drift detection).
5. Unified surface-coverage model — integrate `reconnaissance`, `js_sast`, and runtime XHR seeding outputs into a single queryable model.

**Acceptance criteria**

- Every scan produces a queryable coverage map artifact accessible via API and UI.
- Adaptive probe agent uses coverage map scores for scheduling decisions.
- Coverage delta alerts fire when new surface area is detected.

**Implementation checklist**

- [x] Define `CoverageMap` data model: surface areas keyed by type (auth-state, role, endpoint, JS-runtime), each with likelihood/impact scores and probed flag.
- [x] Emit `CoverageMap` artifact at end of scan from `reconnaissance`, `js_sast`, and runtime XHR seeding data.
- [x] Score each surface area by `likelihood × impact` and persist as ranked list.
- [x] Integrate coverage map scores into adaptive probe agent scheduling decisions.
- [x] Add coverage delta comparison across successive scans for the same target.
- [x] Expose coverage map heatmap in UI and include in export bundles.
- [x] Add coverage delta drift alert to campaign notification system.

### Phase D — Bug Bounty-Native Output

*Goal: One-click export to HackerOne/Bugcrowd-style reports with all required fields pre-filled.*

**Deliverables**

1. Platform-specific report templates — HackerOne, Bugcrowd, and Intigriti templates with mandatory field mapping.
2. Auto-populated report fields — severity rationale, CVSS breakdown, business impact narrative, clear repro steps, remediation guidance, and proof bundle.
3. Submission readiness score — per-finding score that flags missing fields before export.
4. Duplicate pre-check — similarity check against previously submitted findings before every submission.
5. One-click API submission adapters — HackerOne/Bugcrowd API submission gated by configured API key.

**Acceptance criteria**

- Export wizard completes in <2 minutes per finding.
- Submission readiness score ≥90% before one-click submit is enabled.
- Duplicate pre-check fires before every submission attempt.

**Implementation checklist**

- [x] Add platform report template engine with HackerOne, Bugcrowd, and Intigriti field mappings.
- [x] Auto-populate severity rationale, CVSS, business impact, repro steps, remediation, and proof bundle from finding data.
- [x] Implement `SubmissionReadinessScore` function and surface score + missing-field list in UI.
- [x] Add pre-submission duplicate similarity check against historical submissions.
- [x] Implement HackerOne and Bugcrowd API submission adapters gated by per-program API key config.
- [x] Wire export wizard UI with readiness gate that blocks one-click submit below 90%.

---

## Wave 3 — Integrations + Decision Intelligence + Scale Moat

Focus areas: ecosystem fit, executive value, reliability, and defensible quality leadership.

> **Phases in this wave:** [Phase E — Continuous Learning](#phase-e--continuous-learning) · [Phase F — Safer Autonomous Operation](#phase-f--safer-autonomous-operation) (completion) · [Phase G — Team-Grade Operations + Competitive Differentiation](#phase-g--team-grade-operations--competitive-differentiation)

### Deliverables

1. First-party connectors
   - Jira/Linear/Slack integrations with policy-aware routing.
2. CI/CD ergonomics
   - Improved automation event onboarding and campaign scheduling UX.
3. Toolchain drift intelligence
   - Capability drift alerts + fallback strategy recommendations.
4. Config portability
   - Import/export for policy packs, scan profiles, and report templates.
5. Decision dashboards
   - Risk burn-down, drift trends, recurring root causes, control-family coverage.
6. Reporting upgrades
   - Executive risk-delta summaries and stronger compliance evidence ownership mapping.
7. Reliability hardening
   - Scan orchestration and queueing SLOs, campaign retry/circuit-breaker/failure analytics.
8. Onboarding and adoption
   - First-success wizard tied to Juice Shop harness.
9. Continuous evaluation moat
   - Public benchmark suite, CI regression gates for detection/planner/reporting, release scorecards, living capability matrix.
10. Intercept Proxy Plugin Platform (Free Plugin Store)
    - In-product catalog for install/enable/disable/update/remove with free-by-default listing policy (no paid plugins in store).
11. Plugin runtime isolation and policy controls
    - Request/response/passive/UI hook points with per-plugin isolation, timeouts, resource quotas, failure containment, and workspace/admin allow-deny controls.
12. API-first plugin contract for creators
    - Plugins run in Docker containers, expose a declared API, and ship a manifest that defines host↔plugin API endpoints, capabilities, permissions, risk class, and performance-cost metadata.
13. Performance transparency
    - Per-plugin Low/Medium/High performance-cost labels, pre-install warnings for Medium/High, and runtime indicators when plugin overhead increases latency/resource use.
14. Third-party publishing governance
    - Security review + signing workflow before listing and version compatibility matrix for backend/frontend/plugin API.

### Acceptance criteria

- Connectors can create and sync remediation workflows with policy context.
- Teams can track risk delta and remediation progress over time from built-in dashboards.
- SLOs are defined, measured, and reported for scan queueing/orchestration.
- Regression gates block releases on quality/safety drift.
- Release scorecards are published and comparable across releases.
- Users can install, update, and remove free proxy plugins entirely in-product.
- Every plugin displays performance impact metadata before enablement.
- Medium/High cost plugins always present explicit warning flows and can be blocked by policy.
- Plugin creators are required to provide Dockerized plugin services with exposed APIs and manifest-declared contracts.
- Core proxy capture/replay/passive behavior remains stable and within SLO targets when plugins are disabled.

### Remaining implementation checklist

- [ ] Implement first-party Jira and Linear connectors with policy-aware routing.
- [ ] Expand automation trigger/scheduling UX and CI/CD ergonomics.
- [ ] Add capability drift alerts and fallback strategy recommendations in product.
- [ ] Add import/export for policy packs, scan profiles, and report templates.
- [ ] Ship trend dashboards and executive risk-delta summary views.
- [ ] Strengthen compliance evidence linking and remediation ownership tracking.
- [ ] Define and publish orchestration/queueing SLOs with alerting.
- [ ] Add guided onboarding + first-success wizard tied to Juice Shop harness.
- [ ] Publish benchmark suite, CI regression gates, release scorecards, and capability matrix.
- [ ] Implement plugin catalog APIs/UI for free install/enable/disable/update/remove lifecycle.
- [ ] Ship proxy plugin runtime hooks (request/response/passive/UI) with container boundary and failure isolation.
- [ ] Enforce plugin execution contract: Dockerized runtime + exposed API + manifest-declared host/plugin API mapping.
- [ ] Implement permission prompts and capability sandboxing (network/storage/hook scopes) with admin allow/deny policy packs.
- [ ] Add performance-cost labels (Low/Medium/High), Medium/High pre-install warnings, and runtime overhead indicators.
- [ ] Add plugin signing/review flow and compatibility matrix enforcement across backend/frontend/plugin API versions.
- [ ] Add plugin API compatibility tests, no-plugin regression gate, and per-tier plugin performance benchmark thresholds.

### Phase E — Continuous Learning

*Goal: Platform learns from accepted vs rejected bounty submissions and improves ranking.*

**Deliverables**

1. Bounty outcome ingestion — ingest program responses (accepted, duplicate, N/A, payout) via webhook or manual tagging.
2. ML model fine-tuning pipeline — feed outcomes into `ml_triage` with versioned model checkpoints.
3. Regression gates for model promotion — new model versions must match or exceed baseline precision/recall before deployment.
4. Versioned probe configurations — version and benchmark probe configs alongside model versions.
5. Living capability matrix — detection rate per vulnerability class across benchmark targets, updated on each release.

**Acceptance criteria**

- Model retrain-and-promote cycle is fully automated end-to-end.
- Regression gate blocks any model that regresses >2% on benchmark.
- Payout-weighted finding rank improves measurably over baseline.

**Implementation checklist**

- [x] Add bounty outcome webhook endpoint and manual tagging UI for accepted/duplicate/N/A/payout.
- [x] Wire outcome labels into `ml_triage` fine-tuning pipeline with versioned checkpoint storage.
- [x] Implement model promotion gate: block deployment if precision/recall regresses >2% vs baseline.
- [x] Version and archive probe configurations alongside each model checkpoint.
- [x] Publish living capability matrix as a release artifact with per-class detection rates.

### Phase F — Safer Autonomous Operation

*Goal: Auditable guardrails and full transparency for every autonomous agent decision.*

**Deliverables**

1. "Why this probe ran" metadata — attach policy profile, scope reason, ROI score, and triggering signal to every agent action.
2. Anomaly-based autonomy pause — halt scan on scope ambiguity, legal-risk signals, or unexpected behavior spikes.
3. Immutable decision log — every agent action, scope check, and policy evaluation recorded per campaign with timestamp.
4. Guardrail events in UI and exports — surface autonomy-pause events and decision traces in audit trail and export bundles.

**Acceptance criteria**

- Every finding links to a full agent-decision trace.
- Autonomy-pause fires correctly on scope ambiguity and anomaly conditions.
- Audit export is complete, timestamped, and tamper-evident.

**Implementation checklist**

- [ ] Add `AgentDecisionTrace` struct: fields for policy profile, scope check result, ROI score, triggering signal, and timestamp.
- [ ] Attach decision trace to every finding and agent action record.
- [ ] Implement anomaly-based autonomy pause: define anomaly signals (scope overlap, request spike, legal-risk keywords) and halt-on-trigger logic.
- [ ] Persist immutable decision log per campaign in append-only storage.
- [ ] Expose decision traces in finding detail UI panel and include in audit export bundles.
- [ ] Add autonomy-pause event type to campaign notification and audit trail.

### Phase G — Team-Grade Operations + Competitive Differentiation

*Goal: Portfolio management, drift detection, and copilot-mode for live engagements.*

**Deliverables**

1. Multi-project portfolio view — aggregate findings, risk trends, and coverage maps across all active programs.
2. Cross-asset deduplication — suppress duplicate findings across different targets within the same program.
3. SLA-based remediation planning — assign remediation owners with deadline tracking and alert escalation.
4. Drift detection — alert when a previously-remediated finding re-appears (regression scanner).
5. "Next best action" copilot — surface ranked probe suggestions with rationale during live manual engagements.
6. Attack-path graph UI — interactive first-class visualization of multi-step exploit chains.

**Acceptance criteria**

- Portfolio view aggregates findings and risk trends across ≥2 projects.
- Drift detection fires on simulated remediation regression.
- Next-best-action copilot surfaces suggestions with rationale during manual sessions.
- Attack-path graph is interactive and navigable in the UI.

**Implementation checklist**

- [ ] Build multi-project portfolio view: aggregate findings, severity distribution, coverage maps, and risk trends.
- [ ] Implement cross-asset deduplication: fingerprint-based similarity matching across targets in the same program.
- [ ] Add SLA-based remediation tracking: owner assignment, deadline dates, escalation alerts.
- [ ] Implement drift detection: re-scan check against previously-remediated findings and fire regression alerts.
- [ ] Build "next best action" copilot: rank uncovered surface areas + open finding chains and surface top-N suggestions in-session.
- [ ] Promote attack-path graph to first-class UI feature: interactive node/edge visualization with drill-down into finding detail.

---

## Sequencing and Release Mapping

- **Release A (Wave 1):** Trust + quality foundations — includes Phase A (Prove Exploitability, foundations), Phase B (Sharpen Signal-to-Noise, foundations), Phase F (Safer Autonomous Operation, foundations)
- **Release B (Wave 2):** Orchestration intelligence + bug bounty specialization — completes Phase A and Phase B; adds Phase C (Coverage Map) and Phase D (Bug Bounty-Native Output)
- **Release C (Wave 3):** Integrations + decision intelligence + scale moat — adds Phase E (Continuous Learning), completes Phase F (Safer Autonomous Operation), adds Phase G (Team-Grade Operations + Competitive Differentiation)

### Phase → Wave mapping

| Phase | Wave(s) | Theme |
|---|---|---|
| A — Prove Exploitability | Wave 1 finish + Wave 2 | PoC generation, exploit-validation sandbox |
| B — Sharpen Signal-to-Noise | Wave 1 finish + Wave 2 | FP feedback loops, per-probe precision/recall |
| C — Coverage Map | Wave 2 | Surface heatmap, adaptive budget scheduling |
| D — Bug Bounty-Native Output | Wave 2 | HackerOne/Bugcrowd templates, submission readiness |
| E — Continuous Learning | Wave 3 | Outcome-driven model tuning, regression gates |
| F — Safer Autonomous Operation | Wave 1 + Wave 3 | Auditable traces, autonomy pause, decision logs |
| G — Team-Grade + Differentiation | Wave 3 | Portfolio, drift, copilot, attack-path graph UI |

## Out of Scope for this roadmap artifact

- Detailed task breakdown per file/component
- Team staffing estimates
- Calendar-based deadlines

Those should be tracked in implementation tickets/projects once this roadmap is approved.
