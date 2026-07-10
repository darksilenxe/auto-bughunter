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

---

## Wave 2 — Orchestration Intelligence + Bug Bounty Specialization

Focus areas: adaptive automation, explainability, and bug bounty outcome performance.

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

- [ ] Add runtime policy-aware model/prompt tuning profiles with audit traces.
- [x] Ship planner offline replay harness with baseline comparison output.
- [ ] Add per-target adaptive strategy policy using historical drift and ROI signals.
- [x] Surface “why agent ran” and “why ranked high” in UI and report exports.
- [x] Add HackerOne/Bugcrowd-oriented submission bundles and severity rationale helpers.
- [x] Add duplicate detection against prior submissions/scans with similarity thresholds.
- [x] Close payout-feedback loop into prioritization scoring by program profile.
- [ ] Define intercept-proxy plugin SDK contracts (hook surface + API schema + manifest format) and publish creator docs.
- [ ] Add compatibility harness for plugin API versions and baseline no-plugin regression checks.

---

## Wave 3 — Integrations + Decision Intelligence + Scale Moat

Focus areas: ecosystem fit, executive value, reliability, and defensible quality leadership.

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

---

## Sequencing and Release Mapping

- **Release A (Wave 1):** Trust + quality foundations
- **Release B (Wave 2):** Orchestration intelligence + bug bounty specialization
- **Release C (Wave 3):** Integrations + decision intelligence + scale moat

## Out of Scope for this roadmap artifact

- Detailed task breakdown per file/component
- Team staffing estimates
- Calendar-based deadlines

Those should be tracked in implementation tickets/projects once this roadmap is approved.
