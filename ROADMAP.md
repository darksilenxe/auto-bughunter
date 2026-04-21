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

### Acceptance criteria

- Connectors can create and sync remediation workflows with policy context.
- Teams can track risk delta and remediation progress over time from built-in dashboards.
- SLOs are defined, measured, and reported for scan queueing/orchestration.
- Regression gates block releases on quality/safety drift.
- Release scorecards are published and comparable across releases.

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
