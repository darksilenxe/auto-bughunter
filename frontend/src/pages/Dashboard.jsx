import { useMemo, useState } from "react";
import BurpImport from "../components/BurpImport";
import LiveFeed from "../components/LiveFeed";
import SecurityKnowledgePanel from "../components/SecurityKnowledgePanel";
import { useScan } from "../context/ScanContext";
import { DEFAULT_IMPACT_GOALS, IMPACT_GOALS, impactGoalMeta, summarizeFindings, topGoals } from "../lib/impact";

const SCENARIOS = {
  bugbounty: {
    label: "Bug bounty",
    description: "Cautious, reportability-focused scan tuned for real-world submissions.",
    policyPack: "bugbounty",
    useNuclei: true,
    useZap: false,
    useXSSMap: false,
    useMLTriage: true,
    useAttackPath: true,
    useFalsePositiveReview: true,
    useRemediationPlanner: false,
    aggressiveExploitation: false,
    strictReporting: false,
    minReportConfidence: "",
    excludeHosts: "",
    loginSteps: [],
    impactGoals: DEFAULT_IMPACT_GOALS,
  },
  pentest: {
    label: "Internal pentest",
    description: "Full-depth engagement with stronger validation and remediation context.",
    policyPack: "internal",
    useNuclei: true,
    useZap: true,
    useXSSMap: false,
    useMLTriage: true,
    useAttackPath: true,
    useFalsePositiveReview: true,
    useRemediationPlanner: true,
    aggressiveExploitation: true,
    strictReporting: false,
    minReportConfidence: "",
    excludeHosts: "",
    loginSteps: [],
    impactGoals: DEFAULT_IMPACT_GOALS,
  },
  sso_cookie_consent: {
    label: "SSO / cookie consent",
    description: "Pre-tuned for enterprise apps behind consent banners and external IdPs.",
    policyPack: "bugbounty",
    useNuclei: true,
    useZap: false,
    useXSSMap: false,
    useMLTriage: true,
    useAttackPath: true,
    useFalsePositiveReview: true,
    useRemediationPlanner: false,
    aggressiveExploitation: false,
    strictReporting: true,
    minReportConfidence: "0.80",
    excludeHosts: "login.microsoftonline.com, *.microsoftonline.com, login.microsoft.com, *.microsoft.com",
    loginSteps: [
      { action: "click", selector: "#cookie-accept-btn", value: "", waitMillis: 0, optional: true },
      { action: "wait", selector: "", value: "", waitMillis: 1500, optional: false },
      { action: "fill", selector: "#i0116", value: "{{username}}", waitMillis: 0, optional: false },
      { action: "click", selector: "#idSIButton9", value: "", waitMillis: 0, optional: false },
      { action: "wait", selector: "", value: "", waitMillis: 2000, optional: false },
      { action: "fill", selector: "#i0118", value: "{{password}}", waitMillis: 0, optional: false },
      { action: "click", selector: "#idSIButton9", value: "", waitMillis: 0, optional: false },
      { action: "wait", selector: "", value: "", waitMillis: 3000, optional: false },
    ],
    impactGoals: DEFAULT_IMPACT_GOALS,
  },
};

const EMPTY_LOGIN_STEP = { action: "click", selector: "", value: "", waitMillis: 0, optional: false };

export default function Dashboard() {
  const { startScan, stopScan, job, loading, error, scanId, liveEvents } = useScan();
  const [scenario, setScenario] = useState("bugbounty");
  const [target, setTarget] = useState("");
  const [headersJson, setHeadersJson] = useState("");
  const [customHeaderName, setCustomHeaderName] = useState("");
  const [customHeaderValue, setCustomHeaderValue] = useState("");
  const [cookiesJson, setCookiesJson] = useState("");
  const [userAgent, setUserAgent] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [basicAuthUsername, setBasicAuthUsername] = useState("");
  const [basicAuthPassword, setBasicAuthPassword] = useState("");
  const [includeHosts, setIncludeHosts] = useState("");
  const [excludeHosts, setExcludeHosts] = useState("");
  const [excludePaths, setExcludePaths] = useState("");
  const [programRules, setProgramRules] = useState("");
  const [useNuclei, setUseNuclei] = useState(true);
  const [useZap, setUseZap] = useState(false);
  const [useXSSMap, setUseXSSMap] = useState(false);
  const [useMLTriage, setUseMLTriage] = useState(true);
  const [useAttackPath, setUseAttackPath] = useState(true);
  const [useFalsePositiveReview, setUseFalsePositiveReview] = useState(true);
  const [useRemediationPlanner, setUseRemediationPlanner] = useState(false);
  const [workspaceId, setWorkspaceId] = useState("default");
  const [policyPack, setPolicyPack] = useState("bugbounty");
  const [aggressiveExploitation, setAggressiveExploitation] = useState(false);
  const [humanPaced, setHumanPaced] = useState(false);
  const [strictReporting, setStrictReporting] = useState(false);
  const [minReportConfidence, setMinReportConfidence] = useState("");
  const [loginSteps, setLoginSteps] = useState([]);
  const [impactGoals, setImpactGoals] = useState(DEFAULT_IMPACT_GOALS);

  function applyScenario(key) {
    const preset = SCENARIOS[key];
    if (!preset) return;
    setScenario(key);
    setPolicyPack(preset.policyPack);
    setUseNuclei(preset.useNuclei);
    setUseZap(preset.useZap);
    setUseXSSMap(preset.useXSSMap);
    setUseMLTriage(preset.useMLTriage);
    setUseAttackPath(preset.useAttackPath);
    setUseFalsePositiveReview(preset.useFalsePositiveReview);
    setUseRemediationPlanner(preset.useRemediationPlanner);
    setAggressiveExploitation(preset.aggressiveExploitation);
    setStrictReporting(preset.strictReporting ?? false);
    setMinReportConfidence(preset.minReportConfidence ?? "");
    setImpactGoals(preset.impactGoals ?? DEFAULT_IMPACT_GOALS);
    if (preset.excludeHosts !== undefined) setExcludeHosts(preset.excludeHosts);
    if (preset.loginSteps) setLoginSteps(preset.loginSteps.map((step) => ({ ...step })));
  }

  function handleBurpImport(cfg) {
    if (cfg.target) setTarget(cfg.target);
    if (cfg.includeHosts?.length) setIncludeHosts(cfg.includeHosts.join(", "));
    if (cfg.excludeHosts?.length) setExcludeHosts(cfg.excludeHosts.join(", "));
    if (cfg.excludePaths?.length) setExcludePaths(cfg.excludePaths.join(", "));
    if (Object.keys(cfg.headers || {}).length) setHeadersJson(JSON.stringify(cfg.headers, null, 2));
    if (Object.keys(cfg.cookies || {}).length) setCookiesJson(JSON.stringify(cfg.cookies, null, 2));
  }

  function toggleImpactGoal(goalId) {
    setImpactGoals((prev) => {
      if (prev.includes(goalId)) {
        return prev.length === 1 ? prev : prev.filter((goal) => goal !== goalId);
      }
      return [...prev, goalId];
    });
  }

  function addLoginStep() {
    setLoginSteps((prev) => [...prev, { ...EMPTY_LOGIN_STEP }]);
  }

  function removeLoginStep(idx) {
    setLoginSteps((prev) => prev.filter((_, i) => i !== idx));
  }

  function updateLoginStep(idx, field, value) {
    setLoginSteps((prev) => prev.map((step, i) => (i === idx ? { ...step, [field]: value } : step)));
  }

  function handleSubmit(event) {
    event.preventDefault();
    let headers = {};
    let cookies = {};
    try { if (headersJson.trim()) headers = JSON.parse(headersJson); } catch { /* ignore */ }
    try { if (cookiesJson.trim()) cookies = JSON.parse(cookiesJson); } catch { /* ignore */ }

    const trimmedCustomHeaderName = customHeaderName.trim();
    if (trimmedCustomHeaderName) headers[trimmedCustomHeaderName] = customHeaderValue.trim();

    const scopeRules = programRules
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

    startScan({
      target,
      workspaceId,
      programPolicyVersion: policyPack,
      authProfile: {
        headers,
        cookies,
        userAgent: userAgent || undefined,
        loginUrl: loginUrl || undefined,
        username: username || undefined,
        password: password || undefined,
        basicAuthUsername: basicAuthUsername || undefined,
        basicAuthPassword: basicAuthPassword || undefined,
        loginSteps: loginSteps.length ? loginSteps : undefined,
      },
      options: {
        useNucleiIntegration: useNuclei,
        useZapBaselineIntegration: useZap,
        useXssMapIntegration: useXSSMap,
        useMLTriageAgent: useMLTriage,
        useAttackPathAgent: useAttackPath,
        useFalsePositiveReview,
        useRemediationPlanner,
        aggressiveExploitation,
        humanPaced: humanPaced || undefined,
        strictReporting: strictReporting || undefined,
        minReportConfidence: strictReporting && minReportConfidence.trim() ? Number(minReportConfidence) : undefined,
        impactGoals,
      },
      scope: {
        includeHosts: includeHosts ? includeHosts.split(",").map((h) => h.trim()).filter(Boolean) : [],
        excludeHosts: excludeHosts ? excludeHosts.split(",").map((h) => h.trim()).filter(Boolean) : [],
        excludePaths: excludePaths ? excludePaths.split(",").map((h) => h.trim()).filter(Boolean) : [],
        programRules: scopeRules,
      },
    });
  }

  const findingsSummary = useMemo(() => summarizeFindings(job?.findings || []), [job?.findings]);
  const isRunning = job?.status === "running" || loading;
  const highlightedGoals = useMemo(() => topGoals(job?.findings || []), [job?.findings]);

  return (
    <div className="page page--wide">
      <section className="hero-panel">
        <div className="eyebrow">Premium AI operator console</div>
        <div className="toolbar" style={{ alignItems: "flex-start" }}>
          <div>
            <header style={{ marginBottom: 0 }}>
              <h1>Impact-first web pentest command</h1>
              <p>
                Launch agentic scans optimized for demonstrated impact, bug bounty reportability, and proof-grade evidence.
              </p>
            </header>
          </div>
          <div className="filter-row">
            <span className={`status-badge ${job?.status === "completed" ? "success" : isRunning ? "" : "warning"}`}>
              {job?.status || (isRunning ? "running" : "ready")}
            </span>
            <span className="chip">AI tool loop</span>
            <span className="chip chip--goal">Impact goals active</span>
          </div>
        </div>

        <div className="metrics-grid" style={{ marginTop: 22 }}>
          <article className="stat-card">
            <span className="stat-card__label">Submission-ready findings</span>
            <div className="stat-card__value">{findingsSummary.submissionReady}</div>
            <div className="stat-card__hint">Highest-value outcomes the operator can package immediately.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Demonstrated impact</span>
            <div className="stat-card__value">{findingsSummary.demonstrated}</div>
            <div className="stat-card__hint">Findings with business-effect proof, not just technical validation.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Avg bounty score</span>
            <div className="stat-card__value">{(Number(findingsSummary.avgBountyScore || 0) * 100).toFixed(0)}%</div>
            <div className="stat-card__hint">Ranking driven by proof quality, exploitability, and impact.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Top exploit chains</span>
            <div className="stat-card__value">{findingsSummary.chains}</div>
            <div className="stat-card__hint">Chained paths that end in reviewer-friendly business outcomes.</div>
          </article>
        </div>
      </section>

      <div className="two-column-grid">
        <section className="card">
          <div className="toolbar" style={{ alignItems: "flex-start", marginBottom: 14 }}>
            <div>
              <h2>Launch autonomous engagement</h2>
              <p className="meta">Configure targets, auth, scope, impact goals, and proof-tuning in one operator workflow.</p>
            </div>
            <div className="filter-row">
              {Object.entries(SCENARIOS).map(([key, preset]) => (
                <button
                  key={key}
                  type="button"
                  className={`filter-chip ${scenario === key ? "is-active" : ""}`}
                  onClick={() => applyScenario(key)}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          {scenario && (
            <div className="surface" style={{ marginBottom: 14 }}>
              <strong>{SCENARIOS[scenario].label}</strong>
              <p className="meta" style={{ marginTop: 6 }}>{SCENARIOS[scenario].description}</p>
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div className="form-grid form-grid--wide">
              <label>
                Target URL *
                <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://target.example" required />
              </label>
              <label>
                Workspace ID
                <input value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)} placeholder="default" />
              </label>
              <label>
                Policy pack
                <select value={policyPack} onChange={(e) => setPolicyPack(e.target.value)}>
                  <option value="internal">internal</option>
                  <option value="bugbounty">bugbounty</option>
                  <option value="regulated">regulated</option>
                </select>
              </label>
              <label>
                User-Agent
                <input value={userAgent} onChange={(e) => setUserAgent(e.target.value)} placeholder="Mozilla/5.0 ..." />
              </label>
            </div>

            <div>
              <div className="toolbar" style={{ marginBottom: 10 }}>
                <div>
                  <strong>Impact objectives</strong>
                  <p className="meta" style={{ marginTop: 4 }}>These goals steer planning, chain reasoning, verification, and final submissions.</p>
                </div>
                <span className="chip chip--muted">{impactGoals.length} selected</span>
              </div>
              <div className="goal-grid">
                {IMPACT_GOALS.map((goal) => (
                  <button
                    key={goal.id}
                    type="button"
                    className={`goal-card ${impactGoals.includes(goal.id) ? "is-selected" : ""}`}
                    onClick={() => toggleImpactGoal(goal.id)}
                  >
                    <div className="goal-card__title">
                      <span>{goal.label}</span>
                      <span className="chip chip--muted">{goal.shortLabel}</span>
                    </div>
                    <div className="meta">{goal.description}</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="form-grid">
              <label>
                Auth headers (JSON)
                <textarea rows={3} value={headersJson} onChange={(e) => setHeadersJson(e.target.value)} placeholder='{"Authorization":"Bearer token"}' />
              </label>
              <label>
                Auth cookies (JSON)
                <textarea rows={3} value={cookiesJson} onChange={(e) => setCookiesJson(e.target.value)} placeholder='{"session":"abc123"}' />
              </label>
            </div>

            <div className="form-grid">
              <label>
                Custom header name
                <input value={customHeaderName} onChange={(e) => setCustomHeaderName(e.target.value)} placeholder="X-Bug-Bounty" />
              </label>
              <label>
                Custom header value
                <input value={customHeaderValue} onChange={(e) => setCustomHeaderValue(e.target.value)} placeholder="researcher-handle" />
              </label>
              <label>
                Standard login URL
                <input value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} placeholder="https://example.com/login" />
              </label>
            </div>

            <div className="form-grid">
              <label>
                App username
                <input value={username} onChange={(e) => setUsername(e.target.value)} />
              </label>
              <label>
                App password
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
              </label>
              <label>
                HTTP basic auth username
                <input value={basicAuthUsername} onChange={(e) => setBasicAuthUsername(e.target.value)} />
              </label>
              <label>
                HTTP basic auth password
                <input type="password" value={basicAuthPassword} onChange={(e) => setBasicAuthPassword(e.target.value)} />
              </label>
            </div>

            <details>
              <summary>Login steps / browser automation {loginSteps.length ? `(${loginSteps.length})` : ""}</summary>
              <p className="meta" style={{ margin: "10px 0 0" }}>
                Handle cookie banners, SSO, or multi-step entry points. Use <code>{"{{username}}"}</code> and <code>{"{{password}}"}</code> inside fill values.
              </p>
              {loginSteps.map((step, idx) => (
                <div key={idx} className="form-grid" style={{ marginTop: 12 }}>
                  <label>
                    Action
                    <select value={step.action} onChange={(e) => updateLoginStep(idx, "action", e.target.value)}>
                      <option value="click">click</option>
                      <option value="fill">fill</option>
                      <option value="wait">wait</option>
                    </select>
                  </label>
                  <label>
                    CSS selector
                    <input value={step.selector} disabled={step.action === "wait"} onChange={(e) => updateLoginStep(idx, "selector", e.target.value)} />
                  </label>
                  <label>
                    {step.action === "fill" ? "Value" : "Wait ms"}
                    <input
                      value={step.action === "fill" ? step.value : step.waitMillis}
                      type={step.action === "fill" ? "text" : "number"}
                      onChange={(e) => updateLoginStep(idx, step.action === "fill" ? "value" : "waitMillis", step.action === "fill" ? e.target.value : Number(e.target.value))}
                    />
                  </label>
                  <label className="check" style={{ marginTop: 28 }}>
                    <input type="checkbox" checked={step.optional} onChange={(e) => updateLoginStep(idx, "optional", e.target.checked)} />
                    Optional
                  </label>
                  <button type="button" className="button-danger" onClick={() => removeLoginStep(idx)} style={{ marginTop: 26 }}>
                    Remove
                  </button>
                </div>
              ))}
              <div className="button-row" style={{ marginTop: 12 }}>
                <button type="button" className="button-secondary" onClick={addLoginStep}>Add step</button>
                {loginSteps.length > 0 && <button type="button" className="button-ghost" onClick={() => setLoginSteps([])}>Clear all</button>}
              </div>
            </details>

            <div className="form-grid">
              <label>
                Include hosts
                <input value={includeHosts} onChange={(e) => setIncludeHosts(e.target.value)} placeholder="example.com, api.example.com" />
              </label>
              <label>
                Exclude hosts
                <input value={excludeHosts} onChange={(e) => setExcludeHosts(e.target.value)} />
              </label>
              <label>
                Exclude paths
                <input value={excludePaths} onChange={(e) => setExcludePaths(e.target.value)} placeholder="/logout, /admin" />
              </label>
            </div>

            <label>
              Program rules (one per line)
              <textarea rows={3} value={programRules} onChange={(e) => setProgramRules(e.target.value)} placeholder={"in_scope: example.com\nno_dos_testing\nno_account_takeover"} />
            </label>

            <BurpImport onImport={handleBurpImport} />

            <div className="surface">
              <div className="toolbar" style={{ marginBottom: 12 }}>
                <strong>Agent stack and noise controls</strong>
                <span className="chip chip--muted">Proof-aware tuning</span>
              </div>
              <div className="form-grid form-grid--wide">
                <label className="check"><input type="checkbox" checked={useNuclei} onChange={(e) => setUseNuclei(e.target.checked)} />Use Nuclei</label>
                <label className="check"><input type="checkbox" checked={useZap} onChange={(e) => setUseZap(e.target.checked)} />Use ZAP baseline</label>
                <label className="check"><input type="checkbox" checked={useXSSMap} onChange={(e) => setUseXSSMap(e.target.checked)} />Use XSSMap</label>
                <label className="check"><input type="checkbox" checked={useMLTriage} onChange={(e) => setUseMLTriage(e.target.checked)} />ML triage agent</label>
                <label className="check"><input type="checkbox" checked={useAttackPath} onChange={(e) => setUseAttackPath(e.target.checked)} />Attack path agent</label>
                <label className="check"><input type="checkbox" checked={useFalsePositiveReview} onChange={(e) => setUseFalsePositiveReview(e.target.checked)} />False-positive review</label>
                <label className="check"><input type="checkbox" checked={useRemediationPlanner} onChange={(e) => setUseRemediationPlanner(e.target.checked)} />Remediation planner</label>
                <label className="check"><input type="checkbox" checked={aggressiveExploitation} onChange={(e) => setAggressiveExploitation(e.target.checked)} />Aggressive exploitation</label>
                <label className="check"><input type="checkbox" checked={humanPaced} onChange={(e) => setHumanPaced(e.target.checked)} />Human-paced (1–2 min between tools)</label>
                <label className="check"><input type="checkbox" checked={strictReporting} onChange={(e) => setStrictReporting(e.target.checked)} />Strict reporting</label>
              </div>
              {strictReporting && (
                <div className="form-grid" style={{ marginTop: 12 }}>
                  <label>
                    Min confidence (0.0–1.0)
                    <input type="number" min="0" max="1" step="0.05" value={minReportConfidence} onChange={(e) => setMinReportConfidence(e.target.value)} placeholder="0.75" />
                  </label>
                </div>
              )}
            </div>

            <div className="button-row">
              <button disabled={loading}>{loading ? "Scanning…" : "Start scan"}</button>
              {loading && scanId && <button type="button" className="button-danger" onClick={() => stopScan(scanId)}>Stop scan</button>}
            </div>
          </form>

          {error && <p className="error" style={{ marginTop: 12 }}>{error}</p>}
          {scanId && <p className="meta" style={{ marginTop: 12 }}>Scan ID: {scanId}</p>}
        </section>

        <div className="section-grid">
          <section className="card card--soft">
            <div className="toolbar" style={{ alignItems: "flex-start" }}>
              <div>
                <h2>Mission control</h2>
                <p className="meta">A paid-tool style snapshot of reportability, proof maturity, and operator focus.</p>
              </div>
              <span className="chip chip--goal">{impactGoals.length} goals armed</span>
            </div>

            <div className="three-column-grid" style={{ marginTop: 14 }}>
              <article className="meta-block">
                <b>Primary focus</b>
                {impactGoals.slice(0, 2).map((goal) => <div key={goal}>{impactGoalMeta(goal).label}</div>)}
              </article>
              <article className="meta-block">
                <b>Top finding</b>
                <div>{findingsSummary.topFinding?.title || "Awaiting signal"}</div>
                <div className="meta">Bounty {(Number(findingsSummary.topFinding?.bountyScore || 0) * 100).toFixed(0)}%</div>
              </article>
              <article className="meta-block">
                <b>Proof artifacts</b>
                <div>{findingsSummary.proofArtifacts}</div>
                <div className="meta">Captured across current engagement evidence.</div>
              </article>
            </div>

            {highlightedGoals.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <strong>Observed impact patterns</strong>
                <div className="filter-row" style={{ marginTop: 10 }}>
                  {highlightedGoals.map(({ goal, count }) => (
                    <span key={goal} className="chip chip--goal">
                      {impactGoalMeta(goal).shortLabel} · {count}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </section>

          <LiveFeed events={liveEvents} isRunning={isRunning} />

          {job && job.status !== "running" && (
            <>
              <section className="card">
                <div className="toolbar" style={{ alignItems: "flex-start" }}>
                  <div>
                    <h2>Engagement outcome</h2>
                    <p className="meta">Final scan state with impact-grade summary and severity distribution.</p>
                  </div>
                  <span className={`status-badge ${job.status === "completed" ? "success" : job.status === "failed" ? "error" : "warning"}`}>{job.status}</span>
                </div>
                <div className="filter-row" style={{ margin: "12px 0 10px" }}>
                  <span className="pill high">High {findingsSummary.severities.high}</span>
                  <span className="pill medium">Medium {findingsSummary.severities.medium}</span>
                  <span className="pill low">Low {findingsSummary.severities.low}</span>
                  <span className="pill info">Info {findingsSummary.severities.info}</span>
                </div>
                {job.aiSummary ? <pre className="summary">{job.aiSummary}</pre> : <p className="meta">No AI summary captured for this scan.</p>}
              </section>
              <SecurityKnowledgePanel knowledge={job.modelRecommendations?.securityKnowledge} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
