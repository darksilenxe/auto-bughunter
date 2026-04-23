import { useState } from "react";
import { useScan } from "../context/ScanContext";
import BurpImport from "../components/BurpImport";
import SecurityKnowledgePanel from "../components/SecurityKnowledgePanel";

// Scenario presets — each defines the opinionated defaults for a scan mode.
const SCENARIOS = {
  bugbounty: {
    label: "🏆 Bug Bounty",
    description: "Cautious scan tuned for bug-bounty programs: no destructive checks, focuses on high-signal findings.",
    policyPack: "bugbounty",
    useNuclei: true,
    useZap: false,
    useXSSMap: false,
    useMLTriage: true,
    useAttackPath: true,
    useFalsePositiveReview: true,
    useRemediationPlanner: false,
    aggressiveExploitation: false,
  },
  pentest: {
    label: "🔓 Pen Test",
    description: "Full-depth engagement: aggressive exploitation, all integrations, remediation planning.",
    policyPack: "internal",
    useNuclei: true,
    useZap: true,
    useXSSMap: false,
    useMLTriage: true,
    useAttackPath: true,
    useFalsePositiveReview: true,
    useRemediationPlanner: true,
    aggressiveExploitation: true,
  },
};

export default function Dashboard() {
  const { startScan, stopScan, job, loading, error, scanId } = useScan();
  const [scenario, setScenario] = useState("");
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
  const [useNuclei, setUseNuclei] = useState(false);
  const [useZap, setUseZap] = useState(false);
  const [useXSSMap, setUseXSSMap] = useState(false);
  const [useMLTriage, setUseMLTriage] = useState(false);
  const [useAttackPath, setUseAttackPath] = useState(false);
  const [useFalsePositiveReview, setUseFalsePositiveReview] = useState(false);
  const [useRemediationPlanner, setUseRemediationPlanner] = useState(false);
  const [workspaceId, setWorkspaceId] = useState("default");
  const [policyPack, setPolicyPack] = useState("internal");
  const [aggressiveExploitation, setAggressiveExploitation] = useState(false);

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
  }

  function handleBurpImport(cfg) {
    if (cfg.target)       setTarget(cfg.target);
    if (cfg.includeHosts?.length) setIncludeHosts(cfg.includeHosts.join(", "));
    if (cfg.excludeHosts?.length) setExcludeHosts(cfg.excludeHosts.join(", "));
    if (cfg.excludePaths?.length) setExcludePaths(cfg.excludePaths.join(", "));
    if (Object.keys(cfg.headers || {}).length)
      setHeadersJson(JSON.stringify(cfg.headers, null, 2));
    if (Object.keys(cfg.cookies || {}).length)
      setCookiesJson(JSON.stringify(cfg.cookies, null, 2));
  }

  function handleSubmit(e) {
    e.preventDefault();
    let headers = {};
    let cookies = {};
    try { if (headersJson.trim()) headers = JSON.parse(headersJson); } catch { /* ignore */ }
    try { if (cookiesJson.trim()) cookies = JSON.parse(cookiesJson); } catch { /* ignore */ }
    const trimmedCustomHeaderName = customHeaderName.trim();
    if (trimmedCustomHeaderName) headers[trimmedCustomHeaderName] = customHeaderValue.trim();

    const scopeRules = [];
    if (programRules.trim()) {
      for (const line of programRules.split("\n")) {
        const t = line.trim();
        if (t) scopeRules.push(t);
      }
    }

    startScan({
      target,
      workspaceId,
      programPolicyVersion: policyPack,
      authProfile: {
        headers, cookies,
        userAgent: userAgent || undefined,
        loginUrl: loginUrl || undefined,
        username: username || undefined,
        password: password || undefined,
        basicAuthUsername: basicAuthUsername || undefined,
        basicAuthPassword: basicAuthPassword || undefined,
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
      },
      scope: {
        includeHosts: includeHosts ? includeHosts.split(",").map((h) => h.trim()).filter(Boolean) : [],
        excludeHosts: excludeHosts ? excludeHosts.split(",").map((h) => h.trim()).filter(Boolean) : [],
        excludePaths: excludePaths ? excludePaths.split(",").map((h) => h.trim()).filter(Boolean) : [],
        programRules: scopeRules,
      },
    });
  }

  const isRunning = job?.status === "running" || loading;
  const sevCounts = { high: 0, medium: 0, low: 0, info: 0 };
  if (job?.findings) {
    for (const f of job.findings) {
      if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++;
    }
  }

  return (
    <div className="page">
      <header>
        <h1>🐛 Auto BugHunter</h1>
        <p>Fully autonomous bug bounty scanning with local AI</p>
      </header>

      {/* Scan form */}
      <section className="card">
        <h2>Start Autonomous Scan</h2>
        <p className="meta">Authentication is optional. Leave the auth fields empty to run an unauthenticated attack-surface scan.</p>

        {/* ── Scenario selector ── */}
        <div style={{ marginBottom: "1.25rem" }}>
          <p style={{ marginBottom: "0.5rem", fontWeight: 600, fontSize: "0.9rem" }}>Scan Scenario</p>
          <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
            {Object.entries(SCENARIOS).map(([key, s]) => (
              <button
                key={key}
                type="button"
                onClick={() => applyScenario(key)}
                style={{
                  padding: "0.5rem 1.1rem",
                  borderRadius: "8px",
                  border: scenario === key ? "2px solid #60a5fa" : "2px solid rgba(255,255,255,0.15)",
                  background: scenario === key ? "rgba(96,165,250,0.15)" : "rgba(255,255,255,0.05)",
                  color: scenario === key ? "#93c5fd" : "inherit",
                  fontWeight: scenario === key ? 700 : 400,
                  cursor: "pointer",
                  fontSize: "0.9rem",
                  transition: "all 0.15s",
                }}
              >
                {s.label}
              </button>
            ))}
            {scenario && (
              <button
                type="button"
                onClick={() => setScenario("")}
                style={{
                  padding: "0.5rem 0.75rem",
                  borderRadius: "8px",
                  border: "2px solid rgba(255,255,255,0.1)",
                  background: "transparent",
                  color: "#6b7280",
                  cursor: "pointer",
                  fontSize: "0.8rem",
                }}
              >
                ✕ Clear
              </button>
            )}
          </div>
          {scenario && (
            <p className="meta" style={{ marginTop: "0.4rem" }}>
              {SCENARIOS[scenario].description}
            </p>
          )}
        </div>

        <form onSubmit={handleSubmit}>
          <label>
            Target URL *
            <input value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com" required />
          </label>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
            <label>Workspace ID
              <input value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)} placeholder="default" />
            </label>
            <label>Policy Pack
              <select value={policyPack} onChange={(e) => setPolicyPack(e.target.value)}>
                <option value="internal">internal</option>
                <option value="bugbounty">bugbounty</option>
                <option value="regulated">regulated</option>
              </select>
            </label>
          </div>
          <label>
            Auth Headers (JSON)
            <textarea rows={2} value={headersJson} onChange={(e) => setHeadersJson(e.target.value)}
              placeholder='{"Authorization": "Bearer token"}' />
          </label>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
            <label>Custom Header Name
              <input value={customHeaderName} onChange={(e) => setCustomHeaderName(e.target.value)}
                placeholder="X-Bug-Bounty" />
            </label>
            <label>Custom Header Value
              <input value={customHeaderValue} onChange={(e) => setCustomHeaderValue(e.target.value)}
                placeholder="your-hackerone-username" />
            </label>
          </div>
          <p className="meta" style={{ marginTop: "0.25rem" }}>
            This custom header overrides any Auth Headers JSON entry with the same name.
          </p>
          <label>
            Auth Cookies (JSON)
            <textarea rows={2} value={cookiesJson} onChange={(e) => setCookiesJson(e.target.value)}
              placeholder='{"session": "abc123"}' />
          </label>
          <label>
            User-Agent
            <input value={userAgent} onChange={(e) => setUserAgent(e.target.value)}
              placeholder="Mozilla/5.0 ..." />
          </label>
          <label>
            Standard Login URL (optional)
            <input value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)}
              placeholder="https://example.com/login" />
          </label>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
            <label>App Username
              <input value={username} onChange={(e) => setUsername(e.target.value)} />
            </label>
            <label>App Password
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
            <label>HTTP Basic Auth Username
              <input value={basicAuthUsername} onChange={(e) => setBasicAuthUsername(e.target.value)} />
            </label>
            <label>HTTP Basic Auth Password
              <input type="password" value={basicAuthPassword} onChange={(e) => setBasicAuthPassword(e.target.value)} />
            </label>
          </div>
          <label>
            Scope — Include Hosts (comma-separated)
            <input value={includeHosts} onChange={(e) => setIncludeHosts(e.target.value)}
              placeholder="example.com,api.example.com" />
          </label>
          <label>
            Scope — Exclude Hosts
            <input value={excludeHosts} onChange={(e) => setExcludeHosts(e.target.value)} />
          </label>
          <label>
            Scope — Exclude Paths
            <input value={excludePaths} onChange={(e) => setExcludePaths(e.target.value)}
              placeholder="/logout,/admin" />
          </label>
          <label>
            Program Rules (one per line)
            <textarea rows={3} value={programRules} onChange={(e) => setProgramRules(e.target.value)}
              placeholder="in_scope: example.com&#10;no_dos_testing&#10;no_account_takeover" />
          </label>
          <BurpImport onImport={handleBurpImport} />
          <div style={{ display: "flex", gap: "1.5rem", flexWrap: "wrap" }}>
            <label className="check">
              <input type="checkbox" checked={useNuclei} onChange={(e) => setUseNuclei(e.target.checked)} />
              Use Nuclei
            </label>
            <label className="check">
              <input type="checkbox" checked={useZap} onChange={(e) => setUseZap(e.target.checked)} />
              Use ZAP Baseline
            </label>
            <label className="check">
              <input type="checkbox" checked={useXSSMap} onChange={(e) => setUseXSSMap(e.target.checked)} />
              XSSMap (LLM-assisted XSS) — requires ALLOW_DESTRUCTIVE_CHECKS
            </label>
          </div>
          <div style={{ display: "flex", gap: "1.5rem", flexWrap: "wrap", marginTop: "0.5rem" }}>
            <label className="check">
              <input type="checkbox" checked={useMLTriage} onChange={(e) => setUseMLTriage(e.target.checked)} />
              ML Triage Agent
            </label>
            <label className="check">
              <input type="checkbox" checked={useAttackPath} onChange={(e) => setUseAttackPath(e.target.checked)} />
              Attack Path Agent
            </label>
            <label className="check">
              <input type="checkbox" checked={useFalsePositiveReview} onChange={(e) => setUseFalsePositiveReview(e.target.checked)} />
              False Positive Review
            </label>
            <label className="check">
              <input type="checkbox" checked={useRemediationPlanner} onChange={(e) => setUseRemediationPlanner(e.target.checked)} />
              Remediation Planner
            </label>
            <label className="check">
              <input type="checkbox" checked={aggressiveExploitation} onChange={(e) => setAggressiveExploitation(e.target.checked)} />
              Aggressive Exploitation Mode (Metasploit/Burp priority)
            </label>
          </div>
          <button disabled={loading}>{loading ? "Scanning…" : "▶ Start Scan"}</button>
        </form>
        {loading && scanId && (
          <button type="button" onClick={() => stopScan(scanId)} style={{ marginTop: "0.5rem", background: "#ef4444" }}>
            ⏹ Stop Scan
          </button>
        )}
        {error && <p className="error">{error}</p>}
        {scanId && <p className="meta">Scan ID: {scanId}</p>}
      </section>

      {/* Summary when complete */}
      {job && job.status !== "running" && (
        <>
          <section className="card">
            <h2>Status: <span style={{ color: job.status === "completed" ? "#4ade80" : job.status === "cancelled" ? "#facc15" : "#ef4444" }}>{job.status}</span></h2>
            <div className="stats">
              <span className="pill high">High: {sevCounts.high}</span>
              <span className="pill medium">Medium: {sevCounts.medium}</span>
              <span className="pill low">Low: {sevCounts.low}</span>
              <span className="pill info">Info: {sevCounts.info}</span>
            </div>
            {job.aiSummary && (
              <>
                <h3>AI Summary</h3>
                <pre className="summary">{job.aiSummary}</pre>
              </>
            )}
          </section>
          <SecurityKnowledgePanel knowledge={job.modelRecommendations?.securityKnowledge} />
        </>
      )}

    </div>
  );
}
