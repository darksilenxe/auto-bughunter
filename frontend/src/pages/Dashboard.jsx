import { useState } from "react";
import { useScan } from "../context/ScanContext";
import AttackGraph from "../components/AttackGraph";
import AttackPathGraph from "../components/AttackPathGraph";
import BurpImport from "../components/BurpImport";
import SecurityKnowledgePanel from "../components/SecurityKnowledgePanel";

export default function Dashboard() {
  const { startScan, job, loading, error, liveEvents, scanId } = useScan();
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
  const [selectedScreenshot, setSelectedScreenshot] = useState(null);
  const [activeGraphTab, setActiveGraphTab] = useState("chain");

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
        <form onSubmit={handleSubmit}>
          <label>
            Target URL *
            <input value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com" required />
          </label>
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
          </div>
          <button disabled={loading}>{loading ? "Scanning…" : "▶ Start Scan"}</button>
        </form>
        {error && <p className="error">{error}</p>}
        {scanId && <p className="meta">Scan ID: {scanId}</p>}
      </section>

      {/* Attack graph — shown from the moment a scan starts through completion */}
      {(loading || job) && (
        <section className="card" style={{ padding: "0", overflow: "hidden" }}>
          {/* Tab bar */}
          <div style={{
            display: "flex",
            background: "rgba(0,0,0,0.55)",
            borderBottom: "1px solid rgba(124,58,237,0.25)",
          }}>
            {[
              { id: "chain",    label: "⛓ Attack Chain" },
              { id: "pipeline", label: "⚡ Agent Pipeline" },
            ].map(({ id, label }) => {
              const active = activeGraphTab === id;
              return (
                <button
                  key={id}
                  onClick={() => setActiveGraphTab(id)}
                  style={{
                    background: "none",
                    border: "none",
                    borderBottom: active ? "2px solid #a78bfa" : "2px solid transparent",
                    color: active ? "#c4b5fd" : "rgba(255,255,255,0.4)",
                    fontWeight: active ? 700 : 400,
                    fontSize: "0.8rem",
                    padding: "8px 18px",
                    cursor: "pointer",
                    letterSpacing: "0.03em",
                    transition: "color 0.15s, border-color 0.15s",
                  }}
                >
                  {label}
                </button>
              );
            })}
          </div>

          {activeGraphTab === "chain" && (
            <AttackGraph
              job={job}
              liveEvents={liveEvents}
              isRunning={isRunning}
              onScreenshot={(b64) => setSelectedScreenshot(b64)}
            />
          )}
          {activeGraphTab === "pipeline" && (
            <div style={{ padding: "12px" }}>
              <AttackPathGraph events={liveEvents} />
            </div>
          )}
        </section>
      )}

      {/* Summary when complete */}
      {job && job.status !== "running" && (
        <>
          <section className="card">
            <h2>Status: <span style={{ color: job.status === "completed" ? "#4ade80" : "#ef4444" }}>{job.status}</span></h2>
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

      {/* Screenshot lightbox */}
      {selectedScreenshot && (
        <div
          onClick={() => setSelectedScreenshot(null)}
          style={{
            position: "fixed", inset: 0, background: "rgba(0,0,0,0.88)",
            display: "flex", alignItems: "center", justifyContent: "center",
            zIndex: 1000, cursor: "zoom-out",
          }}
        >
          <img src={`data:image/png;base64,${selectedScreenshot}`} alt="Screenshot"
            style={{ maxWidth: "90vw", maxHeight: "90vh", borderRadius: "8px" }}
            onClick={(e) => e.stopPropagation()} />
          <button onClick={() => setSelectedScreenshot(null)}
            style={{ position: "absolute", top: "16px", right: "24px", background: "none", border: "none", color: "#fff", fontSize: "2rem", cursor: "pointer" }}>
            ×
          </button>
        </div>
      )}
    </div>
  );
}
