import { useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8080";

export default function App() {
  const [target, setTarget] = useState("");
  const [headersJson, setHeadersJson] = useState("");
  const [cookiesJson, setCookiesJson] = useState("");
  const [userAgent, setUserAgent] = useState("");
  const [basicAuthUsername, setBasicAuthUsername] = useState("");
  const [basicAuthPassword, setBasicAuthPassword] = useState("");
  const [includeHosts, setIncludeHosts] = useState("");
  const [excludeHosts, setExcludeHosts] = useState("");
  const [excludePaths, setExcludePaths] = useState("");
  const [programRules, setProgramRules] = useState("");
  const [useNucleiIntegration, setUseNucleiIntegration] = useState(false);
  const [useZapBaselineIntegration, setUseZapBaselineIntegration] = useState(false);
  const [useSubfinderIntegration, setUseSubfinderIntegration] = useState(false);
  const [useHttpxIntegration, setUseHttpxIntegration] = useState(false);
  const [useNaabuIntegration, setUseNaabuIntegration] = useState(false);
  const [useDnsxIntegration, setUseDnsxIntegration] = useState(false);
  const [useShuffleDnsIntegration, setUseShuffleDnsIntegration] = useState(false);
  const [useCertificateTransparencyIntegration, setUseCertificateTransparencyIntegration] = useState(false);
  const [useAmassIntegration, setUseAmassIntegration] = useState(false);
  const [useKatanaIntegration, setUseKatanaIntegration] = useState(false);
  const [useTlsxIntegration, setUseTlsxIntegration] = useState(false);
  const [useCdncheckIntegration, setUseCdncheckIntegration] = useState(false);
  const [useAsnmapIntegration, setUseAsnmapIntegration] = useState(false);
  const [useWpScanIntegration, setUseWpScanIntegration] = useState(false);
  const [useNiktoIntegration, setUseNiktoIntegration] = useState(false);
  const [useSqlMapIntegration, setUseSqlMapIntegration] = useState(false);
  const [rescanIntervalMinutes, setRescanIntervalMinutes] = useState(0);
  const [scanId, setScanId] = useState("");
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Proxy panel state
  const [proxyRequests, setProxyRequests] = useState([]);
  const [proxyLoading, setProxyLoading] = useState(false);
  const [proxyError, setProxyError] = useState("");
  const [selectedProxyReq, setSelectedProxyReq] = useState(null);
  const [replayHeaders, setReplayHeaders] = useState("{}");
  const [replayBody, setReplayBody] = useState("");
  const [replayResult, setReplayResult] = useState(null);
  const [replayLoading, setReplayLoading] = useState(false);

  const severityCounts = useMemo(() => {
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    if (!job?.findings) return counts;
    for (const f of job.findings) {
      if (counts[f.severity] !== undefined) counts[f.severity] += 1;
    }
    return counts;
  }, [job]);

  async function fetchProxyRequests() {
    setProxyLoading(true);
    setProxyError("");
    try {
      const res = await fetch(`${API_BASE}/api/proxy/requests`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to load proxy requests");
      setProxyRequests(data || []);
    } catch (err) {
      setProxyError(err.message);
    } finally {
      setProxyLoading(false);
    }
  }

  async function clearProxyRequests() {
    try {
      await fetch(`${API_BASE}/api/proxy/requests`, { method: "DELETE" });
      setProxyRequests([]);
      setSelectedProxyReq(null);
      setReplayResult(null);
    } catch (err) {
      setProxyError(err.message);
    }
  }

  async function replayRequest() {
    if (!selectedProxyReq) return;
    setReplayLoading(true);
    setReplayResult(null);
    try {
      let overrideHeaders = {};
      try { overrideHeaders = JSON.parse(replayHeaders); } catch (jsonErr) {
        setProxyError("Override Headers must be valid JSON (e.g. {\"X-Custom\": \"value\"})");
        setReplayLoading(false);
        return;
      }
      const res = await fetch(`${API_BASE}/api/proxy/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requestId: selectedProxyReq.id,
          overrideHeaders,
          overrideBody: replayBody,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Replay failed");
      setReplayResult(data);
    } catch (err) {
      setProxyError(err.message);
    } finally {
      setReplayLoading(false);
    }
  }

  async function createScan(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    setJob(null);
    setScanId("");

    try {
      const parsedHeaders = safeParseMap(headersJson, "Headers");
      const parsedCookies = safeParseMap(cookiesJson, "Cookies");
      const parsedIncludeHosts = safeParseList(includeHosts);
      const parsedExcludeHosts = safeParseList(excludeHosts);
      const parsedExcludePaths = safeParseList(excludePaths);
      const parsedProgramRules = safeParseList(programRules);

      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          authProfile: {
            headers: parsedHeaders,
            cookies: parsedCookies,
            userAgent,
            basicAuthUsername,
            basicAuthPassword,
          },
          options: {
            useNucleiIntegration,
            useZapBaselineIntegration,
            useSubfinderIntegration,
            useHttpxIntegration,
            useNaabuIntegration,
            useDnsxIntegration,
            useShuffleDnsIntegration,
            useCertificateTransparencyIntegration,
            useAmassIntegration,
            useKatanaIntegration,
            useTlsxIntegration,
            useCdncheckIntegration,
            useAsnmapIntegration,
            useWpScanIntegration,
            useNiktoIntegration,
            useSqlMapIntegration,
            rescanIntervalMinutes: Number(rescanIntervalMinutes) || 0,
          },
          scope: {
            includeHosts: parsedIncludeHosts,
            excludeHosts: parsedExcludeHosts,
            excludePaths: parsedExcludePaths,
            programRules: parsedProgramRules,
          },
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start scan");

      setScanId(data.id);
      await pollScan(data.id);
    } catch (err) {
      setError(err.message || "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  function safeParseMap(raw, label) {
    if (!raw.trim()) return {};

    const out = {};
    const lines = raw.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const idx = trimmed.indexOf(":");
      if (idx <= 0) {
        throw new Error(`${label} lines must be in key:value format`);
      }
      const key = trimmed.slice(0, idx).trim();
      const value = trimmed.slice(idx + 1).trim();
      if (!key) {
        throw new Error(`${label} contains an empty key`);
      }
      out[key] = value;
    }
    return out;
  }

  function safeParseList(raw) {
    if (!raw.trim()) return [];
    return raw
      .split("\n")
      .map((v) => v.trim())
      .filter(Boolean);
  }

  async function pollScan(id) {
    for (let i = 0; i < 80; i += 1) {
      const res = await fetch(`${API_BASE}/api/scan/${id}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Polling failed");

      setJob(data);
      if (data.status === "completed" || data.status === "failed") return;
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    throw new Error("Scan timed out while polling");
  }

  return (
    <div className="page">
      <header>
        <h1>Auto Bughunter</h1>
        <p>Authorized web app security testing with AI-assisted triage.</p>
      </header>

      <section className="card">
        <form onSubmit={createScan}>
          <label htmlFor="target">Target URL</label>
          <input
            id="target"
            type="url"
            placeholder="https://example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            required
          />

          <label htmlFor="headers">Auth Headers (one key:value per line)</label>
          <textarea
            id="headers"
            value={headersJson}
            onChange={(e) => setHeadersJson(e.target.value)}
            rows={3}
            placeholder={"Authorization: Bearer <token>"}
          />

          <label htmlFor="cookies">Auth Cookies (one key:value per line)</label>
          <textarea
            id="cookies"
            value={cookiesJson}
            onChange={(e) => setCookiesJson(e.target.value)}
            rows={3}
            placeholder={"sessionid: abc123"}
          />

          <label htmlFor="ua">User-Agent Override (optional)</label>
          <input
            id="ua"
            type="text"
            value={userAgent}
            onChange={(e) => setUserAgent(e.target.value)}
            placeholder="Mozilla/5.0 ..."
          />

          <label htmlFor="basic-user">Basic Auth Username (optional)</label>
          <input
            id="basic-user"
            type="text"
            value={basicAuthUsername}
            onChange={(e) => setBasicAuthUsername(e.target.value)}
          />

          <label htmlFor="basic-pass">Basic Auth Password (optional)</label>
          <input
            id="basic-pass"
            type="password"
            value={basicAuthPassword}
            onChange={(e) => setBasicAuthPassword(e.target.value)}
          />

          <label htmlFor="scope-include">Scope Include Hosts (one host/wildcard per line)</label>
          <textarea
            id="scope-include"
            value={includeHosts}
            onChange={(e) => setIncludeHosts(e.target.value)}
            rows={3}
            placeholder={"example.com\n*.example.com"}
          />

          <label htmlFor="scope-exclude">Scope Exclude Hosts (one host/wildcard per line)</label>
          <textarea
            id="scope-exclude"
            value={excludeHosts}
            onChange={(e) => setExcludeHosts(e.target.value)}
            rows={3}
            placeholder={"admin.example.com"}
          />

          <label htmlFor="scope-paths">Out-of-scope Paths (one prefix per line)</label>
          <textarea
            id="scope-paths"
            value={excludePaths}
            onChange={(e) => setExcludePaths(e.target.value)}
            rows={3}
            placeholder={"/logout\n/internal"}
          />

          <label htmlFor="scope-rules">Program Rules (notes; one line each)</label>
          <textarea
            id="scope-rules"
            value={programRules}
            onChange={(e) => setProgramRules(e.target.value)}
            rows={2}
            placeholder={"No destructive testing\nNo social engineering"}
          />

          <label className="check">
            <input
              type="checkbox"
              checked={useNucleiIntegration}
              onChange={(e) => setUseNucleiIntegration(e.target.checked)}
            />
            Run optional Nuclei integration
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useZapBaselineIntegration}
              onChange={(e) => setUseZapBaselineIntegration(e.target.checked)}
            />
            Run optional ZAP Baseline integration
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useSubfinderIntegration}
              onChange={(e) => setUseSubfinderIntegration(e.target.checked)}
            />
            Run optional Subfinder integration (subdomain discovery)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useHttpxIntegration}
              onChange={(e) => setUseHttpxIntegration(e.target.checked)}
            />
            Run optional httpx integration (HTTP probing &amp; tech detection)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useNaabuIntegration}
              onChange={(e) => setUseNaabuIntegration(e.target.checked)}
            />
            Run optional Naabu integration (port scanning)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useDnsxIntegration}
              onChange={(e) => setUseDnsxIntegration(e.target.checked)}
            />
            Run optional dnsx integration (DNS enumeration)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useShuffleDnsIntegration}
              onChange={(e) => setUseShuffleDnsIntegration(e.target.checked)}
            />
            Run optional ShuffleDNS integration (subdomain discovery)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useCertificateTransparencyIntegration}
              onChange={(e) => setUseCertificateTransparencyIntegration(e.target.checked)}
            />
            Run optional Certificate Transparency integration (crt.sh discovery)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useAmassIntegration}
              onChange={(e) => setUseAmassIntegration(e.target.checked)}
            />
            Run optional Amass integration (native Go passive discovery)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useKatanaIntegration}
              onChange={(e) => setUseKatanaIntegration(e.target.checked)}
            />
            Run optional Katana integration (web crawling)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useTlsxIntegration}
              onChange={(e) => setUseTlsxIntegration(e.target.checked)}
            />
            Run optional tlsx integration (TLS certificate analysis)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useCdncheckIntegration}
              onChange={(e) => setUseCdncheckIntegration(e.target.checked)}
            />
            Run optional cdncheck integration (CDN/WAF detection)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useAsnmapIntegration}
              onChange={(e) => setUseAsnmapIntegration(e.target.checked)}
            />
            Run optional asnmap integration (ASN/CIDR mapping)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useWpScanIntegration}
              onChange={(e) => setUseWpScanIntegration(e.target.checked)}
            />
            Run WPScan (native WordPress security scan — auto-detects if target is WordPress)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useNiktoIntegration}
              onChange={(e) => setUseNiktoIntegration(e.target.checked)}
            />
            Run Nikto (native Go web app pen-test — server fingerprinting, dangerous files, HTTP methods, API docs)
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={useSqlMapIntegration}
              onChange={(e) => setUseSqlMapIntegration(e.target.checked)}
            />
            Run SQLMap (native Go SQL injection — error-based, boolean-blind &amp; time-based blind; GET/POST/cookies/headers)
          </label>

          <label htmlFor="rescan-interval">Rescan interval (minutes, 0=off)</label>
          <input
            id="rescan-interval"
            type="number"
            min={0}
            max={10080}
            value={rescanIntervalMinutes}
            onChange={(e) => setRescanIntervalMinutes(e.target.value)}
          />

          <button disabled={loading}>{loading ? "Running..." : "Start Scan"}</button>
        </form>
        {error && <p className="error">{error}</p>}
        {scanId && <p className="meta">Scan ID: {scanId}</p>}
      </section>

      {job && (
        <section className="card">
          <h2>Status: {job.status}</h2>
          {job.authProfileSummary && (
            <p className="meta">
              Auth profile used: headers={job.authProfileSummary.headerKeys?.length || 0}, cookies={job.authProfileSummary.cookieNames?.length || 0}, basicAuth={job.authProfileSummary.hasBasicAuth ? "yes" : "no"}
            </p>
          )}
          <p className="meta">
            Scope: includeHosts={job.scope?.includeHosts?.length || 0}, excludeHosts={job.scope?.excludeHosts?.length || 0}, excludePaths={job.scope?.excludePaths?.length || 0}
          </p>
          <p className="meta">
            Integrations requested:{" "}
            {[
              ["nuclei", job.options?.useNucleiIntegration],
              ["zapBaseline", job.options?.useZapBaselineIntegration],
              ["subfinder", job.options?.useSubfinderIntegration],
              ["httpx", job.options?.useHttpxIntegration],
              ["naabu", job.options?.useNaabuIntegration],
              ["dnsx", job.options?.useDnsxIntegration],
              ["shuffleDns", job.options?.useShuffleDnsIntegration],
              ["certificateTransparency", job.options?.useCertificateTransparencyIntegration],
              ["amass", job.options?.useAmassIntegration],
              ["katana", job.options?.useKatanaIntegration],
              ["tlsx", job.options?.useTlsxIntegration],
              ["cdncheck", job.options?.useCdncheckIntegration],
              ["asnmap", job.options?.useAsnmapIntegration],
              ["wpscan", job.options?.useWpScanIntegration],
              ["nikto", job.options?.useNiktoIntegration],
              ["sqlmap", job.options?.useSqlMapIntegration],
            ]
              .map(([name, val]) => `${name}=${val ? "yes" : "no"}`)
              .join(", ")}
          </p>
          <p className="meta">Rescan interval: {job.options?.rescanIntervalMinutes || 0} minute(s)</p>
          <div className="stats">
            <span className="pill high">High: {severityCounts.high}</span>
            <span className="pill medium">Medium: {severityCounts.medium}</span>
            <span className="pill low">Low: {severityCounts.low}</span>
            <span className="pill info">Info: {severityCounts.info}</span>
          </div>

          {job.aiSummary && (
            <>
              <h3>AI Summary</h3>
              <pre className="summary">{job.aiSummary}</pre>
            </>
          )}
          {job.dashboard && (
            <>
              <h3>Decision Dashboard</h3>
              <ul className="findings">
                <li>
                  <strong>Coverage completeness:</strong> {job.dashboard.coverageCompletenessScore}%
                  <p><b>Authenticated coverage rate:</b> {(Number(job.dashboard.authenticatedCoverageRate || 0) * 100).toFixed(0)}%</p>
                  <p><b>Drift:</b> new={job.dashboard.newFindings || 0}, changed={job.dashboard.changedFindings || 0}, resolved={job.dashboard.resolvedFindings || 0}</p>
                  <p><b>Actionable findings:</b> {job.dashboard.actionableFindings || 0}</p>
                  {(job.dashboard.topAttackPaths?.length > 0) && <p><b>Top attack paths:</b> {job.dashboard.topAttackPaths.join(", ")}</p>}
                  {(job.dashboard.untestedReasons?.length > 0) && <p><b>Untested reasons:</b> {job.dashboard.untestedReasons.join(", ")}</p>}
                </li>
              </ul>
            </>
          )}
          {(job.nextActions?.length > 0) && (
            <>
              <h3>Engagement Next Actions</h3>
              <ul className="findings">
                {job.nextActions.map((n, idx) => (
                  <li key={`next-${idx}`}>
                    <p>{n}</p>
                  </li>
                ))}
              </ul>
            </>
          )}
          {job.automatedReport && (
            <>
              <h3>Automated Pen Test Report</h3>
              <pre className="summary">{job.automatedReport}</pre>
            </>
          )}

          {job.findings?.length > 0 && (
            <>
              <h3>Findings</h3>
              <ul className="findings">
                {job.findings.map((f) => (
                  <li key={f.id}>
                    <strong>[{f.severity}] {f.title}</strong>
                    <p>{f.description}</p>
                    <p><b>Evidence:</b> {f.evidence}</p>
                    {f.driftStatus && <p><b>Drift:</b> {f.driftStatus}</p>}
                    {f.sources?.length > 0 && <p><b>Sources:</b> {f.sources.join(", ")}</p>}
                    {(f.confidence !== undefined) && <p><b>Confidence:</b> {Number(f.confidence).toFixed(2)}</p>}
                    {f.evidenceFields && <p><b>Evidence fields:</b> {Object.entries(f.evidenceFields).map(([k, v]) => `${k}=${v}`).join(", ")}</p>}
                    {f.businessTags?.length > 0 && <p><b>Business tags:</b> {f.businessTags.join(", ")}</p>}
                    {f.exploitability && <p><b>Exploitability:</b> reachable={String(f.exploitability.reachable)}, requiredRole={f.exploitability.requiredRole || "unknown"}, prerequisites={(f.exploitability.prerequisites || []).join(", ") || "none"}</p>}
                    <p><b>Fix:</b> {f.recommendation}</p>
                  </li>
                ))}
              </ul>
            </>
          )}

          {job.assets?.length > 0 && (
            <>
              <h3>Asset Inventory</h3>
              <ul className="findings">
                {job.assets.map((a, idx) => (
                  <li key={`${a.assetType}-${a.assetKey}-${idx}`}>
                    <strong>[{a.assetType}] {a.assetKey}</strong>
                    {a.assetValue && <p><b>Details:</b> {a.assetValue}</p>}
                  </li>
                ))}
              </ul>
            </>
          )}
          {job.assetLinks?.length > 0 && (
            <>
              <h3>Asset Relationship Graph</h3>
              <ul className="findings">
                {job.assetLinks.map((l, idx) => (
                  <li key={`${l.fromType}-${l.fromKey}-${l.relation}-${l.toType}-${l.toKey}-${idx}`}>
                    <strong>{l.fromType}:{l.fromKey}</strong>
                    <p>{l.relation} ➜ {l.toType}:{l.toKey}</p>
                  </li>
                ))}
              </ul>
            </>
          )}
          {job.agentRuns?.length > 0 && (
            <>
              <h3>Per-Agent Coverage Telemetry</h3>
              <ul className="findings">
                {job.agentRuns.map((a, idx) => (
                  <li key={`${a.agentName}-${a.startedAt}-${idx}`}>
                    <strong>{a.agentName}</strong>
                    <p><b>Status:</b> {a.status} | <b>Duration:</b> {a.durationMs}ms | <b>Timed out:</b> {a.timedOut ? "yes" : "no"}</p>
                    <p><b>Targets:</b> attempted={a.targetsAttempted || 0}, skipped={a.targetsSkipped || 0}</p>
                    {a.skippedReasons?.length > 0 && <p><b>Skipped reasons:</b> {a.skippedReasons.join(", ")}</p>}
                    {a.error && <p><b>Error:</b> {a.error}</p>}
                  </li>
                ))}
              </ul>
            </>
          )}

          {job.auditTrail?.length > 0 && (
            <>
              <h3>Run Audit Trail</h3>
              <ul className="findings">
                {job.auditTrail.map((e, idx) => (
                  <li key={`${e.timestamp}-${e.stage}-${idx}`}>
                    <strong>{e.stage}</strong>
                    <p>{e.message}</p>
                    <p><b>Time:</b> {e.timestamp}</p>
                  </li>
                ))}
              </ul>
            </>
          )}

          {job.error && <p className="error">{job.error}</p>}
        </section>
      )}

      <section className="card">
        <h2>🕵️ Intercepting Proxy</h2>
        <p className="meta">
          Configure your browser or tool to use the backend as an HTTP proxy (port 8081 by default).
          Requests flow through, are captured here, and can be replayed with modified headers or body.
        </p>
        <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.75rem" }}>
          <button onClick={fetchProxyRequests} disabled={proxyLoading}>
            {proxyLoading ? "Loading…" : "↻ Refresh Captured Requests"}
          </button>
          <button onClick={clearProxyRequests} style={{ background: "#c0392b" }}>
            🗑 Clear All
          </button>
        </div>
        {proxyError && <p className="error">{proxyError}</p>}
        {proxyRequests.length === 0 && !proxyLoading && (
          <p className="meta">No captured requests yet. Start the proxy and browse your target.</p>
        )}
        {proxyRequests.length > 0 && (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid #444" }}>
                <th style={{ padding: "4px 8px" }}>Method</th>
                <th style={{ padding: "4px 8px" }}>URL</th>
                <th style={{ padding: "4px 8px" }}>Status</th>
                <th style={{ padding: "4px 8px" }}>Captured</th>
                <th style={{ padding: "4px 8px" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {proxyRequests.map((pr) => (
                <tr key={pr.id} style={{ borderBottom: "1px solid #2a2a2a", background: selectedProxyReq?.id === pr.id ? "#1e3a2f" : "transparent" }}>
                  <td style={{ padding: "4px 8px" }}><code>{pr.method}</code></td>
                  <td style={{ padding: "4px 8px", maxWidth: "360px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    <span title={pr.url}>{pr.url}</span>
                  </td>
                  <td style={{ padding: "4px 8px" }}>{pr.responseStatus}</td>
                  <td style={{ padding: "4px 8px" }}>{new Date(pr.capturedAt).toLocaleTimeString()}</td>
                  <td style={{ padding: "4px 8px" }}>
                    <button style={{ padding: "2px 8px", fontSize: "0.8rem" }} onClick={() => {
                      setSelectedProxyReq(pr);
                      setReplayHeaders("{}");
                      setReplayBody(pr.requestBody || "");
                      setReplayResult(null);
                    }}>Select</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {selectedProxyReq && (
          <div style={{ marginTop: "1rem", background: "#111", padding: "1rem", borderRadius: "6px" }}>
            <h3>Repeater — {selectedProxyReq.method} {selectedProxyReq.url}</h3>
            <p className="meta">Original response: HTTP {selectedProxyReq.responseStatus}</p>
            <details style={{ marginBottom: "0.5rem" }}>
              <summary style={{ cursor: "pointer", color: "#aaa" }}>Original Request Headers</summary>
              <pre style={{ fontSize: "0.75rem", overflowX: "auto" }}>{JSON.stringify(selectedProxyReq.requestHeaders, null, 2)}</pre>
            </details>
            <details style={{ marginBottom: "0.5rem" }}>
              <summary style={{ cursor: "pointer", color: "#aaa" }}>Original Response Headers</summary>
              <pre style={{ fontSize: "0.75rem", overflowX: "auto" }}>{JSON.stringify(selectedProxyReq.responseHeaders, null, 2)}</pre>
            </details>
            <label>Override Headers (JSON):</label>
            <textarea
              rows={3}
              style={{ width: "100%", fontFamily: "monospace", fontSize: "0.8rem", marginBottom: "0.5rem", background: "#1a1a1a", color: "#eee", border: "1px solid #444", borderRadius: "4px", padding: "6px" }}
              value={replayHeaders}
              onChange={(e) => setReplayHeaders(e.target.value)}
            />
            <label>Override Body (leave blank to keep original):</label>
            <textarea
              rows={4}
              style={{ width: "100%", fontFamily: "monospace", fontSize: "0.8rem", marginBottom: "0.5rem", background: "#1a1a1a", color: "#eee", border: "1px solid #444", borderRadius: "4px", padding: "6px" }}
              value={replayBody}
              onChange={(e) => setReplayBody(e.target.value)}
            />
            <button onClick={replayRequest} disabled={replayLoading}>
              {replayLoading ? "Sending…" : "▶ Send Replay"}
            </button>

            {replayResult && (
              <div style={{ marginTop: "0.75rem" }}>
                <p className="meta">Replay response: HTTP {replayResult.responseStatus}</p>
                <details>
                  <summary style={{ cursor: "pointer", color: "#aaa" }}>Response Headers</summary>
                  <pre style={{ fontSize: "0.75rem", overflowX: "auto" }}>{JSON.stringify(replayResult.responseHeaders, null, 2)}</pre>
                </details>
                <details>
                  <summary style={{ cursor: "pointer", color: "#aaa" }}>Response Body</summary>
                  <pre style={{ fontSize: "0.75rem", overflowX: "auto", maxHeight: "300px" }}>{replayResult.responseBody}</pre>
                </details>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
