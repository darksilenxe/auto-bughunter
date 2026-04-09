import { useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8080";

export default function App() {
  const [target, setTarget] = useState("");
  const [headersJson, setHeadersJson] = useState("");
  const [cookiesJson, setCookiesJson] = useState("");
  const [userAgent, setUserAgent] = useState("");
  const [basicAuthUsername, setBasicAuthUsername] = useState("");
  const [basicAuthPassword, setBasicAuthPassword] = useState("");
  const [useNucleiIntegration, setUseNucleiIntegration] = useState(false);
  const [useZapBaselineIntegration, setUseZapBaselineIntegration] = useState(false);
  const [useSubfinderIntegration, setUseSubfinderIntegration] = useState(false);
  const [useHttpxIntegration, setUseHttpxIntegration] = useState(false);
  const [useNaabuIntegration, setUseNaabuIntegration] = useState(false);
  const [useDnsxIntegration, setUseDnsxIntegration] = useState(false);
  const [useKatanaIntegration, setUseKatanaIntegration] = useState(false);
  const [useTlsxIntegration, setUseTlsxIntegration] = useState(false);
  const [useCdncheckIntegration, setUseCdncheckIntegration] = useState(false);
  const [useAsnmapIntegration, setUseAsnmapIntegration] = useState(false);
  const [useWpScanIntegration, setUseWpScanIntegration] = useState(false);
  const [useNiktoIntegration, setUseNiktoIntegration] = useState(false);
  const [useSqlMapIntegration, setUseSqlMapIntegration] = useState(false);
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
      try { overrideHeaders = JSON.parse(replayHeaders); } catch (_) {
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
            useKatanaIntegration,
            useTlsxIntegration,
            useCdncheckIntegration,
            useAsnmapIntegration,
            useWpScanIntegration,
            useNiktoIntegration,
            useSqlMapIntegration,
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
            Integrations requested:{" "}
            {[
              ["nuclei", job.options?.useNucleiIntegration],
              ["zapBaseline", job.options?.useZapBaselineIntegration],
              ["subfinder", job.options?.useSubfinderIntegration],
              ["httpx", job.options?.useHttpxIntegration],
              ["naabu", job.options?.useNaabuIntegration],
              ["dnsx", job.options?.useDnsxIntegration],
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

          {job.findings?.length > 0 && (
            <>
              <h3>Findings</h3>
              <ul className="findings">
                {job.findings.map((f) => (
                  <li key={f.id}>
                    <strong>[{f.severity}] {f.title}</strong>
                    <p>{f.description}</p>
                    <p><b>Evidence:</b> {f.evidence}</p>
                    <p><b>Fix:</b> {f.recommendation}</p>
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
