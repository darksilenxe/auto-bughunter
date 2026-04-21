import { useEffect, useMemo, useState } from "react";
import { API_BASE, API_KEY, WORKSPACE_ID } from "../context/ScanContext";

const TABS = [
  { id: "history", label: "HTTP History" },
  { id: "repeater", label: "Repeater" },
  { id: "intruder", label: "Intruder" },
  { id: "configure", label: "Configure Browser" },
];

const authHeaders = () => ({
  "X-API-Key": API_KEY,
  "X-Workspace-ID": WORKSPACE_ID,
});

const jsonHeaders = () => ({
  ...authHeaders(),
  "Content-Type": "application/json",
});

export default function Proxy() {
  const [tab, setTab] = useState("history");
  const [requests, setRequests] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [selected, setSelected] = useState(null);
  const [settings, setSettings] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Repeater state
  const [repeaterHeaders, setRepeaterHeaders] = useState("");
  const [repeaterBody, setRepeaterBody] = useState("");
  const [repeaterResult, setRepeaterResult] = useState(null);

  // Intruder state
  const [intruderMarker, setIntruderMarker] = useState("§");
  const [intruderPayloads, setIntruderPayloads] = useState("");
  const [intruderResults, setIntruderResults] = useState([]);

  useEffect(() => {
    loadRequests();
    loadSettings();
  }, []);

  useEffect(() => {
    if (!selectedId) {
      setSelected(null);
      return;
    }
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/api/proxy/requests/${encodeURIComponent(selectedId)}`, {
          headers: authHeaders(),
        });
        const data = await res.json();
        if (!res.ok) {
          setError(data.error || "Failed to load request detail.");
          return;
        }
        setSelected(data);
        setRepeaterHeaders(headersToText(data.requestHeaders));
        setRepeaterBody(data.requestBody || "");
        setRepeaterResult(null);
        setIntruderResults([]);
      } catch (err) {
        setError(err.message || "Failed to load request detail.");
      }
    })();
  }, [selectedId]);

  async function loadRequests() {
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/proxy/requests`, { headers: authHeaders() });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Failed to load proxy history.");
        return;
      }
      setRequests(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || "Failed to load proxy history.");
    }
  }

  async function loadSettings() {
    try {
      const res = await fetch(`${API_BASE}/api/proxy/settings`, { headers: authHeaders() });
      const data = await res.json();
      if (res.ok) setSettings(data);
    } catch {
      // non-fatal
    }
  }

  async function clearHistory() {
    if (!window.confirm("Delete all captured proxy requests?")) return;
    setBusy(true);
    try {
      const res = await fetch(`${API_BASE}/api/proxy/requests`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error || "Failed to clear history.");
        return;
      }
      setSelectedId(null);
      await loadRequests();
    } finally {
      setBusy(false);
    }
  }

  async function sendRepeater() {
    if (!selectedId) return;
    setBusy(true);
    setRepeaterResult(null);
    try {
      const overrideHeaders = textToHeaders(repeaterHeaders);
      const res = await fetch(`${API_BASE}/api/proxy/replay`, {
        method: "POST",
        headers: jsonHeaders(),
        body: JSON.stringify({
          requestId: selectedId,
          overrideHeaders,
          overrideBody: repeaterBody,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Replay failed.");
        return;
      }
      setRepeaterResult(data);
      await loadRequests();
    } catch (err) {
      setError(err.message || "Replay failed.");
    } finally {
      setBusy(false);
    }
  }

  async function runIntruder() {
    if (!selectedId) return;
    const payloads = intruderPayloads
      .split(/\r?\n/)
      .map((p) => p.trim())
      .filter((p) => p.length > 0);
    if (payloads.length === 0) {
      setError("Add at least one payload (one per line).");
      return;
    }
    setBusy(true);
    setIntruderResults([]);
    try {
      const overrideHeaders = textToHeaders(repeaterHeaders);
      const res = await fetch(`${API_BASE}/api/proxy/intruder`, {
        method: "POST",
        headers: jsonHeaders(),
        body: JSON.stringify({
          requestId: selectedId,
          marker: intruderMarker || "§",
          payloads,
          overrideHeaders,
          overrideBody: repeaterBody,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Intruder failed.");
        return;
      }
      setIntruderResults(Array.isArray(data.results) ? data.results : []);
    } catch (err) {
      setError(err.message || "Intruder failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <header>
        <h1>🛰️ Burp-Style Proxy Suite</h1>
        <p>Capture, repeat, and fuzz HTTP traffic through the in-browser proxy.</p>
      </header>

      {!settings?.enabled && (
        <section className="card" style={{ borderColor: "#f97316" }}>
          <h2>Proxy listener is disabled</h2>
          <p className="meta">
            Set <code>ENABLE_PROXY=true</code> in <code>.env</code> and restart the backend to start the
            intercepting proxy on port <code>{settings?.port || "8081"}</code>.
          </p>
        </section>
      )}

      {error && (
        <section className="card" style={{ borderColor: "#dc2626" }}>
          <p style={{ margin: 0, color: "#fecaca" }}>{error}</p>
          <button type="button" onClick={() => setError("")} style={{ marginTop: 8 }}>Dismiss</button>
        </section>
      )}

      <section className="card" style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            style={{
              background: tab === t.id ? "#7c3aed" : "rgba(124,58,237,0.18)",
              color: "#fff",
              fontWeight: tab === t.id ? 700 : 500,
            }}
          >
            {t.label}
          </button>
        ))}
      </section>

      {tab === "history" && (
        <HistoryTab
          requests={requests}
          selectedId={selectedId}
          onSelect={setSelectedId}
          onRefresh={loadRequests}
          onClear={clearHistory}
          busy={busy}
          selected={selected}
        />
      )}

      {tab === "repeater" && (
        <RepeaterTab
          selected={selected}
          repeaterHeaders={repeaterHeaders}
          setRepeaterHeaders={setRepeaterHeaders}
          repeaterBody={repeaterBody}
          setRepeaterBody={setRepeaterBody}
          onSend={sendRepeater}
          busy={busy}
          result={repeaterResult}
        />
      )}

      {tab === "intruder" && (
        <IntruderTab
          selected={selected}
          marker={intruderMarker}
          setMarker={setIntruderMarker}
          payloads={intruderPayloads}
          setPayloads={setIntruderPayloads}
          headers={repeaterHeaders}
          setHeaders={setRepeaterHeaders}
          body={repeaterBody}
          setBody={setRepeaterBody}
          onRun={runIntruder}
          busy={busy}
          results={intruderResults}
        />
      )}

      {tab === "configure" && <ConfigureTab settings={settings} />}
    </div>
  );
}

function HistoryTab({ requests, selectedId, onSelect, onRefresh, onClear, busy, selected }) {
  return (
    <>
      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
          <h2 style={{ margin: 0 }}>HTTP History ({requests.length})</h2>
          <div style={{ display: "flex", gap: 8 }}>
            <button type="button" onClick={onRefresh} disabled={busy}>Refresh</button>
            <button type="button" onClick={onClear} disabled={busy} style={{ background: "#7f1d1d" }}>
              Clear all
            </button>
          </div>
        </div>
        {requests.length === 0 ? (
          <p className="meta">
            No captures yet. Configure your browser to use the proxy (see the Configure Browser tab) and
            visit a target URL.
          </p>
        ) : (
          <div style={{ maxHeight: 360, overflow: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
              <thead>
                <tr style={{ textAlign: "left", color: "#a78bfa" }}>
                  <th style={{ padding: "4px 8px" }}>Time</th>
                  <th style={{ padding: "4px 8px" }}>Method</th>
                  <th style={{ padding: "4px 8px" }}>Status</th>
                  <th style={{ padding: "4px 8px" }}>URL</th>
                </tr>
              </thead>
              <tbody>
                {requests.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => onSelect(r.id)}
                    style={{
                      cursor: "pointer",
                      background: r.id === selectedId ? "rgba(124,58,237,0.25)" : "transparent",
                    }}
                  >
                    <td style={{ padding: "4px 8px", whiteSpace: "nowrap" }}>{formatTime(r.capturedAt)}</td>
                    <td style={{ padding: "4px 8px" }}>{r.method}</td>
                    <td style={{ padding: "4px 8px" }}>{r.responseStatus || "-"}</td>
                    <td style={{ padding: "4px 8px", wordBreak: "break-all" }}>{r.url}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selected && <RequestDetail req={selected} />}
    </>
  );
}

function RequestDetail({ req }) {
  return (
    <section className="card">
      <h2>Request {req.id.slice(0, 8)}</h2>
      <p className="meta">
        <strong>{req.method}</strong> {req.url} · status {req.responseStatus || "-"}
      </p>
      <h3>Request headers</h3>
      <pre className="summary">{headersToText(req.requestHeaders) || "(none)"}</pre>
      {req.requestBody && (
        <>
          <h3>Request body</h3>
          <pre className="summary" style={{ maxHeight: 240, overflow: "auto" }}>{req.requestBody}</pre>
        </>
      )}
      <h3>Response headers</h3>
      <pre className="summary">{headersToText(req.responseHeaders) || "(none)"}</pre>
      {req.responseBody && (
        <>
          <h3>Response body</h3>
          <pre className="summary" style={{ maxHeight: 320, overflow: "auto" }}>{req.responseBody}</pre>
        </>
      )}
      {req.notes && <p className="meta"><em>{req.notes}</em></p>}
    </section>
  );
}

function RepeaterTab({ selected, repeaterHeaders, setRepeaterHeaders, repeaterBody, setRepeaterBody, onSend, busy, result }) {
  if (!selected) {
    return (
      <section className="card">
        <p className="meta">Select a request from HTTP History first, then edit and resend it here.</p>
      </section>
    );
  }
  return (
    <>
      <section className="card">
        <h2>Repeater</h2>
        <p className="meta">
          <strong>{selected.method}</strong> {selected.url}
        </p>
        <label>
          Headers (one <code>Name: value</code> per line)
          <textarea
            rows={8}
            value={repeaterHeaders}
            onChange={(e) => setRepeaterHeaders(e.target.value)}
            spellCheck={false}
          />
        </label>
        <label>
          Body
          <textarea
            rows={10}
            value={repeaterBody}
            onChange={(e) => setRepeaterBody(e.target.value)}
            spellCheck={false}
          />
        </label>
        <button type="button" onClick={onSend} disabled={busy}>
          {busy ? "Sending…" : "▶ Send"}
        </button>
      </section>
      {result && <RequestDetail req={result} />}
    </>
  );
}

function IntruderTab({
  selected, marker, setMarker, payloads, setPayloads,
  headers, setHeaders, body, setBody, onRun, busy, results,
}) {
  if (!selected) {
    return (
      <section className="card">
        <p className="meta">Select a request from HTTP History first, then add payload markers and run.</p>
      </section>
    );
  }
  const summary = useMemo(() => summarizeIntruder(results), [results]);
  return (
    <>
      <section className="card">
        <h2>Intruder</h2>
        <p className="meta">
          Insert the marker (<code>{marker || "§"}</code>) anywhere in the URL, headers, or body — each
          payload below replaces every occurrence.
        </p>
        <p className="meta">
          <strong>{selected.method}</strong> {selected.url}
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          <label>
            Marker
            <input value={marker} onChange={(e) => setMarker(e.target.value)} maxLength={8} />
          </label>
          <label>
            Payload count limit
            <input value="200" disabled />
          </label>
        </div>
        <label>
          Headers
          <textarea
            rows={6}
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
            spellCheck={false}
          />
        </label>
        <label>
          Body
          <textarea
            rows={6}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            spellCheck={false}
          />
        </label>
        <label>
          Payloads (one per line)
          <textarea
            rows={8}
            value={payloads}
            onChange={(e) => setPayloads(e.target.value)}
            spellCheck={false}
            placeholder={"admin\nroot\nguest"}
          />
        </label>
        <button type="button" onClick={onRun} disabled={busy}>
          {busy ? "Running…" : "▶ Start attack"}
        </button>
      </section>
      {results.length > 0 && (
        <section className="card">
          <h2>Results ({results.length})</h2>
          <p className="meta">
            Status codes: {Object.entries(summary.statusCounts).map(([k, v]) => `${k}×${v}`).join(", ") || "none"}
            {summary.errors > 0 && ` · errors: ${summary.errors}`}
          </p>
          <div style={{ maxHeight: 360, overflow: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
              <thead>
                <tr style={{ textAlign: "left", color: "#a78bfa" }}>
                  <th style={{ padding: "4px 8px" }}>#</th>
                  <th style={{ padding: "4px 8px" }}>Payload</th>
                  <th style={{ padding: "4px 8px" }}>Status</th>
                  <th style={{ padding: "4px 8px" }}>Length</th>
                  <th style={{ padding: "4px 8px" }}>ms</th>
                  <th style={{ padding: "4px 8px" }}>Error</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i}>
                    <td style={{ padding: "4px 8px" }}>{i + 1}</td>
                    <td style={{ padding: "4px 8px", wordBreak: "break-all" }}>{r.payload}</td>
                    <td style={{ padding: "4px 8px" }}>{r.status || "-"}</td>
                    <td style={{ padding: "4px 8px" }}>{r.lengthBytes}</td>
                    <td style={{ padding: "4px 8px" }}>{r.durationMs}</td>
                    <td style={{ padding: "4px 8px", color: r.error ? "#fca5a5" : undefined }}>{r.error || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );
}

function ConfigureTab({ settings }) {
  if (!settings) {
    return (
      <section className="card">
        <p className="meta">Loading proxy configuration…</p>
      </section>
    );
  }
  const proxyURL = `${settings.host}:${settings.port}`;
  return (
    <>
      <section className="card">
        <h2>Configure your browser</h2>
        <p className="meta">
          Point your browser's HTTP and HTTPS proxy at <code>{proxyURL}</code>. Examples:
        </p>
        <h3>Firefox</h3>
        <pre className="summary">{`Settings → Network Settings → Manual proxy configuration
HTTP Proxy: ${settings.host}    Port: ${settings.port}
☑ Also use this proxy for HTTPS`}</pre>
        <h3>Chrome / Chromium (CLI)</h3>
        <pre className="summary">{`chromium --proxy-server="http://${proxyURL}"`}</pre>
        <h3>curl</h3>
        <pre className="summary">{`curl -x http://${proxyURL} https://example.com`}</pre>
      </section>
      <section className="card">
        <h2>HTTPS interception (CA certificate)</h2>
        {settings.mitmEnabled ? (
          <>
            <p className="meta">
              TLS interception is <strong>enabled</strong>. Install the proxy CA in your browser/OS trust
              store so HTTPS sites load without warnings and request/response bodies are captured.
            </p>
            <ul className="meta" style={{ marginTop: 0 }}>
              <li>SHA-256 fingerprint: <code>{settings.caFingerprintSHA256}</code></li>
              {settings.caNotAfter && <li>Expires: <code>{settings.caNotAfter}</code></li>}
            </ul>
            <a
              href={`${API_BASE}/api/proxy/ca-certificate`}
              download="auto-bughunter-proxy-ca.pem"
            >
              <button type="button">⬇ Download CA certificate (.pem)</button>
            </a>
            <h3>Install</h3>
            <pre className="summary">{`Firefox: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import…
   ☑ Trust this CA to identify websites
macOS:   open auto-bughunter-proxy-ca.pem → Keychain Access → set "Always Trust"
Linux:   sudo cp auto-bughunter-proxy-ca.pem /usr/local/share/ca-certificates/
         sudo update-ca-certificates`}</pre>
          </>
        ) : (
          <>
            <p className="meta">
              TLS interception is <strong>disabled</strong>. HTTPS tunnels will be passed through without
              decryption (only the CONNECT line is captured).
            </p>
            <p className="meta">
              To enable Burp-style HTTPS capture, set the following in <code>.env</code> and restart:
            </p>
            <pre className="summary">{`PROXY_CA_CERT_FILE=/var/lib/auto-bughunter/proxy-ca.pem
PROXY_CA_KEY_FILE=/var/lib/auto-bughunter/proxy-ca.key
PROXY_CA_AUTOGENERATE=true`}</pre>
          </>
        )}
      </section>
    </>
  );
}

function headersToText(headers) {
  if (!headers) return "";
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

function textToHeaders(text) {
  const out = {};
  if (!text) return out;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function summarizeIntruder(results) {
  const statusCounts = {};
  let errors = 0;
  for (const r of results) {
    if (r.error) errors += 1;
    const key = r.status ? String(r.status) : "—";
    statusCounts[key] = (statusCounts[key] || 0) + 1;
  }
  return { statusCounts, errors };
}

function formatTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString();
}
