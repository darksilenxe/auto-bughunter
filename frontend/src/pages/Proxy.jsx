import { useEffect, useMemo, useState } from "react";
import { API_BASE, API_KEY, WORKSPACE_ID } from "../context/ScanContext";

const TABS = [
  { id: "history", label: "HTTP history" },
  { id: "browser", label: "Proxy browser" },
  { id: "passive", label: "Passive findings" },
  { id: "repeater", label: "Repeater" },
  { id: "intruder", label: "Intruder" },
  { id: "decoder", label: "Decoder" },
  { id: "configure", label: "Configure browser" },
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
  const [repeaterHeaders, setRepeaterHeaders] = useState("");
  const [repeaterBody, setRepeaterBody] = useState("");
  const [repeaterResult, setRepeaterResult] = useState(null);
  const [intruderMarker, setIntruderMarker] = useState("§");
  const [intruderPayloads, setIntruderPayloads] = useState("");
  const [intruderResults, setIntruderResults] = useState([]);
  const [decoderInput, setDecoderInput] = useState("");
  const [decoderOutput, setDecoderOutput] = useState("");
  const [decoderError, setDecoderError] = useState("");

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
        const res = await fetch(`${API_BASE}/api/proxy/requests/${encodeURIComponent(selectedId)}`, { headers: authHeaders() });
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
      const res = await fetch(`${API_BASE}/api/proxy/requests`, { method: "DELETE", headers: authHeaders() });
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
    const payloads = intruderPayloads.split(/\r?\n/).map((payload) => payload.trim()).filter(Boolean);
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

  function runDecoder(action) {
    setDecoderError("");
    try {
      setDecoderOutput(applyDecoderAction(action, decoderInput));
    } catch (err) {
      setDecoderError(err.message || "Transform failed.");
    }
  }

  function copyDecoderOutputToInput() {
    setDecoderInput(decoderOutput);
    setDecoderError("");
  }

  function swapDecoderBuffers() {
    setDecoderInput(decoderOutput);
    setDecoderOutput(decoderInput);
    setDecoderError("");
  }

  function clearDecoderBuffers() {
    setDecoderInput("");
    setDecoderOutput("");
    setDecoderError("");
  }

  const historySummary = useMemo(() => summarizeHistory(requests), [requests]);

  return (
    <div className="page page--wide">
      <section className="hero-panel">
        <div className="toolbar" style={{ alignItems: "flex-start" }}>
          <div>
            <div className="eyebrow">Operator proxy workbench</div>
            <header style={{ marginBottom: 0 }}>
              <h1>Proxy Suite</h1>
              <p>Capture traffic, replay requests, fuzz insertion points, and bootstrap browser interception from one premium operator surface.</p>
            </header>
          </div>
          <div className="filter-row">
            <span className={`status-badge ${settings?.enabled ? "success" : "warning"}`}>{settings?.enabled ? "Listener enabled" : "Listener disabled"}</span>
            <span className={`status-badge ${settings?.mitmEnabled ? "success" : "warning"}`}>{settings?.mitmEnabled ? "HTTPS intercept on" : "HTTPS passthrough"}</span>
          </div>
        </div>

        <div className="metrics-grid" style={{ marginTop: 18 }}>
          <article className="stat-card">
            <span className="stat-card__label">Captured requests</span>
            <div className="stat-card__value">{requests.length}</div>
            <div className="stat-card__hint">HTTP history retained for replay, fuzzing, and reporting pivots.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">2xx responses</span>
            <div className="stat-card__value">{historySummary.success}</div>
            <div className="stat-card__hint">Useful high-signal flows to promote into repeater and intruder sessions.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">5xx responses</span>
            <div className="stat-card__value">{historySummary.serverErrors}</div>
            <div className="stat-card__hint">Potential fault lines for auth, parsing, and input handling pivots.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Proxy endpoint</span>
            <div className="stat-card__value">{settings ? `${settings.host}:${settings.port}` : "…"}</div>
            <div className="stat-card__hint">Operator-facing address for browser and CLI proxy configuration.</div>
          </article>
        </div>
      </section>

      {!settings?.enabled && (
        <section className="card">
          <h2>Listener currently disabled</h2>
          <p className="meta">
            Set <code>ENABLE_PROXY=true</code> and restart the backend to expose the intercepting proxy on port <code>{settings?.port || "8081"}</code>.
          </p>
        </section>
      )}

      {error && (
        <section className="card">
          <div className="toolbar">
            <p className="error" style={{ margin: 0 }}>{error}</p>
            <button type="button" className="button-secondary" onClick={() => setError("")}>Dismiss</button>
          </div>
        </section>
      )}

      <section className="card card--compact">
        <div className="filter-row">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`filter-chip ${tab === item.id ? "is-active" : ""}`}
              onClick={() => setTab(item.id)}
            >
              {item.label}
            </button>
          ))}
        </div>
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

      {tab === "browser" && <BrowserTab apiBase={API_BASE} apiKey={API_KEY} workspaceId={WORKSPACE_ID} onRefreshHistory={loadRequests} />}

      {tab === "passive" && <PassiveFindingsTab apiBase={API_BASE} apiKey={API_KEY} workspaceId={WORKSPACE_ID} />}

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

      {tab === "decoder" && (
        <DecoderTab
          input={decoderInput}
          output={decoderOutput}
          error={decoderError}
          setInput={setDecoderInput}
          setOutput={setDecoderOutput}
          onTransform={runDecoder}
          onCopyOutputToInput={copyDecoderOutputToInput}
          onSwap={swapDecoderBuffers}
          onClear={clearDecoderBuffers}
        />
      )}

      {tab === "configure" && <ConfigureTab settings={settings} />}
    </div>
  );
}

function HistoryTab({ requests, selectedId, onSelect, onRefresh, onClear, busy, selected }) {
  return (
    <div className="two-column-grid">
      <section className="card">
        <div className="toolbar" style={{ marginBottom: 12 }}>
          <div>
            <h2>HTTP history</h2>
            <p className="meta">Capture review queue for selecting replayable or fuzz-worthy flows.</p>
          </div>
          <div className="button-row">
            <button type="button" className="button-secondary" onClick={onRefresh} disabled={busy}>Refresh</button>
            <button type="button" className="button-danger" onClick={onClear} disabled={busy}>Clear all</button>
          </div>
        </div>
        {requests.length === 0 ? (
          <div className="empty-state">No captures yet. Point your browser at the proxy and load a target application.</div>
        ) : (
          <div className="table-wrap" style={{ maxHeight: 420 }}>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Method</th>
                  <th>Status</th>
                  <th>URL</th>
                </tr>
              </thead>
              <tbody>
                {requests.map((request) => (
                  <tr
                    key={request.id}
                    onClick={() => onSelect(request.id)}
                    style={{ cursor: "pointer", background: request.id === selectedId ? "rgba(89,208,255,0.08)" : "transparent" }}
                  >
                    <td>{formatTime(request.capturedAt)}</td>
                    <td>{request.method}</td>
                    <td>{request.responseStatus || "-"}</td>
                    <td style={{ wordBreak: "break-all" }}>{request.url}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selected ? <RequestDetail req={selected} /> : (
        <section className="card empty-state">
          Select a captured request to inspect headers, bodies, and replay inputs.
        </section>
      )}
    </div>
  );
}

function RequestDetail({ req }) {
  return (
    <section className="card">
      <div className="toolbar" style={{ alignItems: "flex-start" }}>
        <div>
          <h2>Selected request</h2>
          <p className="meta"><strong>{req.method}</strong> {req.url}</p>
        </div>
        <span className="chip chip--muted">status {req.responseStatus || "-"}</span>
      </div>
      <div className="two-column-grid" style={{ marginTop: 14 }}>
        <div className="surface">
          <strong>Request headers</strong>
          <pre className="summary" style={{ marginTop: 10 }}>{headersToText(req.requestHeaders) || "(none)"}</pre>
        </div>
        <div className="surface">
          <strong>Response headers</strong>
          <pre className="summary" style={{ marginTop: 10 }}>{headersToText(req.responseHeaders) || "(none)"}</pre>
        </div>
      </div>
      <div className="two-column-grid" style={{ marginTop: 14 }}>
        <div className="surface">
          <strong>Request body</strong>
          <pre className="summary" style={{ marginTop: 10, maxHeight: 260, overflow: "auto" }}>{req.requestBody || "(none)"}</pre>
        </div>
        <div className="surface">
          <strong>Response body</strong>
          <pre className="summary" style={{ marginTop: 10, maxHeight: 260, overflow: "auto" }}>{req.responseBody || "(none)"}</pre>
        </div>
      </div>
      {req.notes && <p className="meta" style={{ marginTop: 12 }}><em>{req.notes}</em></p>}
    </section>
  );
}

function RepeaterTab({ selected, repeaterHeaders, setRepeaterHeaders, repeaterBody, setRepeaterBody, onSend, busy, result }) {
  if (!selected) {
    return <section className="card empty-state">Select a request from HTTP history first, then edit and resend it here.</section>;
  }

  return (
    <div className="two-column-grid">
      <section className="card">
        <div className="toolbar" style={{ alignItems: "flex-start" }}>
          <div>
            <h2>Repeater</h2>
            <p className="meta">Tweak a captured request and resend it with controlled header/body overrides.</p>
          </div>
          <span className="chip chip--muted">{selected.method}</span>
        </div>
        <p className="meta">{selected.url}</p>
        <label>
          Headers
          <textarea rows={10} value={repeaterHeaders} onChange={(e) => setRepeaterHeaders(e.target.value)} spellCheck={false} />
        </label>
        <label>
          Body
          <textarea rows={12} value={repeaterBody} onChange={(e) => setRepeaterBody(e.target.value)} spellCheck={false} />
        </label>
        <div className="button-row">
          <button type="button" onClick={onSend} disabled={busy}>{busy ? "Sending…" : "Send replay"}</button>
        </div>
      </section>
      {result ? <RequestDetail req={result} /> : <section className="card empty-state">Replay results will appear here after the request is sent.</section>}
    </div>
  );
}

function IntruderTab({ selected, marker, setMarker, payloads, setPayloads, headers, setHeaders, body, setBody, onRun, busy, results }) {
  const summary = useMemo(() => summarizeIntruder(results), [results]);

  if (!selected) {
    return <section className="card empty-state">Select a request from HTTP history first, then add payload markers and run an attack batch.</section>;
  }

  return (
    <>
      <div className="two-column-grid">
        <section className="card">
          <div className="toolbar" style={{ alignItems: "flex-start" }}>
            <div>
              <h2>Intruder</h2>
              <p className="meta">Place the marker in headers or body; each payload replaces every occurrence.</p>
            </div>
            <span className="chip chip--muted">cap 200 payloads</span>
          </div>
          <p className="meta"><strong>{selected.method}</strong> {selected.url}</p>
          <div className="form-grid">
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
            <textarea rows={7} value={headers} onChange={(e) => setHeaders(e.target.value)} spellCheck={false} />
          </label>
          <label>
            Body
            <textarea rows={7} value={body} onChange={(e) => setBody(e.target.value)} spellCheck={false} />
          </label>
          <label>
            Payloads
            <textarea rows={10} value={payloads} onChange={(e) => setPayloads(e.target.value)} spellCheck={false} placeholder={"admin\nroot\nguest"} />
          </label>
          <button type="button" onClick={onRun} disabled={busy}>{busy ? "Running…" : "Start attack"}</button>
        </section>

        <section className="card">
          <h2>Attack summary</h2>
          {results.length > 0 ? (
            <>
              <div className="three-column-grid" style={{ marginTop: 12 }}>
                <article className="meta-block">
                  <b>Total payloads</b>
                  <div>{results.length}</div>
                </article>
                <article className="meta-block">
                  <b>Errors</b>
                  <div>{summary.errors}</div>
                </article>
                <article className="meta-block">
                  <b>Status codes</b>
                  <div>{Object.entries(summary.statusCounts).map(([code, count]) => `${code}×${count}`).join(", ") || "none"}</div>
                </article>
              </div>
            </>
          ) : (
            <div className="empty-state">Run Intruder to see response variance and error trends here.</div>
          )}
        </section>
      </div>

      {results.length > 0 && (
        <section className="card">
          <h2>Intruder results</h2>
          <div className="table-wrap" style={{ marginTop: 12, maxHeight: 420 }}>
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Payload</th>
                  <th>Status</th>
                  <th>Length</th>
                  <th>ms</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {results.map((result, idx) => (
                  <tr key={idx}>
                    <td>{idx + 1}</td>
                    <td style={{ wordBreak: "break-all" }}>{result.payload}</td>
                    <td>{result.status || "-"}</td>
                    <td>{result.lengthBytes}</td>
                    <td>{result.durationMs}</td>
                    <td style={{ color: result.error ? "var(--sev-high)" : undefined }}>{result.error || ""}</td>
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

function DecoderTab({ input, output, error, setInput, setOutput, onTransform, onCopyOutputToInput, onSwap, onClear }) {
  return (
    <>
      <section className="card">
        <div className="toolbar" style={{ alignItems: "flex-start" }}>
          <div>
            <h2>Decoder</h2>
            <p className="meta">Convert payloads between common formats, chain transforms, and move results back into the input buffer like a lightweight Burp-style decoder.</p>
          </div>
          <div className="button-row">
            <button type="button" className="button-secondary" onClick={onCopyOutputToInput} disabled={!output}>Use output as input</button>
            <button type="button" className="button-secondary" onClick={onSwap} disabled={!input && !output}>Swap buffers</button>
            <button type="button" className="button-secondary" onClick={onClear} disabled={!input && !output}>Clear</button>
          </div>
        </div>

        <div className="three-column-grid" style={{ marginTop: 16 }}>
          <article className="meta-block">
            <b>URL</b>
            <div className="button-row">
              <button type="button" className="button-secondary" onClick={() => onTransform("url-encode")}>Encode</button>
              <button type="button" className="button-secondary" onClick={() => onTransform("url-decode")}>Decode</button>
            </div>
          </article>
          <article className="meta-block">
            <b>HTML</b>
            <div className="button-row">
              <button type="button" className="button-secondary" onClick={() => onTransform("html-encode")}>Encode</button>
              <button type="button" className="button-secondary" onClick={() => onTransform("html-decode")}>Decode</button>
            </div>
          </article>
          <article className="meta-block">
            <b>Base64</b>
            <div className="button-row">
              <button type="button" className="button-secondary" onClick={() => onTransform("base64-encode")}>Encode</button>
              <button type="button" className="button-secondary" onClick={() => onTransform("base64-decode")}>Decode</button>
            </div>
          </article>
          <article className="meta-block">
            <b>Hex</b>
            <div className="button-row">
              <button type="button" className="button-secondary" onClick={() => onTransform("hex-encode")}>Encode</button>
              <button type="button" className="button-secondary" onClick={() => onTransform("hex-decode")}>Decode</button>
            </div>
          </article>
          <article className="meta-block">
            <b>Text shaping</b>
            <div className="button-row">
              <button type="button" className="button-secondary" onClick={() => onTransform("json-format")}>Format JSON</button>
              <button type="button" className="button-secondary" onClick={() => onTransform("json-minify")}>Minify JSON</button>
            </div>
          </article>
        </div>

        {error && <p className="error" style={{ marginTop: 16, marginBottom: 0 }}>{error}</p>}
      </section>

      <div className="two-column-grid">
        <section className="card">
          <div className="toolbar" style={{ marginBottom: 12 }}>
            <h2 style={{ marginBottom: 0 }}>Input</h2>
            <span className="chip chip--muted">{input.length} chars</span>
          </div>
          <textarea
            rows={18}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            placeholder="Paste URL-encoded, base64, HTML, hex, or JSON content here."
            style={{ fontFamily: "monospace", fontSize: "0.84rem" }}
          />
        </section>

        <section className="card">
          <div className="toolbar" style={{ marginBottom: 12 }}>
            <h2 style={{ marginBottom: 0 }}>Output</h2>
            <span className="chip chip--muted">{output.length} chars</span>
          </div>
          <textarea
            rows={18}
            value={output}
            onChange={(e) => setOutput(e.target.value)}
            spellCheck={false}
            placeholder="Transform results appear here."
            style={{ fontFamily: "monospace", fontSize: "0.84rem" }}
          />
        </section>
      </div>
    </>
  );
}

function ConfigureTab({ settings }) {
  if (!settings) {
    return <section className="card empty-state">Loading proxy configuration…</section>;
  }

  const proxyURL = `${settings.host}:${settings.port}`;
  const caDownloadURL = `${API_BASE}/api/proxy/ca-certificate?api_key=${encodeURIComponent(API_KEY)}`;
  return (
    <div className="two-column-grid">
      <section className="card">
        <h2>Browser bootstrap</h2>
        {settings.mitmEnabled && (
          <div className="meta-block">
            <b>Proxy CA certificate</b>
            <p className="meta" style={{ marginTop: 6 }}>
              Download the auto-generated CA certificate and import it into your browser/OS trust store so HTTPS requests are intercepted without warnings.
            </p>
            <div className="button-row" style={{ marginTop: 10 }}>
              <a href={caDownloadURL} download="auto-bughunter-proxy-ca.pem" className="button-link">Download CA certificate</a>
            </div>
          </div>
        )}
        <div className="meta-block" style={{ marginTop: settings.mitmEnabled ? 10 : 0 }}>
          <b>Firefox</b>
          <pre className="summary" style={{ marginTop: 10 }}>{`Settings → Network Settings → Manual proxy configuration
HTTP Proxy: ${settings.host}    Port: ${settings.port}
☑ Also use this proxy for HTTPS`}</pre>
        </div>
        <div className="meta-block" style={{ marginTop: 10 }}>
          <b>Chromium / Chrome</b>
          <pre className="summary" style={{ marginTop: 10 }}>{`chromium --proxy-server="http://${proxyURL}"`}</pre>
        </div>
        <div className="meta-block" style={{ marginTop: 10 }}>
          <b>curl</b>
          <pre className="summary" style={{ marginTop: 10 }}>{`curl -x http://${proxyURL} https://example.com`}</pre>
        </div>
      </section>

      <section className="card">
        <h2>HTTPS interception</h2>
        {settings.mitmEnabled ? (
          <>
            <p className="meta">TLS interception is enabled. Install the proxy CA to capture HTTPS requests and response bodies without warnings.</p>
            <ul className="bullet-list" style={{ marginTop: 12 }}>
              <li>SHA-256 fingerprint: <code>{settings.caFingerprintSHA256}</code></li>
              {settings.caNotAfter && <li>Expires: <code>{settings.caNotAfter}</code></li>}
            </ul>
            <div className="button-row" style={{ marginTop: 14 }}>
              <a href={caDownloadURL} download="auto-bughunter-proxy-ca.pem" className="button-link">Download CA certificate</a>
            </div>
            <pre className="summary" style={{ marginTop: 14 }}>{`Firefox: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import…
macOS:   open auto-bughunter-proxy-ca.pem → Keychain Access → set "Always Trust"
Linux:   sudo cp auto-bughunter-proxy-ca.pem /usr/local/share/ca-certificates/ && sudo update-ca-certificates`}</pre>
          </>
        ) : (
          <>
            <p className="meta">TLS interception is disabled, so HTTPS traffic passes through without decryption.</p>
            <pre className="summary" style={{ marginTop: 14 }}>{`PROXY_CA_CERT_FILE=/var/lib/auto-bughunter/proxy-ca.pem
PROXY_CA_KEY_FILE=/var/lib/auto-bughunter/proxy-ca.key
PROXY_CA_AUTOGENERATE=true`}</pre>
          </>
        )}
      </section>
    </div>
  );
}

function BrowserTab({ apiBase, apiKey, workspaceId, onRefreshHistory }) {
  const [url, setUrl] = useState("https://");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [iframeSrc, setIframeSrc] = useState(null);
  const [lastFetchedUrl, setLastFetchedUrl] = useState("");

  function navigate(targetUrl) {
    const trimmed = targetUrl.trim();
    if (!trimmed || trimmed === "https://" || trimmed === "http://") {
      setError("Enter a URL to browse.");
      return;
    }
    setError("");
    setLoading(true);
    // Point the iframe directly at the backend browse endpoint so the browser
    // handles content-type, encoding, and sub-resource loading natively.
    // The api_key query param is accepted by the auth middleware alongside
    // the X-API-Key header so the iframe can authenticate without custom headers.
    const browseUrl =
      `${apiBase}/api/proxy/browse` +
      `?url=${encodeURIComponent(trimmed)}` +
      `&api_key=${encodeURIComponent(apiKey)}`;
    setIframeSrc(browseUrl);
    setLastFetchedUrl(trimmed);
    onRefreshHistory();
  }

  function handleKeyDown(e) {
    if (e.key === "Enter") navigate(url);
  }

  return (
    <section className="card" style={{ padding: 0, overflow: "hidden" }}>
      {/* Address bar */}
      <div
        className="toolbar"
        style={{ padding: "12px 16px", background: "rgba(0,0,0,0.18)", borderBottom: "1px solid var(--border)", gap: 8 }}
      >
        <div>
          <h2 style={{ marginBottom: 2 }}>Proxy browser</h2>
          <p className="meta" style={{ marginBottom: 0 }}>
            Fetches the page through the recording transport — traffic is captured in HTTP history and passively scanned for vulnerabilities.
          </p>
        </div>
      </div>
      <div style={{ display: "flex", gap: 8, padding: "10px 16px", borderBottom: "1px solid var(--border)", alignItems: "center" }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="https://example.com"
          spellCheck={false}
          style={{ flex: 1, fontFamily: "monospace", fontSize: "0.85rem" }}
        />
        <button type="button" onClick={() => navigate(url)} disabled={loading} style={{ flexShrink: 0 }}>
          {loading ? "Loading…" : "Go"}
        </button>
        {iframeSrc && (
          <button type="button" className="button-secondary" style={{ flexShrink: 0 }} onClick={() => navigate(url)} disabled={loading}>
            ↺ Reload
          </button>
        )}
      </div>

      {error && (
        <div style={{ padding: "8px 16px" }}>
          <p className="error" style={{ margin: 0 }}>{error}</p>
        </div>
      )}

      {/* Browser viewport */}
      {iframeSrc ? (
        <iframe
          key={iframeSrc}
          src={iframeSrc}
          title={`Proxy browser — ${lastFetchedUrl}`}
          sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
          onLoad={() => setLoading(false)}
          onError={() => { setLoading(false); setError("Failed to load page."); }}
          style={{
            width: "100%",
            height: "640px",
            border: "none",
            display: "block",
            background: "#fff",
          }}
        />
      ) : (
        <div className="empty-state" style={{ padding: "48px 24px" }}>
          Enter a URL above and click <strong>Go</strong> to browse through the intercepting proxy.
          The request will appear in HTTP history and passive findings will be recorded automatically.
        </div>
      )}
    </section>
  );
}

function PassiveFindingsTab({ apiBase, apiKey, workspaceId }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    loadFindings();
  }, []);

  async function loadFindings() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${apiBase}/api/proxy/passive-findings`, {
        headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceId },
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Failed to load passive findings.");
        return;
      }
      setFindings(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || "Failed to load passive findings.");
    } finally {
      setLoading(false);
    }
  }

  async function clearFindings() {
    if (!window.confirm("Clear all passive findings?")) return;
    try {
      await fetch(`${apiBase}/api/proxy/passive-findings`, {
        method: "DELETE",
        headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceId },
      });
      loadFindings();
    } catch (err) {
      setError(err.message || "Failed to clear findings.");
    }
  }

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort(
    (a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9),
  );

  return (
    <section className="card">
      <div className="toolbar" style={{ marginBottom: 16 }}>
        <div>
          <h2 style={{ marginBottom: 2 }}>Passive findings</h2>
          <p className="meta" style={{ marginBottom: 0 }}>
            Vulnerabilities and misconfigurations detected automatically as you browse through the proxy.
            Browse a site using the <strong>Proxy browser</strong> tab, or route your browser through the
            intercepting proxy, to populate this list.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button type="button" className="button-secondary" onClick={loadFindings} disabled={loading}>
            {loading ? "Refreshing…" : "↺ Refresh"}
          </button>
          {findings.length > 0 && (
            <button type="button" className="button-secondary" onClick={clearFindings}>
              Clear all
            </button>
          )}
        </div>
      </div>

      {error && <p className="error" style={{ marginBottom: 12 }}>{error}</p>}

      {sorted.length === 0 ? (
        <div className="empty-state">
          No passive findings yet. Browse through the proxy to start collecting results.
        </div>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 8 }}>
          {sorted.map((f) => {
            const key = encodeURIComponent(f.affectedUrl || "") + "|" + f.id;
            const isOpen = expanded === key;
            return (
              <li
                key={key}
                style={{
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  overflow: "hidden",
                }}
              >
                <button
                  type="button"
                  onClick={() => setExpanded(isOpen ? null : key)}
                  style={{
                    width: "100%",
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "10px 14px",
                    background: "none",
                    border: "none",
                    cursor: "pointer",
                    textAlign: "left",
                    color: "inherit",
                  }}
                >
                  <span className={`severity-badge ${f.severity || "info"}`}>
                    {(f.severity || "info").toUpperCase()}
                  </span>
                  <span style={{ flex: 1, fontWeight: 500 }}>{f.title}</span>
                  <span className="meta" style={{ fontFamily: "monospace", fontSize: "0.78rem", flexShrink: 0, maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {f.affectedUrl || ""}
                  </span>
                  <span style={{ flexShrink: 0, fontSize: "0.75rem", color: "var(--ink-soft)" }}>{isOpen ? "▲" : "▼"}</span>
                </button>

                {isOpen && (
                  <div style={{ padding: "0 14px 14px", borderTop: "1px solid var(--border)" }}>
                    {f.description && (
                      <p style={{ marginTop: 10, marginBottom: 8, fontSize: "0.88rem" }}>{f.description}</p>
                    )}
                    {f.evidence && (
                      <div style={{ marginBottom: 8 }}>
                        <span className="meta">Evidence: </span>
                        <code style={{ fontSize: "0.82rem", wordBreak: "break-all" }}>{f.evidence}</code>
                      </div>
                    )}
                    {f.recommendation && (
                      <div style={{ marginBottom: 8 }}>
                        <span className="meta">Recommendation: </span>
                        <span style={{ fontSize: "0.88rem" }}>{f.recommendation}</span>
                      </div>
                    )}
                    <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                      <span className="chip chip--muted">{f.category}</span>
                      {f.discoveredAt && (
                        <span className="meta" style={{ fontSize: "0.78rem" }}>
                          found {new Date(f.discoveredAt).toLocaleTimeString()}
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function headersToText(headers) {
  if (!headers) return "";
  return Object.entries(headers).map(([key, value]) => `${key}: ${value}`).join("\n");
}

function textToHeaders(text) {
  const out = {};
  if (!text) return out;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (key) out[key] = value;
  }
  return out;
}

function summarizeIntruder(results) {
  const statusCounts = {};
  let errors = 0;
  for (const result of results) {
    if (result.error) errors += 1;
    const key = result.status ? String(result.status) : "—";
    statusCounts[key] = (statusCounts[key] || 0) + 1;
  }
  return { statusCounts, errors };
}

function summarizeHistory(requests) {
  return requests.reduce((summary, request) => {
    const status = Number(request.responseStatus || 0);
    if (status >= 200 && status < 300) summary.success += 1;
    if (status >= 500) summary.serverErrors += 1;
    return summary;
  }, { success: 0, serverErrors: 0 });
}

function applyDecoderAction(action, value) {
  switch (action) {
    case "url-encode":
      return encodeURIComponent(value);
    case "url-decode":
      return decodeURIComponent(value);
    case "html-encode":
      return htmlEncode(value);
    case "html-decode":
      return htmlDecode(value);
    case "base64-encode":
      return base64EncodeUnicode(value);
    case "base64-decode":
      return base64DecodeUnicode(value);
    case "hex-encode":
      return hexEncode(value);
    case "hex-decode":
      return hexDecode(value);
    case "json-format":
      return formatJSON(value);
    case "json-minify":
      return minifyJSON(value);
    default:
      return value;
  }
}

function htmlEncode(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function htmlDecode(value) {
  return value.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (entity, token) => {
    if (token[0] === "#") {
      const isHex = token[1]?.toLowerCase() === "x";
      const raw = isHex ? token.slice(2) : token.slice(1);
      const codePoint = Number.parseInt(raw, isHex ? 16 : 10);
      return Number.isNaN(codePoint) ? entity : String.fromCodePoint(codePoint);
    }
    return HTML_ENTITY_MAP[token] ?? entity;
  });
}

function base64EncodeUnicode(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64DecodeUnicode(value) {
  const normalized = normalizeBase64(value);
  const binary = atob(normalized);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function normalizeBase64(value) {
  const compact = value.replace(/\s+/g, "").replaceAll("-", "+").replaceAll("_", "/");
  if (!compact) return "";
  const padding = compact.length % 4;
  return padding === 0 ? compact : compact.padEnd(compact.length + (4 - padding), "=");
}

function hexEncode(value) {
  return Array.from(new TextEncoder().encode(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexDecode(value) {
  const compact = value.replace(/\s+/g, "");
  if (!compact) return "";
  if (compact.length % 2 !== 0) {
    throw new Error("Hex input must contain an even number of characters.");
  }
  if (!/^[0-9a-fA-F]+$/.test(compact)) {
    throw new Error("Hex input may only contain 0-9 and A-F characters.");
  }
  const bytes = new Uint8Array(compact.match(/.{2}/g).map((pair) => Number.parseInt(pair, 16)));
  return new TextDecoder().decode(bytes);
}

function formatJSON(value) {
  return JSON.stringify(JSON.parse(value), null, 2);
}

function minifyJSON(value) {
  return JSON.stringify(JSON.parse(value));
}

const HTML_ENTITY_MAP = {
  amp: "&",
  apos: "'",
  gt: ">",
  lt: "<",
  nbsp: "\u00A0",
  quot: '"',
};

function formatTime(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleTimeString();
}
