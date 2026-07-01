import { useEffect, useMemo, useState } from "react";
import { API_BASE, getAPIKey, getWorkspaceID } from "../context/ScanContext";

const AUTO_PICK = "__auto__";
const UNSET = "";

function pct(v) {
  if (v === null || v === undefined || Number.isNaN(v)) return "n/a";
  return `${(v * 100).toFixed(1)}%`;
}

// autoPickScan picks the most recent completed scan whose target URL host
// contains the manifest target label (e.g. "juice-shop" matches
// "https://juice-shop.example.com"). Returns "" when nothing matches so the
// operator can pick manually.
function autoPickScan(target, scans) {
  if (!target || !Array.isArray(scans)) return "";
  const needle = target.toLowerCase();
  const sorted = [...scans].sort((a, b) => {
    const ta = a.completedAt || a.startedAt || "";
    const tb = b.completedAt || b.startedAt || "";
    return tb.localeCompare(ta);
  });
  const match = sorted.find((s) => (s.target || "").toLowerCase().includes(needle));
  return match ? match.id : "";
}

export default function Accuracy() {
  const [manifests, setManifests] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [corpusDir, setCorpusDir] = useState("");
  const [picks, setPicks] = useState({}); // target → scanId | AUTO_PICK
  const [passRates, setPassRates] = useState({}); // target → "0.95"
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState(null);
  const [markdown, setMarkdown] = useState("");
  const [usedScans, setUsedScans] = useState({});

  useEffect(() => {
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    setLoading(true);
    setError("");
    Promise.all([
      fetch(`${API_BASE}/api/accuracy/corpus`, {
        headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceID },
      }).then((r) => r.json()),
      fetch(`${API_BASE}/api/scans?workspaceId=${encodeURIComponent(workspaceID)}`, {
        headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceID },
      }).then((r) => r.json()),
    ])
      .then(([corpusResp, scansResp]) => {
        if (corpusResp?.error) throw new Error(corpusResp.error);
        setManifests(corpusResp?.manifests || []);
        setCorpusDir(corpusResp?.corpusDir || "");
        setScans(scansResp?.scans || []);
        const defaults = {};
        (corpusResp?.manifests || []).forEach((m) => { defaults[m.target] = AUTO_PICK; });
        setPicks(defaults);
      })
      .catch((err) => setError(err.message || String(err)))
      .finally(() => setLoading(false));
  }, []);

  const resolvedPicks = useMemo(() => {
    const out = {};
    manifests.forEach((m) => {
      const raw = picks[m.target];
      if (raw === AUTO_PICK) out[m.target] = autoPickScan(m.target, scans);
      else out[m.target] = raw || "";
    });
    return out;
  }, [manifests, picks, scans]);

  const runnableCount = Object.values(resolvedPicks).filter(Boolean).length;

  const runBenchmark = async () => {
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    const actuals = [];
    Object.entries(resolvedPicks).forEach(([target, scanId]) => {
      if (!scanId) return;
      const entry = { target, scanId };
      const pr = passRates[target];
      if (pr !== undefined && pr !== "") {
        const num = Number(pr);
        if (!Number.isNaN(num)) entry.preReportVerificationPassRate = num;
      }
      actuals.push(entry);
    });
    if (actuals.length === 0) {
      setError("Pick at least one scan to grade.");
      return;
    }
    setRunning(true);
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/accuracy/run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey,
          "X-Workspace-ID": workspaceID,
        },
        body: JSON.stringify({ actuals }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
      setReport(data.report || null);
      setMarkdown(data.markdown || "");
      setUsedScans(data.usedScans || {});
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setRunning(false);
    }
  };

  const copyMarkdown = () => {
    if (!markdown) return;
    navigator.clipboard?.writeText(markdown).catch(() => {});
  };

  return (
    <section className="page-shell">
      <header className="page-shell__header">
        <div>
          <div className="eyebrow">Accuracy benchmark</div>
          <h1>Accuracy harness</h1>
          <p className="meta">
            Grade completed scans against the bundled ground-truth corpus and
            see precision / recall / F1 per target and per vulnerability
            category. Mirrors the nightly <code>qa-accuracy</code> CI job so
            you can spot regressions before they land.
          </p>
          {corpusDir && (
            <p className="meta" style={{ fontSize: "0.75rem", opacity: 0.7 }}>
              Corpus: <code>{corpusDir}</code>
            </p>
          )}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            type="button"
            className="button button--primary"
            disabled={loading || running || runnableCount === 0}
            onClick={runBenchmark}
          >
            {running ? "Running…" : `Run benchmark (${runnableCount} target${runnableCount === 1 ? "" : "s"})`}
          </button>
        </div>
      </header>

      {error && (
        <div className="callout callout--danger" style={{ marginBottom: 16 }}>
          {error}
        </div>
      )}

      {loading ? (
        <p className="meta">Loading corpus…</p>
      ) : manifests.length === 0 ? (
        <p className="meta">No manifests found in the accuracy corpus directory.</p>
      ) : (
        <div className="card" style={{ marginBottom: 24 }}>
          <h2>Corpus targets</h2>
          <table className="data-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Description</th>
                <th>Expected</th>
                <th>Safe</th>
                <th>Categories</th>
                <th>Scan to grade</th>
                <th>Verify pass rate (0–1)</th>
              </tr>
            </thead>
            <tbody>
              {manifests.map((m) => {
                const chosen = picks[m.target] ?? AUTO_PICK;
                const resolved = resolvedPicks[m.target];
                return (
                  <tr key={m.target}>
                    <td><strong>{m.target}</strong></td>
                    <td>{m.description || <span className="meta">—</span>}</td>
                    <td>{m.expectedFindingsCount}</td>
                    <td>{m.safeEndpointsCount}</td>
                    <td>{(m.categories || []).join(", ") || <span className="meta">—</span>}</td>
                    <td>
                      <select
                        value={chosen}
                        onChange={(e) => setPicks({ ...picks, [m.target]: e.target.value })}
                      >
                        <option value={AUTO_PICK}>
                          Auto ({resolved ? scans.find((s) => s.id === resolved)?.target || resolved : "no match"})
                        </option>
                        <option value={UNSET}>— Skip —</option>
                        {scans.map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.target} · {s.id.slice(0, 8)}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <input
                        type="number"
                        min="0"
                        max="1"
                        step="0.01"
                        placeholder="—"
                        value={passRates[m.target] ?? ""}
                        onChange={(e) => setPassRates({ ...passRates, [m.target]: e.target.value })}
                        style={{ width: 80 }}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {report && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
            <h2>Aggregate result</h2>
            <button type="button" className="button" onClick={copyMarkdown}>
              Copy markdown
            </button>
          </div>
          <div className="stat-grid" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12, marginTop: 12 }}>
            <div className="stat"><div className="meta">Precision</div><div className="stat__value">{pct(report.precision)}</div></div>
            <div className="stat"><div className="meta">Recall</div><div className="stat__value">{pct(report.recall)}</div></div>
            <div className="stat"><div className="meta">F1</div><div className="stat__value">{pct(report.f1)}</div></div>
            <div className="stat"><div className="meta">TP</div><div className="stat__value">{report.truePositives}</div></div>
            <div className="stat"><div className="meta">FP</div><div className="stat__value">{report.falsePositives}</div></div>
            <div className="stat"><div className="meta">FN</div><div className="stat__value">{report.falseNegatives}</div></div>
            <div className="stat">
              <div className="meta">Mean verify pass</div>
              <div className="stat__value">{pct(report.meanPreReportVerificationPassRate)}</div>
            </div>
          </div>

          {(report.categoryTotals || []).length > 0 && (
            <>
              <h3 style={{ marginTop: 20 }}>Per-category totals</h3>
              <table className="data-table">
                <thead>
                  <tr><th>Category</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th></tr>
                </thead>
                <tbody>
                  {report.categoryTotals.map((c) => (
                    <tr key={c.category}>
                      <td>{c.category}</td>
                      <td>{c.truePositives}</td>
                      <td>{c.falsePositives}</td>
                      <td>{c.falseNegatives}</td>
                      <td>{pct(c.precision)}</td>
                      <td>{pct(c.recall)}</td>
                      <td>{pct(c.f1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {(report.targets || []).length > 0 && (
            <>
              <h3 style={{ marginTop: 20 }}>Per-target</h3>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target</th><th>Scan</th><th>TP</th><th>FP</th><th>FN</th>
                    <th>Precision</th><th>Recall</th><th>F1</th><th>Verify pass</th>
                  </tr>
                </thead>
                <tbody>
                  {report.targets.map((t) => (
                    <tr key={t.target}>
                      <td>{t.target}</td>
                      <td><code>{(usedScans[t.target] || "").slice(0, 8) || "—"}</code></td>
                      <td>{t.truePositives}</td>
                      <td>{t.falsePositives}</td>
                      <td>{t.falseNegatives}</td>
                      <td>{pct(t.precision)}</td>
                      <td>{pct(t.recall)}</td>
                      <td>{pct(t.f1)}</td>
                      <td>{pct(t.preReportVerificationPassRate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {(report.targetsWithoutActuals || []).length > 0 && (
            <>
              <h3 style={{ marginTop: 20 }}>Targets without a graded scan</h3>
              <ul>
                {report.targetsWithoutActuals.map((t) => <li key={t}>{t}</li>)}
              </ul>
            </>
          )}
        </div>
      )}
    </section>
  );
}
