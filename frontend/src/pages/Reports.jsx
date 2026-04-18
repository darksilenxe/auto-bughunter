import { useState } from "react";
import { useScan, API_BASE } from "../context/ScanContext";

export default function Reports() {
  const { job, scanId, screenshots } = useScan();
  const [selectedScreenshot, setSelectedScreenshot] = useState(null);

  if (!job) {
    return (
      <div className="page">
        <header><h1>📄 Reports</h1></header>
        <section className="card">
          <p className="meta">No scan data available. Go to the Dashboard to run a scan.</p>
        </section>
      </div>
    );
  }

  return (
    <div className="page">
      <header>
        <h1>📄 Reports</h1>
        <p>Target: <strong>{job.target}</strong></p>
      </header>

      {/* PDF download */}
      {job.status === "completed" && scanId && (
        <section className="card">
          <h2>Export</h2>
          <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
            <a
              href={`${API_BASE}/api/report/${scanId}`}
              download={`scan-report-${scanId}.pdf`}
              style={{
                display: "inline-block", padding: "0.6rem 1.4rem",
                background: "#7f1d1d", color: "#fff", borderRadius: "8px",
                textDecoration: "none", fontWeight: 700, fontSize: "0.95rem",
              }}
            >
              ⬇ Download PDF Report
            </a>
            <a
              href={`${API_BASE}/api/scan/${scanId}/sarif`}
              download={`scan-${scanId}.sarif.json`}
              style={{
                display: "inline-block", padding: "0.6rem 1.4rem",
                background: "#1e3a8a", color: "#fff", borderRadius: "8px",
                textDecoration: "none", fontWeight: 700, fontSize: "0.95rem",
              }}
              title="SARIF v2.1.0 — upload to GitHub code scanning or any SARIF-aware tool"
            >
              ⬇ Download SARIF
            </a>
          </div>
        </section>
      )}

      {/* Automated pen test report */}
      {job.automatedReport && (
        <section className="card">
          <h2>Automated Penetration Testing Report</h2>
          <pre className="summary">{job.automatedReport}</pre>
        </section>
      )}

      {/* AI Summary */}
      {job.aiSummary && (
        <section className="card">
          <h2>AI Summary</h2>
          <pre className="summary">{job.aiSummary}</pre>
        </section>
      )}

      {/* Screenshots gallery */}
      {screenshots.length > 0 && (
        <section className="card">
          <h2>📷 Evidence Screenshots ({screenshots.length})</h2>
          <p className="meta">Screenshots captured automatically during the attack path.</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: "12px", marginTop: "0.75rem" }}>
            {screenshots.map((s, i) => (
              <div
                key={i}
                onClick={() => setSelectedScreenshot(s.b64)}
                style={{ cursor: "pointer", borderRadius: "8px", overflow: "hidden", border: "2px solid rgba(255,255,255,0.25)", background: "rgba(0,0,0,0.3)" }}
              >
                <img
                  src={`data:image/png;base64,${s.b64}`}
                  alt={`Screenshot ${i + 1}`}
                  style={{ width: "100%", height: "130px", objectFit: "cover", display: "block" }}
                />
                <div style={{ padding: "6px 8px" }}>
                  <div style={{ fontSize: "0.7rem", color: "#000", fontWeight: 600 }}>{s.agentName}</div>
                  <div style={{ fontSize: "0.65rem", color: "#333", marginTop: "2px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.message || `Page ${i + 1}`}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Decision Dashboard */}
      {job.dashboard && (
        <section className="card">
          <h2>Decision Dashboard</h2>
          <ul className="findings">
            <li>
              <p><b>Coverage completeness:</b> {job.dashboard.coverageCompletenessScore}%</p>
              <p><b>Authenticated coverage rate:</b> {(Number(job.dashboard.authenticatedCoverageRate || 0) * 100).toFixed(0)}%</p>
              <p><b>Drift:</b> new={job.dashboard.newFindings || 0}, changed={job.dashboard.changedFindings || 0}, resolved={job.dashboard.resolvedFindings || 0}</p>
              <p><b>Actionable findings:</b> {job.dashboard.actionableFindings || 0}</p>
              {job.dashboard.topAttackPaths?.length > 0 && (
                <p><b>Top attack paths:</b> {job.dashboard.topAttackPaths.join(", ")}</p>
              )}
            </li>
          </ul>
        </section>
      )}

      {/* Next actions */}
      {job.nextActions?.length > 0 && (
        <section className="card">
          <h2>Recommended Next Actions</h2>
          <ul className="findings">
            {job.nextActions.map((n, i) => <li key={i}><p>{n}</p></li>)}
          </ul>
        </section>
      )}

      {/* Lightbox */}
      {selectedScreenshot && (
        <div
          onClick={() => setSelectedScreenshot(null)}
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.88)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, cursor: "zoom-out" }}
        >
          <img src={`data:image/png;base64,${selectedScreenshot}`} alt="Screenshot"
            style={{ maxWidth: "90vw", maxHeight: "90vh", borderRadius: "8px" }}
            onClick={(e) => e.stopPropagation()} />
          <button onClick={() => setSelectedScreenshot(null)}
            style={{ position: "absolute", top: "16px", right: "24px", background: "none", border: "none", color: "#fff", fontSize: "2rem", cursor: "pointer" }}>×</button>
        </div>
      )}
    </div>
  );
}
