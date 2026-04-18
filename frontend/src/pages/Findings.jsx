import { useState } from "react";
import { useScan } from "../context/ScanContext";

export default function Findings() {
  const { job, screenshots } = useScan();
  const [filter, setFilter] = useState("all");
  const [selectedScreenshot, setSelectedScreenshot] = useState(null);

  if (!job) {
    return (
      <div className="page">
        <header><h1>🔍 Findings</h1></header>
        <section className="card">
          <p className="meta">No scan in progress. Go to the Dashboard to start a scan.</p>
        </section>
      </div>
    );
  }

  const findings = job.findings || [];
  const filtered = filter === "all" ? findings : findings.filter((f) => f.severity === filter);

  const sevCounts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++;
  }

  const SEV_COLOR = { high: "#dc2626", medium: "#ea580c", low: "#ca8a04", info: "#6b7280" };
  const BORDER_COLOR = { high: "#fca5a5", medium: "#fdba74", low: "#fde68a", info: "#d1d5db" };

  return (
    <div className="page">
      <header>
        <h1>🔍 Findings</h1>
        <p>Target: <strong>{job.target}</strong> · Status: <strong>{job.status}</strong></p>
      </header>

      {/* Screenshots panel */}
      {screenshots.length > 0 && (
        <section className="card">
          <h2>📷 Screenshots ({screenshots.length})</h2>
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            {screenshots.map((s, i) => (
              <div key={i}
                style={{ cursor: "pointer", borderRadius: "6px", overflow: "hidden", border: "2px solid rgba(255,255,255,0.2)" }}
                onClick={() => setSelectedScreenshot(s.b64)}
                title={s.message}
              >
                <img
                  src={`data:image/png;base64,${s.b64}`}
                  alt={`Screenshot ${i + 1}`}
                  style={{ width: "140px", height: "90px", objectFit: "cover", display: "block" }}
                />
                <div style={{ fontSize: "0.65rem", padding: "2px 4px", background: "rgba(0,0,0,0.6)", color: "#ddd", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "140px" }}>
                  {s.message || `Page ${i + 1}`}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Severity filter */}
      <section className="card">
        <div className="stats" style={{ marginBottom: "1rem" }}>
          {["all", "high", "medium", "low", "info"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              style={{
                background: filter === sev ? "#7f1d1d" : "rgba(0,0,0,0.2)",
                color: filter === sev ? "#fff" : "#000",
                border: "1.5px solid rgba(255,255,255,0.3)",
                borderRadius: "999px",
                padding: "0.3rem 0.8rem",
                fontSize: "0.82rem",
                cursor: "pointer",
                fontWeight: filter === sev ? 700 : 400,
              }}
            >
              {sev === "all" ? `All (${findings.length})` : `${sev} (${sevCounts[sev] || 0})`}
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <p className="meta">No findings at this severity level.</p>
        ) : (
          <ul className="findings">
            {filtered.map((f, idx) => (
              <li key={f.id || idx} style={{ borderColor: BORDER_COLOR[f.severity] || "#e5e7eb" }}>
                <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "4px" }}>
                  <span style={{
                    background: SEV_COLOR[f.severity] || "#6b7280",
                    color: "#fff", padding: "1px 8px", borderRadius: "999px",
                    fontSize: "0.72rem", fontWeight: 700, flexShrink: 0,
                  }}>
                    {f.severity?.toUpperCase()}
                  </span>
                  <strong>{f.title}</strong>
                </div>
                <p>{f.description}</p>
                <p><b>Evidence:</b> {f.evidence}</p>
                {f.driftStatus && <p><b>Drift:</b> {f.driftStatus}</p>}
                {f.sources?.length > 0 && <p><b>Sources:</b> {f.sources.join(", ")}</p>}
                {f.confidence !== undefined && <p><b>Confidence:</b> {Number(f.confidence).toFixed(2)}</p>}
                {f.evidenceFields && (
                  <p><b>Evidence fields:</b> {Object.entries(f.evidenceFields).map(([k, v]) => `${k}=${v}`).join(", ")}</p>
                )}
                {f.businessTags?.length > 0 && <p><b>Business tags:</b> {f.businessTags.join(", ")}</p>}
                {f.exploitability && (
                  <p><b>Exploitability:</b> reachable={String(f.exploitability.reachable)}, role={f.exploitability.requiredRole || "n/a"}</p>
                )}
                <p><b>Fix:</b> {f.recommendation}</p>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Screenshot lightbox */}
      {selectedScreenshot && (
        <div
          onClick={() => setSelectedScreenshot(null)}
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.88)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, cursor: "zoom-out" }}
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
