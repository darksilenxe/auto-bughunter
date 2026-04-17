import { useEffect } from "react";
import { useScan } from "../context/ScanContext";

export default function Scans() {
  const { scanHistory, historyLoading, loadHistory } = useScan();

  useEffect(() => { loadHistory(); }, [loadHistory]);

  const SEV_COLOR = { high: "#dc2626", medium: "#ea580c", low: "#ca8a04", info: "#6b7280" };

  return (
    <div className="page">
      <header>
        <h1>📋 Scan History</h1>
        <p>All completed scans</p>
      </header>

      <section className="card">
        <div style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: "0.75rem" }}>
          <button onClick={loadHistory} style={{ fontSize: "0.85rem" }}>
            {historyLoading ? "Loading…" : "⟳ Refresh"}
          </button>
        </div>

        {scanHistory.length === 0 && !historyLoading && (
          <p className="meta">No completed scans yet.</p>
        )}

        {scanHistory.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
              <thead>
                <tr style={{ borderBottom: "2px solid rgba(255,255,255,0.2)", textAlign: "left" }}>
                  <th style={{ padding: "8px 10px" }}>Target</th>
                  <th style={{ padding: "8px 10px" }}>Status</th>
                  <th style={{ padding: "8px 10px" }}>High</th>
                  <th style={{ padding: "8px 10px" }}>Total</th>
                  <th style={{ padding: "8px 10px" }}>Started</th>
                  <th style={{ padding: "8px 10px" }}>Completed</th>
                </tr>
              </thead>
              <tbody>
                {scanHistory.map((s) => (
                  <tr key={s.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                    <td style={{ padding: "8px 10px", wordBreak: "break-all", maxWidth: "260px" }}>
                      <span title={s.id} style={{ fontSize: "0.8rem", color: "#555" }}>{s.id.slice(0, 8)}…</span><br />
                      {s.target}
                    </td>
                    <td style={{ padding: "8px 10px" }}>
                      <span style={{
                        background: s.status === "completed" ? "#166534" : s.status === "failed" ? "#7f1d1d" : "#92400e",
                        color: "#fff", padding: "2px 8px", borderRadius: "999px", fontSize: "0.75rem",
                      }}>{s.status}</span>
                    </td>
                    <td style={{ padding: "8px 10px", color: s.highCount > 0 ? SEV_COLOR.high : "inherit", fontWeight: s.highCount > 0 ? 700 : 400 }}>
                      {s.highCount}
                    </td>
                    <td style={{ padding: "8px 10px" }}>{s.findingCount}</td>
                    <td style={{ padding: "8px 10px", fontSize: "0.78rem", color: "#555" }}>
                      {s.createdAt ? new Date(s.createdAt).toLocaleString() : "—"}
                    </td>
                    <td style={{ padding: "8px 10px", fontSize: "0.78rem", color: "#555" }}>
                      {s.completedAt ? new Date(s.completedAt).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
