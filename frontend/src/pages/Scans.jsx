import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useScan } from "../context/ScanContext";

function fmtDuration(startIso, endIso) {
  if (!startIso || !endIso) return "—";
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime();
  if (ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export default function Scans() {
  const { scanHistory, historyLoading, loadHistory, loadScan } = useScan();
  const navigate = useNavigate();
  const [loadingId, setLoadingId] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const handleView = async (id, destination = "/findings") => {
    setLoadingId(id + destination);
    const ok = await loadScan(id);
    setLoadingId(null);
    if (ok) {
      navigate(destination);
    } else {
      setLoadError("Failed to load scan — it may have been deleted or is inaccessible.");
    }
  };

  const filtered = useMemo(() => {
    return scanHistory.filter((scan) => {
      if (statusFilter !== "all" && scan.status !== statusFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (scan.target || "").toLowerCase().includes(q) || (scan.id || "").toLowerCase().includes(q);
      }
      return true;
    });
  }, [scanHistory, searchQuery, statusFilter]);

  const allStatuses = useMemo(() => {
    return ["all", ...Array.from(new Set(scanHistory.map((s) => s.status).filter(Boolean))).sort()];
  }, [scanHistory]);

  return (
    <div className="page page--wide">
      <header>
        <h1>Engagement history</h1>
        <p>Track previous scans, their severity counts, and delivery cadence like a premium operator console.</p>
      </header>

      <section className="card">
        <div className="toolbar">
          <div>
            <h2>Scan archive</h2>
            <p className="meta">Refresh to sync the latest completed engagements from the backend.</p>
          </div>
          <button type="button" className="button-secondary" onClick={loadHistory}>
            {historyLoading ? "Loading…" : "Refresh"}
          </button>
        </div>

        <div className="filter-row" style={{ marginTop: 12, marginBottom: 10, flexWrap: "wrap", gap: 10 }}>
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by target or scan ID…"
            style={{ maxWidth: 300 }}
          />
          {allStatuses.map((s) => (
            <button
              key={s}
              type="button"
              className={`filter-chip ${statusFilter === s ? "is-active" : ""}`}
              onClick={() => setStatusFilter(s)}
            >
              {s === "all" ? `All (${scanHistory.length})` : `${s} (${scanHistory.filter((sc) => sc.status === s).length})`}
            </button>
          ))}
        </div>

        {loadError && <p className="error" style={{ marginTop: 8 }}>{loadError}</p>}

        {filtered.length === 0 && !historyLoading ? (
          <div className="empty-state">
            <div style={{ fontSize: "2rem", marginBottom: 10 }}>◫</div>
            {scanHistory.length === 0 ? "No completed scans have been recorded yet." : "No scans match the current filter."}
          </div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 14 }}>
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>High</th>
                  <th>Med</th>
                  <th>Low</th>
                  <th>Total</th>
                  <th>Duration</th>
                  <th>Started</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((scan) => {
                  const isRunning = scan.status === "running" || scan.status === "finalizing";
                  const isFailed = scan.status === "failed";
                  const rowStyle = isFailed
                    ? { background: "rgba(255,95,122,0.05)" }
                    : isRunning
                    ? { background: "rgba(89,208,255,0.04)" }
                    : undefined;

                  return (
                    <tr key={scan.id} style={rowStyle}>
                      <td>
                        <div style={{ fontWeight: 700 }}>{scan.target}</div>
                        <div className="meta">{scan.id}</div>
                      </td>
                      <td>
                        <span className={`status-badge ${scan.status === "completed" ? "success" : scan.status === "failed" ? "error" : isRunning ? "" : "warning"}`}>
                          {isRunning && <span className="scan-running-dot" />}
                          {scan.status}
                        </span>
                      </td>
                      <td style={{ color: "#ff5f7a", fontWeight: 700 }}>{scan.highCount ?? "—"}</td>
                      <td style={{ color: "#ffad66", fontWeight: 700 }}>{scan.mediumCount ?? "—"}</td>
                      <td style={{ color: "#ffd966", fontWeight: 700 }}>{scan.lowCount ?? "—"}</td>
                      <td>{scan.findingCount ?? "—"}</td>
                      <td className="meta">{fmtDuration(scan.createdAt, scan.completedAt)}</td>
                      <td className="meta">{scan.createdAt ? new Date(scan.createdAt).toLocaleString() : "—"}</td>
                      <td>
                        <div className="button-row">
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={() => handleView(scan.id, "/findings")}
                            disabled={!!loadingId}
                          >
                            {loadingId === scan.id + "/findings" ? "Loading…" : "Triage"}
                          </button>
                          <button
                            type="button"
                            className="button-ghost"
                            title="View attack graph"
                            onClick={() => handleView(scan.id, "/attack-graph")}
                            disabled={!!loadingId}
                          >
                            {loadingId === scan.id + "/attack-graph" ? "…" : "⛓"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
