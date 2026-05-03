import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useScan } from "../context/ScanContext";

export default function Scans() {
  const { scanHistory, historyLoading, loadHistory, loadScan } = useScan();
  const navigate = useNavigate();
  const [loadingId, setLoadingId] = useState(null);
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const handleView = async (id) => {
    setLoadingId(id);
    const ok = await loadScan(id);
    setLoadingId(null);
    if (ok) {
      navigate("/findings");
    } else {
      setLoadError("Failed to load scan — it may have been deleted or is inaccessible.");
    }
  };

  return (
    <div className="page page--wide">
      <header>
        <h1>Engagement history</h1>
        <p>Track previous scans, their high-severity counts, and delivery cadence like a premium operator console.</p>
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

        {loadError && (
          <p className="error" style={{ marginTop: 8 }}>{loadError}</p>
        )}
        {scanHistory.length === 0 && !historyLoading ? (
          <div className="empty-state">No completed scans have been recorded yet.</div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 14 }}>
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>High</th>
                  <th>Total findings</th>
                  <th>Started</th>
                  <th>Completed</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scanHistory.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <div style={{ fontWeight: 700 }}>{scan.target}</div>
                      <div className="meta">{scan.id}</div>
                    </td>
                    <td>
                      <span className={`status-badge ${scan.status === "completed" ? "success" : scan.status === "failed" ? "error" : "warning"}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td>{scan.highCount}</td>
                    <td>{scan.findingCount}</td>
                    <td className="meta">{scan.createdAt ? new Date(scan.createdAt).toLocaleString() : "—"}</td>
                    <td className="meta">{scan.completedAt ? new Date(scan.completedAt).toLocaleString() : "—"}</td>
                    <td>
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={() => handleView(scan.id)}
                        disabled={loadingId === scan.id}
                      >
                        {loadingId === scan.id ? "Loading…" : "View"}
                      </button>
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
