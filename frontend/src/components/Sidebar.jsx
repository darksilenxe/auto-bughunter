import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { API_BASE, getAPIKey, getWorkspaceID, useScan } from "../context/ScanContext";

const NAV = [
  { path: "/", label: "Dashboard" },
  { path: "/attack-graph", label: "Attack Graph" },
  { path: "/findings", label: "Findings" },
  { path: "/reports", label: "Reports" },
  { path: "/scans", label: "Scan History" },
  { path: "/proxy", label: "Proxy" },
  { path: "/ide", label: "PoC IDE" },
  { path: "/agent-activity", label: "Agent Activity" },
  { path: "/agent-console", label: "Agent Console" },
  { path: "/probe-coverage", label: "Probe Coverage" },
  { path: "/scan-timeline", label: "Scan Timeline" },
  { path: "/surface-map", label: "Surface Map" },
  { path: "/accuracy", label: "Accuracy Bench" },
  { path: "/references", label: "References" },
  { path: "/settings", label: "Settings" },
];

export default function Sidebar() {
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();
  const { isScanActive, job } = useScan();
  const [backendVersion, setBackendVersion] = useState("v2.0");
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || "dark");

  useEffect(() => {
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    fetch(`${API_BASE}/api/health`, { headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceID } })
      .then((r) => r.ok ? r.json() : null)
      .then((data) => { if (data?.version) setBackendVersion(data.version); })
      .catch(() => { /* ignore */ });
  }, []);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    if (next === "light") {
      document.documentElement.dataset.theme = "light";
    } else {
      delete document.documentElement.dataset.theme;
    }
  };

  // Count unreviewed high-severity findings (lifecycle = new)
  const newHighCount = (job?.findings || []).filter(
    (f) => f.severity === "high" && (!f.exploitability?.verifiedStatus || f.exploitability.verifiedStatus === "new")
  ).length;

  return (
    <>
      <button className="sidebar-toggle" onClick={() => setOpen((value) => !value)} aria-label={open ? "Close navigation" : "Open navigation"}>
        {open ? "✕" : "☰"}
        {isScanActive && !open && (
          <span className="sidebar-scan-dot" title="Scan active" />
        )}
      </button>

      {open && <div className="sidebar-backdrop" onClick={() => setOpen(false)} />}

      <aside className={`sidebar ${open ? "is-open" : ""}`}>
        <section className="sidebar__brand">
          <div className="eyebrow">Security platform</div>
          <h2>Auto BugHunter</h2>
          <p className="meta">
            Authorized web application security assessment with evidence-driven triage.
          </p>
          <div className="sidebar__meta">
            <span className="chip">Operational</span>
            <span className="chip chip--goal">Evidence-focused</span>
          </div>
        </section>

        <nav className="sidebar__nav">
          <ul>
            {NAV.map(({ path, label }) => {
              const isActive = pathname === path;
              const isDashboard = path === "/";
              const isFindings = path === "/findings";

              return (
                <li key={path}>
                  <Link to={path} onClick={() => setOpen(false)} className={isActive ? "is-active" : ""}>
                    <span className="sidebar__link-label">{label}</span>
                    {isDashboard && isScanActive && (
                      <span className="sidebar-live-dot" title="Scan active" />
                    )}
                    {isFindings && newHighCount > 0 && (
                      <span className="sidebar-badge">{newHighCount}</span>
                    )}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        <section className="sidebar__footer">
          <div className="meta">Backend</div>
          <div style={{ marginTop: 6, fontWeight: 700 }}>{backendVersion} · Web UI</div>
          <div className="sidebar__meta">
            {isScanActive ? (
              <span className="status-badge success">Scan active</span>
            ) : (
              <span className="status-badge">Ready</span>
            )}
            <span className="status-badge">Workspace</span>
          </div>
          <div style={{ marginTop: 10, display: "flex", alignItems: "center", gap: 10 }}>
            <button type="button" className="theme-toggle" onClick={toggleTheme} title="Toggle dark/light mode">
              {theme === "dark" ? "Switch to light" : "Switch to dark"}
            </button>
          </div>
          <div className="meta" style={{ marginTop: 8, fontSize: "0.72rem" }}>
            Press <kbd style={{ background: "rgba(255,255,255,0.08)", borderRadius: 4, padding: "1px 5px", fontSize: "0.72rem" }}>Ctrl+K</kbd> for quick actions
          </div>
        </section>
      </aside>
    </>
  );
}
