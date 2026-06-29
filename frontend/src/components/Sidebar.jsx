import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { API_BASE, getAPIKey, getWorkspaceID, useScan } from "../context/ScanContext";

const NAV = [
  { path: "/", label: "Operator Console", icon: "✦" },
  { path: "/attack-graph", label: "Attack Graph", icon: "⛓" },
  { path: "/findings", label: "Impact Triage", icon: "◎" },
  { path: "/reports", label: "Submission Center", icon: "⬢" },
  { path: "/scans", label: "Engagement History", icon: "◫" },
  { path: "/proxy", label: "Proxy Suite", icon: "⌁" },
  { path: "/ide",            label: "PoC IDE",           icon: "⌥" },
  { path: "/agent-activity", label: "Agent Activity",    icon: "⌗" },
  { path: "/agent-console",  label: "Agent Console",  icon: "⌘" },
  { path: "/probe-coverage", label: "Probe Coverage", icon: "◈" },
  { path: "/scan-timeline", label: "Scan Timeline", icon: "▦" },
  { path: "/surface-map", label: "Surface Map", icon: "⊕" },
  { path: "/references", label: "Knowledge Base", icon: "☰" },
  { path: "/settings", label: "Environment", icon: "⚙" },
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
          <div className="eyebrow">AI pentest operator</div>
          <h2>Auto BugHunter</h2>
          <p className="meta">
            Impact-first agentic web pentesting with proof-state driven bounty triage.
          </p>
          <div className="sidebar__meta">
            <span className="chip">Impact-first</span>
            <span className="chip chip--goal">Submission-ready focus</span>
          </div>
        </section>

        <nav className="sidebar__nav">
          <ul>
            {NAV.map(({ path, label, icon }) => {
              const isActive = pathname === path;
              const isDashboard = path === "/";
              const isFindings = path === "/findings";

              return (
                <li key={path}>
                  <Link to={path} onClick={() => setOpen(false)} className={isActive ? "is-active" : ""}>
                    <span aria-hidden="true">{icon}</span>
                    <span style={{ flex: 1 }}>{label}</span>
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
          <div className="meta">Premium UI pass</div>
          <div style={{ marginTop: 6, fontWeight: 700 }}>{backendVersion} · AI Console</div>
          <div className="sidebar__meta">
            {isScanActive ? (
              <span className="status-badge success">Scan active</span>
            ) : (
              <span className="status-badge">Live reasoning</span>
            )}
            <span className="status-badge">Operator mode</span>
          </div>
          <div style={{ marginTop: 10, display: "flex", alignItems: "center", gap: 10 }}>
            <button type="button" className="theme-toggle" onClick={toggleTheme} title="Toggle dark/light mode">
              {theme === "dark" ? "☀ Light" : "☾ Dark"}
            </button>
          </div>
          <div className="meta" style={{ marginTop: 8, fontSize: "0.72rem" }}>
            Press <kbd style={{ background: "rgba(255,255,255,0.08)", borderRadius: 4, padding: "1px 5px", fontSize: "0.72rem" }}>Ctrl+K</kbd> for commands
          </div>
        </section>
      </aside>
    </>
  );
}
