import { useState } from "react";
import { Link, useLocation } from "react-router-dom";

const NAV = [
  { path: "/", label: "Operator Console", icon: "✦" },
  { path: "/attack-graph", label: "Attack Graph", icon: "⛓" },
  { path: "/findings", label: "Impact Triage", icon: "◎" },
  { path: "/reports", label: "Submission Center", icon: "⬢" },
  { path: "/scans", label: "Engagement History", icon: "◫" },
  { path: "/proxy", label: "Proxy Suite", icon: "⌁" },
  { path: "/references", label: "Knowledge Base", icon: "☰" },
  { path: "/settings", label: "Environment", icon: "⚙" },
];

export default function Sidebar() {
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();

  return (
    <>
      <button className="sidebar-toggle" onClick={() => setOpen((value) => !value)} aria-label={open ? "Close navigation" : "Open navigation"}>
        {open ? "✕" : "☰"}
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
            {NAV.map(({ path, label, icon }) => (
              <li key={path}>
                <Link to={path} onClick={() => setOpen(false)} className={pathname === path ? "is-active" : ""}>
                  <span aria-hidden="true">{icon}</span>
                  <span>{label}</span>
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <section className="sidebar__footer">
          <div className="meta">Premium UI pass</div>
          <div style={{ marginTop: 6, fontWeight: 700 }}>v2.0 · AI Console</div>
          <div className="sidebar__meta">
            <span className="status-badge success">Live reasoning</span>
            <span className="status-badge">Operator mode</span>
          </div>
        </section>
      </aside>
    </>
  );
}
