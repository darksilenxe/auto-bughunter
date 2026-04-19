import { useState } from "react";
import { Link, useLocation } from "react-router-dom";

const NAV = [
  { path: "/",         label: "Dashboard",    icon: "⚡" },
  { path: "/findings", label: "Findings",     icon: "🔍" },
  { path: "/reports",  label: "Reports",      icon: "📄" },
  { path: "/scans",    label: "Scan History", icon: "📋" },
  { path: "/settings", label: "Settings",     icon: "⚙️" },
];

export default function Sidebar() {
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();

  return (
    <>
      {/* Hamburger toggle – always visible */}
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label={open ? "Close menu" : "Open menu"}
        style={{
          position: "fixed",
          top: "14px",
          left: "14px",
          zIndex: 200,
          background: "rgba(0,0,0,0.55)",
          border: "1.5px solid rgba(255,255,255,0.25)",
          borderRadius: "8px",
          width: "42px",
          height: "42px",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: "5px",
          cursor: "pointer",
          padding: 0,
        }}
      >
        {open ? (
          <span style={{ color: "#fff", fontSize: "1.3rem", lineHeight: 1 }}>✕</span>
        ) : (
          <>
            <span style={{ display: "block", width: "20px", height: "2px", background: "#fff", borderRadius: "2px" }} />
            <span style={{ display: "block", width: "20px", height: "2px", background: "#fff", borderRadius: "2px" }} />
            <span style={{ display: "block", width: "20px", height: "2px", background: "#fff", borderRadius: "2px" }} />
          </>
        )}
      </button>

      {/* Backdrop */}
      {open && (
        <div
          onClick={() => setOpen(false)}
          style={{
            position: "fixed", inset: 0,
            background: "rgba(0,0,0,0.45)",
            zIndex: 150,
          }}
        />
      )}

      {/* Drawer */}
      <nav
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          height: "100vh",
          width: "240px",
          background: "linear-gradient(180deg, #1e1230 0%, #0d0b14 100%)",
          zIndex: 160,
          transform: open ? "translateX(0)" : "translateX(-100%)",
          transition: "transform 0.25s cubic-bezier(.4,0,.2,1)",
          boxShadow: "4px 0 24px rgba(0,0,0,0.5)",
          display: "flex",
          flexDirection: "column",
          paddingTop: "70px",
        }}
      >
        <div style={{ padding: "0 20px 24px", borderBottom: "1px solid rgba(255,255,255,0.12)" }}>
          <span style={{ color: "#fff", fontWeight: 800, fontSize: "1.1rem", letterSpacing: ".04em" }}>
            🐛 Auto BugHunter
          </span>
        </div>

        <ul style={{ listStyle: "none", margin: 0, padding: "16px 0", flexGrow: 1 }}>
          {NAV.map(({ path, label, icon }) => {
            const active = pathname === path;
            return (
              <li key={path}>
                <Link
                  to={path}
                  onClick={() => setOpen(false)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "12px",
                    padding: "12px 24px",
                    color: active ? "#0d0b14" : "rgba(255,255,255,0.85)",
                    background: active ? "#a78bfa" : "transparent",
                    fontWeight: active ? 700 : 500,
                    fontSize: "0.95rem",
                    textDecoration: "none",
                    borderRadius: "0 24px 24px 0",
                    marginRight: "16px",
                    transition: "background 0.15s",
                  }}
                >
                  <span style={{ fontSize: "1.1rem" }}>{icon}</span>
                  {label}
                </Link>
              </li>
            );
          })}
        </ul>

        <div style={{ padding: "16px 24px", borderTop: "1px solid rgba(255,255,255,0.12)" }}>
          <span style={{ color: "rgba(255,255,255,0.45)", fontSize: "0.75rem" }}>v2.0 · Local AI</span>
        </div>
      </nav>
    </>
  );
}
