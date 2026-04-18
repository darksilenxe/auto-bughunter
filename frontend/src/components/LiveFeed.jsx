import { useEffect, useRef } from "react";

const ICON = {
  agent_start:    "▶",
  agent_complete: "✔",
  agent_spawned:  "⚡",
  finding:        "🔍",
  command:        "$",
  screenshot:     "📷",
  info:           "ℹ",
};

const SEV_COLOR = {
  high:   "#ef4444",
  medium: "#f97316",
  low:    "#eab308",
  info:   "#94a3b8",
};

export default function LiveFeed({ events, isRunning, onScreenshot }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [events]);

  if (!events.length) return null;

  return (
    <div>
      <h3 style={{ margin: "1rem 0 0.4rem", fontSize: "1rem" }}>
        ⚡ Live Activity Feed{" "}
        {isRunning && (
          <span style={{ fontSize: "0.72rem", color: "#4ade80", marginLeft: "6px" }}>● streaming</span>
        )}
      </h3>
      <div
        ref={ref}
        style={{
          background: "#0d1117",
          borderRadius: "8px",
          padding: "0.75rem 1rem",
          maxHeight: "280px",
          overflowY: "auto",
          fontFamily: "monospace",
          fontSize: "0.76rem",
          lineHeight: 1.6,
          border: "1px solid rgba(255,255,255,0.1)",
        }}
      >
        {events.map((evt, idx) => (
          <div key={idx} style={{ display: "flex", gap: "0.5rem", alignItems: "flex-start", marginBottom: "1px" }}>
            <span style={{ color: "#4b5563", flexShrink: 0, minWidth: "80px" }}>
              {new Date(evt.timestamp).toLocaleTimeString()}
            </span>
            <span style={{ flexShrink: 0, width: "16px" }}>{ICON[evt.type] || "·"}</span>

            {evt.type === "finding" && (
              <span style={{ color: SEV_COLOR[evt.severity] || "#cdd9e5" }}>
                [{evt.severity?.toUpperCase()}] {evt.findingTitle}
              </span>
            )}
            {evt.type === "command" && (
              <span style={{ color: "#79c0ff" }}>
                <span style={{ color: "#4b5563" }}>$ </span>{evt.command}
              </span>
            )}
            {evt.type === "screenshot" && (
              <span style={{ color: "#d2a8ff" }}>
                {evt.message}{" "}
                {onScreenshot && (
                  <button
                    onClick={() => onScreenshot(evt.screenshot)}
                    style={{
                      background: "none", border: "1px solid #555", color: "#d2a8ff",
                      cursor: "pointer", fontSize: "0.68rem", borderRadius: "3px",
                      padding: "0 4px",
                    }}
                  >view</button>
                )}
              </span>
            )}
            {evt.type === "agent_spawned" && (
              <span style={{ color: "#fde68a" }}>{evt.message}</span>
            )}
            {!["finding","command","screenshot","agent_spawned"].includes(evt.type) && (
              <span style={{
                color: evt.type === "agent_start" ? "#56d364"
                     : evt.type === "agent_complete" ? "#3fb950"
                     : "#cdd9e5",
              }}>
                {evt.agentName ? `[${evt.agentName}] ` : ""}{evt.message}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
