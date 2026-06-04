import { useScan } from "../context/ScanContext";

const AGENT_EVENT_TYPES = new Set([
  "agent_start",
  "agent_complete",
  "agent_spawned",
  "info",
  "reasoning_loop",
  "command",
  "command_result",
  "finding",
]);

const EVENT_TYPE_LABELS = {
  agent_start: "▶ Agent started",
  agent_complete: "✓ Agent completed",
  agent_spawned: "⤷ Agent queued",
  info: "ℹ Info",
  reasoning_loop: "⟳ Reasoning",
  command: "$ Command",
  command_result: "⇐ Output",
  finding: "⚑ Finding",
};

const EVENT_TYPE_ACCENT = {
  agent_start: "#4db8ff",
  agent_complete: "#4dff91",
  agent_spawned: "#c084fc",
  info: "#aaa",
  reasoning_loop: "#fbbf24",
  command: "#4db8ff",
  command_result: "#ccc",
  finding: "#f87171",
};

export default function AgentActivity() {
  const { liveEvents } = useScan();
  const agentEvents = liveEvents.filter((e) => AGENT_EVENT_TYPES.has(e.type));

  return (
    <div className="layout-panel">
      <header className="layout-panel__header">
        <h1>Agent Activity</h1>
        <p className="meta">Real-time agent execution and results</p>
      </header>

      <div className="layout-panel__content" style={{ padding: "1.5rem" }}>
        {agentEvents.length === 0 ? (
          <div className="empty-state">No agent activity recorded yet.</div>
        ) : (
          <div className="command-list" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {agentEvents.map((evt, idx) => {
              const accent = EVENT_TYPE_ACCENT[evt.type] || "#aaa";
              const label = EVENT_TYPE_LABELS[evt.type] || evt.type;
              return (
                <div key={idx} className="command-item" style={{ background: "var(--surface-color, #1a1a1a)", border: "1px solid var(--border-color, #333)", borderRadius: "6px", padding: "1rem" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                    <div style={{ display: "flex", gap: "0.75rem", alignItems: "baseline" }}>
                      <span style={{ fontSize: "0.75rem", fontWeight: 600, color: accent, textTransform: "uppercase", letterSpacing: "0.05em" }}>{label}</span>
                      {evt.agentName && (
                        <strong style={{ color: accent, fontSize: "0.9rem" }}>{evt.agentName}</strong>
                      )}
                    </div>
                    <span className="meta" style={{ fontSize: "0.85rem" }}>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                  </div>
                  {evt.message && (
                    <div style={{ marginBottom: "0.5rem", fontSize: "0.9rem", color: "var(--text-secondary, #aaa)" }}>
                      {evt.message}
                    </div>
                  )}
                  {evt.type === "command" && evt.command && (
                    <pre style={{ margin: 0, padding: "0.75rem", background: "#000", borderRadius: "4px", fontSize: "0.85rem", overflowX: "auto", whiteSpace: "pre-wrap" }}>
                      <code style={{ color: "#0f0" }}>$ {evt.command}</code>
                    </pre>
                  )}
                  {evt.type === "command_result" && evt.output && (
                    <div style={{ marginTop: "0.5rem" }}>
                      <div style={{ fontSize: "0.8rem", marginBottom: "0.25rem", color: "#888" }}>Output:</div>
                      <pre style={{ margin: 0, padding: "0.75rem", background: "#111", border: "1px solid #222", borderRadius: "4px", fontSize: "0.85rem", overflowX: "auto", whiteSpace: "pre-wrap" }}>
                        <code style={{ color: "#ccc" }}>{evt.output}</code>
                      </pre>
                    </div>
                  )}
                  {evt.type === "reasoning_loop" && evt.metadata && Object.keys(evt.metadata).length > 0 && (
                    <div style={{ marginTop: "0.5rem", display: "flex", flexWrap: "wrap", gap: "0.4rem" }}>
                      {Object.entries(evt.metadata).map(([k, v]) => (
                        <span key={k} style={{ fontSize: "0.75rem", background: "#222", border: "1px solid #333", borderRadius: "4px", padding: "0.15rem 0.4rem", color: "#888" }}>
                          <span style={{ color: "#555" }}>{k}:</span> {v}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
