import { useScan } from "../context/ScanContext";

export default function AgentActivity() {
  const { liveEvents } = useScan();
  const commandEvents = liveEvents.filter(
    (e) => e.type === "command" || e.type === "command_result"
  );

  return (
    <div className="layout-panel">
      <header className="layout-panel__header">
        <h1>Agent Activity</h1>
        <p className="meta">Real-time command execution and results</p>
      </header>

      <div className="layout-panel__content" style={{ padding: "1.5rem" }}>
        {commandEvents.length === 0 ? (
          <div className="empty-state">No agent commands recorded yet.</div>
        ) : (
          <div className="command-list" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            {commandEvents.map((evt, idx) => (
              <div key={idx} className="command-item" style={{ background: "var(--surface-color, #1a1a1a)", border: "1px solid var(--border-color, #333)", borderRadius: "6px", padding: "1rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                  <strong style={{ color: "var(--accent-color, #4db8ff)" }}>{evt.agentName || "Agent"}</strong>
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
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
