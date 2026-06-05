import { useMemo, useState } from "react";
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

function fmtMs(ms) {
  if (!ms || ms < 0) return null;
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

export default function AgentActivity() {
  const { liveEvents } = useScan();
  const [typeFilter, setTypeFilter] = useState(new Set());
  const [agentFilter, setAgentFilter] = useState("all");
  const [groupByAgent, setGroupByAgent] = useState(false);
  const [search, setSearch] = useState("");

  const agentEvents = liveEvents.filter((e) => AGENT_EVENT_TYPES.has(e.type));

  // Derive per-agent durations by pairing agent_start / agent_complete
  const agentDurations = useMemo(() => {
    const starts = {};
    const durationMap = {};
    for (const evt of agentEvents) {
      const key = evt.agentName || "_";
      if (evt.type === "agent_start") starts[key] = new Date(evt.timestamp).getTime();
      if (evt.type === "agent_complete" && starts[key]) {
        durationMap[key] = new Date(evt.timestamp).getTime() - starts[key];
      }
    }
    return durationMap;
  }, [agentEvents]);

  // All unique agent names
  const allAgents = useMemo(() => {
    const names = new Set();
    for (const e of agentEvents) { if (e.agentName) names.add(e.agentName); }
    return ["all", ...Array.from(names).sort()];
  }, [agentEvents]);

  const filtered = useMemo(() => {
    return agentEvents.filter((evt) => {
      if (typeFilter.size > 0 && !typeFilter.has(evt.type)) return false;
      if (agentFilter !== "all" && evt.agentName !== agentFilter) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          (evt.message || "").toLowerCase().includes(q) ||
          (evt.agentName || "").toLowerCase().includes(q) ||
          (evt.command || "").toLowerCase().includes(q) ||
          (evt.output || "").toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [agentEvents, typeFilter, agentFilter, search]);

  // Group filtered events by agent name
  const grouped = useMemo(() => {
    if (!groupByAgent) return null;
    const map = {};
    for (const evt of filtered) {
      const key = evt.agentName || "(no agent)";
      if (!map[key]) map[key] = [];
      map[key].push(evt);
    }
    return Object.entries(map).sort(([a], [b]) => a.localeCompare(b));
  }, [filtered, groupByAgent]);

  function toggleType(t) {
    setTypeFilter((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t); else next.add(t);
      return next;
    });
  }

  function renderEvent(evt, idx) {
    const accent = EVENT_TYPE_ACCENT[evt.type] || "#aaa";
    const label = EVENT_TYPE_LABELS[evt.type] || evt.type;
    return (
      <div key={idx} className="command-item" style={{ background: "var(--surface-color, #1a1a1a)", border: "1px solid var(--border-color, #333)", borderRadius: "6px", padding: "1rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
          <div style={{ display: "flex", gap: "0.75rem", alignItems: "baseline" }}>
            <span style={{ fontSize: "0.75rem", fontWeight: 600, color: accent, textTransform: "uppercase", letterSpacing: "0.05em" }}>{label}</span>
            {evt.agentName && <strong style={{ color: accent, fontSize: "0.9rem" }}>{evt.agentName}</strong>}
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
  }

  return (
    <div className="layout-panel">
      <header className="layout-panel__header">
        <h1>Agent Activity</h1>
        <p className="meta">Real-time agent execution and results</p>
      </header>

      <div className="layout-panel__content" style={{ padding: "1.5rem" }}>
        {/* Controls */}
        <div className="card" style={{ marginBottom: "1rem" }}>
          <div className="toolbar" style={{ alignItems: "flex-start", marginBottom: 10 }}>
            <div>
              <strong>Filters</strong>
              <p className="meta" style={{ marginTop: 4 }}>{filtered.length} / {agentEvents.length} events</p>
            </div>
            <div className="button-row">
              <button
                type="button"
                className={`filter-chip ${groupByAgent ? "is-active" : ""}`}
                onClick={() => setGroupByAgent((p) => !p)}
              >
                Group by agent
              </button>
            </div>
          </div>

          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search message, agent, command…"
            style={{ marginBottom: 10 }}
          />

          <div className="filter-row" style={{ marginBottom: 8 }}>
            <span className="meta" style={{ alignSelf: "center" }}>Type:</span>
            {Array.from(AGENT_EVENT_TYPES).map((t) => (
              <button
                key={t}
                type="button"
                className={`filter-chip ${typeFilter.has(t) ? "is-active" : ""}`}
                onClick={() => toggleType(t)}
              >
                {EVENT_TYPE_LABELS[t] || t}
              </button>
            ))}
            {typeFilter.size > 0 && (
              <button type="button" className="filter-chip" onClick={() => setTypeFilter(new Set())}>Clear</button>
            )}
          </div>

          {allAgents.length > 2 && (
            <div className="filter-row">
              <span className="meta" style={{ alignSelf: "center" }}>Agent:</span>
              {allAgents.map((a) => (
                <button
                  key={a}
                  type="button"
                  className={`filter-chip ${agentFilter === a ? "is-active" : ""}`}
                  onClick={() => setAgentFilter(a)}
                >
                  {a === "all" ? `All (${agentEvents.length})` : (
                    <>
                      {a}
                      {agentDurations[a] && <span className="meta" style={{ marginLeft: 4 }}>{fmtMs(agentDurations[a])}</span>}
                    </>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {filtered.length === 0 ? (
          <div className="empty-state">
            <div style={{ fontSize: "2rem", marginBottom: 12 }}>⌗</div>
            {agentEvents.length === 0 ? "No agent activity recorded yet." : "No events match the current filters."}
          </div>
        ) : groupByAgent && grouped ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            {grouped.map(([agentName, evts]) => (
              <details key={agentName} open>
                <summary style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }}>
                  <strong>{agentName}</strong>
                  <span className="chip chip--muted">{evts.length} events</span>
                  {agentDurations[agentName] && (
                    <span className="chip chip--goal">{fmtMs(agentDurations[agentName])}</span>
                  )}
                </summary>
                <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "0.75rem" }}>
                  {evts.map((evt, idx) => renderEvent(evt, idx))}
                </div>
              </details>
            ))}
          </div>
        ) : (
          <div className="command-list" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {filtered.map((evt, idx) => renderEvent(evt, idx))}
          </div>
        )}
      </div>
    </div>
  );
}
