import { useEffect, useMemo, useRef } from "react";

const ICON = {
  agent_start: "▶",
  agent_complete: "✓",
  agent_spawned: "⚡",
  finding: "◎",
  command: "$",
  screenshot: "◫",
  info: "•",
};

const SEV_COLOR = {
  high: "#ff5f7a",
  medium: "#ffad66",
  low: "#ffd966",
  info: "#8aa0bf",
};

export default function LiveFeed({ events, isRunning, onScreenshot }) {
  const ref = useRef(null);

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [events]);

  const counters = useMemo(() => {
    return events.reduce(
      (acc, evt) => {
        acc.total += 1;
        if (evt.type === "finding") acc.findings += 1;
        if (evt.type === "command") acc.commands += 1;
        if (evt.type === "agent_start" || evt.type === "agent_complete" || evt.type === "agent_spawned") acc.agentSteps += 1;
        return acc;
      },
      { total: 0, findings: 0, commands: 0, agentSteps: 0 }
    );
  }, [events]);

  if (!events.length) {
    return (
      <section className="card card--compact">
        <div className="live-feed__head">
          <h2>AI activity stream</h2>
          <span className="status-badge">Idle</span>
        </div>
        <p className="meta">Start a scan to watch agents reason, spawn probes, and prove impact live.</p>
      </section>
    );
  }

  return (
    <section className="card">
      <div className="live-feed__head">
        <div>
          <h2 style={{ marginBottom: 4 }}>AI activity stream</h2>
          <p className="meta">Operator-grade event timeline for agent decisions, tool calls, and promoted findings.</p>
        </div>
        <div className="filter-row">
          <span className={`status-badge ${isRunning ? "success" : ""}`}>{isRunning ? "Streaming" : "Complete"}</span>
          <span className="chip chip--muted">{counters.agentSteps} agent steps</span>
          <span className="chip chip--muted">{counters.commands} commands</span>
          <span className="chip chip--muted">{counters.findings} findings</span>
        </div>
      </div>

      <div ref={ref} className="terminal live-feed__stream">
        {events.map((evt, idx) => (
          <div key={idx} className="live-feed__item">
            <span className="meta">{evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : "live"}</span>
            <span>{ICON[evt.type] || "·"}</span>
            <span style={{ color: evt.type === "finding" ? SEV_COLOR[evt.severity] || "#dff1ff" : "#dff1ff" }}>
              {evt.type === "finding" && <>[{evt.severity?.toUpperCase() || "INFO"}] {evt.findingTitle}</>}
              {evt.type === "command" && <><span style={{ color: "#7c8aa5" }}>$ </span>{evt.command}</>}
              {evt.type === "screenshot" && (
                <>
                  {evt.message}
                  {onScreenshot && evt.screenshot && (
                    <button
                      type="button"
                      onClick={() => onScreenshot(evt.screenshot)}
                      className="button-ghost"
                      style={{ marginLeft: 10, padding: "0.18rem 0.5rem", fontSize: "0.72rem" }}
                    >
                      View
                    </button>
                  )}
                </>
              )}
              {!["finding", "command", "screenshot"].includes(evt.type) && (
                <>
                  {evt.agentName ? `[${evt.agentName}] ` : ""}
                  {evt.message}
                </>
              )}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}
