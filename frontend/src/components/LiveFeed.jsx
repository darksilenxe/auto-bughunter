import { useMemo } from "react";
import { useAutoScrollToLatest, formatLiveEventText } from "../lib/liveEventFormat.js";

const ICON = {
  agent_start:     "▶",
  agent_complete:  "✓",
  agent_spawned:   "⚡",
  finding:         "◎",
  command:         "$",
  command_result:  "⇐",
  screenshot:      "◫",
  info:            "•",
  reasoning_loop:  "⟳",
};

const SEV_COLOR = {
  high:   "#ff5f7a",
  medium: "#ffad66",
  low:    "#ffd966",
  info:   "#8aa0bf",
};

const REASONING_STATUS_COLOR = {
  probing:    "#59d0ff",
  reflection: "#a78bfa",
  exhausted:  "#47d7ac",
};

export default function LiveFeed({ events, isRunning, onScreenshot }) {
  const ref = useAutoScrollToLatest(events);

  const counters = useMemo(() => {
    return events.reduce(
      (acc, evt) => {
        acc.total += 1;
        if (evt.type === "finding") acc.findings += 1;
        if (evt.type === "command") acc.commands += 1;
        if (evt.type === "command_result") acc.commandResults += 1;
        if (evt.type === "reasoning_loop") acc.reasoningSteps += 1;
        if (evt.type === "agent_start" || evt.type === "agent_complete" || evt.type === "agent_spawned") acc.agentSteps += 1;
        return acc;
      },
      { total: 0, findings: 0, commands: 0, commandResults: 0, agentSteps: 0, reasoningSteps: 0 }
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
          {counters.reasoningSteps > 0 && (
            <span className="chip chip--reasoning">{counters.reasoningSteps} reasoning</span>
          )}
          <span className="chip chip--muted">{counters.commands} commands</span>
          {counters.commandResults > 0 && (
            <span className="chip chip--muted">{counters.commandResults} outputs</span>
          )}
          <span className="chip chip--muted">{counters.findings} findings</span>
        </div>
      </div>

      <div ref={ref} className="terminal live-feed__stream">
        {events.map((evt, idx) => {
          const isReasoning = evt.type === "reasoning_loop";
          const reasoningStatus = evt.metadata?.status;
          const reasoningColor = isReasoning ? (REASONING_STATUS_COLOR[reasoningStatus] || "#59d0ff") : null;
          const { agentName, primary, screenshot } = formatLiveEventText(evt);

          return (
            <div
              key={idx}
              className={`live-feed__item${isReasoning ? " live-feed__item--reasoning" : ""}`}
              style={isReasoning ? { borderLeft: `2px solid ${reasoningColor}`, paddingLeft: 10 } : undefined}
            >
              <span className="meta">{evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : "live"}</span>
              <span style={reasoningColor ? { color: reasoningColor } : undefined}>{ICON[evt.type] || "·"}</span>
              <span style={{ color: evt.type === "finding" ? SEV_COLOR[evt.severity] || "#dff1ff" : isReasoning ? reasoningColor : "#dff1ff" }}>
                {agentName && <span style={{ color: "#7c8aa5" }}>[{agentName}] </span>}
                {primary}
                {screenshot && onScreenshot && (
                  <button
                    type="button"
                    onClick={() => onScreenshot(screenshot)}
                    className="button-ghost"
                    style={{ marginLeft: 10, padding: "0.18rem 0.5rem", fontSize: "0.72rem" }}
                  >
                    View
                  </button>
                )}
              </span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
