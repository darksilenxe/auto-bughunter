import { useMemo, useState } from "react";
import { useScan } from "../context/ScanContext";

const STATUS_COLOR = {
  completed: "#47d7ac",
  complete: "#47d7ac",
  failed: "#ff5f7a",
  error: "#ff5f7a",
  running: "#59d0ff",
  in_progress: "#59d0ff",
  cancelled: "#ffad66",
};

function fmtDuration(ms) {
  if (!ms || ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m < 60) return `${m}m ${rem}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function DecisionTraceBadges({ trace }) {
  if (!trace) return null;
  const items = [
    trace.policyProfile && { label: "Policy", value: trace.policyProfile },
    trace.scopeCheck && { label: "Scope", value: trace.scopeCheck },
    trace.scopeReason && { label: "Scope reason", value: trace.scopeReason },
    trace.roiScore != null && trace.roiScore !== 0 && { label: "ROI", value: Number(trace.roiScore).toFixed(2) },
    trace.triggeringSignal && { label: "Trigger", value: trace.triggeringSignal },
  ].filter(Boolean);
  if (!items.length) return null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", marginTop: 6 }}>
      {items.map((item) => (
        <span key={item.label} style={{ fontSize: "0.72rem", background: "rgba(89,208,255,0.08)", border: "1px solid rgba(89,208,255,0.2)", borderRadius: 4, padding: "0.1rem 0.45rem", color: "#9cd9f5" }}>
          <span style={{ color: "#59d0ff", fontWeight: 600 }}>{item.label}:</span> {item.value}
        </span>
      ))}
    </div>
  );
}

export default function ScanTimeline() {
  const { job } = useScan();
  const [hovered, setHovered] = useState(null);

  const agentRuns = job?.agentRuns || [];

  const { minTime, maxTime, rows } = useMemo(() => {
    if (!agentRuns.length) return { minTime: 0, maxTime: 0, rows: [] };

    const withTimes = agentRuns
      .map((run, idx) => ({
        ...run,
        _idx: idx,
        _start: run.startedAt ? new Date(run.startedAt).getTime() : null,
        _end: run.completedAt ? new Date(run.completedAt).getTime() : null,
      }))
      .filter((r) => r._start);

    if (!withTimes.length) return { minTime: 0, maxTime: 0, rows: [] };

    const minT = Math.min(...withTimes.map((r) => r._start));
    const maxT = Math.max(...withTimes.map((r) => r._end || Date.now()));

    return { minTime: minT, maxTime: maxT, rows: withTimes };
  }, [agentRuns]);

  const totalSpan = maxTime - minTime || 1;

  if (!job) {
    return (
      <div className="page">
        <header>
          <h1>Scan timeline</h1>
          <p>Gantt-style view of agent execution over the course of a scan.</p>
        </header>
        <section className="card empty-state">
          <div style={{ fontSize: "2rem", marginBottom: 12 }}>◫</div>
          No scan loaded. Start or load a scan to view the timeline.
        </section>
      </div>
    );
  }

  if (!rows.length) {
    return (
      <div className="page">
        <header>
          <h1>Scan timeline</h1>
          <p>Gantt-style view of agent execution — <strong>{job.target}</strong></p>
        </header>
        <section className="card empty-state">
          <div style={{ fontSize: "2rem", marginBottom: 12 }}>◫</div>
          No agent run timing data available for this scan.
        </section>
      </div>
    );
  }

  return (
    <div className="page page--wide">
      <header>
        <div className="eyebrow">Temporal analysis</div>
        <h1>Scan timeline</h1>
        <p>
          Agent execution timeline for <strong>{job.target}</strong> — concurrency, bottlenecks, and where time was spent.
        </p>
      </header>

      <section className="hero-panel">
        <div className="metrics-grid">
          <article className="stat-card">
            <span className="stat-card__label">Total agents</span>
            <div className="stat-card__value">{rows.length}</div>
            <div className="stat-card__hint">Individual agent runs recorded.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Total span</span>
            <div className="stat-card__value">{fmtDuration(totalSpan)}</div>
            <div className="stat-card__hint">Wall-clock time from first to last agent.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Completed</span>
            <div className="stat-card__value" style={{ color: "#47d7ac" }}>
              {rows.filter((r) => ["completed", "complete"].includes(String(r.status || "").toLowerCase())).length}
            </div>
            <div className="stat-card__hint">Agents that finished successfully.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Failed</span>
            <div className="stat-card__value" style={{ color: "#ff5f7a" }}>
              {rows.filter((r) => ["failed", "error"].includes(String(r.status || "").toLowerCase())).length}
            </div>
            <div className="stat-card__hint">Agents that errored during execution.</div>
          </article>
        </div>
      </section>

      <section className="card">
        <div className="toolbar" style={{ marginBottom: 16 }}>
          <div>
            <h2>Agent execution timeline</h2>
            <p className="meta">Each bar represents one agent run. Width is proportional to wall-clock duration.</p>
          </div>
          <div className="filter-row">
            {Object.entries(STATUS_COLOR).filter(([k]) => !["complete", "in_progress", "error"].includes(k)).map(([status, color]) => (
              <span key={status} className="chip chip--muted" style={{ fontSize: "0.74rem" }}>
                <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: color, marginRight: 4 }} />
                {status}
              </span>
            ))}
          </div>
        </div>

        <div style={{ overflowX: "auto" }}>
          <div style={{ minWidth: 600 }}>
            {/* Time axis */}
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, paddingLeft: 200 }}>
              {[0, 0.25, 0.5, 0.75, 1].map((frac) => (
                <span key={frac} className="meta" style={{ fontSize: "0.72rem" }}>
                  {fmtDuration(frac * totalSpan)}
                </span>
              ))}
            </div>

            {/* Rows */}
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {rows.map((run) => {
                const normStart = (run._start - minTime) / totalSpan;
                const normEnd = run._end ? (run._end - minTime) / totalSpan : 1;
                const normWidth = Math.max(normEnd - normStart, 0.004);
                const statusKey = String(run.status || "").toLowerCase();
                const color = STATUS_COLOR[statusKey] || "#7c8aa5";
                const duration = run._end ? run._end - run._start : null;
                const isHovered = hovered === run._idx;

                return (
                  <div key={run._idx}>
                    <div
                      style={{ display: "flex", alignItems: "center", gap: 8 }}
                      onMouseEnter={() => setHovered(run._idx)}
                      onMouseLeave={() => setHovered(null)}
                    >
                    {/* Label */}
                    <div
                      style={{
                        width: 196,
                        flexShrink: 0,
                        fontSize: "0.8rem",
                        color: "var(--ink-soft)",
                        textAlign: "right",
                        paddingRight: 8,
                        fontWeight: isHovered ? 700 : 400,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        transition: "font-weight 0.1s",
                      }}
                      title={run.agentName || run.name || `Agent ${run._idx + 1}`}
                    >
                      {run.agentName || run.name || `Agent ${run._idx + 1}`}
                    </div>

                    {/* Bar track */}
                    <div style={{ flex: 1, height: 24, position: "relative", borderRadius: 4, background: "rgba(255,255,255,0.03)" }}>
                      <div
                        style={{
                          position: "absolute",
                          left: `${normStart * 100}%`,
                          width: `${normWidth * 100}%`,
                          top: 0,
                          bottom: 0,
                          background: color,
                          opacity: isHovered ? 1 : 0.72,
                          borderRadius: 4,
                          transition: "opacity 0.15s",
                          cursor: "default",
                        }}
                        title={`${run.agentName || run.name} — ${fmtDuration(duration)} — ${run.status}`}
                      />
                    </div>

                    {/* Duration label */}
                    <div style={{ width: 60, flexShrink: 0, fontSize: "0.76rem", color: "var(--ink-muted)" }}>
                      {fmtDuration(duration)}
                    </div>

                    {/* Status */}
                    <div style={{ width: 80, flexShrink: 0 }}>
                      <span style={{ fontSize: "0.72rem", fontWeight: 700, color, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                        {run.status || "—"}
                      </span>
                    </div>
                    </div>
                  {isHovered && run.agentDecisionTrace && (
                    <div style={{ paddingLeft: 204, paddingBottom: 6 }}>
                      <DecisionTraceBadges trace={run.agentDecisionTrace} />
                    </div>
                  )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      {(job.auditTrail?.length > 0) && (
        <section className="card">
          <div className="toolbar" style={{ marginBottom: 16 }}>
            <div>
              <h2>Audit trail</h2>
              <p className="meta">Decision-traced events recorded during this scan ({job.auditTrail.length} entries).</p>
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {job.auditTrail.map((entry, idx) => (
              <div key={idx} style={{ display: "flex", gap: 12, alignItems: "flex-start", padding: "6px 4px", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <span className="meta" style={{ flexShrink: 0, minWidth: 60, fontSize: "0.72rem" }}>
                  {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : "—"}
                </span>
                <span style={{ flexShrink: 0, minWidth: 120, fontSize: "0.76rem", fontWeight: 600, color: "#59d0ff", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  {entry.stage || "—"}
                </span>
                <div style={{ flex: 1 }}>
                  <span style={{ fontSize: "0.84rem", color: "var(--ink-soft)" }}>{entry.message}</span>
                  {entry.agentDecisionTrace && (
                    <DecisionTraceBadges trace={entry.agentDecisionTrace} />
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
