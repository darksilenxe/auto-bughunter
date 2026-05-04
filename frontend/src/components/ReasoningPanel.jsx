import { useMemo } from "react";

const STATUS_META = {
  probing:    { icon: "⟳", label: "Probing",    color: "#59d0ff" },
  reflection: { icon: "◈", label: "Reflecting",  color: "#a78bfa" },
  exhausted:  { icon: "✓", label: "Exhausted",  color: "#47d7ac" },
};

function categoryChipClass(cat) {
  const map = {
    xss:            "reasoning-chip--xss",
    sqli:           "reasoning-chip--sqli",
    cors:           "reasoning-chip--cors",
    ssrf:           "reasoning-chip--ssrf",
    idor:           "reasoning-chip--idor",
    ssti:           "reasoning-chip--ssti",
    open_redirect:  "reasoning-chip--redirect",
    auth_bypass:    "reasoning-chip--auth",
    business_logic: "reasoning-chip--biz",
  };
  return "reasoning-chip " + (map[cat] || "reasoning-chip--default");
}

// Parse comma-separated metadata strings into arrays, filtering blanks.
function parseList(str) {
  if (!str) return [];
  return str.split(",").map((s) => s.trim()).filter(Boolean);
}

// Build the rounds timeline from all reasoning_loop events.
function buildRounds(events) {
  const roundMap = {};
  for (const evt of events) {
    if (evt.type !== "reasoning_loop") continue;
    const m = evt.metadata || {};
    const r = parseInt(m.round, 10) || 0;
    if (!roundMap[r]) {
      roundMap[r] = { round: r, probing: null, reflection: null, timestamp: evt.timestamp };
    }
    if (m.status === "probing") {
      roundMap[r].probing = { ...m, message: evt.message, timestamp: evt.timestamp };
    } else if (m.status === "reflection") {
      roundMap[r].reflection = { ...m, message: evt.message, timestamp: evt.timestamp };
    } else if (m.status === "exhausted") {
      roundMap[r].exhausted = { message: evt.message, timestamp: evt.timestamp };
    }
  }
  return Object.values(roundMap).sort((a, b) => a.round - b.round);
}

export default function ReasoningPanel({ events, isRunning }) {
  const reasoningEvents = useMemo(
    () => events.filter((e) => e.type === "reasoning_loop"),
    [events]
  );
  const rounds = useMemo(() => buildRounds(events), [events]);

  if (reasoningEvents.length === 0) return null;

  const latest = rounds[rounds.length - 1];
  const latestReflection = latest?.reflection;

  return (
    <section className="card reasoning-panel">
      <div className="reasoning-panel__head">
        <div>
          <h2>AI reasoning loop</h2>
          <p className="meta">
            Live view of the model's decision-making: why it iterates, what it targets next, and where it identified gaps.
          </p>
        </div>
        <div className="filter-row">
          <span className={`status-badge ${isRunning ? "" : "success"}`}>
            {isRunning ? "Iterating…" : `${rounds.length} round${rounds.length !== 1 ? "s" : ""} complete`}
          </span>
          <span className="chip chip--muted">{reasoningEvents.length} reasoning events</span>
        </div>
      </div>

      {/* ── Current iteration rationale ──────────────────────────────── */}
      {latestReflection && (
        <div className="reasoning-rationale">
          <div className="reasoning-rationale__label">
            <span className="reasoning-rationale__icon">◈</span>
            AI iteration rationale — round {latestReflection.round}
          </div>
          <p className="reasoning-rationale__text">
            {latestReflection.iterationRationale || latestReflection.gapAnalysis || latestReflection.message}
          </p>
          {latestReflection.shouldEscalate === "true" && (
            <div className="reasoning-escalation">
              <span className="reasoning-escalation__icon">⚠</span>
              <span>{latestReflection.escalationReason || "Escalation to deeper probing recommended."}</span>
            </div>
          )}
        </div>
      )}

      {/* ── Focus areas for next round ───────────────────────────────── */}
      {latestReflection && parseList(latestReflection.focusAreas).length > 0 && (
        <div className="reasoning-focus">
          <span className="reasoning-focus__label">Next round focus</span>
          <div className="filter-row">
            {parseList(latestReflection.focusAreas).map((cat) => (
              <span key={cat} className={categoryChipClass(cat)}>{cat}</span>
            ))}
          </div>
          {parseList(latestReflection.skipCategories).length > 0 && (
            <div className="reasoning-focus__skipped">
              <span className="meta">Skipping (exhausted): </span>
              {parseList(latestReflection.skipCategories).map((cat) => (
                <span key={cat} className="reasoning-chip reasoning-chip--skip">{cat}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Coverage counters ─────────────────────────────────────────── */}
      {latestReflection && (
        <div className="reasoning-coverage">
          <article className="reasoning-stat">
            <span className="reasoning-stat__value">{latestReflection.totalTried || "0"}</span>
            <span className="reasoning-stat__label">probes sent</span>
          </article>
          <article className="reasoning-stat">
            <span className="reasoning-stat__value" style={{ color: "var(--success)" }}>
              {latestReflection.totalConfirmed || "0"}
            </span>
            <span className="reasoning-stat__label">confirmed</span>
          </article>
          <article className="reasoning-stat">
            <span className="reasoning-stat__value">{latestReflection.refinedHints || "0"}</span>
            <span className="reasoning-stat__label">refined hints</span>
          </article>
          <article className="reasoning-stat">
            <span className="reasoning-stat__value">{rounds.length}</span>
            <span className="reasoning-stat__label">rounds</span>
          </article>
        </div>
      )}

      {/* ── Round-by-round timeline ───────────────────────────────────── */}
      {rounds.length > 0 && (
        <details className="reasoning-timeline" open={rounds.length <= 3}>
          <summary>Round timeline ({rounds.length})</summary>
          <div className="reasoning-timeline__list">
            {rounds.map((r) => (
              <div key={r.round} className="reasoning-round">
                <div className="reasoning-round__badge">R{r.round}</div>
                <div className="reasoning-round__body">
                  {r.probing && (
                    <div className="reasoning-round__step">
                      <span style={{ color: STATUS_META.probing.color }}>{STATUS_META.probing.icon}</span>
                      <span className="meta">{new Date(r.probing.timestamp).toLocaleTimeString()}</span>
                      <span>
                        Testing <strong>{r.probing.hypotheses || "?"}</strong> hypotheses
                        {parseList(r.probing.focusAreas).length > 0 && (
                          <> — focus: {parseList(r.probing.focusAreas).map((c) => (
                            <span key={c} className={categoryChipClass(c)} style={{ marginLeft: 4 }}>{c}</span>
                          ))}</>
                        )}
                      </span>
                    </div>
                  )}
                  {r.reflection && (
                    <div className="reasoning-round__step reasoning-round__step--reflect">
                      <span style={{ color: STATUS_META.reflection.color }}>{STATUS_META.reflection.icon}</span>
                      <span className="meta">{new Date(r.reflection.timestamp).toLocaleTimeString()}</span>
                      <span className="reasoning-round__rationale">
                        {r.reflection.iterationRationale || r.reflection.gapAnalysis || r.reflection.message}
                      </span>
                    </div>
                  )}
                  {r.exhausted && (
                    <div className="reasoning-round__step">
                      <span style={{ color: STATUS_META.exhausted.color }}>{STATUS_META.exhausted.icon}</span>
                      <span>{r.exhausted.message}</span>
                    </div>
                  )}
                  {r.reflection && (
                    <div className="reasoning-round__meta">
                      <span className="chip chip--muted">+{r.reflection.roundFindings || 0} findings</span>
                      <span className="chip chip--muted">+{r.reflection.roundChains || 0} chains</span>
                      {r.reflection.refinedHints > 0 && (
                        <span className="chip chip--muted">{r.reflection.refinedHints} hints refined</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </details>
      )}
    </section>
  );
}
