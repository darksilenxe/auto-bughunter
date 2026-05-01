import { useEffect, useMemo, useState } from "react";
import AttackGraphChart from "../components/AttackGraph";
import AttackPathGraph from "../components/AttackPathGraph";
import { useScan } from "../context/ScanContext";
import { summarizeFindings } from "../lib/impact";

export default function AttackGraph() {
  const { job, loading, liveEvents } = useScan();
  const [activeGraphTab, setActiveGraphTab] = useState("chain");
  const [selectedScreenshot, setSelectedScreenshot] = useState(null);
  const [isGraphFullscreen, setIsGraphFullscreen] = useState(false);

  const isRunning = job?.status === "running" || loading;
  const findingsSummary = useMemo(function() { return summarizeFindings(job?.findings || []); }, [job?.findings]);
  const topAttackPaths = job?.dashboard?.topAttackPaths || [];
  const agentRuns = job?.agentRuns || [];
  const activeAgents = agentRuns.filter(function(run) { return ["running", "in_progress"].includes(String(run.status || "").toLowerCase()); }).length;

  // Close fullscreen on Escape
  useEffect(() => {
    if (!isGraphFullscreen) return;
    const handleKey = (e) => {
      if (e.key === "Escape") {
        setIsGraphFullscreen(false);
      }
    };
    document.addEventListener("keydown", handleKey);
    return function() { return document.removeEventListener("keydown", handleKey); };
  }, [isGraphFullscreen]);

  return (
    <div className="page page--wide">
      <section className="hero-panel">
        <div className="toolbar" style={{ alignItems: "flex-start" }}>
          <div>
            <div className="eyebrow">Live exploit chain mapping</div>
            <header style={{ marginBottom: 0 }}>
              <h1>Attack graph workbench</h1>
              <p>
                Watch the engagement unfold as chains, agents, and validated impact paths converge into submission-ready proof.
              </p>
            </header>
          </div>
          <div className="filter-row">
            <span className={`status-badge ${job?.status === "completed" ? "success" : isRunning ? "" : "warning"}`}>{job?.status || (isRunning ? "running" : "ready")}</span>
            <span className="chip chip--goal">{topAttackPaths.length} top paths</span>
          </div>
        </div>

        <div className="metrics-grid" style={{ marginTop: 18 }}>
          <article className="stat-card">
            <span className="stat-card__label">Submission-ready findings</span>
            <div className="stat-card__value">{findingsSummary.submissionReady}</div>
            <div className="stat-card__hint">Chains with enough evidence to transition into reporting immediately.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Active agents</span>
            <div className="stat-card__value">{activeAgents}</div>
            <div className="stat-card__hint">Currently running agent steps visible in the pipeline view.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Live events</span>
            <div className="stat-card__value">{liveEvents.length}</div>
            <div className="stat-card__hint">Operator timeline entries captured for this engagement.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Exploit chains</span>
            <div className="stat-card__value">{topAttackPaths.length}</div>
            <div className="stat-card__hint">{topAttackPaths[0] || "Waiting for graph evidence to accumulate."}</div>
          </article>
        </div>
      </section>

      {!(loading || job) && (
        <section className="card empty-state">
          No scan is currently loaded. Start a scan from the dashboard to render the chain and pipeline views.
        </section>
      )}

      {(loading || job) && (
        <div className="two-column-grid">
          <section className="card" style={{ padding: 0, overflow: "hidden" }}>
            <div className="toolbar" style={{ padding: "18px 18px 0" }}>
              <div>
                <h2 style={{ marginBottom: 6 }}>Operator graph views</h2>
                <p className="meta">
                  Toggle between impact chain view and agent pipeline view to understand what the AI is proving and why.
                </p>
              </div>
              <div className="filter-row">
                {[
                  { id: "chain", label: "Attack chain" },
                  { id: "pipeline", label: "Agent pipeline" },
                ].map(({ id, label }) => (
                  <button
                    key={id}
                    type="button"
                    className={`filter-chip ${activeGraphTab === id ? "is-active" : ""}`}
                    onClick={() => setActiveGraphTab(id)}
                  >
                    {label}
                  </button>
                ))}
                <button
                  type="button"
                  className="filter-chip"
                  onClick={() => setIsGraphFullscreen(true)}
                  title="Expand graph to fullscreen (Esc to close)"
                >
                  ⛶ Fullscreen
                </button>
              </div>
            </div>

            <div style={{ padding: 18 }}>
              {activeGraphTab === "chain" ? (
                <AttackGraphChart
                  job={job}
                  liveEvents={liveEvents}
                  isRunning={isRunning}
                  onScreenshot={(b64) => setSelectedScreenshot(b64)}
                />
              ) : (
                <AttackPathGraph events={liveEvents} job={job} />
              )}
            </div>
          </section>

          <div className="section-grid">
            <section className="card">
              <h2>Chain priorities</h2>
              {topAttackPaths.length > 0 ? (
                <ul className="bullet-list" style={{ marginTop: 10 }}>
                  {topAttackPaths.map((path, idx) => <li key={idx}>{path}</li>)}
                </ul>
              ) : (
                <p className="meta">No ranked attack paths available yet.</p>
              )}
            </section>

            <section className="card">
              <h2>Graph operator notes</h2>
              <div className="meta-block">
                <b>Attack chain view</b>
                <div>Tracks hosts, services, and high-value findings over time so you can see how impact emerged.</div>
              </div>
              <div className="meta-block" style={{ marginTop: 10 }}>
                <b>Agent pipeline view</b>
                <div>Shows which reasoning stages are active, completed, dynamically spawned, or blocked.</div>
              </div>
              <div className="meta-block" style={{ marginTop: 10 }}>
                <b>Primary target</b>
                <div>{job?.target || "n/a"}</div>
              </div>
            </section>

            <section className="card">
              <h2>Impact snapshot</h2>
              <div className="filter-row">
                <span className="pill high">High {findingsSummary.severities.high}</span>
                <span className="pill medium">Medium {findingsSummary.severities.medium}</span>
                <span className="pill low">Low {findingsSummary.severities.low}</span>
                <span className="pill info">Info {findingsSummary.severities.info}</span>
              </div>
              <p className="meta" style={{ marginTop: 12 }}>
                The graph is optimized to explain exploit paths and proof progression, not just show scanner output.
              </p>
            </section>
          </div>
        </div>
      )}

      {isGraphFullscreen && (
        <div className="graph-fullscreen-overlay" onClick={() => setIsGraphFullscreen(false)}>
          <div className="graph-fullscreen-inner" onClick={(e) => e.stopPropagation()}>
            <div className="graph-fullscreen-header">
              <span className="eyebrow">Attack graph — fullscreen</span>
              <div className="filter-row">
                {[
                  { id: "chain", label: "Attack chain" },
                  { id: "pipeline", label: "Agent pipeline" },
                ].map(({ id, label }) => (
                  <button
                    key={id}
                    type="button"
                    className={`filter-chip ${activeGraphTab === id ? "is-active" : ""}`}
                    onClick={() => setActiveGraphTab(id)}
                  >
                    {label}
                  </button>
                ))}
                <button
                  type="button"
                  className="button-ghost"
                  style={{ padding: "0.42rem 0.8rem", fontSize: "0.8rem", fontWeight: 700 }}
                  onClick={() => setIsGraphFullscreen(false)}
                >
                  ✕ Close
                </button>
              </div>
            </div>
            <div className="graph-fullscreen-body">
              {activeGraphTab === "chain" ? (
                <AttackGraphChart
                  job={job}
                  liveEvents={liveEvents}
                  isRunning={isRunning}
                  onScreenshot={(b64) => setSelectedScreenshot(b64)}
                />
              ) : (
                <AttackPathGraph events={liveEvents} job={job} />
              )}
            </div>
          </div>
        </div>
      )}

      {selectedScreenshot && (
        <div onClick={() => setSelectedScreenshot(null)} style={{ position: "fixed", inset: 0, background: "rgba(1,4,12,0.86)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, cursor: "zoom-out" }}>
          <img src={`data:image/png;base64,${selectedScreenshot}`} alt="Screenshot" style={{ maxWidth: "92vw", maxHeight: "92vh", borderRadius: 18 }} onClick={(e) => e.stopPropagation()} />
          <button type="button" className="button-ghost" style={{ position: "absolute", top: 20, right: 20 }} onClick={() => setSelectedScreenshot(null)}>Close</button>
        </div>
      )}
    </div>
  );
}
