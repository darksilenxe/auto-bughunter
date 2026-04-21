import { useState } from "react";
import { useScan } from "../context/ScanContext";
import AttackGraphChart from "../components/AttackGraph";
import AttackPathGraph from "../components/AttackPathGraph";

export default function AttackGraph() {
  const { job, loading, liveEvents } = useScan();
  const [activeGraphTab, setActiveGraphTab] = useState("chain");
  const [selectedScreenshot, setSelectedScreenshot] = useState(null);

  const isRunning = job?.status === "running" || loading;

  return (
    <div className="page" style={{ maxWidth: "none" }}>
      <header>
        <h1>⛓ Attack Graph</h1>
        <p>Live attack chain and agent pipeline visualisation</p>
      </header>

      {!(loading || job) && (
        <section className="card">
          <p className="meta">No scan is currently running or loaded. Start a scan from the <a href="/">Dashboard</a> to see the graph.</p>
        </section>
      )}

      {(loading || job) && (
        <section className="card" style={{ padding: "0", overflow: "hidden" }}>
          {/* Tab bar */}
          <div style={{
            display: "flex",
            background: "rgba(0,0,0,0.55)",
            borderBottom: "1px solid rgba(124,58,237,0.25)",
          }}>
            {[
              { id: "chain",    label: "⛓ Attack Chain" },
              { id: "pipeline", label: "⚡ Agent Pipeline" },
            ].map(({ id, label }) => {
              const active = activeGraphTab === id;
              return (
                <button
                  key={id}
                  onClick={() => setActiveGraphTab(id)}
                  style={{
                    background: "none",
                    border: "none",
                    borderBottom: active ? "2px solid #a78bfa" : "2px solid transparent",
                    color: active ? "#c4b5fd" : "rgba(255,255,255,0.4)",
                    fontWeight: active ? 700 : 400,
                    fontSize: "0.8rem",
                    padding: "8px 18px",
                    cursor: "pointer",
                    letterSpacing: "0.03em",
                    transition: "color 0.15s, border-color 0.15s",
                  }}
                >
                  {label}
                </button>
              );
            })}
          </div>

          {activeGraphTab === "chain" && (
            <AttackGraphChart
              job={job}
              liveEvents={liveEvents}
              isRunning={isRunning}
              onScreenshot={(b64) => setSelectedScreenshot(b64)}
            />
          )}
          {activeGraphTab === "pipeline" && (
            <div style={{ padding: "12px" }}>
              <AttackPathGraph events={liveEvents} job={job} />
            </div>
          )}
        </section>
      )}

      {/* Screenshot lightbox */}
      {selectedScreenshot && (
        <div
          onClick={() => setSelectedScreenshot(null)}
          style={{
            position: "fixed", inset: 0, background: "rgba(0,0,0,0.88)",
            display: "flex", alignItems: "center", justifyContent: "center",
            zIndex: 1000, cursor: "zoom-out",
          }}
        >
          <img src={`data:image/png;base64,${selectedScreenshot}`} alt="Screenshot"
            style={{ maxWidth: "90vw", maxHeight: "90vh", borderRadius: "8px" }}
            onClick={(e) => e.stopPropagation()} />
          <button onClick={() => setSelectedScreenshot(null)}
            style={{ position: "absolute", top: "16px", right: "24px", background: "none", border: "none", color: "#fff", fontSize: "2rem", cursor: "pointer" }}>
            ×
          </button>
        </div>
      )}
    </div>
  );
}
