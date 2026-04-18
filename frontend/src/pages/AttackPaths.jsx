import AttackPathGraph from "../components/AttackPathGraph";
import { useScan } from "../context/ScanContext";

/**
 * AttackPaths — visualises the agent execution graph for the active scan.
 * The underlying SVG component already exists in components/AttackPathGraph
 * but had no route, so live runs could not be inspected. This page wires it
 * to the SSE event stream exposed via ScanContext.
 */
export default function AttackPaths() {
  const { job, liveEvents } = useScan();

  return (
    <div className="page">
      <header>
        <h1>🕸️ Attack Paths</h1>
        <p>Real-time agent pipeline graph. Nodes light up as agents start, complete, or spawn dynamic children.</p>
      </header>

      <section className="card">
        {!job && (
          <p className="meta">No scan in progress. Start one from the Dashboard to see the live attack path.</p>
        )}
        {job && (
          <p className="meta" style={{ marginBottom: "10px" }}>
            Target: <strong>{job.target}</strong> · Status: <strong>{job.status}</strong> · Events: {liveEvents?.length || 0}
          </p>
        )}
        <div style={{ background: "rgba(0,0,0,0.25)", borderRadius: "8px", padding: "10px" }}>
          <AttackPathGraph events={liveEvents || []} />
        </div>
      </section>
    </div>
  );
}
