import { useCallback, useEffect, useRef, useState } from "react";
import { useScan } from "../context/ScanContext";

const EVENT_ACCENT = {
  agent_start:    "#4db8ff",
  agent_complete: "#4dff91",
  info:           "#aaa",
  reasoning_loop: "#fbbf24",
  thinking:       "#c084fc",
  discovery:      "#34d399",
  command:        "#4db8ff",
  command_result: "#ccc",
  finding:        "#f87171",
  error:          "#f87171",
};

const EVENT_ICON = {
  agent_start:    "▶",
  agent_complete: "✓",
  info:           "ℹ",
  reasoning_loop: "⟳",
  thinking:       "◈",
  discovery:      "◎",
  command:        "$",
  command_result: "⇐",
  finding:        "⚑",
  error:          "✗",
};

function formatEvt(evt) {
  return (
    evt.message ||
    evt.command ||
    evt.output ||
    evt.thinking ||
    (evt.discovery?.value ?? "") ||
    JSON.stringify(evt)
  );
}

export default function AgentConsole() {
  const { activeScanID } = useScan();

  // Form state
  const [agentName, setAgentName]       = useState("");
  const [target, setTarget]             = useState("");
  const [instructions, setInstructions] = useState("");
  const [agents, setAgents]             = useState([]);

  // Run state
  const [jobId, setJobId]       = useState(null);
  const [running, setRunning]   = useState(false);
  const [events, setEvents]     = useState([]);
  const [error, setError]       = useState(null);

  const esRef     = useRef(null);
  const bottomRef = useRef(null);

  // Fetch available agents on mount.
  useEffect(() => {
    fetch("/api/agent/dispatch")
      .then((r) => r.ok ? r.json() : null)
      .then((data) => { if (data?.agents) setAgents(data.agents); })
      .catch(() => {});
  }, []);

  // Auto-scroll to bottom.
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events]);

  // Cleanup SSE on unmount.
  useEffect(() => {
    return () => { if (esRef.current) esRef.current.close(); };
  }, []);

  const handleRun = useCallback(async () => {
    setError(null);
    setEvents([]);
    setJobId(null);

    if (!agentName) { setError("Select an agent."); return; }
    if (!target.trim()) { setError("Enter a target URL."); return; }

    setRunning(true);
    try {
      const res = await fetch("/api/agent/dispatch", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ agentName, target: target.trim(), instructions }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      const { jobId: jid } = await res.json();
      setJobId(jid);

      // Open SSE stream.
      const es = new EventSource(`/api/scan/${jid}/events`);
      esRef.current = es;

      es.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data);
          setEvents((prev) => [...prev, { ...evt, _seq: Date.now() + Math.random() }]);
          // Stop listening when terminal.
          if (evt.type === "info" &&
              typeof evt.message === "string" &&
              /completed|failed|cancelled/i.test(evt.message)) {
            es.close();
            setRunning(false);
          }
        } catch {/* ignore */ }
      };
      es.onerror = () => { es.close(); setRunning(false); };
    } catch (e) {
      setError(e.message);
      setRunning(false);
    }
  }, [agentName, target, instructions]);

  const handleStop = useCallback(() => {
    if (esRef.current) { esRef.current.close(); esRef.current = null; }
    setRunning(false);
  }, []);

  return (
    <div style={{ padding: "1.5rem", height: "100%", display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {/* Header */}
      <div>
        <h2 style={{ color: "#e2e8f0", margin: 0, fontSize: "1.1rem", letterSpacing: ".04em" }}>
          ⌘ Agent Console
        </h2>
        <p style={{ color: "#64748b", fontSize: ".82rem", margin: "4px 0 0" }}>
          Dispatch a single agent with custom instructions and stream its output live.
        </p>
      </div>

      {/* Form */}
      <div style={{
        background: "#0f172a", border: "1px solid #1e293b", borderRadius: "8px",
        padding: "1rem", display: "grid", gap: ".75rem",
        gridTemplateColumns: "1fr 1fr",
      }}>
        {/* Agent selector */}
        <div style={{ display: "flex", flexDirection: "column", gap: ".35rem" }}>
          <label style={{ color: "#94a3b8", fontSize: ".78rem", letterSpacing: ".04em" }}>
            AGENT
          </label>
          <select
            value={agentName}
            onChange={(e) => setAgentName(e.target.value)}
            disabled={running}
            style={{
              background: "#1e293b", border: "1px solid #334155", borderRadius: "5px",
              color: "#e2e8f0", padding: ".45rem .6rem", fontSize: ".88rem",
            }}
          >
            <option value="">— select agent —</option>
            {agents.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </div>

        {/* Target */}
        <div style={{ display: "flex", flexDirection: "column", gap: ".35rem" }}>
          <label style={{ color: "#94a3b8", fontSize: ".78rem", letterSpacing: ".04em" }}>
            TARGET URL
          </label>
          <input
            type="text"
            placeholder="https://example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={running}
            style={{
              background: "#1e293b", border: "1px solid #334155", borderRadius: "5px",
              color: "#e2e8f0", padding: ".45rem .6rem", fontSize: ".88rem",
              outline: "none",
            }}
          />
        </div>

        {/* Instructions — full width */}
        <div style={{ gridColumn: "1 / -1", display: "flex", flexDirection: "column", gap: ".35rem" }}>
          <label style={{ color: "#94a3b8", fontSize: ".78rem", letterSpacing: ".04em" }}>
            INSTRUCTIONS <span style={{ color: "#475569" }}>(optional)</span>
          </label>
          <textarea
            placeholder="e.g. Focus on JWT authentication bypass. Check for horizontal privilege escalation on /api/orders."
            value={instructions}
            onChange={(e) => setInstructions(e.target.value)}
            disabled={running}
            rows={3}
            style={{
              background: "#1e293b", border: "1px solid #334155", borderRadius: "5px",
              color: "#e2e8f0", padding: ".45rem .6rem", fontSize: ".88rem",
              resize: "vertical", outline: "none", fontFamily: "inherit",
            }}
          />
        </div>

        {/* Actions */}
        <div style={{ gridColumn: "1 / -1", display: "flex", gap: ".75rem", alignItems: "center" }}>
          <button
            onClick={handleRun}
            disabled={running || !agentName || !target.trim()}
            style={{
              background: running ? "#334155" : "#3b82f6",
              border: "none", borderRadius: "5px", color: "#fff",
              padding: ".5rem 1.2rem", fontWeight: 600, cursor: running ? "default" : "pointer",
              fontSize: ".88rem", letterSpacing: ".03em",
            }}
          >
            {running ? "Running…" : "▶ Run Agent"}
          </button>
          {running && (
            <button
              onClick={handleStop}
              style={{
                background: "transparent", border: "1px solid #ef4444",
                borderRadius: "5px", color: "#ef4444",
                padding: ".45rem 1rem", cursor: "pointer", fontSize: ".88rem",
              }}
            >
              ◼ Stop
            </button>
          )}
          {jobId && (
            <span style={{ color: "#475569", fontSize: ".78rem" }}>
              Job&nbsp;<span style={{ color: "#64748b", fontFamily: "monospace" }}>{jobId}</span>
            </span>
          )}
          {error && (
            <span style={{ color: "#f87171", fontSize: ".82rem" }}>{error}</span>
          )}
        </div>
      </div>

      {/* Event stream */}
      <div style={{
        flex: 1, overflowY: "auto", background: "#0a0f1a",
        border: "1px solid #1e293b", borderRadius: "8px",
        padding: ".75rem", fontFamily: "monospace",
        minHeight: "300px",
      }}>
        {events.length === 0 && !running && (
          <div style={{ color: "#334155", fontSize: ".82rem", padding: ".25rem" }}>
            No events yet. Fill in the form above and click ▶ Run Agent.
          </div>
        )}
        {events.map((evt) => {
          const type    = evt.type || "info";
          const accent  = EVENT_ACCENT[type] || "#94a3b8";
          const icon    = EVENT_ICON[type]   || "·";
          const text    = formatEvt(evt);
          const ts      = evt.timestamp
            ? new Date(evt.timestamp).toLocaleTimeString()
            : "";

          return (
            <div
              key={evt._seq}
              style={{ display: "flex", gap: ".5rem", padding: ".2rem 0", alignItems: "flex-start" }}
            >
              <span style={{ color: "#334155", fontSize: ".7rem", minWidth: "6ch", paddingTop: "1px" }}>
                {ts}
              </span>
              <span style={{ color: accent, minWidth: "1.2rem" }}>{icon}</span>
              <span style={{ color: "#cbd5e1", fontSize: ".82rem", wordBreak: "break-word", flex: 1 }}>
                {type === "finding" && evt.title ? (
                  <>
                    <span style={{ color: "#f87171", fontWeight: 600 }}>{evt.title}</span>
                    {evt.severity && (
                      <span style={{ color: "#94a3b8", marginLeft: ".5rem", fontSize: ".75rem" }}>
                        [{evt.severity}]
                      </span>
                    )}
                    {evt.url && (
                      <div style={{ color: "#64748b", fontSize: ".75rem" }}>{evt.url}</div>
                    )}
                  </>
                ) : (
                  text
                )}
              </span>
            </div>
          );
        })}
        {running && (
          <div style={{ color: "#334155", fontSize: ".82rem", padding: ".25rem 0" }}>
            <span style={{ animation: "pulse 1.5s infinite" }}>●</span>
            &nbsp;Streaming…
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Finding summary */}
      {!running && events.filter((e) => e.type === "finding").length > 0 && (
        <div style={{
          background: "#0f172a", border: "1px solid #1e293b", borderRadius: "8px",
          padding: ".75rem",
        }}>
          <div style={{ color: "#94a3b8", fontSize: ".78rem", marginBottom: ".5rem", letterSpacing: ".04em" }}>
            FINDINGS ({events.filter((e) => e.type === "finding").length})
          </div>
          {events.filter((e) => e.type === "finding").map((evt) => (
            <div key={evt._seq} style={{
              display: "flex", gap: ".75rem", padding: ".3rem 0",
              borderBottom: "1px solid #1e293b", alignItems: "center",
            }}>
              <span style={{
                background: evt.severity === "critical" ? "#7f1d1d"
                  : evt.severity === "high" ? "#7c2d12"
                  : evt.severity === "medium" ? "#713f12"
                  : "#1e293b",
                color: "#f1f5f9", fontSize: ".72rem", padding: ".15rem .45rem",
                borderRadius: "3px", minWidth: "5ch", textAlign: "center",
              }}>
                {evt.severity || "info"}
              </span>
              <span style={{ color: "#e2e8f0", fontSize: ".84rem" }}>
                {evt.title || evt.message}
              </span>
              {evt.url && (
                <span style={{ color: "#475569", fontSize: ".75rem", marginLeft: "auto" }}>
                  {evt.url}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
