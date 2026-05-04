/**
 * ScanNetworkGraph — SVG-based network graph that visualises HTTP traffic
 * captured by the intercepting proxy during a scan.  Nodes are unique hosts;
 * edges are coloured by the dominant response-status class of traffic flowing
 * to that host.  Auto-refreshes every 8 s while a scan is running.
 */

import { useEffect, useState } from "react";
import { API_BASE, API_KEY, WORKSPACE_ID } from "../context/ScanContext";

const authHeaders = () => ({
  "X-API-Key": API_KEY,
  "X-Workspace-ID": WORKSPACE_ID,
});

function getHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function statusColor(status) {
  const s = Number(status || 0);
  if (s >= 500) return "#f87171";
  if (s >= 400) return "#fb923c";
  if (s >= 300) return "#fbbf24";
  if (s >= 200) return "#4ade80";
  return "rgba(255,255,255,0.3)";
}

function statusLabel(status) {
  const s = Number(status || 0);
  if (s >= 500) return "5xx";
  if (s >= 400) return "4xx";
  if (s >= 300) return "3xx";
  if (s >= 200) return "2xx";
  return "—";
}

const MAX_GRAPH_HOSTS = 8;
const SVG_W = 800;
const SCANNER_X = 80;
const HOST_X = 580;

export default function ScanNetworkGraph({ job = null, expanded = false }) {
  const [requests, setRequests] = useState([]);
  const [initialLoading, setInitialLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function fetchRequests() {
      try {
        const res = await fetch(`${API_BASE}/api/proxy/requests`, { headers: authHeaders() });
        if (cancelled) return;
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          setError(data.error || "Failed to load network traffic.");
          return;
        }
        const data = await res.json();
        if (!cancelled) {
          setRequests(Array.isArray(data) ? data : []);
          setError("");
        }
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load network traffic.");
      } finally {
        if (!cancelled) setInitialLoading(false);
      }
    }

    fetchRequests();

    let pollId = null;
    if (job?.status === "running") {
      pollId = setInterval(fetchRequests, 8000);
    }

    return () => {
      cancelled = true;
      if (pollId !== null) clearInterval(pollId);
    };
  }, [job?.status]);

  // Build host → aggregated request stats
  const hostMap = {};
  for (const r of requests) {
    const host = getHost(r.url);
    if (!hostMap[host]) hostMap[host] = { count: 0, statusCounts: {} };
    hostMap[host].count += 1;
    const sl = statusLabel(r.responseStatus);
    hostMap[host].statusCounts[sl] = (hostMap[host].statusCounts[sl] || 0) + 1;
  }

  // Sort by request count descending; cap at MAX_GRAPH_HOSTS for the SVG
  const allHosts = Object.keys(hostMap).sort((a, b) => hostMap[b].count - hostMap[a].count);
  const graphHosts = allHosts.slice(0, MAX_GRAPH_HOSTS);
  const overflow = allHosts.length - graphHosts.length;

  // Identify the job's primary target host for highlighting
  let targetHost = null;
  if (job?.target) {
    try {
      targetHost = new URL(job.target).hostname;
    } catch {
      targetHost = job.target;
    }
  }

  const svgH = Math.max(200, graphHosts.length * 68 + 60);
  const scannerY = svgH / 2;

  function hostY(idx) {
    const totalH = graphHosts.length * 68;
    const startY = svgH / 2 - totalH / 2 + 34;
    return startY + idx * 68;
  }

  const recent = [...requests].reverse().slice(0, 12);

  if (initialLoading) {
    return <div style={expanded ? { ...emptyStyle, flex: 1 } : emptyStyle}>Loading proxy traffic…</div>;
  }

  if (requests.length === 0) {
    return (
      <div style={expanded ? { ...emptyStyle, flex: 1 } : emptyStyle}>
        {error
          ? error
          : "No proxy traffic captured. Configure your browser or scanner to route through the intercepting proxy."}
      </div>
    );
  }

  return (
    <div style={expanded ? { display: "flex", flexDirection: "column", flex: 1, minHeight: 0 } : undefined}>
      {error && (
        <p style={{ color: "#f87171", fontSize: "0.8rem", marginBottom: 8 }}>{error}</p>
      )}

      <svg
        viewBox={`0 0 ${SVG_W} ${svgH}`}
        width="100%"
        style={{
          background: "rgba(0,0,0,0.35)",
          borderRadius: "10px",
          display: "block",
          ...(expanded ? { flex: 1, minHeight: 320 } : {}),
        }}
      >
        <defs>
          <marker id="ng-arrow" markerWidth="8" markerHeight="6" refX="6" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="rgba(255,255,255,0.25)" />
          </marker>
        </defs>

        {/* Scanner node */}
        <circle cx={SCANNER_X} cy={scannerY} r="30" fill="#1e1b4b" stroke="#7c3aed" strokeWidth="2" />
        <text
          x={SCANNER_X}
          y={scannerY - (job?.target ? 5 : 0)}
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize="7.5"
          fontFamily="monospace"
          fill="#c4b5fd"
        >
          Scanner
        </text>
        {job?.target && (
          <text
            x={SCANNER_X}
            y={scannerY + 8}
            textAnchor="middle"
            dominantBaseline="middle"
            fontSize="5.5"
            fontFamily="monospace"
            fill="rgba(196,181,253,0.55)"
          >
            {job.target.length > 16 ? job.target.slice(0, 15) + "…" : job.target}
          </text>
        )}

        {/* Host nodes and edges */}
        {graphHosts.map((host, idx) => {
          const hy = hostY(idx);
          const { count, statusCounts } = hostMap[host];
          const isTarget = targetHost !== null && host === targetHost;

          let domColor = statusColor(0);
          if (statusCounts["5xx"]) domColor = statusColor(500);
          else if (statusCounts["4xx"]) domColor = statusColor(400);
          else if (statusCounts["3xx"]) domColor = statusColor(300);
          else if (statusCounts["2xx"]) domColor = statusColor(200);

          const shortLabel = host.length > 24 ? host.slice(0, 22) + "…" : host;
          const mx = (SCANNER_X + 30 + HOST_X - 38) / 2;
          const my = (scannerY + hy) / 2;

          return (
            <g key={host}>
              <line
                x1={SCANNER_X + 30}
                y1={scannerY}
                x2={HOST_X - 38}
                y2={hy}
                stroke={domColor}
                strokeWidth="1.5"
                strokeOpacity="0.45"
                markerEnd="url(#ng-arrow)"
              />
              <text
                x={mx}
                y={my - 7}
                textAnchor="middle"
                fontSize="6.5"
                fontFamily="monospace"
                fill="rgba(255,255,255,0.45)"
              >
                {count} req{count !== 1 ? "s" : ""}
              </text>
              <rect
                x={HOST_X - 38}
                y={hy - 18}
                width={152}
                height={36}
                rx="6"
                fill={isTarget ? "rgba(124,58,237,0.18)" : "#0f172a"}
                stroke={isTarget ? "#7c3aed" : domColor}
                strokeWidth={isTarget ? "2" : "1.5"}
              />
              <text
                x={HOST_X - 38 + 76}
                y={hy - 4}
                textAnchor="middle"
                fontSize="8"
                fontFamily="monospace"
                fill="#e2e8f0"
              >
                {shortLabel}
              </text>
              <text
                x={HOST_X - 38 + 76}
                y={hy + 8}
                textAnchor="middle"
                fontSize="6.5"
                fontFamily="monospace"
                fill="rgba(226,232,240,0.45)"
              >
                {Object.entries(statusCounts).map(([k, v]) => `${k}:${v}`).join("  ")}
              </text>
            </g>
          );
        })}

        {overflow > 0 && (
          <text
            x={HOST_X + 38}
            y={hostY(graphHosts.length) + 10}
            textAnchor="middle"
            fontSize="7.5"
            fontFamily="monospace"
            fill="rgba(255,255,255,0.35)"
          >
            +{overflow} more host{overflow !== 1 ? "s" : ""} (see table below)
          </text>
        )}
      </svg>

      {/* Legend + summary */}
      <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", padding: "6px 4px", fontSize: "0.72rem" }}>
        {[
          { label: "2xx OK", color: statusColor(200) },
          { label: "3xx redirect", color: statusColor(300) },
          { label: "4xx client err", color: statusColor(400) },
          { label: "5xx server err", color: statusColor(500) },
        ].map(({ label, color }) => (
          <span key={label} style={{ display: "flex", alignItems: "center", gap: "5px", color: "rgba(255,255,255,0.8)" }}>
            <span style={{ display: "inline-block", width: "10px", height: "10px", borderRadius: "50%", background: color }} />
            {label}
          </span>
        ))}
        <span style={{ marginLeft: "auto", color: "rgba(255,255,255,0.4)", alignSelf: "center", fontSize: "0.7rem" }}>
          {requests.length} request{requests.length !== 1 ? "s" : ""} · {allHosts.length} host{allHosts.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Recent requests table */}
      <div style={{ marginTop: 12 }}>
        <div className="table-wrap" style={{ maxHeight: 220 }}>
          <table>
            <thead>
              <tr>
                <th>Method</th>
                <th>Status</th>
                <th>Host</th>
                <th>Path</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((r) => {
                let host = "";
                let path = r.url;
                try {
                  const u = new URL(r.url);
                  host = u.hostname;
                  path = u.pathname + (u.search || "");
                } catch {}
                const color = statusColor(r.responseStatus);
                return (
                  <tr key={r.id}>
                    <td>
                      <span style={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{r.method}</span>
                    </td>
                    <td>
                      <span style={{ color, fontFamily: "monospace", fontSize: "0.75rem" }}>
                        {r.responseStatus || "—"}
                      </span>
                    </td>
                    <td style={{ fontSize: "0.75rem" }}>{host}</td>
                    <td style={{ wordBreak: "break-all", fontSize: "0.75rem" }}>{path}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {job?.status === "running" && (
        <p className="meta" style={{ marginTop: 8, fontSize: "0.72rem" }}>
          Auto-refreshing every 8 s while scan is running.
        </p>
      )}
    </div>
  );
}

const emptyStyle = {
  padding: "32px 16px",
  textAlign: "center",
  color: "rgba(255,255,255,0.35)",
  fontSize: "0.85rem",
  background: "rgba(0,0,0,0.2)",
  borderRadius: "10px",
};
