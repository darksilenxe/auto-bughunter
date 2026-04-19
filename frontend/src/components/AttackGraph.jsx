/**
 * AttackGraph — NodeZero-style horizontal timeline attack graph.
 *
 * Visualises the attack chain from a completed (or in-progress) scan:
 *   scanner → hosts → services → vulnerabilities → credentials / compromises
 *
 * Nodes are positioned on a horizontal timeline (x = elapsed time from scan
 * start) and on a vertical tier (y = node type).  Edges are cubic bezier
 * curves.  Clicking a node opens a detail panel below the graph.
 *
 * Props
 * ─────
 *   job        {object}  – ScanJob object (required)
 *   liveEvents {array}   – SSE events array; used to timestamp findings in
 *                          real time (optional, falls back to estimation)
 */
import { useMemo, useState } from "react";

// ── SVG geometry constants ────────────────────────────────────────────────

const R      = 26;         // node radius
const SVG_W  = 1100;       // viewBox width
const SVG_H  = 450;        // viewBox height
const TL_Y   = SVG_H - 26; // timeline y
const PAD_L  = 85;         // left padding (origin node)

/** Vertical step between successive collision-avoidance attempts (px). */
const COLLISION_STEP = 55;
/** How many radii of clearance are required before two same-tier nodes are
 *  considered non-overlapping.  Slightly >2 to add breathing room. */
const COLLISION_RADIUS_MULTIPLIER = 2.4;
/** Maximum label character width for the first and second display lines. */
const LABEL_FIRST_LINE_MAX  = 20;
const LABEL_SECOND_LINE_MAX = 40;
const PAD_R  = 65;         // right padding

/** Base vertical position for each node type. */
const TIER_Y = {
  host:       88,
  service:    168,
  scanner:    230,
  finding:    300,
  credential: 368,
  compromise: 230,
};

// ── Visual styles per node type ───────────────────────────────────────────

const STYLE = {
  scanner:    { fill: "#3b0a0a", stroke: "#f43f5e", text: "#fecdd3" },
  host:       { fill: "#172554", stroke: "#60a5fa", text: "#bfdbfe" },
  service:    { fill: "#052e16", stroke: "#4ade80", text: "#bbf7d0" },
  credential: { fill: "#1e1b4b", stroke: "#a78bfa", text: "#ddd6fe" },
  compromise: { fill: "#3b0808", stroke: "#f43f5e", text: "#fecdd3" },
  finding_high:   { fill: "#3b0808", stroke: "#ef4444", text: "#fca5a5" },
  finding_medium: { fill: "#431407", stroke: "#f97316", text: "#fdba74" },
  finding_low:    { fill: "#3f2a01", stroke: "#fbbf24", text: "#fde68a" },
  finding_info:   { fill: "#1f2937", stroke: "#4b5563", text: "#9ca3af" },
};

function nodeStyle(node) {
  if (node.type === "finding") {
    return STYLE[`finding_${node.severity}`] || STYLE.finding_info;
  }
  return STYLE[node.type] || STYLE.finding_info;
}

/** Unicode icon for each node type. */
const ICON = {
  scanner:    "◎",
  host:       "▦",
  service:    "◈",
  finding:    "⚠",
  credential: "⚿",
  compromise: "⊗",
};

// ── Helpers ───────────────────────────────────────────────────────────────

/** Cubic bezier path with vertical control arms. */
function bezier(x1, y1, x2, y2) {
  const cx = (x1 + x2) / 2;
  return `M${x1} ${y1} C${cx} ${y1},${cx} ${y2},${x2} ${y2}`;
}

/** Format elapsed milliseconds as mm:ss. */
function fmtMs(ms) {
  const s = Math.floor(ms / 1000);
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

/** Trim a URL/string to a displayable label. */
function shortLabel(str, max = 24) {
  if (!str) return "";
  const s = str.replace(/^https?:\/\//, "");
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

// ── Graph data builder ────────────────────────────────────────────────────

/**
 * Build nodes + edges from a ScanJob and optional live event stream.
 * Returns { nodes, edges, scanStart, scanEnd }.
 */
function buildGraph(job, liveEvents) {
  const scanStart = new Date(job.startedAt).getTime();
  const scanEnd   = job.completedAt
    ? new Date(job.completedAt).getTime()
    : Date.now();
  const totalMs = Math.max(scanEnd - scanStart, 1000);

  // Index finding timestamps from SSE stream (more accurate than estimation).
  const findingTs = {};
  for (const e of liveEvents || []) {
    if (e.type === "finding" && e.findingTitle && e.timestamp) {
      findingTs[e.findingTitle] = new Date(e.timestamp).getTime();
    }
  }

  const nodeMap = new Map();
  const edges   = [];

  function add(node) {
    if (!nodeMap.has(node.id)) nodeMap.set(node.id, node);
  }

  // ── 1. Scanner / origin ────────────────────────────────────────────────
  let targetHost = job.target;
  try { targetHost = new URL(job.target).hostname; } catch { /* keep raw */ }
  add({
    id:       "__scanner__",
    type:     "scanner",
    label:    "Auto BugHunter",
    sublabel: targetHost,
    ts:       scanStart,
    finding:  null,
  });

  // ── 2. Discovered assets ───────────────────────────────────────────────
  for (const asset of job.assets || []) {
    const t  = new Date(asset.discoveredAt).getTime();
    const at = (asset.assetType || "").toLowerCase();
    let type;
    if (["host", "subdomain", "domain"].includes(at))                  type = "host";
    else if (["endpoint", "url", "port", "service", "path"].includes(at)) type = "service";
    else continue;

    add({
      id:       asset.assetKey,
      type,
      label:    type === "host" ? "Found Host" : "Found Service",
      sublabel: shortLabel(asset.assetKey),
      ts:       Math.max(scanStart, Math.min(t, scanEnd)),
      finding:  null,
    });
  }

  // ── 3. Findings ────────────────────────────────────────────────────────
  const allFindings = job.findings || [];
  for (const [i, f] of allFindings.entries()) {
    const id = f.id || `__f${i}__`;
    // Spread findings evenly across the second half of the scan timeline
    // when no live timestamp is available.
    const estimated = scanStart + totalMs * 0.35
      + (i / Math.max(allFindings.length, 1)) * totalMs * 0.6;
    const t = findingTs[f.title] || estimated;

    const tl = (f.title    || "").toLowerCase();
    const cl = (f.category || "").toLowerCase();

    let type = "finding";
    if (
      (f.severity === "high" && f.exploitability?.reachable) ||
      tl.includes("rce") || tl.includes("remote code") ||
      tl.includes("takeover") || tl.includes("bypass") ||
      tl.includes("injection")
    ) {
      type = "compromise";
    } else if (
      cl.includes("exposure") ||
      tl.includes("credential") || tl.includes("password") ||
      tl.includes("token")      || tl.includes("secret")   ||
      tl.includes("api key")
    ) {
      type = "credential";
    }

    add({
      id,
      type,
      severity: f.severity || "info",
      label:    f.title,
      sublabel: shortLabel(f.affectedUrl || ""),
      ts:       Math.max(scanStart, Math.min(t, scanEnd)),
      finding:  f,
    });
  }

  // ── 4. Edges from explicit asset links ────────────────────────────────
  for (const link of job.assetLinks || []) {
    if (nodeMap.has(link.fromKey) && nodeMap.has(link.toKey)) {
      edges.push({ from: link.fromKey, to: link.toKey });
    }
  }

  const hosts    = [...nodeMap.values()].filter(n => n.type === "host")
    .sort((a, b) => a.ts - b.ts);
  const services = [...nodeMap.values()].filter(n => n.type === "service");

  // ── 5. Scanner → earliest host (or directly to findings) ──────────────
  if (hosts.length > 0) {
    edges.push({ from: "__scanner__", to: hosts[0].id });
  }

  // ── 6. Host → service (URL substring match) ───────────────────────────
  for (const svc of services) {
    const h = hosts.find(h => svc.id.includes(h.id));
    if (h && !edges.some(e => e.from === h.id && e.to === svc.id)) {
      edges.push({ from: h.id, to: svc.id });
    }
  }

  // ── 7. Service / host / scanner → finding via affectedUrl ─────────────
  const findingNodes = [...nodeMap.values()].filter(n =>
    ["finding", "credential", "compromise"].includes(n.type)
  );
  for (const fn of findingNodes) {
    if (edges.some(e => e.to === fn.id)) continue; // already wired

    const au = fn.finding?.affectedUrl;
    if (!au) {
      const anchor = hosts[0]?.id || "__scanner__";
      edges.push({ from: anchor, to: fn.id });
      continue;
    }
    const svcMatch  = services.find(s => au.startsWith(s.id) || s.id.startsWith(au.split("?")[0]));
    const hostMatch = hosts.find(h => au.includes(h.id));
    const anchor    = svcMatch?.id || hostMatch?.id || hosts[0]?.id || "__scanner__";
    edges.push({ from: anchor, to: fn.id });
  }

  return { nodes: [...nodeMap.values()], edges, scanStart, scanEnd };
}

// ── Layout ────────────────────────────────────────────────────────────────

/**
 * Assign (lx, ly) canvas coordinates to each node.
 * x = proportional to elapsed time, y = tier with overlap avoidance.
 */
function computeLayout(nodes, scanStart, scanEnd) {
  const totalMs = Math.max(scanEnd - scanStart, 1);
  const usableW = SVG_W - PAD_L - PAD_R;
  const placed  = [];
  const sorted  = [...nodes].sort((a, b) => a.ts - b.ts);

  return sorted.map(node => {
    const elapsed = node.ts - scanStart;
    const rawX    = PAD_L + (elapsed / totalMs) * usableW;
    const baseY   = TIER_Y[node.type] || TIER_Y.finding;

    // Try vertical offsets to avoid collision with previously placed nodes.
    // Offsets alternate above/below the tier baseline in increasing magnitude.
    const offsets = [0, COLLISION_STEP, -COLLISION_STEP,
                     COLLISION_STEP * 2, -COLLISION_STEP * 2, COLLISION_STEP * 3];
    let y = baseY;
    for (const off of offsets) {
      const ty = baseY + off;
      const blocked = placed.some(
        p => p.type === node.type
          && Math.abs(p.lx - rawX) < COLLISION_RADIUS_MULTIPLIER * R
          && Math.abs(p.ly - ty)  < COLLISION_RADIUS_MULTIPLIER * R
      );
      if (!blocked) { y = ty; break; }
    }

    const lx = Math.min(Math.max(rawX, PAD_L), SVG_W - PAD_R);
    placed.push({ type: node.type, lx, ly: y });
    return { ...node, lx, ly: y };
  });
}

// ── Main component ────────────────────────────────────────────────────────

const SEV_LABEL = { high: "HIGH", medium: "MED", low: "LOW", info: "INFO" };
const SEV_COLOR = { high: "#ef4444", medium: "#f97316", low: "#fbbf24", info: "#6b7280" };

export default function AttackGraph({ job, liveEvents = [] }) {
  const [selected, setSelected] = useState(null);

  // Build and lay out the graph every time job/events change.
  const laid = useMemo(() => {
    if (!job) return [];
    const { nodes, edges, scanStart, scanEnd } = buildGraph(job, liveEvents);
    const laidNodes = computeLayout(nodes, scanStart, scanEnd);
    return { nodes: laidNodes, edges, scanStart, scanEnd };
  }, [job, liveEvents]);

  if (!job) return null;

  const { nodes, edges, scanStart, scanEnd } = laid;
  if (!nodes || nodes.length === 0) return null;

  // Build a lookup map for edge rendering.
  const byId = Object.fromEntries(nodes.map(n => [n.id, n]));

  // Stats from job findings.
  const sev = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of job.findings || []) sev[f.severity] = (sev[f.severity] || 0) + 1;
  const hostCount    = (job.assets || []).filter(a => ["host","subdomain","domain"].includes((a.assetType||"").toLowerCase())).length;
  const serviceCount = (job.assets || []).filter(a => ["endpoint","url","port","service","path"].includes((a.assetType||"").toLowerCase())).length;

  // Timeline ticks (6 evenly spaced).
  const TICK_COUNT = 6;
  const ticks = Array.from({ length: TICK_COUNT + 1 }, (_, i) => ({
    x:   PAD_L + ((SVG_W - PAD_L - PAD_R) * i) / TICK_COUNT,
    ms:  ((scanEnd - scanStart) * i) / TICK_COUNT,
  }));

  const selectedNode = selected ? byId[selected] : null;

  return (
    <div style={{ width: "100%" }}>
      {/* ── Stats row ─────────────────────────────────────────────────── */}
      <div style={{
        display: "flex", gap: "10px", flexWrap: "wrap",
        marginBottom: "10px", fontSize: "0.8rem",
      }}>
        {[
          { label: "High",    count: sev.high,    color: SEV_COLOR.high },
          { label: "Medium",  count: sev.medium,  color: SEV_COLOR.medium },
          { label: "Low",     count: sev.low,     color: SEV_COLOR.low },
          { label: "Info",    count: sev.info,    color: SEV_COLOR.info },
          { label: "Hosts",   count: hostCount,    color: "#60a5fa" },
          { label: "Services",count: serviceCount, color: "#4ade80" },
        ].map(({ label, count, color }) => (
          <span key={label} style={{
            background: "rgba(0,0,0,0.55)",
            border: `1px solid ${color}44`,
            color: "#fff",
            borderRadius: "999px",
            padding: "2px 10px",
            display: "flex", alignItems: "center", gap: "6px",
          }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} />
            <strong style={{ color }}>{count}</strong> {label}
          </span>
        ))}
      </div>

      {/* ── Graph SVG ─────────────────────────────────────────────────── */}
      <div style={{ width: "100%", overflowX: "auto" }}>
        <svg
          viewBox={`0 0 ${SVG_W} ${SVG_H}`}
          width="100%"
          style={{
            background: "rgba(0,0,0,0.5)",
            borderRadius: "12px",
            minWidth: "680px",
            border: "1px solid rgba(255,255,255,0.08)",
          }}
        >
          <defs>
            <marker id="ag-arrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
              <polygon points="0 0,8 3,0 6" fill="rgba(255,255,255,0.25)" />
            </marker>
            {/* Glow filter for selected node */}
            <filter id="ag-glow">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            {/* Subtle pulse filter for compromise nodes */}
            <filter id="ag-danger">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>

          {/* ── Timeline axis ─────────────────────────────────────────── */}
          <line
            x1={PAD_L} y1={TL_Y}
            x2={SVG_W - PAD_R} y2={TL_Y}
            stroke="rgba(255,255,255,0.15)" strokeWidth="1"
          />
          {ticks.map((tk, i) => (
            <g key={i}>
              <line
                x1={tk.x} y1={TL_Y - 5}
                x2={tk.x} y2={TL_Y + 5}
                stroke="rgba(255,255,255,0.2)" strokeWidth="1"
              />
              <text
                x={tk.x} y={TL_Y + 16}
                textAnchor="middle" fontSize="9"
                fill="rgba(255,255,255,0.4)"
                fontFamily="monospace"
              >
                {fmtMs(tk.ms)}
              </text>
            </g>
          ))}

          {/* ── Edges ─────────────────────────────────────────────────── */}
          {edges.map((e, i) => {
            const a = byId[e.from], b = byId[e.to];
            if (!a || !b) return null;
            const isToCompromise = b.type === "compromise";
            return (
              <path
                key={i}
                d={bezier(a.lx, a.ly, b.lx, b.ly)}
                stroke={isToCompromise ? "rgba(244,63,94,0.45)" : "rgba(255,255,255,0.18)"}
                strokeWidth={isToCompromise ? "1.8" : "1.4"}
                strokeDasharray={isToCompromise ? "5 3" : undefined}
                fill="none"
                markerEnd="url(#ag-arrow)"
              />
            );
          })}

          {/* ── Nodes ─────────────────────────────────────────────────── */}
          {nodes.map(node => {
            const st      = nodeStyle(node);
            const isSelected  = selected === node.id;
            const isCompromise = node.type === "compromise";
            const isHighFinding = node.type === "finding" && node.severity === "high";
            const showProof = isHighFinding || isCompromise;
            const labelLines  = node.label.length > LABEL_FIRST_LINE_MAX
              ? [node.label.slice(0, LABEL_FIRST_LINE_MAX), node.label.slice(LABEL_FIRST_LINE_MAX, LABEL_SECOND_LINE_MAX)]
              : [node.label];

            return (
              <g
                key={node.id}
                transform={`translate(${node.lx},${node.ly})`}
                onClick={() => setSelected(selected === node.id ? null : node.id)}
                style={{ cursor: "pointer" }}
              >
                {/* Selection / danger glow ring */}
                {(isSelected || isCompromise) && (
                  <circle
                    r={R + 10}
                    fill="none"
                    stroke={isCompromise ? "#f43f5e" : "#fff"}
                    strokeWidth={isSelected ? "2" : "1"}
                    opacity={isSelected ? "0.7" : "0.3"}
                    filter="url(#ag-glow)"
                  >
                    {isSelected && (
                      <animate attributeName="opacity" values="0.7;0.3;0.7" dur="1.6s" repeatCount="indefinite" />
                    )}
                  </circle>
                )}

                {/* Main circle */}
                <circle
                  r={R}
                  fill={st.fill}
                  stroke={isSelected ? "#fff" : st.stroke}
                  strokeWidth={isSelected ? "2.5" : "2"}
                  filter={isCompromise ? "url(#ag-danger)" : undefined}
                />

                {/* Type icon */}
                <text
                  y="1" textAnchor="middle" dominantBaseline="middle"
                  fontSize="13" fill={st.text}
                  style={{ userSelect: "none", pointerEvents: "none" }}
                >
                  {ICON[node.type] || "·"}
                </text>

                {/* Severity dot (findings only) */}
                {node.finding && (
                  <circle
                    cx={R - 6} cy={-(R - 6)}
                    r="5"
                    fill={SEV_COLOR[node.severity] || "#6b7280"}
                    stroke="#000" strokeWidth="1"
                  />
                )}

                {/* PROOF / COMPROMISE badge */}
                {showProof && (
                  <g transform={`translate(0,${R + 10})`}>
                    <rect
                      x={isCompromise ? -38 : -22}
                      y="0" rx="3"
                      width={isCompromise ? 76 : 44}
                      height="14"
                      fill={isCompromise ? "#7f1d1d" : "#450a0a"}
                      stroke={isCompromise ? "#f43f5e" : "#ef4444"}
                      strokeWidth="1"
                    />
                    <text
                      textAnchor="middle" y="10"
                      fontSize="7" fill="#fff"
                      fontFamily="monospace" fontWeight="bold"
                      style={{ userSelect: "none", pointerEvents: "none" }}
                    >
                      {isCompromise ? "HOST COMPROMISE" : "PROOF"}
                    </text>
                  </g>
                )}

                {/* Node label (type) */}
                <text
                  y={-(R + 10)}
                  textAnchor="middle"
                  fontSize="8"
                  fill="rgba(255,255,255,0.55)"
                  fontFamily="monospace"
                  style={{ userSelect: "none", pointerEvents: "none" }}
                >
                  {node.type === "finding" ? `${SEV_LABEL[node.severity] || "INFO"} finding` : node.type}
                </text>

                {/* Node label lines */}
                {labelLines.map((line, li) => (
                  <text
                    key={li}
                    y={-(R + 22) - (labelLines.length - 1 - li) * 11}
                    textAnchor="middle"
                    fontSize="9"
                    fontWeight="600"
                    fill={isSelected ? "#fff" : "rgba(255,255,255,0.85)"}
                    fontFamily="monospace"
                    style={{ userSelect: "none", pointerEvents: "none" }}
                  >
                    {line}
                  </text>
                ))}

                {/* Sublabel (URL / hostname) */}
                {node.sublabel && (
                  <text
                    y={-(R + (labelLines.length > 1 ? 46 : 34))}
                    textAnchor="middle"
                    fontSize="7.5"
                    fill="rgba(255,255,255,0.4)"
                    fontFamily="monospace"
                    style={{ userSelect: "none", pointerEvents: "none" }}
                  >
                    {node.sublabel}
                  </text>
                )}

                {/* Vertical timeline drop-line */}
                <line
                  x1="0" y1={R + (showProof ? 24 : 2)}
                  x2="0" y2={TL_Y - node.ly}
                  stroke="rgba(255,255,255,0.07)"
                  strokeWidth="1"
                  strokeDasharray="3 4"
                />
              </g>
            );
          })}
        </svg>
      </div>

      {/* ── Legend ────────────────────────────────────────────────────── */}
      <div style={{
        display: "flex", gap: "14px", flexWrap: "wrap",
        padding: "6px 2px", marginTop: "6px", fontSize: "0.72rem",
        color: "rgba(255,255,255,0.55)",
      }}>
        {Object.entries(STYLE)
          .filter(([k]) => !k.startsWith("finding_"))
          .map(([type, s]) => (
            <span key={type} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
              <span style={{
                display: "inline-block", width: 10, height: 10, borderRadius: "50%",
                background: s.fill, border: `2px solid ${s.stroke}`,
              }} />
              {type}
            </span>
          ))}
        <span style={{ display: "flex", alignItems: "center", gap: "5px" }}>
          <span style={{ display: "inline-block", width: 10, height: 10, borderRadius: "50%", background: STYLE.finding_high.fill, border: `2px solid ${STYLE.finding_high.stroke}` }} />
          finding (high)
        </span>
      </div>

      {/* ── Detail panel ──────────────────────────────────────────────── */}
      {selectedNode && (
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "1rem",
          marginTop: "1rem",
          background: "rgba(0,0,0,0.45)",
          border: "1px solid rgba(255,255,255,0.1)",
          borderRadius: "10px",
          padding: "1rem",
          fontSize: "0.82rem",
          color: "rgba(255,255,255,0.85)",
        }}>
          {/* Left: node metadata */}
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "0.5rem" }}>
              <span style={{
                fontSize: "1.4rem",
                color: nodeStyle(selectedNode).stroke,
              }}>
                {ICON[selectedNode.type]}
              </span>
              <span style={{ fontWeight: 700, fontSize: "0.95rem" }}>
                {selectedNode.label}
              </span>
            </div>
            {selectedNode.sublabel && (
              <p style={{ margin: "0 0 0.4rem", color: "rgba(255,255,255,0.5)", fontFamily: "monospace", fontSize: "0.78rem" }}>
                {selectedNode.sublabel}
              </p>
            )}
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
              <tbody>
                <tr>
                  <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>Type</td>
                  <td style={{ color: nodeStyle(selectedNode).stroke, fontWeight: 600 }}>{selectedNode.type}</td>
                </tr>
                {selectedNode.finding && (
                  <>
                    <tr>
                      <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>Severity</td>
                      <td style={{ color: SEV_COLOR[selectedNode.severity], fontWeight: 700 }}>
                        {(selectedNode.severity || "").toUpperCase()}
                      </td>
                    </tr>
                    {selectedNode.finding.cvssScore > 0 && (
                      <tr>
                        <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>CVSS</td>
                        <td>{selectedNode.finding.cvssScore.toFixed(1)}</td>
                      </tr>
                    )}
                    {selectedNode.finding.cwe && (
                      <tr>
                        <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>CWE</td>
                        <td style={{ fontFamily: "monospace" }}>{selectedNode.finding.cwe}</td>
                      </tr>
                    )}
                    {selectedNode.finding.owaspCategory && (
                      <tr>
                        <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>OWASP</td>
                        <td>{selectedNode.finding.owaspCategory}</td>
                      </tr>
                    )}
                    {selectedNode.finding.affectedUrl && (
                      <tr>
                        <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>URL</td>
                        <td style={{ wordBreak: "break-all", fontFamily: "monospace", fontSize: "0.73rem" }}>
                          {selectedNode.finding.affectedUrl}
                        </td>
                      </tr>
                    )}
                    <tr>
                      <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>T+</td>
                      <td style={{ fontFamily: "monospace" }}>{fmtMs(selectedNode.ts - (laid.scanStart || 0))}</td>
                    </tr>
                  </>
                )}
              </tbody>
            </table>
          </div>

          {/* Right: finding details */}
          <div>
            {selectedNode.finding ? (
              <>
                {selectedNode.finding.description && (
                  <div style={{ marginBottom: "0.6rem" }}>
                    <div style={{ color: "rgba(255,255,255,0.45)", fontSize: "0.72rem", marginBottom: "3px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Description</div>
                    <p style={{ margin: 0, lineHeight: 1.5, fontSize: "0.8rem" }}>{selectedNode.finding.description}</p>
                  </div>
                )}
                {selectedNode.finding.recommendation && (
                  <div style={{ marginBottom: "0.6rem" }}>
                    <div style={{ color: "#4ade80", fontSize: "0.72rem", marginBottom: "3px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Mitigation</div>
                    <p style={{ margin: 0, lineHeight: 1.5, fontSize: "0.8rem" }}>{selectedNode.finding.recommendation}</p>
                  </div>
                )}
                {selectedNode.finding.evidence && (
                  <div>
                    <div style={{ color: "rgba(255,255,255,0.45)", fontSize: "0.72rem", marginBottom: "3px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Evidence</div>
                    <pre style={{
                      margin: 0, padding: "6px 8px",
                      background: "#0d1117", borderRadius: "6px",
                      fontSize: "0.72rem", overflowX: "auto",
                      maxHeight: "100px", lineHeight: 1.4,
                      border: "1px solid rgba(255,255,255,0.07)",
                      color: "#79c0ff",
                    }}>{selectedNode.finding.evidence}</pre>
                  </div>
                )}
              </>
            ) : (
              <div style={{ color: "rgba(255,255,255,0.4)", paddingTop: "1rem" }}>
                {selectedNode.type === "scanner" && (
                  <p>Scan target: <strong style={{ color: "#fff" }}>{job.target}</strong></p>
                )}
                {(selectedNode.type === "host" || selectedNode.type === "service") && (
                  <p style={{ marginTop: 0 }}>Asset discovered at <strong style={{ color: "#fff", fontFamily: "monospace" }}>{fmtMs(selectedNode.ts - (laid.scanStart || 0))}</strong> into the scan.</p>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
