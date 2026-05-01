/**
 * AttackGraph — NodeZero-style live attack chain visualization.
 *
 * Renders during AND after a scan:
 *   ┌───────────────────────────────────────────────────────────────┐
 *   │  target: example.com   ● RUNNING  0:05:17  [scanning agent]  │  ← header bar
 *   │  ⚠ 2 High  △ 3 Med  ▿ 1 Low  ▦ 4 Hosts  ◈ 7 Services        │  ← stat pills
 *   ├───────────────────────────────────────────────────────────────┤
 *   │                   [  attack chain SVG  ]                      │  ← graph
 *   ├────────────────────────┬──────────────────────────────────────┤
 *   │  Activity Log          │  Finding Detail                      │  ← detail panes
 *   │  0:02:14 [recon] ...   │  [HIGH] Insecure JWT                 │
 *   └────────────────────────┴──────────────────────────────────────┘
 *
 * Props:
 *   job          {object}   – ScanJob (required; findings empty while running)
 *   liveEvents   {array}    – SSE ScanEvent stream
 *   isRunning    {boolean}  – true while scan is in progress
 *   onScreenshot {fn}       – callback(b64) for screenshot lightbox
 */
import { useEffect, useMemo, useRef, useState } from "react";

// ── SVG geometry ────────────────────────────────────────────────────────────

const R      = 26;
const SVG_W  = 1100;
const SVG_H  = 420;
const TL_Y   = SVG_H - 26;
const PAD_L  = 85;
const PAD_R  = 65;

/** Vertical step between successive collision-avoidance attempts (px). */
const COLLISION_STEP = 55;
/** Clearance multiplier for overlap detection. */
const COLLISION_RADIUS_MULTIPLIER = 2.4;
/** Label line character limits. */
const LABEL_FIRST_LINE_MAX  = 20;
const LABEL_SECOND_LINE_MAX = 40;

/** Base vertical position (y) for each node type tier. */
const TIER_Y = {
  host:       80,
  service:    155,
  scanner:    220,
  finding:    285,
  credential: 350,
  compromise: 220,
};

// ── Visual styles ────────────────────────────────────────────────────────────

const STYLE = {
  scanner:        { fill: "#1e1230", stroke: "#a78bfa", text: "#ddd6fe" },
  host:           { fill: "#172554", stroke: "#60a5fa", text: "#bfdbfe" },
  service:        { fill: "#052e16", stroke: "#4ade80", text: "#bbf7d0" },
  credential:     { fill: "#1e1b4b", stroke: "#818cf8", text: "#c7d2fe" },
  compromise:     { fill: "#3b0a0a", stroke: "#f43f5e", text: "#fecdd3" },
  finding_high:   { fill: "#3b0808", stroke: "#ef4444", text: "#fca5a5" },
  finding_medium: { fill: "#431407", stroke: "#f97316", text: "#fdba74" },
  finding_low:    { fill: "#3f2a01", stroke: "#fbbf24", text: "#fde68a" },
  finding_info:   { fill: "#1f2937", stroke: "#4b5563", text: "#9ca3af" },
};

function nodeStyle(node) {
  if (node.type === "finding") return STYLE[`finding_${node.severity}`] || STYLE.finding_info;
  return STYLE[node.type] || STYLE.finding_info;
}

const ICON = {
  scanner:    "◎",
  host:       "▦",
  service:    "◈",
  finding:    "⚠",
  credential: "⚿",
  compromise: "⊗",
};

const SEV_LABEL = { high: "HIGH", medium: "MED", low: "LOW", info: "INFO" };
const SEV_COLOR = { high: "#ef4444", medium: "#f97316", low: "#fbbf24", info: "#6b7280" };

// ── Helper functions ─────────────────────────────────────────────────────────

function bezier(x1, y1, x2, y2) {
  const cx = (x1 + x2) / 2;
  return `M${x1} ${y1} C${cx} ${y1},${cx} ${y2},${x2} ${y2}`;
}

function fmtMs(ms) {
  const totalS = Math.floor(ms / 1000);
  const h = Math.floor(totalS / 3600);
  const m = Math.floor((totalS % 3600) / 60);
  const s = totalS % 60;
  if (h > 0) {
    return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function shortLabel(str, max = 24) {
  if (!str) return "";
  const s = str.replace(/^https?:\/\//, "");
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

function classifyFinding(title, category, severity, exploitability) {
  const tl = (title    || "").toLowerCase();
  const cl = (category || "").toLowerCase();
  if (
    (severity === "high" && exploitability?.reachable) ||
    tl.includes("rce") || tl.includes("remote code") ||
    tl.includes("takeover") || tl.includes("bypass") ||
    tl.includes("injection")
  ) return "compromise";
  if (
    cl.includes("exposure") ||
    tl.includes("credential") || tl.includes("password") ||
    tl.includes("token")      || tl.includes("secret")   ||
    tl.includes("api key")
  ) return "credential";
  return "finding";
}

function findingGraphID(finding, index) {
  const id = String(finding?.id || "").trim();
  return id || `__f${index}__`;
}

function findingSignature(title = "", affectedUrl = "") {
  return JSON.stringify([
    String(title || "").trim(),
    String(affectedUrl || "").trim(),
  ]);
}

function resolveBackendNodeFinding(node, findings = []) {
  if (!["finding", "credential", "compromise"].includes(String(node?.type || "").toLowerCase())) {
    return null;
  }
  const findingByID = new Map();
  const findingBySignature = new Map();
  const findingByTitle = new Map();

  findings.forEach((finding, index) => {
    findingByID.set(findingGraphID(finding, index), finding);
    findingBySignature.set(findingSignature(finding.title, finding.affectedUrl), finding);
    const title = String(finding.title || "").trim();
    if (!title) return;
    const matches = findingByTitle.get(title) || [];
    matches.push(finding);
    findingByTitle.set(title, matches);
  });

  const titleMatches = findingByTitle.get(String(node.label || "").trim()) || [];
  return (
    findingByID.get(node.id) ||
    findingBySignature.get(findingSignature(node.label, node.sublabel)) ||
    (titleMatches.length === 1 ? titleMatches[0] : null) ||
    { title: String(node.label || "Unknown Finding"), severity: node.severity || "info" }
  );
}

function buildGraphFromBackend(job, scanStart, scanEnd) {
  const data = job?.attackGraph;
  if (!data || !Array.isArray(data.nodes) || data.nodes.length === 0) return null;
  const nodes = data.nodes
    .filter((n) => n?.id)
    .map((n) => ({
      id: n.id,
      type: n.type || "finding",
      severity: n.severity || "info",
      label: n.label || n.id,
      sublabel: n.sublabel || "",
      ts: Math.max(scanStart, Math.min(Number(n.ts) || scanStart, scanEnd)),
      finding: resolveBackendNodeFinding(n, job.findings || []),
    }));
  const nodeSet = new Set(nodes.map((n) => n.id));
  const edges = (data.edges || [])
    .filter((e) => e?.from && e?.to && nodeSet.has(e.from) && nodeSet.has(e.to))
    .map((e) => ({ from: e.from, to: e.to }));
  return { nodes, edges };
}

// ── Graph data builder ────────────────────────────────────────────────────────

function buildGraph(job, liveEvents) {
  const scanStart = new Date(job.startedAt).getTime();
  const scanEnd   = job.completedAt
    ? new Date(job.completedAt).getTime()
    : Date.now();

  const nodeMap = new Map();
  const edges   = [];

  function add(node) {
    if (!nodeMap.has(node.id)) nodeMap.set(node.id, node);
  }

  // Origin / scanner node
  let targetHost = job.target;
  try { targetHost = new URL(job.target).hostname; } catch { /* keep raw */ }
  add({ id: "__scanner__", type: "scanner", label: "Auto BugHunter", sublabel: targetHost, ts: scanStart, finding: null });

  // Index finding events from SSE stream (timestamps + basic metadata)
  const liveFindingMap = {};
  for (const e of liveEvents || []) {
    if (e.type === "finding" && e.findingTitle && e.timestamp) {
      liveFindingMap[e.findingTitle] = {
        ts:        new Date(e.timestamp).getTime(),
        severity:  e.severity  || "info",
        agentName: e.agentName || "",
      };
    }
  }

  const isComplete = !!job.completedAt;

  if (isComplete) {
    const backendGraph = buildGraphFromBackend(job, scanStart, scanEnd);
    if (backendGraph) {
      return { nodes: backendGraph.nodes, edges: backendGraph.edges, scanStart, scanEnd };
    }
    // ── Post-completion: use full job data ────────────────────────────────
    for (const asset of job.assets || []) {
      const at = (asset.assetType || "").toLowerCase();
      let type;
      if (["host", "subdomain", "domain"].includes(at))                      type = "host";
      else if (["endpoint", "url", "port", "service", "path"].includes(at))  type = "service";
      else continue;
      const t = new Date(asset.discoveredAt).getTime();
      add({
        id: asset.assetKey, type,
        label:    type === "host" ? "Found Host" : "Found Service",
        sublabel: shortLabel(asset.assetKey),
        ts:       Math.max(scanStart, Math.min(t, scanEnd)),
        finding:  null,
      });
    }

    const allFindings = job.findings || [];
    for (const [i, f] of allFindings.entries()) {
      const id        = f.id || `__f${i}__`;
      const liveInfo  = liveFindingMap[f.title];
      const estimated = scanStart + (scanEnd - scanStart) * 0.35
        + (i / Math.max(allFindings.length, 1)) * (scanEnd - scanStart) * 0.6;
      const ts   = liveInfo?.ts || estimated;
      const type = classifyFinding(f.title, f.category, f.severity, f.exploitability);
      add({ id, type, severity: f.severity || "info", label: f.title, sublabel: shortLabel(f.affectedUrl || ""), ts: Math.max(scanStart, Math.min(ts, scanEnd)), finding: f });
    }

    // Edges from explicit asset links
    for (const link of job.assetLinks || []) {
      if (nodeMap.has(link.fromKey) && nodeMap.has(link.toKey)) {
        edges.push({ from: link.fromKey, to: link.toKey });
      }
    }

    const hosts    = [...nodeMap.values()].filter(n => n.type === "host").sort((a, b) => a.ts - b.ts);
    const services = [...nodeMap.values()].filter(n => n.type === "service");
    if (hosts.length > 0) edges.push({ from: "__scanner__", to: hosts[0].id });
    for (const svc of services) {
      const h = hosts.find(h => svc.id.includes(h.id));
      if (h && !edges.some(e => e.from === h.id && e.to === svc.id)) {
        edges.push({ from: h.id, to: svc.id });
      }
    }
    const findingNodes = [...nodeMap.values()].filter(n => ["finding", "credential", "compromise"].includes(n.type));
    for (const fn of findingNodes) {
      if (edges.some(e => e.to === fn.id)) continue;
      const au       = fn.finding?.affectedUrl;
      const anchor   = au
        ? (services.find(s => au.startsWith(s.id) || s.id.startsWith(au.split("?")[0]))?.id
          || hosts.find(h => au.includes(h.id))?.id
          || hosts[0]?.id
          || "__scanner__")
        : (hosts[0]?.id || "__scanner__");
      edges.push({ from: anchor, to: fn.id });
    }

  } else {
    // ── Live: build finding nodes from SSE stream ─────────────────────────
    for (const [title, info] of Object.entries(liveFindingMap)) {
      const id   = `live_${title}`;
      const type = classifyFinding(title, "", info.severity, null);
      add({
        id, type,
        severity: info.severity,
        label:    title,
        sublabel: info.agentName,
        ts:       Math.max(scanStart, Math.min(info.ts, scanEnd)),
        finding:  { title, severity: info.severity },
        live:     true,
      });
    }
    // Wire all live nodes directly to the scanner origin
    for (const node of nodeMap.values()) {
      if (node.type !== "scanner") edges.push({ from: "__scanner__", to: node.id });
    }
  }

  return { nodes: [...nodeMap.values()], edges, scanStart, scanEnd };
}

// ── Layout ────────────────────────────────────────────────────────────────────

function computeLayout(nodes, scanStart, scanEnd) {
  const totalMs = Math.max(scanEnd - scanStart, 1);
  const usableW = SVG_W - PAD_L - PAD_R;
  const placed  = [];
  const sorted  = [...nodes].sort((a, b) => a.ts - b.ts);

  return sorted.map(node => {
    const elapsed = node.ts - scanStart;
    const rawX    = PAD_L + (elapsed / totalMs) * usableW;
    const baseY   = TIER_Y[node.type] || TIER_Y.finding;

    const offsets = [
      0,
      COLLISION_STEP, -COLLISION_STEP,
      COLLISION_STEP * 2, -COLLISION_STEP * 2,
      COLLISION_STEP * 3,
    ];
    let y = baseY;
    for (const off of offsets) {
      const ty      = baseY + off;
      const blocked = placed.some(
        p => p.type === node.type
          && Math.abs(p.lx - rawX) < COLLISION_RADIUS_MULTIPLIER * R
          && Math.abs(p.ly - ty)  < COLLISION_RADIUS_MULTIPLIER * R,
      );
      if (!blocked) { y = ty; break; }
    }

    const lx = Math.min(Math.max(rawX, PAD_L), SVG_W - PAD_R);
    placed.push({ type: node.type, lx, ly: y });
    return { ...node, lx, ly: y };
  });
}

// ── Activity log entry formatter ──────────────────────────────────────────────

function formatActivity(evt) {
  switch (evt.type) {
    case "agent_start":
      return { icon: "▶", color: "#a78bfa", text: `Starting: ${evt.agentName}` };
    case "agent_complete":
      return { icon: "✔", color: "#4ade80", text: evt.message || `${evt.agentName} completed` };
    case "agent_spawned":
      return { icon: "⚡", color: "#fde68a", text: evt.message || `Spawned: ${evt.agentName}` };
    case "finding": {
      const c = SEV_COLOR[evt.severity] || "#9ca3af";
      return { icon: "⚠", color: c, text: `[${(evt.severity || "info").toUpperCase()}] ${evt.findingTitle}` };
    }
    case "command":
      return { icon: "$", color: "#79c0ff", text: evt.command || evt.message };
    case "screenshot":
      return { icon: "📷", color: "#c084fc", text: evt.message || "Screenshot captured", screenshot: evt.screenshot };
    default:
      return { icon: "·", color: "#9ca3af", text: evt.message || "" };
  }
}

// ── Sub-components ────────────────────────────────────────────────────────────

function ActivityLog({ events, scanStart, onScreenshot }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [events]);

  const loggable = (events || []).filter(e =>
    e.type !== "screenshot" ||
    (e.type === "screenshot" && e.message)
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{
        fontSize: "0.7rem", fontWeight: 700, letterSpacing: "0.07em",
        color: "rgba(255,255,255,0.4)", textTransform: "uppercase",
        padding: "8px 12px 4px", borderBottom: "1px solid rgba(255,255,255,0.06)",
      }}>
        Activity Log
      </div>
      <div
        ref={ref}
        style={{
          flex: 1, overflowY: "auto",
          padding: "6px 10px",
          fontFamily: "monospace", fontSize: "0.72rem", lineHeight: 1.7,
        }}
      >
        {loggable.length === 0 && (
          <div style={{ color: "rgba(255,255,255,0.3)", padding: "6px 0" }}>
            Waiting for activity…
          </div>
        )}
        {loggable.map((evt, idx) => {
          const { icon, color, text, screenshot } = formatActivity(evt);
          const elapsed = scanStart ? Math.max(0, new Date(evt.timestamp).getTime() - scanStart) : 0;
          return (
            <div key={idx} style={{ display: "flex", gap: "6px", alignItems: "flex-start", marginBottom: "1px" }}>
              <span style={{ color: "rgba(255,255,255,0.3)", flexShrink: 0, minWidth: "44px", fontSize: "0.68rem" }}>
                {fmtMs(elapsed)}
              </span>
              <span style={{ color, flexShrink: 0, width: "14px" }}>{icon}</span>
              <span style={{ color: "rgba(255,255,255,0.78)", flex: 1, wordBreak: "break-all" }}>
                {text}
                {screenshot && onScreenshot && (
                  <button
                    onClick={() => onScreenshot(screenshot)}
                    style={{
                      marginLeft: "6px", background: "none",
                      border: "1px solid rgba(192,132,252,0.4)",
                      color: "#c084fc", cursor: "pointer",
                      fontSize: "0.62rem", borderRadius: "3px",
                      padding: "0 4px",
                    }}
                  >view</button>
                )}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function FindingDetail({ node, scanStart }) {
  if (!node) {
    return (
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "center",
        height: "100%", color: "rgba(255,255,255,0.25)",
        fontSize: "0.8rem", textAlign: "center", padding: "16px",
      }}>
        Click a node in the graph<br />to see details here
      </div>
    );
  }

  const st = nodeStyle(node);

  return (
    <div style={{ padding: "10px 14px", overflowY: "auto", height: "100%" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: "8px", marginBottom: "8px" }}>
        <span style={{ fontSize: "1.5rem", color: st.stroke, flexShrink: 0 }}>{ICON[node.type]}</span>
        <div>
          {node.finding && (
            <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "2px" }}>
              <span style={{
                background: SEV_COLOR[node.severity] || "#6b7280",
                color: "#fff", padding: "1px 7px", borderRadius: "999px",
                fontSize: "0.65rem", fontWeight: 700, flexShrink: 0,
              }}>
                {(node.severity || "info").toUpperCase()}
              </span>
            </div>
          )}
          <div style={{ fontWeight: 700, fontSize: "0.88rem", color: "#fff", lineHeight: 1.3 }}>
            {node.label}
          </div>
          {node.sublabel && (
            <div style={{ fontSize: "0.72rem", color: "rgba(255,255,255,0.4)", fontFamily: "monospace", marginTop: "2px" }}>
              {node.sublabel}
            </div>
          )}
        </div>
      </div>

      {/* Metadata table */}
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.74rem", marginBottom: "8px" }}>
        <tbody>
          <tr>
            <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px", whiteSpace: "nowrap" }}>Type</td>
            <td style={{ color: st.stroke, fontWeight: 600 }}>{node.type}</td>
          </tr>
          {scanStart > 0 && (
            <tr>
              <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>T+</td>
              <td style={{ fontFamily: "monospace" }}>{fmtMs(Math.max(0, node.ts - scanStart))}</td>
            </tr>
          )}
          {node.finding?.cvssScore > 0 && (
            <tr>
              <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>CVSS</td>
              <td>{node.finding.cvssScore.toFixed(1)}</td>
            </tr>
          )}
          {node.finding?.cwe && (
            <tr>
              <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>CWE</td>
              <td style={{ fontFamily: "monospace" }}>{node.finding.cwe}</td>
            </tr>
          )}
          {node.finding?.owaspCategory && (
            <tr>
              <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>OWASP</td>
              <td>{node.finding.owaspCategory}</td>
            </tr>
          )}
          {node.finding?.affectedUrl && (
            <tr>
              <td style={{ color: "rgba(255,255,255,0.4)", paddingRight: "8px", paddingBottom: "3px" }}>URL</td>
              <td style={{ wordBreak: "break-all", fontFamily: "monospace", fontSize: "0.68rem" }}>
                {node.finding.affectedUrl}
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {/* Description */}
      {node.finding?.description && (
        <div style={{ marginBottom: "8px" }}>
          <div style={{ color: "rgba(255,255,255,0.4)", fontSize: "0.68rem", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "3px" }}>
            Description
          </div>
          <p style={{ margin: 0, lineHeight: 1.5, fontSize: "0.76rem", color: "rgba(255,255,255,0.8)" }}>
            {node.finding.description}
          </p>
        </div>
      )}

      {/* Mitigations */}
      {node.finding?.recommendation && (
        <div style={{ marginBottom: "8px" }}>
          <div style={{ color: "#4ade80", fontSize: "0.68rem", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "3px" }}>
            Mitigations
          </div>
          <p style={{ margin: 0, lineHeight: 1.5, fontSize: "0.76rem", color: "rgba(255,255,255,0.8)" }}>
            {node.finding.recommendation}
          </p>
        </div>
      )}

      {/* Evidence */}
      {node.finding?.evidence && (
        <div>
          <div style={{ color: "rgba(255,255,255,0.4)", fontSize: "0.68rem", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "3px" }}>
            Evidence
          </div>
          <pre style={{
            margin: 0, padding: "6px 8px",
            background: "#0d0b14", borderRadius: "6px",
            fontSize: "0.68rem", overflowX: "auto",
            maxHeight: "80px", lineHeight: 1.4,
            border: "1px solid rgba(124,58,237,0.2)",
            color: "#79c0ff",
          }}>
            {node.finding.evidence}
          </pre>
        </div>
      )}

      {/* No-finding fallback */}
      {!node.finding && node.type !== "scanner" && (
        <p style={{ margin: 0, color: "rgba(255,255,255,0.4)", fontSize: "0.76rem" }}>
          Asset discovered {scanStart > 0 ? `at T+${fmtMs(Math.max(0, node.ts - scanStart))}` : ""}.
        </p>
      )}
    </div>
  );
}

// ── Main export ────────────────────────────────────────────────────────────────

export default function AttackGraph({ job, liveEvents = [], isRunning = false, onScreenshot }) {
  const [selected,     setSelected]     = useState(null);
  const [nowMs,        setNowMs]        = useState(() => Date.now());
  const [nodeOffsets,  setNodeOffsets]  = useState({});   // { [id]: {dx,dy} }
  const dragState  = useRef(null);   // { id, startX, startY, origDx, origDy }
  const didDrag    = useRef(false);
  const svgRef     = useRef(null);

  // Live elapsed timer – ticks every second while the scan is running.
  useEffect(() => {
    if (!isRunning) return;
    const t = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(t);
  }, [isRunning]);

  // Reset drag offsets whenever a new scan job starts.
  useEffect(() => { setNodeOffsets({}); }, [job?.id]);

  // ── Drag helpers ──────────────────────────────────────────────────────────
  /** Convert a PointerEvent's client coordinates into SVG viewBox coordinates. */
  function svgPoint(e) {
    const svg = svgRef.current;
    if (!svg) return { x: e.clientX, y: e.clientY };
    const pt = svg.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    return pt.matrixTransform(svg.getScreenCTM().inverse());
  }

  function onNodePointerDown(e, nodeId) {
    e.stopPropagation();
    // Capture pointer on the SVG so we keep receiving events even when the
    // pointer leaves the node or the SVG boundary.
    svgRef.current?.setPointerCapture(e.pointerId);
    const p = svgPoint(e);
    const off = nodeOffsets[nodeId] || { dx: 0, dy: 0 };
    dragState.current = { id: nodeId, startX: p.x, startY: p.y, origDx: off.dx, origDy: off.dy };
    didDrag.current   = false;
  }

  function onSVGPointerMove(e) {
    if (!dragState.current) return;
    const p  = svgPoint(e);
    const dx = dragState.current.origDx + (p.x - dragState.current.startX);
    const dy = dragState.current.origDy + (p.y - dragState.current.startY);
    if (Math.abs(p.x - dragState.current.startX) > 3 ||
        Math.abs(p.y - dragState.current.startY) > 3) {
      didDrag.current = true;
    }
    setNodeOffsets(prev => ({ ...prev, [dragState.current.id]: { dx, dy } }));
  }

  function onSVGPointerUp() {
    dragState.current = null;
  }

  /** Returns the effective (post-drag) screen position of a laid-out node. */
  function effPos(node) {
    const off = nodeOffsets[node.id];
    return { lx: node.lx + (off?.dx || 0), ly: node.ly + (off?.dy || 0) };
  }

  // Build + lay out the graph every time job or events change.
  const laid = useMemo(() => {
    if (!job) return null;
    const { nodes, edges, scanStart, scanEnd } = buildGraph(job, liveEvents);
    return { nodes: computeLayout(nodes, scanStart, scanEnd), edges, scanStart, scanEnd };
  }, [job, liveEvents]);

  if (!job || !laid) return null;
  const { nodes, edges, scanStart, scanEnd } = laid;
  if (!nodes || nodes.length === 0) return null;

  const byId = Object.fromEntries(nodes.map(n => [n.id, n]));

  // ── Stats ─────────────────────────────────────────────────────────────────
  // Use job.findings when complete; otherwise count from SSE events.
  const completedFindings = job.findings || [];
  const liveFindingEvents = (liveEvents || []).filter(e => e.type === "finding");
  const findings = completedFindings.length > 0 ? completedFindings : liveFindingEvents;
  const sev = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const s = f.severity || "info";
    sev[s] = (sev[s] || 0) + 1;
  }
  const hostCount    = completedFindings.length > 0
    ? (job.assets || []).filter(a => ["host","subdomain","domain"].includes((a.assetType||"").toLowerCase())).length
    : nodes.filter(n => n.type === "host").length;
  const serviceCount = completedFindings.length > 0
    ? (job.assets || []).filter(a => ["endpoint","url","port","service","path"].includes((a.assetType||"").toLowerCase())).length
    : nodes.filter(n => n.type === "service").length;

  // ── Elapsed time ──────────────────────────────────────────────────────────
  const elapsedMs = scanStart
    ? Math.max(0, (isRunning ? nowMs : (job.completedAt ? new Date(job.completedAt).getTime() : nowMs)) - scanStart)
    : 0;

  // ── Currently running agent ───────────────────────────────────────────────
  const completedAgents = new Set(
    (liveEvents || []).filter(e => e.type === "agent_complete").map(e => e.agentName)
  );
  let currentAgent = "";
  for (let i = (liveEvents || []).length - 1; i >= 0; i--) {
    const e = liveEvents[i];
    if (e.type === "agent_start" && !completedAgents.has(e.agentName)) {
      currentAgent = e.agentName;
      break;
    }
  }

  // ── Timeline ticks ────────────────────────────────────────────────────────
  const TICK_COUNT = 6;
  const ticks = Array.from({ length: TICK_COUNT + 1 }, (_, i) => ({
    x:  PAD_L + ((SVG_W - PAD_L - PAD_R) * i) / TICK_COUNT,
    ms: ((scanEnd - scanStart) * i) / TICK_COUNT,
  }));

  const selectedNode = selected ? byId[selected] : null;

  return (
    <div style={{ width: "100%", color: "rgba(255,255,255,0.85)" }}>

      {/* ── Header bar ──────────────────────────────────────────────────── */}
      <div style={{
        background: "rgba(0,0,0,0.5)",
        border: "1px solid rgba(124,58,237,0.2)",
        borderRadius: "10px 10px 0 0",
        padding: "8px 14px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        flexWrap: "wrap", gap: "8px",
        fontSize: "0.8rem",
      }}>
        {/* Left: target + status */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span style={{ color: "rgba(255,255,255,0.5)" }}>target:</span>
          <span style={{ fontWeight: 700, fontFamily: "monospace", color: "#c4b5fd" }}>
            {(() => { try { return new URL(job.target).hostname; } catch { return job.target; } })()}
          </span>
          <span style={{
            display: "inline-flex", alignItems: "center", gap: "5px",
            padding: "1px 8px", borderRadius: "999px", fontSize: "0.7rem", fontWeight: 700,
            background: isRunning ? "rgba(74,222,128,0.15)" : (job.status === "completed" ? "rgba(96,165,250,0.15)" : "rgba(239,68,68,0.15)"),
            border: `1px solid ${isRunning ? "#4ade80" : (job.status === "completed" ? "#60a5fa" : "#ef4444")}55`,
            color: isRunning ? "#4ade80" : (job.status === "completed" ? "#60a5fa" : "#ef4444"),
          }}>
            {isRunning && <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#4ade80", display: "inline-block", animation: "ag-pulse 1s infinite" }} />}
            {isRunning ? "RUNNING" : job.status?.toUpperCase()}
          </span>
          {isRunning && currentAgent && (
            <span style={{ color: "#a78bfa", fontSize: "0.72rem", fontFamily: "monospace" }}>
              [{currentAgent}]
            </span>
          )}
        </div>

        {/* Right: elapsed time + reset button */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          {Object.keys(nodeOffsets).length > 0 && (
            <button
              onClick={() => setNodeOffsets({})}
              title="Reset node positions"
              style={{
                background: "none",
                border: "1px solid rgba(167,139,250,0.35)",
                color: "#a78bfa",
                fontSize: "0.7rem",
                padding: "2px 8px",
                borderRadius: "4px",
                cursor: "pointer",
              }}
            >
              ↺ Reset Layout
            </button>
          )}
          <div style={{ fontFamily: "monospace", color: "rgba(255,255,255,0.5)", fontSize: "0.78rem" }}>
            {fmtMs(elapsedMs)}
          </div>
        </div>
      </div>

      {/* ── Stat pills row ───────────────────────────────────────────────── */}
      <div style={{
        background: "rgba(0,0,0,0.35)",
        borderLeft: "1px solid rgba(124,58,237,0.2)",
        borderRight: "1px solid rgba(124,58,237,0.2)",
        padding: "6px 14px",
        display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap",
        fontSize: "0.75rem",
      }}>
        {[
          { label: "High",     count: sev.high,     color: SEV_COLOR.high },
          { label: "Med",      count: sev.medium,   color: SEV_COLOR.medium },
          { label: "Low",      count: sev.low,      color: SEV_COLOR.low },
          { label: "Info",     count: sev.info,     color: SEV_COLOR.info },
          { label: "Hosts",    count: hostCount,    color: "#60a5fa" },
          { label: "Services", count: serviceCount, color: "#4ade80" },
        ].map(({ label, count, color }) => (
          <span key={label} style={{
            display: "inline-flex", alignItems: "center", gap: "5px",
            background: "rgba(0,0,0,0.4)",
            border: `1px solid ${color}33`,
            borderRadius: "999px", padding: "1px 8px",
          }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: color }} />
            <strong style={{ color }}>{count}</strong>
            <span style={{ color: "rgba(255,255,255,0.5)" }}>{label}</span>
          </span>
        ))}
      </div>

      {/* ── Graph SVG ────────────────────────────────────────────────────── */}
      <div style={{ width: "100%", overflowX: "auto" }}>
        <svg
          ref={svgRef}
          viewBox={`0 0 ${SVG_W} ${SVG_H}`}
          width="100%"
          onPointerMove={onSVGPointerMove}
          onPointerUp={onSVGPointerUp}
          onPointerLeave={onSVGPointerUp}
          style={{
            background: "rgba(0,0,0,0.5)",
            borderLeft: "1px solid rgba(124,58,237,0.2)",
            borderRight: "1px solid rgba(124,58,237,0.2)",
            cursor: dragState.current ? "grabbing" : "default",
          }}
        >
          <defs>
            <marker id="ag-arrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
              <polygon points="0 0,8 3,0 6" fill="rgba(255,255,255,0.25)" />
            </marker>
            <filter id="ag-glow">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <filter id="ag-danger">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>

          {/* Timeline axis */}
          <line x1={PAD_L} y1={TL_Y} x2={SVG_W - PAD_R} y2={TL_Y} stroke="rgba(255,255,255,0.12)" strokeWidth="1" />
          {ticks.map((tk, i) => (
            <g key={i}>
              <line x1={tk.x} y1={TL_Y - 4} x2={tk.x} y2={TL_Y + 4} stroke="rgba(255,255,255,0.18)" strokeWidth="1" />
              <text x={tk.x} y={TL_Y + 14} textAnchor="middle" fontSize="9" fill="rgba(255,255,255,0.35)" fontFamily="monospace">
                {fmtMs(tk.ms)}
              </text>
            </g>
          ))}

          {/* Edges */}
          {edges.map((e, i) => {
            const a = byId[e.from], b = byId[e.to];
            if (!a || !b) return null;
            const ea = effPos(a), eb = effPos(b);
            const toCompromise = b.type === "compromise";
            return (
              <path
                key={i}
                d={bezier(ea.lx, ea.ly, eb.lx, eb.ly)}
                stroke={toCompromise ? "rgba(244,63,94,0.4)" : "rgba(167,139,250,0.2)"}
                strokeWidth={toCompromise ? "1.8" : "1.4"}
                strokeDasharray={toCompromise ? "5 3" : undefined}
                fill="none"
                markerEnd="url(#ag-arrow)"
              />
            );
          })}

          {/* Nodes */}
          {nodes.map(node => {
            const st          = nodeStyle(node);
            const isSel       = selected === node.id;
            const isComp      = node.type === "compromise";
            const isHighFind  = node.type === "finding" && node.severity === "high";
            const showBadge   = isHighFind || isComp;
            const labelLines  = node.label.length > LABEL_FIRST_LINE_MAX
              ? [node.label.slice(0, LABEL_FIRST_LINE_MAX), node.label.slice(LABEL_FIRST_LINE_MAX, LABEL_FIRST_LINE_MAX + LABEL_SECOND_LINE_MAX)]
              : [node.label];
            const { lx, ly } = effPos(node);

            return (
              <g
                key={node.id}
                transform={`translate(${lx},${ly})`}
                onPointerDown={(e) => onNodePointerDown(e, node.id)}
                onClick={() => {
                  if (didDrag.current) { didDrag.current = false; return; }
                  setSelected(isSel ? null : node.id);
                }}
                style={{ cursor: "grab" }}
              >
                {(isSel || isComp) && (
                  <circle
                    r={R + 10} fill="none"
                    stroke={isComp ? "#f43f5e" : "#a78bfa"}
                    strokeWidth={isSel ? "2" : "1"}
                    opacity={isSel ? "0.7" : "0.3"}
                    filter="url(#ag-glow)"
                  >
                    {isSel && <animate attributeName="opacity" values="0.7;0.3;0.7" dur="1.6s" repeatCount="indefinite" />}
                  </circle>
                )}

                <circle
                  r={R}
                  fill={st.fill}
                  stroke={isSel ? "#a78bfa" : st.stroke}
                  strokeWidth={isSel ? "2.5" : "2"}
                  filter={isComp ? "url(#ag-danger)" : undefined}
                />

                <text y="1" textAnchor="middle" dominantBaseline="middle" fontSize="13" fill={st.text}
                  style={{ userSelect: "none", pointerEvents: "none" }}>
                  {ICON[node.type] || "·"}
                </text>

                {node.finding && (
                  <circle cx={R - 6} cy={-(R - 6)} r="5" fill={SEV_COLOR[node.severity] || "#6b7280"} stroke="#000" strokeWidth="1" />
                )}

                {showBadge && (
                  <g transform={`translate(0,${R + 10})`}>
                    <rect
                      x={isComp ? -38 : -22} y="0" rx="3"
                      width={isComp ? 76 : 44} height="14"
                      fill={isComp ? "#3b0808" : "#450a0a"}
                      stroke={isComp ? "#f43f5e" : "#ef4444"} strokeWidth="1"
                    />
                    <text textAnchor="middle" y="10" fontSize="7" fill="#fff" fontFamily="monospace" fontWeight="bold"
                      style={{ userSelect: "none", pointerEvents: "none" }}>
                      {isComp ? "HOST COMPROMISE" : "PROOF"}
                    </text>
                  </g>
                )}

                <text y={-(R + 10)} textAnchor="middle" fontSize="8" fill="rgba(255,255,255,0.45)" fontFamily="monospace"
                  style={{ userSelect: "none", pointerEvents: "none" }}>
                  {node.type === "finding" ? `${SEV_LABEL[node.severity] || "INFO"} finding` : node.type}
                </text>

                {labelLines.map((line, li) => (
                  <text key={li}
                    y={-(R + 22) - (labelLines.length - 1 - li) * 11}
                    textAnchor="middle" fontSize="9" fontWeight="600"
                    fill={isSel ? "#e9d5ff" : "rgba(255,255,255,0.85)"}
                    fontFamily="monospace"
                    style={{ userSelect: "none", pointerEvents: "none" }}>
                    {line}
                  </text>
                ))}

                {node.sublabel && (
                  <text
                    y={-(R + (labelLines.length > 1 ? 46 : 34))}
                    textAnchor="middle" fontSize="7.5"
                    fill="rgba(255,255,255,0.35)" fontFamily="monospace"
                    style={{ userSelect: "none", pointerEvents: "none" }}>
                    {node.sublabel}
                  </text>
                )}

                <line
                  x1="0" y1={R + (showBadge ? 24 : 2)}
                  x2="0" y2={TL_Y - ly}
                  stroke="rgba(255,255,255,0.05)" strokeWidth="1" strokeDasharray="3 4"
                />
              </g>
            );
          })}
        </svg>
      </div>

      {/* ── Bottom two-pane (Activity Log | Finding Detail) ─────────────── */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        background: "rgba(0,0,0,0.45)",
        border: "1px solid rgba(124,58,237,0.2)",
        borderRadius: "0 0 10px 10px",
        height: "220px",
        overflow: "hidden",
      }}>
        <div style={{ borderRight: "1px solid rgba(124,58,237,0.15)", overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <ActivityLog events={liveEvents} scanStart={scanStart} onScreenshot={onScreenshot} />
        </div>
        <div style={{ overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <div style={{
            fontSize: "0.7rem", fontWeight: 700, letterSpacing: "0.07em",
            color: "rgba(255,255,255,0.4)", textTransform: "uppercase",
            padding: "8px 12px 4px", borderBottom: "1px solid rgba(255,255,255,0.06)",
            flexShrink: 0,
          }}>
            {selectedNode ? `${selectedNode.type} detail` : "Finding Detail"}
          </div>
          <div style={{ flex: 1, overflow: "hidden" }}>
            <FindingDetail node={selectedNode} scanStart={scanStart} />
          </div>
        </div>
      </div>

      {/* Pulse keyframe */}
      <style>{`@keyframes ag-pulse { 0%,100% { opacity:1; } 50% { opacity:0.35; } }`}</style>
    </div>
  );
}
