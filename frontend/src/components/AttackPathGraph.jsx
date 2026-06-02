/**
 * AttackPathGraph — SVG-based directed graph that visualises agent pipeline
 * progress in real time.  Nodes are coloured by state:
 *   pending   → dark red ring
 *   running   → amber pulse
 *   complete  → green fill
 *   spawned   → orange outline (dynamically added agent)
 *   failed    → red fill
 */

import { useRef, useState } from "react";

// Fixed layout positions (x, y as % of the SVG viewBox 0 0 900 420)
const LAYOUT = {
  reconnaissance:         { x: 60,  y: 200 },
  scanning:               { x: 190, y: 200 },
  input_validation:       { x: 320, y: 110 },
  information_disclosure: { x: 320, y: 200 },
  access_control:         { x: 320, y: 290 },
  api_security:           { x: 450, y: 110 },
  cors_redirect:          { x: 450, y: 200 },
  wordlist:               { x: 450, y: 290 },
  auth_bypass:            { x: 450, y: 375 },
  analysis:               { x: 570, y: 200 },
  dynamic_commands:       { x: 680, y: 130 },
  tool_builder:           { x: 680, y: 200 },
  ml_triage:              { x: 790, y: 100 },
  attack_path:            { x: 790, y: 185 },
  false_positive_review:  { x: 790, y: 270 },
  remediation_planner:    { x: 880, y: 145 },
  reporting:              { x: 880, y: 240 },
};

// Default directed edges (source → target)
const DEFAULT_EDGES = [
  ["reconnaissance", "scanning"],
  ["scanning", "input_validation"],
  ["scanning", "information_disclosure"],
  ["scanning", "access_control"],
  ["input_validation", "api_security"],
  ["information_disclosure", "cors_redirect"],
  ["access_control", "wordlist"],
  ["access_control", "auth_bypass"],
  ["auth_bypass", "wordlist"],
  ["api_security", "analysis"],
  ["cors_redirect", "analysis"],
  ["wordlist", "analysis"],
  ["analysis", "dynamic_commands"],
  ["analysis", "tool_builder"],
  ["dynamic_commands", "ml_triage"],
  ["tool_builder", "ml_triage"],
  ["ml_triage", "attack_path"],
  ["ml_triage", "false_positive_review"],
  ["attack_path", "remediation_planner"],
  ["false_positive_review", "remediation_planner"],
  ["remediation_planner", "reporting"],
];

const STATE_COLOR = {
  pending:  { fill: "transparent", stroke: "#6b0000",       text: "rgba(255,255,255,0.5)" },
  running:  { fill: "#b45309",     stroke: "#fbbf24",        text: "#fff" },
  complete: { fill: "#166534",     stroke: "#4ade80",        text: "#fff" },
  spawned:  { fill: "#7c2d12",     stroke: "#f97316",        text: "#fff" },
  failed:   { fill: "#7f1d1d",     stroke: "#f87171",        text: "#fff" },
};

function arrowPath(x1, y1, x2, y2) {
  const dx = x2 - x1, dy = y2 - y1;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  const ux = dx / len, uy = dy / len;
  const r = 26;
  return `M ${x1 + ux * r} ${y1 + uy * r} L ${x2 - ux * r} ${y2 - uy * r}`;
}

function normalizeAgentName(name) {
  return String(name || "")
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_");
}

export default function AttackPathGraph({ events = [], job = null }) {
  const [nodeOffsets, setNodeOffsets] = useState({});
  const dragState = useRef(null);   // { id, startX, startY, origDx, origDy }
  const didDrag   = useRef(false);
  const svgRef    = useRef(null);

  // ── Drag helpers ─────────────────────────────────────────────────────────
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
    svgRef.current?.setPointerCapture(e.pointerId);
    const p   = svgPoint(e);
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

  /** Effective position of a named node accounting for user drag. */
  function effPos(name, basePos) {
    const off = nodeOffsets[name];
    return { x: basePos.x + (off?.dx || 0), y: basePos.y + (off?.dy || 0) };
  }

  // ── Derive node states from the live event stream ────────────────────────
  const nodeStates = {};
  const dynamicEdges = []; // edges for spawned agents

  for (const evt of events) {
    const agentName = normalizeAgentName(evt.agentName);
    if (!agentName) continue;
    if (evt.type === "agent_start") {
      nodeStates[agentName] = "running";
    } else if (evt.type === "agent_complete") {
      nodeStates[agentName] = "complete";
    } else if (evt.type === "agent_spawned") {
      if (!nodeStates[agentName]) {
        nodeStates[agentName] = "spawned";
      }
      // Try to extract which agent triggered the spawn from the message.
      const match = evt.message && evt.message.match(/from "([^"]+)"/);
      if (match) {
        dynamicEdges.push([normalizeAgentName(match[1]), agentName]);
      }
    }
  }

  for (const run of job?.agentRuns || []) {
    const agentName = normalizeAgentName(run.agentName);
    if (!agentName) continue;
    const status = String(run.status || "").trim().toLowerCase();
    if (status === "error" || status === "failed" || run.timedOut) {
      nodeStates[agentName] = "failed";
      continue;
    }
    if (status === "running" || status === "in_progress") {
      nodeStates[agentName] = "running";
      continue;
    }
    if (status === "completed" || status === "complete" || status === "success") {
      nodeStates[agentName] = "complete";
    }
  }

  // Some autonomous plans may execute downstream ML stages without emitting an
  // explicit ml_triage lifecycle event; infer it so the pipeline remains
  // visually continuous for operators.
  if (nodeStates.ml_triage === undefined) {
    const downstreamStates = ["attack_path", "false_positive_review", "remediation_planner"]
      .map((name) => nodeStates[name])
      .filter(Boolean);
    const downstreamActive = downstreamStates.some((state) => ["running", "complete", "failed"].includes(state));
    if (downstreamActive) {
      nodeStates.ml_triage = downstreamStates.includes("failed")
        ? "failed"
        : (["running", "finalizing"].includes(String(job?.status || "").toLowerCase()) ? "running" : "complete");
    }
  }

  const terminalStatus = String(job?.status || "").toLowerCase();
  if (terminalStatus === "completed" || terminalStatus === "failed" || terminalStatus === "cancelled") {
    const fallbackState = terminalStatus === "completed" ? "complete" : "failed";
    for (const name of Object.keys(nodeStates)) {
      if (nodeStates[name] === "running") {
        nodeStates[name] = fallbackState;
      }
    }
  }

  // Build a mutable layout copy so we never mutate the module-level const.
  const layout = { ...LAYOUT };
  let dynamicY = 360;
  const allNames = new Set(Object.keys(layout));

  for (const name of Object.keys(nodeStates)) {
    if (!allNames.has(name)) {
      layout[name] = { x: 580 + (dynamicEdges.length * 40), y: dynamicY };
      dynamicY += 50;
      allNames.add(name);
    }
  }

  const allEdges = [...DEFAULT_EDGES, ...dynamicEdges];

  // Identify running agent for pulsing
  const runningAgents = new Set(Object.entries(nodeStates).filter(([, v]) => v === "running").map(([k]) => k));

  return (
    <div style={{ width: "100%", overflowX: "auto" }}>
      <svg
        ref={svgRef}
        viewBox="0 0 900 420"
        width="100%"
        onPointerMove={onSVGPointerMove}
        onPointerUp={onSVGPointerUp}
        onPointerLeave={onSVGPointerUp}
        style={{ background: "rgba(0,0,0,0.35)", borderRadius: "10px" }}
      >
        <defs>
          <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="6" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="rgba(255,255,255,0.3)" />
          </marker>
          {Array.from(runningAgents).map((name) => (
            <filter key={`glow-${name}`} id={`glow-${name}`}>
              <feGaussianBlur stdDeviation="3" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          ))}
        </defs>

        {/* Edges — use effective positions so edges track dragged nodes */}
        {allEdges.map(([a, b], i) => {
          const pa = layout[a], pb = layout[b];
          if (!pa || !pb) return null;
          const ea = effPos(a, pa), eb = effPos(b, pb);
          return (
            <path
              key={i}
              d={arrowPath(ea.x, ea.y, eb.x, eb.y)}
              stroke="rgba(255,255,255,0.2)"
              strokeWidth="1.5"
              fill="none"
              markerEnd="url(#arrowhead)"
            />
          );
        })}

        {/* Nodes */}
        {Array.from(allNames).map((name) => {
          const base = layout[name];
          if (!base) return null;
          const { x, y } = effPos(name, base);
          const state  = nodeStates[name] || "pending";
          const colors = STATE_COLOR[state];
          const isRunning = state === "running";
          const label = name.replace(/_/g, " ");
          return (
            <g
              key={name}
              transform={`translate(${x},${y})`}
              onPointerDown={(e) => onNodePointerDown(e, name)}
              style={{ cursor: "grab" }}
            >
              {isRunning && (
                <circle r="34" fill="none" stroke="#fbbf24" strokeWidth="2" opacity="0.5">
                  <animate attributeName="r" values="28;38;28" dur="1.4s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.5;0.1;0.5" dur="1.4s" repeatCount="indefinite" />
                </circle>
              )}
              <circle
                r="26"
                fill={colors.fill}
                stroke={colors.stroke}
                strokeWidth="2"
                filter={isRunning ? `url(#glow-${name})` : undefined}
              />
              <text
                y="1"
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize="7"
                fontFamily="monospace"
                fill={colors.text}
                style={{ userSelect: "none", pointerEvents: "none" }}
              >
                {label.length > 16
                  ? label.split(" ").map((w, i) => (
                      <tspan key={i} x="0" dy={i === 0 ? "-4" : "9"}>{w}</tspan>
                    ))
                  : label}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Controls row: Reset Layout button + legend */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", padding: "6px 4px", fontSize: "0.72rem" }}>
        <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
          {Object.entries(STATE_COLOR).map(([state, c]) => (
            <span key={state} style={{ display: "flex", alignItems: "center", gap: "5px", color: "rgba(255,255,255,0.8)" }}>
              <span style={{ display: "inline-block", width: "10px", height: "10px", borderRadius: "50%", background: c.stroke }} />
              {state}
            </span>
          ))}
        </div>
        {Object.keys(nodeOffsets).length > 0 && (
          <button
            onClick={() => setNodeOffsets({})}
            style={{
              background: "none",
              border: "1px solid rgba(167,139,250,0.4)",
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
      </div>
    </div>
  );
}
