/**
 * AttackPathGraph — SVG-based directed graph that visualises agent pipeline
 * progress in real time.  Nodes are coloured by state:
 *   pending   → dark red ring
 *   running   → amber pulse
 *   complete  → green fill
 *   spawned   → orange outline (dynamically added agent)
 *   failed    → red fill
 */

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

export default function AttackPathGraph({ events }) {
  // Derive node states from the live event stream.
  const nodeStates = {};
  const dynamicEdges = []; // edges for spawned agents

  for (const evt of events) {
    if (evt.type === "agent_start") {
      nodeStates[evt.agentName] = "running";
    } else if (evt.type === "agent_complete") {
      nodeStates[evt.agentName] = "complete";
    } else if (evt.type === "agent_spawned") {
      if (!nodeStates[evt.agentName]) {
        nodeStates[evt.agentName] = "spawned";
      }
      // Try to extract which agent triggered the spawn from the message.
      const match = evt.message && evt.message.match(/from "([^"]+)"/);
      if (match) {
        dynamicEdges.push([match[1], evt.agentName]);
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
        viewBox="0 0 900 420"
        width="100%"
        style={{ background: "rgba(0,0,0,0.35)", borderRadius: "10px", minWidth: "600px" }}
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

        {/* Edges */}
        {allEdges.map(([a, b], i) => {
          const pa = layout[a], pb = layout[b];
          if (!pa || !pb) return null;
          return (
            <path
              key={i}
              d={arrowPath(pa.x, pa.y, pb.x, pb.y)}
              stroke="rgba(255,255,255,0.2)"
              strokeWidth="1.5"
              fill="none"
              markerEnd="url(#arrowhead)"
            />
          );
        })}

        {/* Nodes */}
        {Array.from(allNames).map((name) => {
          const pos = layout[name];
          if (!pos) return null;
          const state = nodeStates[name] || "pending";
          const colors = STATE_COLOR[state];
          const isRunning = state === "running";
          const label = name.replace(/_/g, " ");
          return (
            <g key={name} transform={`translate(${pos.x},${pos.y})`}>
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
                style={{ userSelect: "none" }}
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
      {/* Legend */}
      <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", padding: "6px 4px", fontSize: "0.72rem" }}>
        {Object.entries(STATE_COLOR).map(([state, c]) => (
          <span key={state} style={{ display: "flex", alignItems: "center", gap: "5px", color: "rgba(0,0,0,0.8)" }}>
            <span style={{ display: "inline-block", width: "10px", height: "10px", borderRadius: "50%", background: c.stroke }} />
            {state}
          </span>
        ))}
      </div>
    </div>
  );
}
