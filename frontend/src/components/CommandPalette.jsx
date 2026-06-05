import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useScan } from "../context/ScanContext";

const ROUTES = [
  { label: "Operator Console", path: "/" },
  { label: "Attack Graph", path: "/attack-graph" },
  { label: "Impact Triage", path: "/findings" },
  { label: "Submission Center", path: "/reports" },
  { label: "Engagement History", path: "/scans" },
  { label: "Proxy Suite", path: "/proxy" },
  { label: "Agent Activity", path: "/agent-activity" },
  { label: "Knowledge Base", path: "/references" },
  { label: "Environment", path: "/settings" },
  { label: "Probe Coverage", path: "/probe-coverage" },
  { label: "Scan Timeline", path: "/scan-timeline" },
  { label: "Surface Map", path: "/surface-map" },
];

export default function CommandPalette({ onClose }) {
  const [query, setQuery] = useState("");
  const inputRef = useRef(null);
  const navigate = useNavigate();
  const { isScanActive, stopScan, scanId } = useScan();

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const actions = [
    ...ROUTES.map((r) => ({ label: `Go to: ${r.label}`, action: () => { navigate(r.path); onClose(); } })),
    ...(isScanActive ? [{ label: "Stop current scan", action: () => { stopScan(scanId); onClose(); } }] : []),
  ];

  const filtered = query.trim()
    ? actions.filter((a) => a.label.toLowerCase().includes(query.toLowerCase()))
    : actions;

  const handleKey = (e) => {
    if (e.key === "Escape") onClose();
  };

  return (
    <div className="cmd-palette-overlay" onClick={onClose} onKeyDown={handleKey}>
      <div className="cmd-palette" role="dialog" aria-label="Command palette" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="cmd-palette__input"
          placeholder="Type a command or navigate…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") onClose();
          }}
        />
        <ul className="cmd-palette__list">
          {filtered.length === 0 ? (
            <li className="cmd-palette__empty">No commands match</li>
          ) : (
            filtered.map((a, idx) => (
              <li key={idx}>
                <button type="button" className="cmd-palette__item" onClick={a.action}>
                  {a.label}
                </button>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}
