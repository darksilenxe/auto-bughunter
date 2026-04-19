/**
 * BurpImport — Drag-and-drop / file-picker widget for importing a Burp Suite
 * project configuration file (.json or .burp) into the scan form.
 *
 * Props:
 *   onImport(config) – called with a BurpParsedConfig object when the user
 *                      clicks "Apply to scan". The parent is responsible for
 *                      updating its form state.
 */
import { useRef, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "";

export default function BurpImport({ onImport }) {
  const [open, setOpen]       = useState(false);
  const [dragging, setDragging] = useState(false);
  const [parsing, setParsing] = useState(false);
  const [parsed, setParsed]   = useState(null);   // BurpParsedConfig | null
  const [error, setError]     = useState("");
  const inputRef              = useRef(null);

  // ── File handling ─────────────────────────────────────────────────────────

  async function handleFile(file) {
    if (!file) return;
    const ext = file.name.split(".").pop().toLowerCase();
    if (ext !== "json" && ext !== "burp") {
      setError("Please upload a .json (project options export) or .burp file.");
      return;
    }
    setError("");
    setParsed(null);
    setParsing(true);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(`${API_BASE}/api/burp/parse`, { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Parse failed.");
        return;
      }
      setParsed(data);
    } catch (e) {
      setError("Network error: " + e.message);
    } finally {
      setParsing(false);
    }
  }

  function onInputChange(e) {
    handleFile(e.target.files?.[0]);
    e.target.value = "";
  }

  function onDrop(e) {
    e.preventDefault();
    setDragging(false);
    handleFile(e.dataTransfer.files?.[0]);
  }

  function apply() {
    if (!parsed) return;
    onImport(parsed);
    setParsed(null);
    setOpen(false);
  }

  function dismiss() {
    setParsed(null);
    setError("");
    setOpen(false);
  }

  // ── Colours ───────────────────────────────────────────────────────────────

  const border   = "rgba(124,58,237,0.3)";
  const accent   = "#7c3aed";
  const accentLt = "#9d5ff5";
  const bg       = "rgba(124,58,237,0.08)";
  const bgHover  = "rgba(124,58,237,0.14)";
  const textMut  = "rgba(255,255,255,0.45)";
  const text     = "rgba(255,255,255,0.85)";

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div style={{ marginTop: "0.5rem" }}>
      {/* Toggle button */}
      <button
        type="button"
        onClick={() => setOpen(v => !v)}
        style={{
          background: "none", border: `1px dashed ${border}`,
          color: textMut, fontSize: "0.8rem", padding: "0.35rem 0.8rem",
          borderRadius: "6px", cursor: "pointer", display: "flex",
          alignItems: "center", gap: "6px",
          transition: "color 0.15s, border-color 0.15s",
        }}
        onMouseEnter={e => { e.currentTarget.style.color = text; e.currentTarget.style.borderColor = accentLt; }}
        onMouseLeave={e => { e.currentTarget.style.color = textMut; e.currentTarget.style.borderColor = border; }}
      >
        <span style={{ fontSize: "1rem" }}>🕵️</span>
        Import Burp Suite configuration
        <span style={{ marginLeft: "auto", fontSize: "0.7rem" }}>{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div style={{
          marginTop: "0.5rem",
          background: bg,
          border: `1px solid ${border}`,
          borderRadius: "8px",
          padding: "1rem",
        }}>
          <p style={{ margin: "0 0 0.75rem", fontSize: "0.8rem", color: textMut, lineHeight: 1.5 }}>
            Upload a Burp Suite <strong style={{ color: text }}>project options export</strong>{" "}
            (<code style={{ color: "#c4b5fd" }}>Project → Save project options → .json</code>) or a{" "}
            <strong style={{ color: text }}>.burp</strong> project file. Target URL, scope rules, and
            any authentication headers/cookies found in match-replace rules will be pre-filled.
          </p>

          {/* Drop zone */}
          {!parsed && (
            <div
              onDragOver={e => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              onClick={() => inputRef.current?.click()}
              style={{
                border: `2px dashed ${dragging ? accentLt : border}`,
                borderRadius: "8px",
                padding: "1.5rem",
                textAlign: "center",
                cursor: "pointer",
                background: dragging ? bgHover : "transparent",
                transition: "background 0.15s, border-color 0.15s",
              }}
            >
              <input
                ref={inputRef}
                type="file"
                accept=".json,.burp"
                style={{ display: "none" }}
                onChange={onInputChange}
              />
              {parsing ? (
                <span style={{ color: accentLt, fontSize: "0.85rem" }}>⏳ Parsing…</span>
              ) : (
                <>
                  <div style={{ fontSize: "1.8rem", marginBottom: "6px" }}>📂</div>
                  <div style={{ color: text, fontSize: "0.85rem" }}>
                    Drop <code style={{ color: "#c4b5fd" }}>.json</code> or <code style={{ color: "#c4b5fd" }}>.burp</code> here, or click to browse
                  </div>
                </>
              )}
            </div>
          )}

          {error && (
            <p style={{ margin: "0.5rem 0 0", color: "#f87171", fontSize: "0.8rem" }}>{error}</p>
          )}

          {/* Preview of parsed data */}
          {parsed && (
            <div style={{ marginTop: "0.5rem" }}>
              <div style={{ fontSize: "0.78rem", color: textMut, marginBottom: "0.5rem" }}>
                Extracted configuration — review and click <strong style={{ color: text }}>Apply</strong>:
              </div>

              <div style={{
                background: "rgba(0,0,0,0.35)", borderRadius: "6px",
                padding: "0.75rem 1rem", fontSize: "0.78rem", lineHeight: 1.7,
              }}>
                {parsed.target && (
                  <Row label="Target URL" value={parsed.target} color="#c4b5fd" />
                )}
                {parsed.includeHosts?.length > 0 && (
                  <Row label="Include hosts" value={parsed.includeHosts.join(", ")} />
                )}
                {parsed.excludeHosts?.length > 0 && (
                  <Row label="Exclude hosts" value={parsed.excludeHosts.join(", ")} />
                )}
                {parsed.excludePaths?.length > 0 && (
                  <Row label="Exclude paths" value={parsed.excludePaths.join(", ")} />
                )}
                {Object.keys(parsed.headers || {}).length > 0 && (
                  <Row label="Headers" value={
                    Object.entries(parsed.headers).map(([k, v]) =>
                      `${k}: ${v.length > 32 ? v.slice(0, 30) + "…" : v}`
                    ).join("; ")
                  } />
                )}
                {Object.keys(parsed.cookies || {}).length > 0 && (
                  <Row label="Cookies" value={
                    Object.keys(parsed.cookies).join(", ")
                  } />
                )}
                {parsed.notes?.length > 0 && parsed.notes.map((n, i) => (
                  <p key={i} style={{ margin: "4px 0 0", color: "#fbbf24", fontSize: "0.75rem" }}>⚠ {n}</p>
                ))}
              </div>

              <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.75rem" }}>
                <button
                  type="button"
                  onClick={apply}
                  style={{
                    background: accent, color: "#fff", border: "none",
                    borderRadius: "6px", padding: "0.4rem 1rem",
                    fontSize: "0.82rem", fontWeight: 700, cursor: "pointer",
                  }}
                >
                  ✓ Apply to scan form
                </button>
                <button
                  type="button"
                  onClick={() => { setParsed(null); setError(""); }}
                  style={{
                    background: "transparent", color: textMut,
                    border: `1px solid ${border}`, borderRadius: "6px",
                    padding: "0.4rem 0.8rem", fontSize: "0.82rem", cursor: "pointer",
                  }}
                >
                  ✕ Clear
                </button>
                <button
                  type="button"
                  onClick={dismiss}
                  style={{
                    background: "transparent", color: textMut,
                    border: "none", fontSize: "0.8rem", cursor: "pointer",
                    marginLeft: "auto",
                  }}
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, value, color }) {
  return (
    <div style={{ display: "flex", gap: "8px", marginBottom: "2px" }}>
      <span style={{ color: "rgba(255,255,255,0.4)", minWidth: "110px", flexShrink: 0 }}>{label}</span>
      <span style={{ color: color || "rgba(255,255,255,0.85)", wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}
