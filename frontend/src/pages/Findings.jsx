import { useState } from "react";
import { API_BASE, API_KEY, WORKSPACE_ID, useScan } from "../context/ScanContext";

const HACKTRICKS_URLS = {
  xss:               "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting",
  sqli:              "https://book.hacktricks.xyz/pentesting-web/sql-injection",
  "sql injection":   "https://book.hacktricks.xyz/pentesting-web/sql-injection",
  csrf:              "https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery",
  ssrf:              "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery",
  xxe:               "https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity",
  rce:               "https://book.hacktricks.xyz/pentesting-web/command-injection",
  "command injection": "https://book.hacktricks.xyz/pentesting-web/command-injection",
  "path traversal":  "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
  lfi:               "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
  rfi:               "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
  idor:              "https://book.hacktricks.xyz/pentesting-web/idor",
  "open redirect":   "https://book.hacktricks.xyz/pentesting-web/open-redirect",
  "request smuggling": "https://book.hacktricks.xyz/pentesting-web/http-request-smuggling",
  ssti:              "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
  "template injection": "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
  clickjacking:      "https://book.hacktricks.xyz/pentesting-web/clickjacking",
  jwt:               "https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens",
  oauth:             "https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover",
  "auth bypass":     "https://book.hacktricks.xyz/pentesting-web/login-bypass",
  "broken access":   "https://book.hacktricks.xyz/pentesting-web/broken-access-control",
  "mass assignment": "https://book.hacktricks.xyz/pentesting-web/mass-assignment",
};

function hackTricksUrl(finding) {
  const haystack = `${finding.title || ""} ${finding.category || ""} ${finding.description || ""}`.toLowerCase();
  for (const [keyword, url] of Object.entries(HACKTRICKS_URLS)) {
    if (haystack.includes(keyword)) return url;
  }
  return "https://book.hacktricks.xyz/pentesting-web/web-vulnerabilities-methodology";
}

const LIFECYCLE_TRANSITIONS = {
  "": ["verified", "rejected", "suppressed"],
  new: ["verified", "rejected", "suppressed"],
  verified: ["accepted", "remediated", "suppressed", "rejected"],
  rejected: ["verified"],
  accepted: ["remediated", "suppressed"],
  suppressed: ["verified"],
  remediated: ["verified"],
};

export default function Findings() {
  const { job, screenshots } = useScan();
  const [filter, setFilter] = useState("all");
  const [selectedScreenshot, setSelectedScreenshot] = useState(null);
  const [lifecycleStatus, setLifecycleStatus] = useState({});

  async function transitionFinding(findingId, nextStatus, currentStatus) {
    if (!job?.id) return;
    const ownerNeeded = nextStatus === "accepted" || nextStatus === "remediated";
    let owner = "";
    if (ownerNeeded) {
      owner = window.prompt(`Owner email or handle for "${nextStatus}" transition?`) || "";
      if (!owner.trim()) {
        setLifecycleStatus((p) => ({ ...p, [findingId]: "Owner required for this transition." }));
        return;
      }
    }
    setLifecycleStatus((p) => ({ ...p, [findingId]: "Updating..." }));
    try {
      const res = await fetch(`${API_BASE}/api/finding-verification`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
          "X-Workspace-ID": WORKSPACE_ID,
        },
        body: JSON.stringify({
          scanId: job.id,
          findingId,
          status: nextStatus,
          owner: owner.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setLifecycleStatus((p) => ({ ...p, [findingId]: data.error || `Failed (${res.status})` }));
        return;
      }
      setLifecycleStatus((p) => ({
        ...p,
        [findingId]: `${currentStatus || "new"} → ${data.status}${data.owner ? ` (owner: ${data.owner})` : ""}`,
      }));
    } catch (err) {
      setLifecycleStatus((p) => ({ ...p, [findingId]: err.message || "Network error" }));
    }
  }

  if (!job) {
    return (
      <div className="page">
        <header><h1>🔍 Findings</h1></header>
        <section className="card">
          <p className="meta">No scan in progress. Go to the Dashboard to start a scan.</p>
        </section>
      </div>
    );
  }

  const findings = job.findings || [];
  const filtered = filter === "all" ? findings : findings.filter((f) => f.severity === filter);

  const sevCounts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++;
  }

  const SEV_COLOR = { high: "#dc2626", medium: "#ea580c", low: "#ca8a04", info: "#6b7280" };
  const BORDER_COLOR = { high: "#fca5a5", medium: "#fdba74", low: "#fde68a", info: "#d1d5db" };

  return (
    <div className="page">
      <header>
        <h1>🔍 Findings</h1>
        <p>Target: <strong>{job.target}</strong> · Status: <strong>{job.status}</strong></p>
      </header>

      {/* Screenshots panel */}
      {screenshots.length > 0 && (
        <section className="card">
          <h2>📷 Screenshots ({screenshots.length})</h2>
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            {screenshots.map((s, i) => (
              <div key={i}
                style={{ cursor: "pointer", borderRadius: "6px", overflow: "hidden", border: "2px solid rgba(255,255,255,0.2)" }}
                onClick={() => setSelectedScreenshot(s.b64)}
                title={s.message}
              >
                <img
                  src={`data:image/png;base64,${s.b64}`}
                  alt={`Screenshot ${i + 1}`}
                  style={{ width: "140px", height: "90px", objectFit: "cover", display: "block" }}
                />
                <div style={{ fontSize: "0.65rem", padding: "2px 4px", background: "rgba(0,0,0,0.6)", color: "#ddd", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "140px" }}>
                  {s.message || `Page ${i + 1}`}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Severity filter */}
      <section className="card">
        <div className="stats" style={{ marginBottom: "1rem" }}>
          {["all", "high", "medium", "low", "info"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              style={{
                background: filter === sev ? "#7c3aed" : "rgba(124,58,237,0.15)",
                color: filter === sev ? "#fff" : "rgba(255,255,255,0.8)",
                border: "1.5px solid rgba(124,58,237,0.35)",
                borderRadius: "999px",
                padding: "0.3rem 0.8rem",
                fontSize: "0.82rem",
                cursor: "pointer",
                fontWeight: filter === sev ? 700 : 400,
              }}
            >
              {sev === "all" ? `All (${findings.length})` : `${sev} (${sevCounts[sev] || 0})`}
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <p className="meta">No findings at this severity level.</p>
        ) : (
          <ul className="findings">
            {filtered.map((f, idx) => (
              <li key={f.id || idx} style={{ borderColor: BORDER_COLOR[f.severity] || "#e5e7eb" }}>
                <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "4px" }}>
                  <span style={{
                    background: SEV_COLOR[f.severity] || "#6b7280",
                    color: "#fff", padding: "1px 8px", borderRadius: "999px",
                    fontSize: "0.72rem", fontWeight: 700, flexShrink: 0,
                  }}>
                    {f.severity?.toUpperCase()}
                  </span>
                  <strong>{f.title}</strong>
                </div>
                <p>{f.description}</p>
                <p><b>Evidence:</b> {f.evidence}</p>
                {f.driftStatus && <p><b>Drift:</b> {f.driftStatus}</p>}
                {f.sources?.length > 0 && <p><b>Sources:</b> {f.sources.join(", ")}</p>}
                {f.confidence !== undefined && <p><b>Confidence:</b> {Number(f.confidence).toFixed(2)}</p>}
                {f.evidenceFields && (
                  <p><b>Evidence fields:</b> {Object.entries(f.evidenceFields).map(([k, v]) => `${k}=${v}`).join(", ")}</p>
                )}
                {f.businessTags?.length > 0 && <p><b>Business tags:</b> {f.businessTags.join(", ")}</p>}
                {f.exploitability && (
                  <p><b>Exploitability:</b> reachable={String(f.exploitability.reachable)}, role={f.exploitability.requiredRole || "n/a"}</p>
                )}
                <p><b>Fix:</b> {f.recommendation}</p>
                <div style={{ marginTop: "6px" }}>
                  <a
                    href={hackTricksUrl(f)}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: "inline-block",
                      padding: "2px 10px",
                      background: "rgba(124,58,237,0.15)",
                      border: "1px solid rgba(124,58,237,0.35)",
                      borderRadius: "4px",
                      color: "#c4b5fd",
                      fontSize: "0.72rem",
                      textDecoration: "none",
                    }}
                  >
                    🎩 HackTricks ↗
                  </a>
                </div>
                {(() => {
                  const current = (f.exploitability && f.exploitability.verifiedStatus) || "new";
                  const transitions = LIFECYCLE_TRANSITIONS[current] || [];
                  return (
                    <div style={{ marginTop: "6px", display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
                      <span className="meta" style={{ fontSize: "0.72rem" }}>Lifecycle: <b>{current}</b></span>
                      {transitions.map((next) => (
                        <button
                          key={next}
                          type="button"
                          onClick={() => transitionFinding(f.id, next, current)}
                          style={{
                            background: "rgba(124,58,237,0.15)",
                            color: "#fff",
                            border: "1px solid rgba(124,58,237,0.35)",
                            borderRadius: "4px",
                            padding: "2px 8px",
                            fontSize: "0.72rem",
                            cursor: "pointer",
                          }}
                        >
                          {next}
                        </button>
                      ))}
                      {lifecycleStatus[f.id] && <span className="meta" style={{ fontSize: "0.7rem" }}>{lifecycleStatus[f.id]}</span>}
                    </div>
                  );
                })()}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Screenshot lightbox */}
      {selectedScreenshot && (
        <div
          onClick={() => setSelectedScreenshot(null)}
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.88)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, cursor: "zoom-out" }}
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
