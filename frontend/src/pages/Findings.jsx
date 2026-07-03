import { useCallback, useMemo, useRef, useState } from "react";
import { useToast } from "../components/Toast";
import { API_BASE, getAPIKey, getWorkspaceID, useScan } from "../context/ScanContext";
import { impactGoalMeta, proofStateLabel, sortFindings, summarizeFindings } from "../lib/impact";
import { coverageReferenceForFinding } from "../lib/webVulnerabilityCoverage";

const LIFECYCLE_TRANSITIONS = {
  "": ["verified", "rejected", "suppressed"],
  new: ["verified", "rejected", "suppressed"],
  verified: ["accepted", "remediated", "suppressed", "rejected"],
  rejected: ["verified"],
  accepted: ["remediated", "suppressed"],
  suppressed: ["verified"],
  remediated: ["verified"],
};

function hackTricksUrl(finding) {
  return coverageReferenceForFinding(finding) || "https://hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology";
}

export default function Findings() {
  const { job, screenshots, scanId } = useScan();
  const { toast } = useToast();
  const [severityFilter, setSeverityFilter] = useState("all");
  const [proofFilter, setProofFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedScreenshot, setSelectedScreenshot] = useState(null);
  const [lifecycleStatus, setLifecycleStatus] = useState({});
  const [localLifecycle, setLocalLifecycle] = useState({});
  // Inline owner input: maps findingId -> pending next status requiring owner
  const [pendingOwnerInput, setPendingOwnerInput] = useState({});
  const [ownerInputValue, setOwnerInputValue] = useState({});
  // Operator notes persisted in localStorage
  const [notes, setNotes] = useState(() => {
    try { return JSON.parse(localStorage.getItem("finding_notes") || "{}"); } catch { return {}; }
  });
  // Probe history per finding
  const [probeHistories, setProbeHistories] = useState({});
  const [probeLoading, setProbeLoading] = useState({});
  // Bulk selection
  const [selected, setSelected] = useState(new Set());

  const searchTimerRef = useRef(null);
  const [debouncedSearch, setDebouncedSearch] = useState("");

  function handleSearchChange(value) {
    setSearchQuery(value);
    clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => setDebouncedSearch(value), 250);
  }

  function saveNote(findingId, value) {
    const key = `${scanId}::${findingId}`;
    const updated = { ...notes, [key]: value };
    setNotes(updated);
    localStorage.setItem("finding_notes", JSON.stringify(updated));
  }

  async function loadProbeHistory(findingId) {
    if (!job?.id || probeHistories[findingId]) return;
    setProbeLoading((prev) => ({ ...prev, [findingId]: true }));
    try {
      const apiKey = getAPIKey();
      const workspaceID = getWorkspaceID();
      const res = await fetch(
        `${API_BASE}/api/scan/${encodeURIComponent(job.id)}/probes?findingId=${encodeURIComponent(findingId)}&workspaceId=${encodeURIComponent(workspaceID)}`,
        { headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceID } }
      );
      if (res.ok) {
        const data = await res.json();
        setProbeHistories((prev) => ({ ...prev, [findingId]: Array.isArray(data) ? data : (data.probes || []) }));
      } else {
        setProbeHistories((prev) => ({ ...prev, [findingId]: [] }));
      }
    } catch {
      setProbeHistories((prev) => ({ ...prev, [findingId]: [] }));
    } finally {
      setProbeLoading((prev) => ({ ...prev, [findingId]: false }));
    }
  }

  async function transitionFinding(findingId, nextStatus, currentStatus, ownerOverride) {
    if (!job?.id) return;
    const ownerNeeded = nextStatus === "accepted" || nextStatus === "remediated";
    let owner = ownerOverride || "";
    if (ownerNeeded && !owner) {
      // Show inline input instead of prompt
      setPendingOwnerInput((prev) => ({ ...prev, [findingId]: nextStatus }));
      return;
    }

    setLifecycleStatus((prev) => ({ ...prev, [findingId]: "Updating…" }));
    try {
      const apiKey = getAPIKey();
      const workspaceID = getWorkspaceID();
      const res = await fetch(`${API_BASE}/api/finding-verification`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey, "X-Workspace-ID": workspaceID },
        body: JSON.stringify({ scanId: job.id, findingId, status: nextStatus, owner: owner.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        const msg = data.error || `Failed (${res.status})`;
        setLifecycleStatus((prev) => ({ ...prev, [findingId]: msg }));
        toast(msg, { type: "error" });
        return;
      }
      setLocalLifecycle((prev) => ({ ...prev, [findingId]: data.status }));
      const msg = `${currentStatus || "new"} → ${data.status}${data.owner ? ` (owner: ${data.owner})` : ""}`;
      setLifecycleStatus((prev) => ({ ...prev, [findingId]: msg }));
      setPendingOwnerInput((prev) => { const n = { ...prev }; delete n[findingId]; return n; });
      setOwnerInputValue((prev) => { const n = { ...prev }; delete n[findingId]; return n; });
      toast(`Finding ${nextStatus}`, { type: "success" });
    } catch (err) {
      const msg = err.message || "Network error";
      setLifecycleStatus((prev) => ({ ...prev, [findingId]: msg }));
      toast(msg, { type: "error" });
    }
  }

  async function bulkTransition(nextStatus) {
    if (!job?.id || selected.size === 0) return;
    const ids = Array.from(selected);
    await Promise.all(ids.map((id) => transitionFinding(id, nextStatus, localLifecycle[id] || "new", "")));
    setSelected(new Set());
    toast(`${ids.length} findings marked ${nextStatus}`, { type: "success" });
  }

  function exportSelected() {
    if (!job) return;
    const findings = (job.findings || []).filter((f) => selected.has(f.id));
    const blob = new Blob([JSON.stringify(findings, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `findings-export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast(`${findings.length} findings exported`, { type: "success" });
  }

  function toggleSelect(id) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleSelectAll(ids) {
    if (ids.every((id) => selected.has(id))) {
      setSelected((prev) => { const n = new Set(prev); ids.forEach((id) => n.delete(id)); return n; });
    } else {
      setSelected((prev) => { const n = new Set(prev); ids.forEach((id) => n.add(id)); return n; });
    }
  }

  if (!job) {
    return (
      <div className="page">
        <header>
          <h1>Impact triage board</h1>
          <p>Run a scan to see proof-state driven findings, artifacts, and bounty-prioritized triage.</p>
        </header>
        <section className="card empty-state">
          <div style={{ fontSize: "2rem", marginBottom: 12 }}>◎</div>
          No scan loaded yet. Start an autonomous engagement from the dashboard.
        </section>
      </div>
    );
  }

  const findings = sortFindings(job.findings || []);
  const summary = summarizeFindings(findings);

  // Derive unique categories for category filter
  const allCategories = ["all", ...Array.from(new Set(findings.map((f) => f.category).filter(Boolean))).sort()];

  const filteredFindings = findings.filter((finding) => {
    if (severityFilter !== "all" && finding.severity !== severityFilter) return false;
    if (proofFilter !== "all" && (finding.proofState || "suspected") !== proofFilter) return false;
    if (categoryFilter !== "all" && finding.category !== categoryFilter) return false;
    if (debouncedSearch.trim()) {
      const q = debouncedSearch.toLowerCase();
      return (
        (finding.title || "").toLowerCase().includes(q) ||
        (finding.description || "").toLowerCase().includes(q) ||
        (finding.affectedUrl || "").toLowerCase().includes(q) ||
        (finding.evidence || "").toLowerCase().includes(q) ||
        (finding.category || "").toLowerCase().includes(q)
      );
    }
    return true;
  });

  const filteredIds = filteredFindings.map((f) => f.id).filter(Boolean);

  return (
    <div className="page page--wide">
      <header>
        <h1>Impact triage board</h1>
        <p>
          Target <strong>{job.target}</strong> · status <strong>{job.status}</strong> · findings sorted by bounty value and proof maturity.
        </p>
      </header>

      <section className="hero-panel">
        <div className="toolbar" style={{ alignItems: "flex-start" }}>
          <div>
            <div className="eyebrow">Reportability first</div>
            <h2 style={{ fontSize: "1.4rem", marginBottom: 8 }}>Promote weak signal into submission-ready outcomes</h2>
            <p className="meta">Filter by severity, proof state, and category, then validate what a bug bounty triager would reward.</p>
          </div>
          <div className="filter-row">
            <span className="chip chip--goal">{summary.submissionReady} submission-ready</span>
            <span className="chip">{summary.demonstrated} impact-demonstrated</span>
          </div>
        </div>

        <div className="metrics-grid" style={{ marginTop: 18 }}>
          <article className="stat-card">
            <span className="stat-card__label">Top bounty score</span>
            <div className="stat-card__value">{((Number(summary.topFinding?.bountyScore || 0)) * 100).toFixed(0)}%</div>
            <div className="stat-card__hint">{summary.topFinding?.title || "Awaiting validated findings"}</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Proof artifacts</span>
            <div className="stat-card__value">{summary.proofArtifacts}</div>
            <div className="stat-card__hint">Before/after diffs, role evidence, curl reproducers, and screenshots.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">High severity</span>
            <div className="stat-card__value">{summary.severities.high}</div>
            <div className="stat-card__hint">Still visible, but ranked below higher proof-value outcomes when needed.</div>
          </article>
        </div>
      </section>

      {screenshots.length > 0 && (
        <section className="card">
          <div className="toolbar">
            <div>
              <h2>Captured evidence gallery</h2>
              <p className="meta">Attack-path screenshots gathered during scan execution.</p>
            </div>
            <span className="chip chip--muted">{screenshots.length} screenshots</span>
          </div>
          <div className="three-column-grid" style={{ marginTop: 14 }}>
            {screenshots.map((s, idx) => (
              <button
                key={idx}
                type="button"
                className="surface"
                style={{ textAlign: "left", cursor: "pointer", padding: 0, overflow: "hidden" }}
                onClick={() => setSelectedScreenshot(s.b64)}
                title={s.message}
              >
                <img src={`data:image/png;base64,${s.b64}`} alt={`Screenshot ${idx + 1}`} style={{ width: "100%", height: 180, objectFit: "cover", display: "block" }} />
                <div style={{ padding: 12 }}>
                  <div style={{ fontWeight: 700 }}>{s.agentName || "scanner"}</div>
                  <div className="meta">{s.message || `Evidence ${idx + 1}`}</div>
                </div>
              </button>
            ))}
          </div>
        </section>
      )}

      <section className="card">
        <div className="toolbar" style={{ alignItems: "flex-start" }}>
          <div>
            <h2>Bounty-oriented finding queue</h2>
            <p className="meta">Each finding surfaces impact narrative, proof state, exploitability, goals, artifacts, and triage actions.</p>
          </div>
          <div className="filter-row">
            {["all", "high", "medium", "low", "info"].map((severity) => (
              <button
                key={severity}
                type="button"
                className={`filter-chip ${severityFilter === severity ? "is-active" : ""}`}
                onClick={() => setSeverityFilter(severity)}
              >
                {severity === "all" ? `All (${findings.length})` : `${severity} (${summary.severities[severity] || 0})`}
              </button>
            ))}
          </div>
        </div>

        <div className="filter-row" style={{ marginTop: 10 }}>
          {["all", "suspected", "validated", "exploited", "impact_demonstrated", "submission_ready"].map((state) => (
            <button
              key={state}
              type="button"
              className={`filter-chip ${proofFilter === state ? "is-active" : ""}`}
              onClick={() => setProofFilter(state)}
            >
              {state === "all" ? "All proof states" : proofStateLabel(state)}
            </button>
          ))}
        </div>

        {allCategories.length > 2 && (
          <div className="filter-row" style={{ marginTop: 8 }}>
            {allCategories.map((cat) => (
              <button
                key={cat}
                type="button"
                className={`filter-chip ${categoryFilter === cat ? "is-active" : ""}`}
                onClick={() => setCategoryFilter(cat)}
              >
                {cat === "all" ? "All categories" : `${cat} (${findings.filter((f) => f.category === cat).length})`}
              </button>
            ))}
          </div>
        )}

        <div style={{ marginTop: 10, marginBottom: 14 }}>
          <input
            value={searchQuery}
            onChange={(e) => handleSearchChange(e.target.value)}
            placeholder="Search title, description, URL, evidence…"
          />
        </div>

        {/* Bulk action toolbar */}
        {selected.size > 0 && (
          <div className="bulk-action-bar">
            <span className="chip chip--muted">{selected.size} selected</span>
            <button type="button" className="button-secondary" onClick={() => bulkTransition("suppressed")}>Bulk suppress</button>
            <button type="button" className="button-secondary" onClick={() => bulkTransition("accepted")}>Bulk accept</button>
            <button type="button" className="button-secondary" onClick={exportSelected}>Export selected</button>
            <button type="button" className="button-ghost" onClick={() => setSelected(new Set())}>Clear selection</button>
          </div>
        )}

        {filteredFindings.length === 0 ? (
          <div className="empty-state">
            <div style={{ fontSize: "2rem", marginBottom: 10 }}>◎</div>
            No findings match the selected filters.
          </div>
        ) : (
          <>
            <div style={{ marginBottom: 10, display: "flex", alignItems: "center", gap: 10 }}>
              <input
                type="checkbox"
                id="select-all"
                checked={filteredIds.length > 0 && filteredIds.every((id) => selected.has(id))}
                onChange={() => toggleSelectAll(filteredIds)}
              />
              <label htmlFor="select-all" className="meta" style={{ cursor: "pointer" }}>Select all visible</label>
            </div>
            <ul className="findings">
              {filteredFindings.map((finding, idx) => {
                const currentLifecycle = localLifecycle[finding.id] || finding.exploitability?.verifiedStatus || "new";
                const transitions = LIFECYCLE_TRANSITIONS[currentLifecycle] || [];
                const noteKey = `${scanId}::${finding.id}`;
                const noteValue = notes[noteKey] || "";
                const pendingNext = pendingOwnerInput[finding.id];
                const probes = probeHistories[finding.id];

                return (
                  <li key={finding.id || idx} className="finding-card">
                    <div className="finding-card__header">
                      <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                        <input
                          type="checkbox"
                          checked={selected.has(finding.id)}
                          onChange={() => toggleSelect(finding.id)}
                          style={{ marginTop: 4, flexShrink: 0 }}
                        />
                        <div>
                          <div className="inline-metrics" style={{ marginBottom: 8 }}>
                            <span className={`severity-badge ${finding.severity || "info"}`}>{(finding.severity || "info").toUpperCase()}</span>
                            <span className={`proof-badge ${finding.proofState || "suspected"}`}>{proofStateLabel(finding.proofState)}</span>
                            {finding.triageLabel && (
                              <span className="chip" style={{ background: "rgba(124,92,255,0.14)", color: "#c084fc" }}>{finding.triageLabel}</span>
                            )}
                            {finding.cvss && (
                              <span className="chip chip--muted">CVSS {Number(finding.cvss).toFixed(1)}</span>
                            )}
                            <span className="chip chip--muted">Bounty {(Number(finding.bountyScore || 0) * 100).toFixed(0)}%</span>
                            <span className="chip chip--muted">Impact {(Number(finding.impactScore || 0) * 100).toFixed(0)}%</span>
                          </div>
                          <h3 className="finding-card__title">{finding.title}</h3>
                          <div className="meta">#{finding.id || "finding"} · {finding.category || "uncategorized"}</div>
                        </div>
                      </div>
                      <div className="button-row">
                        <a href={hackTricksUrl(finding)} target="_blank" rel="noopener noreferrer" className="button-link">
                          HackTricks
                        </a>
                      </div>
                    </div>

                    <div className="finding-card__body">
                      {finding.impact && (
                        <div className="finding-card__insight">
                          <b style={{ display: "block", marginBottom: 6 }}>Why this matters</b>
                          <div>{finding.impact}</div>
                        </div>
                      )}

                      <div className="finding-card__meta">
                        <div className="meta-block">
                          <b>Exploitability</b>
                          <div>Reachable: {String(Boolean(finding.exploitability?.reachable))}</div>
                          <div>Role: {finding.exploitability?.requiredRole || "n/a"}</div>
                          <div>Confidence: {Number(finding.confidence || 0).toFixed(2)}</div>
                        </div>
                        <div className="meta-block">
                          <b>Affected surface</b>
                          <div>{finding.affectedUrl || "n/a"}</div>
                          <div className="meta">Parameter: {finding.affectedParameter || "n/a"}</div>
                        </div>
                        <div className="meta-block">
                          <b>Lifecycle</b>
                          <div>{currentLifecycle}</div>
                          {lifecycleStatus[finding.id] && <div className="meta" style={{ marginTop: 6 }}>{lifecycleStatus[finding.id]}</div>}
                        </div>
                      </div>

                      {(finding.impactGoals?.length > 0 || finding.businessTags?.length > 0) && (
                        <div>
                          <strong>Impact context</strong>
                          <div className="filter-row" style={{ marginTop: 8 }}>
                            {(finding.impactGoals || []).map((goal) => (
                              <span key={goal} className="chip chip--goal">{impactGoalMeta(goal).label}</span>
                            ))}
                            {(finding.businessTags || []).slice(0, 4).map((tag) => (
                              <span key={tag} className="chip chip--muted">{tag}</span>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="two-column-grid">
                        <div className="surface">
                          <strong>Evidence</strong>
                          <p className="meta" style={{ marginTop: 8 }}>{finding.evidence || "No raw evidence captured."}</p>
                          {finding.evidenceFields && Object.keys(finding.evidenceFields).length > 0 && (
                            <ul className="artifact-list" style={{ marginTop: 10 }}>
                              {Object.entries(finding.evidenceFields).slice(0, 8).map(([key, value]) => (
                                <li key={key}><b>{key}:</b> {String(value)}</li>
                              ))}
                            </ul>
                          )}
                        </div>

                        <div className="surface">
                          <strong>Proof artifacts</strong>
                          {finding.proofArtifacts?.length ? (
                            <ul className="artifact-list" style={{ marginTop: 10 }}>
                              {finding.proofArtifacts.map((artifact, artifactIdx) => (
                                <li key={`${artifact.type}-${artifactIdx}`}>
                                  <b>{artifact.label || artifact.type}:</b> {artifact.value || artifact.description || "captured"}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="meta" style={{ marginTop: 8 }}>No structured proof artifacts were attached.</p>
                          )}
                        </div>
                      </div>

                      {(finding.reproductionSteps?.length > 0 || finding.poc) && (
                        <div className="two-column-grid">
                          <div className="surface" style={{ overflowY: "auto", maxHeight: "300px" }}>
                            <strong>Reproduction steps</strong>
                            {finding.reproductionSteps?.length ? (
                              <ol className="bullet-list" style={{ marginTop: 10 }}>
                                {finding.reproductionSteps.map((step, stepIdx) => <li key={stepIdx}>{step}</li>)}
                              </ol>
                            ) : (
                              <p className="meta" style={{ marginTop: 8 }}>No reproduction steps recorded.</p>
                            )}
                          </div>
                          <div className="surface" style={{ overflowY: "auto", maxHeight: "300px" }}>
                            <strong>Proof of concept</strong>
                            {finding.poc ? <pre className="summary" style={{ marginTop: 10 }}>{finding.poc}</pre> : <p className="meta" style={{ marginTop: 8 }}>No PoC payload recorded.</p>}
                          </div>
                        </div>
                      )}

                      <div>
                        <strong>Remediation</strong>
                        <p className="meta" style={{ marginTop: 8 }}>{finding.recommendation || "No remediation guidance captured."}</p>
                      </div>

                      {/* Operator notes */}
                      <div>
                        <strong>Operator notes</strong>
                        <textarea
                          rows={2}
                          style={{ marginTop: 8, minHeight: 60 }}
                          value={noteValue}
                          placeholder="Add private triage notes (saved locally)…"
                          onChange={(e) => saveNote(finding.id, e.target.value)}
                        />
                      </div>

                      {/* Probe history */}
                      <details onToggle={(e) => { if (e.target.open) loadProbeHistory(finding.id); }}>
                        <summary>Probe history</summary>
                        {probeLoading[finding.id] ? (
                          <p className="meta" style={{ marginTop: 8 }}>Loading probes…</p>
                        ) : probes?.length ? (
                          <div className="table-wrap" style={{ marginTop: 10 }}>
                            <table>
                              <thead>
                                <tr>
                                  <th>Category</th>
                                  <th>Endpoint</th>
                                  <th>Param</th>
                                  <th>Outcome</th>
                                  <th>Status</th>
                                </tr>
                              </thead>
                              <tbody>
                                {probes.map((p, pi) => (
                                  <tr key={pi}>
                                    <td><span className="chip chip--muted">{p.category || "—"}</span></td>
                                    <td className="meta" style={{ wordBreak: "break-all", maxWidth: 180 }}>{p.endpoint || "—"}</td>
                                    <td>{p.paramName || "—"}</td>
                                    <td style={{ fontWeight: 700, color: p.outcome === "confirmed" ? "#47d7ac" : p.outcome === "signal" ? "#59d0ff" : "#7c8aa5" }}>{p.outcome || "—"}</td>
                                    <td>{p.statusCode || "—"}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <p className="meta" style={{ marginTop: 8 }}>{probes === undefined ? "Open to load probe history." : "No probe records found for this finding."}</p>
                        )}
                      </details>

                      {/* Inline owner input for transitions requiring owner */}
                      {pendingNext && (
                        <div className="cancel-confirm-strip">
                          <span>Owner email / handle for <strong>{pendingNext}</strong> transition:</span>
                          <input
                            value={ownerInputValue[finding.id] || ""}
                            onChange={(e) => setOwnerInputValue((prev) => ({ ...prev, [finding.id]: e.target.value }))}
                            placeholder="owner@example.com"
                            style={{ flex: 1, minWidth: 0 }}
                          />
                          <button
                            type="button"
                            className="button-secondary"
                            disabled={!(ownerInputValue[finding.id] || "").trim()}
                            onClick={() => transitionFinding(finding.id, pendingNext, currentLifecycle, ownerInputValue[finding.id])}
                          >
                            Confirm
                          </button>
                          <button
                            type="button"
                            className="button-ghost"
                            onClick={() => { setPendingOwnerInput((p) => { const n = { ...p }; delete n[finding.id]; return n; }); }}
                          >
                            Cancel
                          </button>
                        </div>
                      )}

                      {transitions.length > 0 && !pendingNext && (
                        <div className="button-row">
                          {transitions.map((nextStatus) => (
                            <button key={nextStatus} type="button" className="button-secondary" onClick={() => transitionFinding(finding.id, nextStatus, currentLifecycle)}>
                              Mark {nextStatus}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </section>

      {selectedScreenshot && (
        <div onClick={() => setSelectedScreenshot(null)} style={{ position: "fixed", inset: 0, background: "rgba(1,4,12,0.86)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, cursor: "zoom-out" }}>
          <img src={`data:image/png;base64,${selectedScreenshot}`} alt="Screenshot" style={{ maxWidth: "92vw", maxHeight: "92vh", borderRadius: 18 }} onClick={(e) => e.stopPropagation()} />
          <button type="button" className="button-ghost" style={{ position: "absolute", top: 20, right: 20 }} onClick={() => setSelectedScreenshot(null)}>Close</button>
        </div>
      )}
    </div>
  );
}
