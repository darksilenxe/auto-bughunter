import { useMemo, useState } from "react";
import { API_BASE, API_KEY, WORKSPACE_ID, useScan } from "../context/ScanContext";
import { isAbortError, useAbortable } from "../lib/useAbortable";
import { impactGoalMeta, proofStateLabel, sortFindings, summarizeFindings } from "../lib/impact";

const HACKTRICKS_URLS = {
  xss: "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting",
  sqli: "https://book.hacktricks.xyz/pentesting-web/sql-injection",
  "sql injection": "https://book.hacktricks.xyz/pentesting-web/sql-injection",
  csrf: "https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery",
  ssrf: "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery",
  xxe: "https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity",
  rce: "https://book.hacktricks.xyz/pentesting-web/command-injection",
  "command injection": "https://book.hacktricks.xyz/pentesting-web/command-injection",
  "path traversal": "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
  lfi: "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
  rfi: "https://book.hacktricks.xyz/pentesting-web/file-inclusion",
  idor: "https://book.hacktricks.xyz/pentesting-web/idor",
  "open redirect": "https://book.hacktricks.xyz/pentesting-web/open-redirect",
  "request smuggling": "https://book.hacktricks.xyz/pentesting-web/http-request-smuggling",
  ssti: "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
  "template injection": "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
  clickjacking: "https://book.hacktricks.xyz/pentesting-web/clickjacking",
  jwt: "https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens",
  oauth: "https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover",
  "auth bypass": "https://book.hacktricks.xyz/pentesting-web/login-bypass",
  "broken access": "https://book.hacktricks.xyz/pentesting-web/broken-access-control",
  "mass assignment": "https://book.hacktricks.xyz/pentesting-web/mass-assignment",
};

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
  const haystack = `${finding.title || ""} ${finding.category || ""} ${finding.description || ""}`.toLowerCase();
  for (const [keyword, url] of Object.entries(HACKTRICKS_URLS)) {
    if (haystack.includes(keyword)) return url;
  }
  return "https://book.hacktricks.xyz/pentesting-web/web-vulnerabilities-methodology";
}

export default function Findings() {
  const { job, screenshots } = useScan();
  const [severityFilter, setSeverityFilter] = useState("all");
  const [proofFilter, setProofFilter] = useState("all");
  const [selectedScreenshot, setSelectedScreenshot] = useState(null);
  const [lifecycleStatus, setLifecycleStatus] = useState({});
  const newController = useAbortable();

  async function transitionFinding(findingId, nextStatus, currentStatus) {
    if (!job?.id) return;
    if (!findingId) return;
    const ownerNeeded = nextStatus === "accepted" || nextStatus === "remediated";
    let owner = "";
    if (ownerNeeded) {
      owner = window.prompt(`Owner email or handle for "${nextStatus}" transition?`) || "";
      if (!owner.trim()) {
        setLifecycleStatus((prev) => ({ ...prev, [findingId]: "Owner required for this transition." }));
        return;
      }
    }

    setLifecycleStatus((prev) => ({ ...prev, [findingId]: "Updating…" }));
    const ac = newController();
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
        signal: ac.signal,
      });
      const data = await res.json();
      if (ac.signal.aborted) return;
      if (!res.ok) {
        setLifecycleStatus((prev) => ({ ...prev, [findingId]: data.error || `Failed (${res.status})` }));
        return;
      }
      setLifecycleStatus((prev) => ({
        ...prev,
        [findingId]: `${currentStatus || "new"} → ${data.status}${data.owner ? ` (owner: ${data.owner})` : ""}`,
      }));
    } catch (err) {
      if (isAbortError(err)) return;
      setLifecycleStatus((prev) => ({ ...prev, [findingId]: err.message || "Network error" }));
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
          No scan loaded yet. Start an autonomous engagement from the dashboard.
        </section>
      </div>
    );
  }

  const findings = sortFindings(job.findings || []);
  const summary = summarizeFindings(findings);
  const filteredFindings = findings.filter((finding) => {
    const severityValue = (finding.severity || "info").toLowerCase();
    const severityMatches = severityFilter === "all" || severityValue === severityFilter;
    const proofMatches = proofFilter === "all" || (finding.proofState || "suspected") === proofFilter;
    return severityMatches && proofMatches;
  });

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
            <p className="meta">Filter by severity and proof state, then validate what a bug bounty triager would actually reward.</p>
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
            <span className="stat-card__label">Critical / High severity</span>
            <div className="stat-card__value">{summary.severities.critical + summary.severities.high}</div>
            <div className="stat-card__hint">Most urgent exposures based on severity, even when proof is still maturing.</div>
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
            {["all", "critical", "high", "medium", "low", "info"].map((severity) => (
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

        <div className="filter-row" style={{ marginTop: 12, marginBottom: 14 }}>
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

        {filteredFindings.length === 0 ? (
          <div className="empty-state">No findings match the selected severity / proof filters.</div>
        ) : (
          <ul className="findings">
            {filteredFindings.map((finding, idx) => {
              const currentLifecycle = finding.exploitability?.verifiedStatus || "new";
              const transitions = LIFECYCLE_TRANSITIONS[currentLifecycle] || [];
              const severityValue = (finding.severity || "info").toLowerCase();
              const canTransition = Boolean(finding.id);

              return (
                <li key={finding.id || idx} className="finding-card">
                  <div className="finding-card__header">
                    <div>
                      <div className="inline-metrics" style={{ marginBottom: 8 }}>
                        <span className={`severity-badge ${severityValue}`}>{severityValue.toUpperCase()}</span>
                        <span className={`proof-badge ${finding.proofState || "suspected"}`}>{proofStateLabel(finding.proofState)}</span>
                        <span className="chip chip--muted">Bounty {(Number(finding.bountyScore || 0) * 100).toFixed(0)}%</span>
                        <span className="chip chip--muted">Impact {(Number(finding.impactScore || 0) * 100).toFixed(0)}%</span>
                      </div>
                      <h3 className="finding-card__title">{finding.title}</h3>
                      <div className="meta">#{finding.id || "finding"} · {finding.category || "uncategorized"}</div>
                    </div>
                    <div className="button-row">
                      <a href={hackTricksUrl(finding)} target="_blank" rel="noopener noreferrer" className="button-secondary button-link">
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
                        <div className="surface">
                          <strong>Reproduction steps</strong>
                          {finding.reproductionSteps?.length ? (
                            <ol className="bullet-list" style={{ marginTop: 10 }}>
                              {finding.reproductionSteps.map((step, stepIdx) => <li key={stepIdx}>{step}</li>)}
                            </ol>
                          ) : (
                            <p className="meta" style={{ marginTop: 8 }}>No reproduction steps recorded.</p>
                          )}
                        </div>
                        <div className="surface">
                          <strong>Proof of concept</strong>
                          {finding.poc ? <pre className="summary" style={{ marginTop: 10 }}>{finding.poc}</pre> : <p className="meta" style={{ marginTop: 8 }}>No PoC payload recorded.</p>}
                        </div>
                      </div>
                    )}

                    <div>
                      <strong>Remediation</strong>
                      <p className="meta" style={{ marginTop: 8 }}>{finding.recommendation || "No remediation guidance captured."}</p>
                    </div>

                    {transitions.length > 0 && (
                      <div className="button-row">
                        {!canTransition && (
                          <span className="meta">Lifecycle updates are unavailable until this finding has an ID.</span>
                        )}
                        {transitions.map((nextStatus) => (
                          <button
                            key={nextStatus}
                            type="button"
                            className="button-secondary"
                            onClick={() => transitionFinding(finding.id, nextStatus, currentLifecycle)}
                            disabled={!canTransition}
                          >
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
