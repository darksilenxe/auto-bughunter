import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import SecurityKnowledgePanel from "../components/SecurityKnowledgePanel";
import { API_BASE, getAPIKey, getWorkspaceID, useScan } from "../context/ScanContext";
import { proofStateLabel, sortFindings, summarizeFindings } from "../lib/impact";

const SUBMISSION_CHECKS = [
  { id: "poc", label: "Proof of concept (PoC) payload is present" },
  { id: "steps", label: "Reproduction steps are included" },
  { id: "cvss", label: "CVSS score is recorded" },
  { id: "remediation", label: "Remediation / fix guidance is provided" },
  { id: "scope", label: "Affected URL is within program scope" },
];

export default function Reports() {
  const { job, scanId, screenshots } = useScan();
  const [selectedScreenshot, setSelectedScreenshot] = useState(null);
  const [format, setFormat] = useState("pdf");
  const [reportType, setReportType] = useState("pentest");
  const [showOptions, setShowOptions] = useState(false);
  const [companyName, setCompanyName] = useState("");
  const [classification, setClassification] = useState("");
  const [contact, setContact] = useState("");
  const [programHandle, setProgramHandle] = useState("");
  const [logoPath, setLogoPath] = useState("");
  const [optionsStatus, setOptionsStatus] = useState("");
  const [copyStatus, setCopyStatus] = useState({});
  const [checklist, setChecklist] = useState({});
  const [showChecklist, setShowChecklist] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [previewURL, setPreviewURL] = useState("");

  const findings = useMemo(() => sortFindings(job?.findings || []), [job?.findings]);
  const summary = useMemo(() => summarizeFindings(findings), [findings]);
  const highMedFindings = useMemo(
    () => findings.filter((f) => f.severity === "high" || f.severity === "medium"),
    [findings]
  );

  if (!job) {
    return (
      <div className="page">
        <header>
          <h1>Submission center</h1>
          <p>Generate polished pentest and bug bounty reports after a scan completes.</p>
        </header>
        <section className="card empty-state">
          <div style={{ fontSize: "2rem", marginBottom: 10 }}>📋</div>
          No scan data available. Run an engagement from the dashboard first, or{" "}
          <Link to="/scans">load a past scan from Engagement History</Link>.
        </section>
      </div>
    );
  }

  const reportURL = (overrides = {}) => {
    const workspaceId = getWorkspaceID();
    const params = new URLSearchParams();
    params.set("format", overrides.format || format);
    params.set("type", overrides.type || reportType);
    params.set("workspaceId", workspaceId);
    if (companyName) params.set("companyName", companyName);
    if (classification) params.set("classification", classification);
    if (contact) params.set("contact", contact);
    if (programHandle) params.set("programHandle", programHandle);
    if (logoPath) params.set("logoPath", logoPath);
    return `${API_BASE}/api/report/${scanId}?${params.toString()}`;
  };

  const filenameFor = () => {
    const ext = format === "md" ? "md" : format === "html" ? "html" : format === "json" ? "json" : "pdf";
    const base = reportType === "executive" ? "executive-summary" : "scan-report";
    return `${base}-${scanId}.${ext}`;
  };

  const submitTemplateOptions = async () => {
    setOptionsStatus("Generating...");
    try {
      const apiKey = getAPIKey();
      const workspaceId = getWorkspaceID();
      const res = await fetch(reportURL(), {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey, "X-Workspace-ID": workspaceId },
        body: JSON.stringify({ companyName, classification, contact, programHandle, logoPath, reportType }),
      });
      if (!res.ok) {
        setOptionsStatus(`Error ${res.status}`);
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filenameFor();
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setOptionsStatus("Downloaded");
    } catch (err) {
      setOptionsStatus(`Error: ${err.message}`);
    }
  };

  const downloadWithAuth = async (url, filename) => {
    const apiKey = getAPIKey();
    const workspaceId = getWorkspaceID();
    const res = await fetch(url, { headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceId } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const objectURL = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectURL;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectURL);
  };

  const togglePreview = async () => {
    if (showPreview) {
      setShowPreview(false);
      if (previewURL) URL.revokeObjectURL(previewURL);
      setPreviewURL("");
      return;
    }
    const apiKey = getAPIKey();
    const workspaceId = getWorkspaceID();
    const res = await fetch(reportURL({ format: "html" }), { headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceId } });
    if (!res.ok) return;
    const blob = await res.blob();
    setPreviewURL(URL.createObjectURL(blob));
    setShowPreview(true);
  };

  const copyBugBountySubmission = async (finding) => {
    const apiKey = getAPIKey();
    const workspaceId = getWorkspaceID();
    const url = `${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=md&workspaceId=${encodeURIComponent(workspaceId)}`;
    try {
      const res = await fetch(url, { headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceId } });
      if (!res.ok) {
        setCopyStatus((prev) => ({ ...prev, [finding.id]: `Error ${res.status}` }));
        return;
      }
      const text = await res.text();
      await navigator.clipboard.writeText(text);
      setCopyStatus((prev) => ({ ...prev, [finding.id]: "Copied!" }));
      setTimeout(() => setCopyStatus((prev) => ({ ...prev, [finding.id]: "" })), 2000);
    } catch (err) {
      setCopyStatus((prev) => ({ ...prev, [finding.id]: `Error: ${err.message}` }));
    }
  };

  const copyFindingMarkdown = async (finding) => {
    const lines = [
      `## ${finding.title}`,
      `**Severity:** ${(finding.severity || "info").toUpperCase()}${finding.cvss ? `  |  **CVSS:** ${Number(finding.cvss).toFixed(1)}` : ""}`,
      `**Affected URL:** ${finding.affectedUrl || "n/a"}`,
      `**Category:** ${finding.category || "n/a"}`,
      "",
      `### Description`,
      finding.description || finding.impact || "No description provided.",
      "",
      `### Proof of Concept`,
      finding.poc || "No PoC recorded.",
      "",
      `### Reproduction Steps`,
      ...(finding.reproductionSteps?.length
        ? finding.reproductionSteps.map((s, i) => `${i + 1}. ${s}`)
        : ["No reproduction steps recorded."]),
      "",
      `### Remediation`,
      finding.recommendation || "No remediation guidance captured.",
    ];
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopyStatus((prev) => ({ ...prev, [finding.id + "_md"]: "Copied!" }));
      setTimeout(() => setCopyStatus((prev) => ({ ...prev, [finding.id + "_md"]: "" })), 2000);
    } catch {
      setCopyStatus((prev) => ({ ...prev, [finding.id + "_md"]: "Failed" }));
    }
  };

  const allChecked = SUBMISSION_CHECKS.every((c) => checklist[c.id]);

  return (
    <div className="page page--wide">
      <section className="hero-panel">
        <div className="toolbar" style={{ alignItems: "flex-start" }}>
          <div>
            <div className="eyebrow">Submission-ready reporting</div>
            <header style={{ marginBottom: 0 }}>
              <h1>Bug bounty & pentest report workspace</h1>
              <p>Package proof-state aware findings into premium-looking downloads, per-finding submissions, and executive deliverables.</p>
            </header>
          </div>
          <div className="filter-row">
            <span className="chip chip--goal">{summary.submissionReady} ready to submit</span>
            <span className="chip">{summary.demonstrated} impact-demonstrated</span>
          </div>
        </div>

        <div className="metrics-grid" style={{ marginTop: 18 }}>
          <article className="stat-card">
            <span className="stat-card__label">Top bounty score</span>
            <div className="stat-card__value">{(Number(summary.topFinding?.bountyScore || 0) * 100).toFixed(0)}%</div>
            <div className="stat-card__hint">{summary.topFinding?.title || "No findings yet"}</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Proof artifacts</span>
            <div className="stat-card__value">{summary.proofArtifacts}</div>
            <div className="stat-card__hint">Reusable evidence that maps cleanly into submission forms.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Bundle target</span>
            <div className="stat-card__value">{job.target?.replace(/^https?:\/\//, "") || "target"}</div>
            <div className="stat-card__hint">Current engagement asset for all generated reports.</div>
          </article>
        </div>
      </section>

      {/* Submission checklist */}
      {highMedFindings.length > 0 && (
        <section className="card">
          <div className="toolbar">
            <div>
              <h2>Submission checklist</h2>
              <p className="meta">Verify common requirements are met for high and medium severity findings before generating a report.</p>
            </div>
            <button type="button" className="button-ghost" onClick={() => setShowChecklist((v) => !v)}>
              {showChecklist ? "Hide" : "Show"} checklist
            </button>
          </div>
          {showChecklist && (
            <div style={{ marginTop: 14 }}>
              {SUBMISSION_CHECKS.map((check) => (
                <label key={check.id} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={!!checklist[check.id]}
                    onChange={(e) => setChecklist((prev) => ({ ...prev, [check.id]: e.target.checked }))}
                  />
                  <span style={{ color: checklist[check.id] ? "#47d7ac" : undefined }}>{check.label}</span>
                </label>
              ))}
              {!allChecked && (
                <p className="meta" style={{ color: "#ffad66", marginTop: 6 }}>
                  {SUBMISSION_CHECKS.filter((c) => !checklist[c.id]).length} item(s) unchecked — verify before submitting.
                </p>
              )}
              {allChecked && <p className="meta" style={{ color: "#47d7ac", marginTop: 6 }}>✔ All checklist items confirmed.</p>}
            </div>
          )}
        </section>
      )}

      {job.status === "completed" && scanId && (
        <section className="card">
          <div className="toolbar" style={{ alignItems: "flex-start" }}>
            <div>
              <h2>Generate deliverables</h2>
              <p className="meta">Choose a format, then export a full pentest report or a per-finding bounty submission bundle.</p>
            </div>
            <div className="button-row">
              <button type="button" className="button-secondary" onClick={() => setShowOptions(true)}>Customize template</button>
            </div>
          </div>

          <div className="form-grid" style={{ marginTop: 14 }}>
            <label>
              Format
              <select value={format} onChange={(e) => { setFormat(e.target.value); setShowPreview(false); }}>
                <option value="pdf">PDF</option>
                <option value="md">Markdown</option>
                <option value="html">HTML</option>
                <option value="json">JSON</option>
              </select>
            </label>
            <label>
              Report type
              <select value={reportType} onChange={(e) => setReportType(e.target.value)}>
                <option value="pentest">Pen test</option>
                <option value="executive">Executive</option>
              </select>
            </label>
          </div>

          <div className="button-row" style={{ marginTop: 16 }}>
            <button type="button" className="button-link" onClick={() => downloadWithAuth(reportURL(), filenameFor())}>Download report</button>
            <button type="button" className="button-link" onClick={() => downloadWithAuth(`${API_BASE}/api/report/${scanId}/bugbounty.zip?workspaceId=${encodeURIComponent(getWorkspaceID())}`, `bugbounty-${scanId}.zip`)}>Download bounty bundle</button>
            {format === "html" && (
              <button type="button" className="button-secondary" onClick={togglePreview}>
                {showPreview ? "Hide preview" : "Preview HTML"}
              </button>
            )}
          </div>

          {format === "html" && showPreview && (
            <div style={{ marginTop: 16 }}>
              <p className="meta" style={{ marginBottom: 8 }}>Inline HTML preview (scrollable):</p>
              <iframe
                src={previewURL}
                title="HTML report preview"
                style={{ width: "100%", height: 600, border: "1px solid var(--border)", borderRadius: 10, background: "#fff" }}
                sandbox="allow-same-origin"
              />
            </div>
          )}

          <p className="meta" style={{ marginTop: 12 }}>
            Reports include CVSS/CWE, reproduction steps, impact statements, proof states, and submission-focused evidence.
          </p>
        </section>
      )}

      {findings.length > 0 && (
        <section className="card">
          <div className="toolbar" style={{ alignItems: "flex-start" }}>
            <div>
              <h2>Per-finding submissions</h2>
              <p className="meta">Copy individual Markdown submissions or download them as separate artifacts for triage workflows.</p>
            </div>
            <span className="chip chip--muted">{findings.length} findings in queue</span>
          </div>

          <div className="table-wrap" style={{ marginTop: 14 }}>
            <table>
              <thead>
                <tr>
                  <th>Finding</th>
                  <th>Proof state</th>
                  <th>Bounty score</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <div style={{ fontWeight: 700 }}>{finding.title}</div>
                      <div className="meta">{finding.category || "uncategorized"} · {(finding.severity || "info").toUpperCase()}</div>
                    </td>
                    <td>
                      <span className={`proof-badge ${finding.proofState || "suspected"}`}>{proofStateLabel(finding.proofState)}</span>
                    </td>
                    <td>{(Number(finding.bountyScore || 0) * 100).toFixed(0)}%</td>
                    <td>
                      <div className="button-row">
                        <button type="button" className="button-secondary" title="Copy pre-formatted Markdown" onClick={() => copyFindingMarkdown(finding)}>
                          {copyStatus[finding.id + "_md"] || "📋 Copy MD"}
                        </button>
                        <button type="button" className="button-secondary" onClick={() => copyBugBountySubmission(finding)}>
                          {copyStatus[finding.id] || "Copy via API"}
                        </button>
                        <button type="button" className="button-link" onClick={() => downloadWithAuth(`${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=md&workspaceId=${encodeURIComponent(getWorkspaceID())}`, `bugbounty-${scanId}-${finding.id}.md`)}>.md</button>
                        <button type="button" className="button-link" onClick={() => downloadWithAuth(`${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=pdf&workspaceId=${encodeURIComponent(getWorkspaceID())}`, `bugbounty-${scanId}-${finding.id}.pdf`)}>.pdf</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {job.automatedReport && (
        <section className="card">
          <h2>Automated penetration testing report</h2>
          <pre className="summary">{job.automatedReport}</pre>
        </section>
      )}

      {job.aiSummary && (
        <section className="card">
          <h2>AI summary</h2>
          <pre className="summary">{job.aiSummary}</pre>
        </section>
      )}

      <SecurityKnowledgePanel knowledge={job.modelRecommendations?.securityKnowledge} />

      {screenshots.length > 0 && (
        <section className="card">
          <div className="toolbar">
            <div>
              <h2>Evidence screenshots</h2>
              <p className="meta">Visual artifacts captured automatically during attack-path execution.</p>
            </div>
            <span className="chip chip--muted">{screenshots.length} images</span>
          </div>
          <div className="three-column-grid" style={{ marginTop: 14 }}>
            {screenshots.map((s, i) => (
              <button key={i} type="button" className="surface" style={{ cursor: "pointer", padding: 0, overflow: "hidden", textAlign: "left" }} onClick={() => setSelectedScreenshot(s.b64)}>
                <img src={`data:image/png;base64,${s.b64}`} alt={`Screenshot ${i + 1}`} style={{ width: "100%", height: 150, objectFit: "cover", display: "block" }} />
                <div style={{ padding: 12 }}>
                  <div style={{ fontWeight: 700 }}>{s.agentName}</div>
                  <div className="meta">{s.message || `Evidence ${i + 1}`}</div>
                </div>
              </button>
            ))}
          </div>
        </section>
      )}

      {job.dashboard && (
        <section className="card">
          <h2>Decision dashboard</h2>
          <div className="three-column-grid" style={{ marginTop: 12 }}>
            <article className="meta-block">
              <b>Coverage completeness</b>
              <div>{job.dashboard.coverageCompletenessScore}%</div>
            </article>
            <article className="meta-block">
              <b>Authenticated coverage</b>
              <div>{(Number(job.dashboard.authenticatedCoverageRate || 0) * 100).toFixed(0)}%</div>
            </article>
            <article className="meta-block">
              <b>Actionable findings</b>
              <div>{job.dashboard.actionableFindings || 0}</div>
            </article>
          </div>
        </section>
      )}

      {job.nextActions?.length > 0 && (
        <section className="card">
          <h2>Recommended next actions</h2>
          <ul className="bullet-list" style={{ marginTop: 10 }}>
            {job.nextActions.map((nextAction, idx) => <li key={idx}>{nextAction}</li>)}
          </ul>
        </section>
      )}

      {selectedScreenshot && (
        <div onClick={() => setSelectedScreenshot(null)} style={{ position: "fixed", inset: 0, background: "rgba(1,4,12,0.86)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, cursor: "zoom-out" }}>
          <img src={`data:image/png;base64,${selectedScreenshot}`} alt="Screenshot" style={{ maxWidth: "92vw", maxHeight: "92vh", borderRadius: 18 }} onClick={(e) => e.stopPropagation()} />
          <button type="button" className="button-ghost" style={{ position: "absolute", top: 20, right: 20 }} onClick={() => setSelectedScreenshot(null)}>Close</button>
        </div>
      )}

      {showOptions && (
        <div onClick={() => setShowOptions(false)} style={{ position: "fixed", inset: 0, background: "rgba(1,4,12,0.78)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1100 }}>
          <div onClick={(e) => e.stopPropagation()} className="card" style={{ width: "min(520px, 92vw)", marginBottom: 0 }}>
            <h2>Report template options</h2>
            <p className="meta">Embed custom branding and contact information in the final report cover page.</p>
            <div className="form-grid" style={{ marginTop: 12 }}>
              {[
                ["Company name", companyName, setCompanyName],
                ["Classification", classification, setClassification],
                ["Contact", contact, setContact],
                ["Program handle", programHandle, setProgramHandle],
                ["Logo path", logoPath, setLogoPath],
              ].map(([label, value, setter]) => (
                <label key={label}>
                  {label}
                  <input type="text" value={value} onChange={(e) => setter(e.target.value)} />
                </label>
              ))}
            </div>
            <div className="button-row" style={{ marginTop: 16 }}>
              <button type="button" onClick={submitTemplateOptions}>Generate with options</button>
              <button type="button" className="button-ghost" onClick={() => setShowOptions(false)}>Close</button>
            </div>
            {optionsStatus && <p className="meta" style={{ marginTop: 10 }}>{optionsStatus}</p>}
          </div>
        </div>
      )}
    </div>
  );
}
