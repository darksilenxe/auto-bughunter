import { useEffect, useMemo, useState } from "react";
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

function formatProofArtifactLine(artifact) {
  const label = artifact?.label || artifact?.type || "Artifact";
  const value = artifact?.value ? `: ${artifact.value}` : "";
  const description = artifact?.description ? ` — ${artifact.description}` : "";
  return `- **${label}**${value}${description}`;
}

function computeSubmissionReadiness(finding) {
  let score = 0;
  const missing = [];
  const add = (points, present, label) => {
    if (present) score += points;
    else missing.push(label);
  };
  add(10, !!String(finding?.title || "").trim(), "title");
  add(10, !!String(finding?.description || "").trim(), "description / summary");
  add(10, !!finding?.severity && finding?.severity !== "info", "severity (non-informational)");
  add(10, !!String(finding?.affectedUrl || "").trim(), "affected URL");
  add(15, Array.isArray(finding?.reproductionSteps) && finding.reproductionSteps.length > 0, "step-by-step reproduction steps");
  add(10, !!String(finding?.evidence || "").trim(), "raw evidence");
  add(5, !!String(finding?.cwe || "").trim(), "CWE mapping");
  add(5, Number(finding?.cvss || 0) > 0, "CVSS score");
  add(5, !!String(finding?.impact || "").trim(), "business impact statement");
  add(5, !!String(finding?.recommendation || "").trim(), "remediation recommendation");
  add(5, Array.isArray(finding?.proofArtifacts) && finding.proofArtifacts.length > 0, "proof artifacts");
  add(5, Number(finding?.confidence || 0) >= 0.7, "detection confidence >= 0.70");
  add(5, !!String(finding?.affectedParameter || "").trim(), "affected parameter");
  return { score: Math.min(100, score), missing, readyToSubmit: score >= 90 };
}

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
  const [platform, setPlatform] = useState("hackerone");
  const [duplicateGroups, setDuplicateGroups] = useState({});
  const [duplicateStatus, setDuplicateStatus] = useState("");
  const [submitStatus, setSubmitStatus] = useState({});
  const [feedbackForms, setFeedbackForms] = useState({});
  const [feedbackStatus, setFeedbackStatus] = useState({});

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
    if (platform) params.set("platform", platform);
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
    const url = `${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=md&platform=${encodeURIComponent(platform)}&workspaceId=${encodeURIComponent(workspaceId)}`;
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

  const submitFinding = async (finding) => {
    const readiness = readinessByFinding[finding.id] || { readyToSubmit: false };
    if (!readiness.readyToSubmit) return;
    const apiKey = getAPIKey();
    const workspaceId = getWorkspaceID();
    setSubmitStatus((prev) => ({ ...prev, [finding.id]: "Submitting…" }));
    try {
      const url = `${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}/submit?platform=${encodeURIComponent(platform)}&workspaceId=${encodeURIComponent(workspaceId)}`;
      const res = await fetch(url, { method: "POST", headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceId } });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setSubmitStatus((prev) => ({ ...prev, [finding.id]: data?.error || `HTTP ${res.status}` }));
        return;
      }
      setSubmitStatus((prev) => ({ ...prev, [finding.id]: data?.status || "Submitted" }));
    } catch (err) {
      setSubmitStatus((prev) => ({ ...prev, [finding.id]: `Error: ${err.message}` }));
    }
  };

  const submitOutcomeFeedback = async (finding) => {
    const form = feedbackForms[finding.id] || { outcome: "accepted", payoutUsd: "", notes: "" };
    const apiKey = getAPIKey();
    const workspaceId = getWorkspaceID();
    setFeedbackStatus((prev) => ({ ...prev, [finding.id]: "Saving…" }));
    try {
      const res = await fetch(`${API_BASE}/api/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey, "X-Workspace-ID": workspaceId },
        body: JSON.stringify({
          scanId,
          findingId: finding.id,
          category: finding.category,
          title: finding.title,
          outcome: form.outcome,
          payoutUsd: form.payoutUsd ? Number(form.payoutUsd) : 0,
          notes: form.notes || "",
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setFeedbackStatus((prev) => ({ ...prev, [finding.id]: data?.error || `HTTP ${res.status}` }));
        return;
      }
      setFeedbackStatus((prev) => ({ ...prev, [finding.id]: "Saved" }));
    } catch (err) {
      setFeedbackStatus((prev) => ({ ...prev, [finding.id]: `Error: ${err.message}` }));
    }
  };

  const copyFindingMarkdown = async (finding) => {
    const lines = [
      `## ${finding.title}`,
      `**Severity:** ${(finding.severity || "info").toUpperCase()}${finding.cvss ? `  |  **CVSS:** ${Number(finding.cvss).toFixed(1)}` : ""}`,
      `**Affected URL:** ${finding.affectedUrl || "n/a"}`,
      `**Category:** ${finding.category || "n/a"}`,
      finding.proofState ? `**Proof State:** ${proofStateLabel(finding.proofState)}` : "",
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
      `### Proof Artifacts`,
      ...(finding.proofArtifacts?.length
        ? finding.proofArtifacts.map((artifact) => formatProofArtifactLine(artifact))
        : ["No structured proof artifacts were attached."]),
      "",
      `### Remediation`,
      finding.recommendation || "No remediation guidance captured.",
    ].filter(Boolean);
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopyStatus((prev) => ({ ...prev, [finding.id + "_md"]: "Copied!" }));
      setTimeout(() => setCopyStatus((prev) => ({ ...prev, [finding.id + "_md"]: "" })), 2000);
    } catch {
      setCopyStatus((prev) => ({ ...prev, [finding.id + "_md"]: "Failed" }));
    }
  };

  const allChecked = SUBMISSION_CHECKS.every((c) => checklist[c.id]);
  const readinessByFinding = useMemo(() => {
    const out = {};
    findings.forEach((f) => { out[f.id] = computeSubmissionReadiness(f); });
    return out;
  }, [findings]);

  useEffect(() => {
    if (!scanId) return;
    const apiKey = getAPIKey();
    const workspaceId = getWorkspaceID();
    setDuplicateStatus("Checking duplicates…");
    fetch(`${API_BASE}/api/findings/duplicates?scanId=${encodeURIComponent(scanId)}&workspaceId=${encodeURIComponent(workspaceId)}`, {
      headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceId },
    })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then((data) => {
        const grouped = {};
        (data?.duplicateGroups || []).forEach((g) => { grouped[g.findingId] = g; });
        setDuplicateGroups(grouped);
        setDuplicateStatus("");
      })
      .catch((err) => {
        setDuplicateStatus(`Duplicate check unavailable: ${err.message}`);
        setDuplicateGroups({});
      });
  }, [scanId]);

  useEffect(() => {
    setFeedbackForms((prev) => {
      const next = { ...prev };
      findings.forEach((finding) => {
        if (!next[finding.id]) next[finding.id] = { outcome: "accepted", payoutUsd: "", notes: "" };
      });
      return next;
    });
  }, [findings]);

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
            <label>
              Submission platform
              <select value={platform} onChange={(e) => setPlatform(e.target.value)}>
                <option value="hackerone">HackerOne</option>
                <option value="bugcrowd">Bugcrowd</option>
                <option value="intigriti">Intigriti</option>
              </select>
            </label>
          </div>

          <div className="button-row" style={{ marginTop: 16 }}>
            <button type="button" className="button-link" onClick={() => downloadWithAuth(reportURL(), filenameFor())}>Download report</button>
            <button type="button" className="button-link" onClick={() => downloadWithAuth(`${API_BASE}/api/report/${scanId}/bugbounty.zip?platform=${encodeURIComponent(platform)}&workspaceId=${encodeURIComponent(getWorkspaceID())}`, `bugbounty-${scanId}.zip`)}>Download bounty bundle</button>
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
                  <th>Readiness</th>
                  <th>Duplicate check</th>
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
                    <td>
                      {(() => {
                        const readiness = readinessByFinding[finding.id] || { score: 0, readyToSubmit: false, missing: [] };
                        return (
                          <span className={`chip ${readiness.readyToSubmit ? "chip--goal" : "chip--muted"}`} title={readiness.missing?.join(", ") || "Ready"}>
                            {readiness.score}/100
                          </span>
                        );
                      })()}
                    </td>
                    <td>
                      {duplicateGroups[finding.id]?.candidates?.length ? (
                        <span className="chip chip--warning">{duplicateGroups[finding.id].candidates.length} possible</span>
                      ) : (
                        <span className="chip chip--muted">none</span>
                      )}
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
                        <button type="button" className="button-link" onClick={() => downloadWithAuth(`${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=md&platform=${encodeURIComponent(platform)}&workspaceId=${encodeURIComponent(getWorkspaceID())}`, `bugbounty-${scanId}-${finding.id}.md`)}>.md</button>
                        <button type="button" className="button-link" onClick={() => downloadWithAuth(`${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=pdf&workspaceId=${encodeURIComponent(getWorkspaceID())}`, `bugbounty-${scanId}-${finding.id}.pdf`)}>.pdf</button>
                        <button type="button" className="button-link" disabled={!readinessByFinding[finding.id]?.readyToSubmit} onClick={() => submitFinding(finding)}>
                          {submitStatus[finding.id] || "Submit"}
                        </button>
                      </div>
                      <div className="form-grid" style={{ marginTop: 10 }}>
                        <label>
                          Outcome
                          <select value={feedbackForms[finding.id]?.outcome || "accepted"} onChange={(e) => setFeedbackForms((prev) => ({ ...prev, [finding.id]: { ...(prev[finding.id] || {}), outcome: e.target.value } }))}>
                            <option value="accepted">accepted</option>
                            <option value="duplicate">duplicate</option>
                            <option value="rejected">rejected</option>
                            <option value="informative">informative</option>
                            <option value="n/a">n/a</option>
                          </select>
                        </label>
                        <label>
                          Payout USD
                          <input value={feedbackForms[finding.id]?.payoutUsd || ""} onChange={(e) => setFeedbackForms((prev) => ({ ...prev, [finding.id]: { ...(prev[finding.id] || {}), payoutUsd: e.target.value } }))} />
                        </label>
                      </div>
                      <label style={{ display: "block", marginTop: 10 }}>
                        Notes
                        <textarea rows={2} value={feedbackForms[finding.id]?.notes || ""} onChange={(e) => setFeedbackForms((prev) => ({ ...prev, [finding.id]: { ...(prev[finding.id] || {}), notes: e.target.value } }))} />
                      </label>
                      <div className="button-row" style={{ marginTop: 8 }}>
                        <button type="button" className="button-secondary" onClick={() => submitOutcomeFeedback(finding)}>Save outcome</button>
                        {feedbackStatus[finding.id] && <span className="meta">{feedbackStatus[finding.id]}</span>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {duplicateStatus && <p className="meta" style={{ marginTop: 10 }}>{duplicateStatus}</p>}
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
