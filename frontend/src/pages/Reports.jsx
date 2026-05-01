import { useMemo, useState } from "react";
import SecurityKnowledgePanel from "../components/SecurityKnowledgePanel";
import { API_BASE, useScan } from "../context/ScanContext";
import { isAbortError, useAbortable } from "../lib/useAbortable";
import { proofStateLabel, sortFindings, summarizeFindings } from "../lib/impact";

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
  const newController = useAbortable();

  const findings = useMemo(function () { return sortFindings(job?.findings || []); }, [job?.findings]);
  const summary = useMemo(() => summarizeFindings(findings), [findings]);

  if (!job) {
    return (
      <div className="page">
        <header>
          <h1>Submission center</h1>
          <p>Generate polished pentest and bug bounty reports after a scan completes.</p>
        </header>
        <section className="card empty-state">No scan data available. Run an engagement from the dashboard first.</section>
      </div>
    );
  }

  const reportURL = (overrides = {}) => {
    const params = new URLSearchParams();
    params.set("format", overrides.format || format);
    params.set("type", overrides.type || reportType);
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
    const ac = newController();
    try {
      const res = await fetch(reportURL(), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ companyName, classification, contact, programHandle, logoPath, reportType }),
        signal: ac.signal,
      });
      if (ac.signal.aborted) return;
      if (!res.ok) {
        setOptionsStatus(`Error ${res.status}`);
        return;
      }
      const blob = await res.blob();
      if (ac.signal.aborted) return;
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
      if (isAbortError(err)) return;
      setOptionsStatus(`Error: ${err.message}`);
    }
  };

  const copyBugBountySubmission = async (finding) => {
    const url = `${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=md`;
    const ac = newController();
    try {
      const res = await fetch(url, { signal: ac.signal });
      if (ac.signal.aborted) return;
      if (!res.ok) {
        setCopyStatus((prev) => ({ ...prev, [finding.id]: `Error ${res.status}` }));
        return;
      }
      const text = await res.text();
      if (ac.signal.aborted) return;
      await navigator.clipboard.writeText(text);
      if (ac.signal.aborted) return;
      setCopyStatus((prev) => ({ ...prev, [finding.id]: "Copied!" }));
      setTimeout(() => setCopyStatus((prev) => ({ ...prev, [finding.id]: "" })), 2000);
    } catch (err) {
      if (isAbortError(err)) return;
      setCopyStatus((prev) => ({ ...prev, [finding.id]: `Error: ${err.message}` }));
    }
  };

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
              <select value={format} onChange={(e) => setFormat(e.target.value)}>
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
            <a href={reportURL()} download={filenameFor()} className="button-link">Download report</a>
            <a href={`${API_BASE}/api/report/${scanId}/bugbounty.zip`} download={`bugbounty-${scanId}.zip`} className="button-link">Download bounty bundle</a>
          </div>
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
                        <button type="button" className="button-secondary" onClick={() => copyBugBountySubmission(finding)}>Copy</button>
                        <a href={`${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=md`} download={`bugbounty-${scanId}-${finding.id}.md`} className="button-link">.md</a>
                        <a href={`${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=pdf`} download={`bugbounty-${scanId}-${finding.id}.pdf`} className="button-link">.pdf</a>
                        {copyStatus[finding.id] && <span className="meta">{copyStatus[finding.id]}</span>}
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
