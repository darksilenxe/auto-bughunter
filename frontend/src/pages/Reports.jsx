import { useState } from "react";
import { useScan, API_BASE } from "../context/ScanContext";

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

  if (!job) {
    return (
      <div className="page">
        <header><h1>📄 Reports</h1></header>
        <section className="card">
          <p className="meta">No scan data available. Go to the Dashboard to run a scan.</p>
        </section>
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
    try {
      const res = await fetch(reportURL(), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          companyName, classification, contact, programHandle, logoPath,
          reportType,
        }),
      });
      if (!res.ok) {
        setOptionsStatus(`Error ${res.status}`);
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filenameFor();
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setOptionsStatus("Downloaded");
    } catch (err) {
      setOptionsStatus(`Error: ${err.message}`);
    }
  };

  const copyBugBountySubmission = async (finding) => {
    const url = `${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(finding.id)}?format=md`;
    try {
      const res = await fetch(url);
      if (!res.ok) {
        setCopyStatus({ ...copyStatus, [finding.id]: `Error ${res.status}` });
        return;
      }
      const text = await res.text();
      await navigator.clipboard.writeText(text);
      setCopyStatus({ ...copyStatus, [finding.id]: "Copied!" });
      setTimeout(() => setCopyStatus((s) => ({ ...s, [finding.id]: "" })), 2000);
    } catch (err) {
      setCopyStatus({ ...copyStatus, [finding.id]: `Error: ${err.message}` });
    }
  };

  const findings = job.findings || [];

  return (
    <div className="page">
      <header>
        <h1>📄 Reports</h1>
        <p>Target: <strong>{job.target}</strong></p>
      </header>

      {/* Report generator panel */}
      {job.status === "completed" && scanId && (
        <section className="card">
          <h2>Generate Report</h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem", alignItems: "center", marginBottom: "0.75rem" }}>
            <label style={{ display: "flex", flexDirection: "column", fontSize: "0.85rem" }}>
              Format
              <select value={format} onChange={(e) => setFormat(e.target.value)}
                style={{ padding: "0.4rem", borderRadius: "6px", marginTop: "4px" }}>
                <option value="pdf">PDF</option>
                <option value="md">Markdown</option>
                <option value="html">HTML</option>
                <option value="json">JSON</option>
              </select>
            </label>
            <label style={{ display: "flex", flexDirection: "column", fontSize: "0.85rem" }}>
              Type
              <select value={reportType} onChange={(e) => setReportType(e.target.value)}
                style={{ padding: "0.4rem", borderRadius: "6px", marginTop: "4px" }}>
                <option value="pentest">Pen Test</option>
                <option value="executive">Executive</option>
              </select>
            </label>
            <a
              href={reportURL()}
              download={filenameFor()}
              style={{
                display: "inline-block", padding: "0.6rem 1.4rem",
                background: "#7f1d1d", color: "#fff", borderRadius: "8px",
                textDecoration: "none", fontWeight: 700, fontSize: "0.9rem",
              }}
            >
              ⬇ Download Report
            </a>
            <a
              href={`${API_BASE}/api/report/${scanId}/bugbounty.zip`}
              download={`bugbounty-${scanId}.zip`}
              style={{
                display: "inline-block", padding: "0.6rem 1.4rem",
                background: "#1e3a8a", color: "#fff", borderRadius: "8px",
                textDecoration: "none", fontWeight: 700, fontSize: "0.9rem",
              }}
            >
              ⬇ Bug Bounty Bundle (.zip)
            </a>
            <button
              type="button"
              onClick={() => setShowOptions(true)}
              style={{
                padding: "0.55rem 1.1rem", borderRadius: "8px", background: "#374151",
                color: "#fff", border: "none", cursor: "pointer", fontWeight: 600, fontSize: "0.85rem",
              }}
            >
              Customize template…
            </button>
          </div>
          <p className="meta" style={{ fontSize: "0.8rem" }}>
            Pen-test reports include CVSS / CWE / OWASP mapping, reproduction steps, and an appendix
            of tools and commands. Bug-bounty bundles produce one Markdown submission per finding.
          </p>
        </section>
      )}

      {/* Per-finding bug-bounty submissions */}
      {findings.length > 0 && (
        <section className="card">
          <h2>Bug Bounty Submissions</h2>
          <p className="meta">Click a row to copy a Markdown submission to the clipboard, or download as PDF/MD.</p>
          <ul className="findings" style={{ listStyle: "none", padding: 0 }}>
            {findings.map((f, i) => (
              <li key={`${f.id}-${i}`} style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", padding: "0.5rem 0" }}>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "center" }}>
                  <strong style={{ flex: "1 1 280px" }}>
                    [{(f.severity || "info").toUpperCase()}] {f.title}
                  </strong>
                  <button type="button" onClick={() => copyBugBountySubmission(f)}
                    style={{ padding: "0.35rem 0.75rem", background: "#0f766e", color: "#fff",
                      border: "none", borderRadius: "6px", cursor: "pointer", fontSize: "0.78rem" }}>
                    📋 Copy submission
                  </button>
                  <a href={`${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(f.id)}?format=md`}
                    download={`bugbounty-${scanId}-${f.id}.md`}
                    style={{ padding: "0.35rem 0.75rem", background: "#1e40af", color: "#fff",
                      borderRadius: "6px", textDecoration: "none", fontSize: "0.78rem", fontWeight: 600 }}>
                    .md
                  </a>
                  <a href={`${API_BASE}/api/report/${scanId}/finding/${encodeURIComponent(f.id)}?format=pdf`}
                    download={`bugbounty-${scanId}-${f.id}.pdf`}
                    style={{ padding: "0.35rem 0.75rem", background: "#7f1d1d", color: "#fff",
                      borderRadius: "6px", textDecoration: "none", fontSize: "0.78rem", fontWeight: 600 }}>
                    .pdf
                  </a>
                  {copyStatus[f.id] && (
                    <span style={{ fontSize: "0.75rem", color: "#0ea5e9" }}>{copyStatus[f.id]}</span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Automated pen test report */}
      {job.automatedReport && (
        <section className="card">
          <h2>Automated Penetration Testing Report</h2>
          <pre className="summary">{job.automatedReport}</pre>
        </section>
      )}

      {/* AI Summary */}
      {job.aiSummary && (
        <section className="card">
          <h2>AI Summary</h2>
          <pre className="summary">{job.aiSummary}</pre>
        </section>
      )}

      {/* Screenshots gallery */}
      {screenshots.length > 0 && (
        <section className="card">
          <h2>📷 Evidence Screenshots ({screenshots.length})</h2>
          <p className="meta">Screenshots captured automatically during the attack path.</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: "12px", marginTop: "0.75rem" }}>
            {screenshots.map((s, i) => (
              <div
                key={i}
                onClick={() => setSelectedScreenshot(s.b64)}
                style={{ cursor: "pointer", borderRadius: "8px", overflow: "hidden", border: "2px solid rgba(255,255,255,0.25)", background: "rgba(0,0,0,0.3)" }}
              >
                <img
                  src={`data:image/png;base64,${s.b64}`}
                  alt={`Screenshot ${i + 1}`}
                  style={{ width: "100%", height: "130px", objectFit: "cover", display: "block" }}
                />
                <div style={{ padding: "6px 8px" }}>
                  <div style={{ fontSize: "0.7rem", color: "#000", fontWeight: 600 }}>{s.agentName}</div>
                  <div style={{ fontSize: "0.65rem", color: "#333", marginTop: "2px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.message || `Page ${i + 1}`}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Decision Dashboard */}
      {job.dashboard && (
        <section className="card">
          <h2>Decision Dashboard</h2>
          <ul className="findings">
            <li>
              <p><b>Coverage completeness:</b> {job.dashboard.coverageCompletenessScore}%</p>
              <p><b>Authenticated coverage rate:</b> {(Number(job.dashboard.authenticatedCoverageRate || 0) * 100).toFixed(0)}%</p>
              <p><b>Drift:</b> new={job.dashboard.newFindings || 0}, changed={job.dashboard.changedFindings || 0}, resolved={job.dashboard.resolvedFindings || 0}</p>
              <p><b>Actionable findings:</b> {job.dashboard.actionableFindings || 0}</p>
              {job.dashboard.topAttackPaths?.length > 0 && (
                <p><b>Top attack paths:</b> {job.dashboard.topAttackPaths.join(", ")}</p>
              )}
            </li>
          </ul>
        </section>
      )}

      {/* Next actions */}
      {job.nextActions?.length > 0 && (
        <section className="card">
          <h2>Recommended Next Actions</h2>
          <ul className="findings">
            {job.nextActions.map((n, i) => <li key={i}><p>{n}</p></li>)}
          </ul>
        </section>
      )}

      {/* Lightbox */}
      {selectedScreenshot && (
        <div
          onClick={() => setSelectedScreenshot(null)}
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.88)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, cursor: "zoom-out" }}
        >
          <img src={`data:image/png;base64,${selectedScreenshot}`} alt="Screenshot"
            style={{ maxWidth: "90vw", maxHeight: "90vh", borderRadius: "8px" }}
            onClick={(e) => e.stopPropagation()} />
          <button onClick={() => setSelectedScreenshot(null)}
            style={{ position: "absolute", top: "16px", right: "24px", background: "none", border: "none", color: "#fff", fontSize: "2rem", cursor: "pointer" }}>×</button>
        </div>
      )}

      {/* Template options modal */}
      {showOptions && (
        <div
          onClick={() => setShowOptions(false)}
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1100 }}
        >
          <div onClick={(e) => e.stopPropagation()}
            style={{ background: "#0f172a", color: "#e2e8f0", padding: "1.5rem", borderRadius: "10px", width: "min(480px, 92vw)" }}>
            <h2 style={{ marginTop: 0 }}>Report Template Options</h2>
            <p className="meta" style={{ fontSize: "0.8rem", color: "#94a3b8" }}>
              These optional fields are embedded in the generated report cover page.
            </p>
            {[
              ["Company name", companyName, setCompanyName],
              ["Classification (e.g. TLP:RED)", classification, setClassification],
              ["Contact (email)", contact, setContact],
              ["Bug bounty program handle", programHandle, setProgramHandle],
              ["Logo path (server-side)", logoPath, setLogoPath],
            ].map(([label, value, setter]) => (
              <label key={label} style={{ display: "block", marginTop: "0.6rem", fontSize: "0.85rem" }}>
                {label}
                <input type="text" value={value} onChange={(e) => setter(e.target.value)}
                  style={{ width: "100%", padding: "0.45rem", marginTop: "4px", borderRadius: "6px",
                    background: "#1e293b", color: "#e2e8f0", border: "1px solid #334155" }} />
              </label>
            ))}
            <div style={{ display: "flex", gap: "0.5rem", marginTop: "1rem", justifyContent: "flex-end" }}>
              <button type="button" onClick={() => setShowOptions(false)}
                style={{ padding: "0.5rem 1rem", borderRadius: "6px", border: "1px solid #334155",
                  background: "transparent", color: "#cbd5e1", cursor: "pointer" }}>
                Close
              </button>
              <button type="button" onClick={submitTemplateOptions}
                style={{ padding: "0.5rem 1rem", borderRadius: "6px", border: "none",
                  background: "#7f1d1d", color: "#fff", cursor: "pointer", fontWeight: 600 }}>
                Generate &amp; Download
              </button>
            </div>
            {optionsStatus && <p style={{ marginTop: "0.6rem", fontSize: "0.8rem", color: "#0ea5e9" }}>{optionsStatus}</p>}
          </div>
        </div>
      )}
    </div>
  );
}
