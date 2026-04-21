import { useEffect, useState } from "react";
import { API_BASE, API_KEY, WORKSPACE_ID, useScan } from "../context/ScanContext";

const EMPTY_PROGRAM = {
  name: "",
  description: "",
  allowedTargets: "",
  excludeHosts: "",
  excludePaths: "",
  programRules: "",
  allowDestructive: false,
  notes: "",
};

const DEFAULT_AI_CONFIG = {
  summaryModel: "phi3:mini",
  triageModel: "phi3:mini",
  plannerModel: "phi3:mini",
  temperature: "0.2",
  plannerTemperature: "0.1",
  maxTokens: "1200",
  topP: "1.0",
  summarySystemPrompt: "You are a defensive AppSec assistant. Summarize scanner findings for authorized remediation only.",
  summaryUserPromptTemplate: "Target: {{target}}\\nFindings JSON: {{findings}}\\nKnowledge Context JSON: {{knowledge}}\\nProvide: 1) risk summary 2) top 3 priorities 3) remediation sequence 4) supporting citations when knowledge context is present.",
  plannerSystemPrompt: "You are an autonomous defensive AppSec orchestrator. Decide which scanning/analysis agents to run next. Reply with strict JSON.",
  plannerInstructionTemplate: "Pick zero or more agents to run next from the available_agents list. You may repeat agents from history when new findings warrant it. Set done=true once additional agents are unlikely to surface new value. Reply with strict JSON only: {\"agents\":[{\"name\":string,\"reason\":string}],\"done\":bool}",
};

export default function Settings() {
  const { programs, savePrograms } = useScan();
  const [editing, setEditing] = useState(null); // null | index | "new"
  const [form, setForm] = useState(EMPTY_PROGRAM);
  const [aiConfig, setAIConfig] = useState(() => {
    try {
      const stored = JSON.parse(localStorage.getItem("ai_model_preferences") || "{}");
      return { ...DEFAULT_AI_CONFIG, ...(stored || {}) };
    } catch {
      return DEFAULT_AI_CONFIG;
    }
  });
  const [aiConfigStatus, setAIConfigStatus] = useState("");
  const [feedForm, setFeedForm] = useState({ scanId: "", findingId: "", outcome: "accepted", notes: "", payoutUsd: "" });
  const [feedStatus, setFeedStatus] = useState("");
  const [datasetPreview, setDatasetPreview] = useState([]);
  const [datasetError, setDatasetError] = useState("");
  const [policyPacks, setPolicyPacks] = useState([]);
  const [policyAudit, setPolicyAudit] = useState([]);
  const [policyForm, setPolicyForm] = useState({
    name: "internal",
    strategyVersion: 1,
    canaryPercent: 0,
    automationMode: "autonomous",
    minExpectedRoiUsd: 75,
    maxAutomationConcurrency: 2,
    maxPerTargetConcurrency: 2,
    maxExploitAttempts: 1,
    dailyScanLimit: 30,
    dailyRuntimeLimitMinutes: 240,
    dailyProbeLimit: 5000,
    escalateOnNewHigh: true,
    escalateOnChangedHigh: true,
  });
  const [policyStatus, setPolicyStatus] = useState("");

  useEffect(() => {
    loadPolicyPacks();
    loadPolicyAudit();
  }, []);

  function openNew() {
    setForm(EMPTY_PROGRAM);
    setEditing("new");
  }

  function openEdit(idx) {
    setForm({ ...programs[idx] });
    setEditing(idx);
  }

  function handleDelete(idx) {
    savePrograms(programs.filter((_, i) => i !== idx));
    if (editing === idx) setEditing(null);
  }

  function handleSave() {
    if (!form.name.trim()) return;
    if (editing === "new") {
      savePrograms([...programs, { ...form }]);
    } else {
      const next = [...programs];
      next[editing] = { ...form };
      savePrograms(next);
    }
    setEditing(null);
  }

  function saveAIConfig() {
    localStorage.setItem("ai_model_preferences", JSON.stringify(aiConfig));
    setAIConfigStatus("Saved local AI preferences.");
  }

  function resetAIConfig() {
    setAIConfig(DEFAULT_AI_CONFIG);
    localStorage.setItem("ai_model_preferences", JSON.stringify(DEFAULT_AI_CONFIG));
    setAIConfigStatus("Reset to defaults.");
  }

  async function submitEnrichmentFeedback(e) {
    e.preventDefault();
    setFeedStatus("");
    const payload = {
      scanId: feedForm.scanId.trim(),
      findingId: feedForm.findingId.trim(),
      outcome: feedForm.outcome,
      notes: feedForm.notes.trim(),
      payoutUsd: feedForm.payoutUsd ? Number(feedForm.payoutUsd) : 0,
    };
    if (!payload.scanId || !payload.findingId) {
      setFeedStatus("scanId and findingId are required.");
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/feedback`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
          "X-Workspace-ID": WORKSPACE_ID,
        },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setFeedStatus(data.error || "Failed to submit enrichment feedback.");
        return;
      }
      setFeedStatus(`Recorded feedback ${data.id}.`);
      setFeedForm((prev) => ({ ...prev, notes: "", payoutUsd: "" }));
    } catch (err) {
      setFeedStatus(err.message || "Failed to submit enrichment feedback.");
    }
  }

  async function loadDatasetPreview() {
    setDatasetError("");
    try {
      const res = await fetch(`${API_BASE}/api/ml/engagements?limit=5`, {
        headers: { "X-API-Key": API_KEY, "X-Workspace-ID": WORKSPACE_ID },
      });
      const data = await res.json();
      if (!res.ok) {
        setDatasetError(data.error || "Failed to load dataset preview.");
        return;
      }
      setDatasetPreview(Array.isArray(data) ? data : (data.items || []));
    } catch (err) {
      setDatasetError(err.message || "Failed to load dataset preview.");
    }
  }

  async function loadPolicyPacks() {
    try {
      const res = await fetch(`${API_BASE}/api/automation/policy-packs`, {
        headers: { "X-API-Key": API_KEY, "X-Workspace-ID": WORKSPACE_ID },
      });
      const data = await res.json();
      if (res.ok) setPolicyPacks(Array.isArray(data) ? data : []);
    } catch {
      // noop
    }
  }

  async function loadPolicyAudit() {
    try {
      const res = await fetch(`${API_BASE}/api/automation/policy-audit`, {
        headers: { "X-API-Key": API_KEY, "X-Workspace-ID": WORKSPACE_ID },
      });
      const data = await res.json();
      if (res.ok) setPolicyAudit(Array.isArray(data) ? data : []);
    } catch {
      // noop
    }
  }

  async function savePolicyPack(e) {
    e.preventDefault();
    setPolicyStatus("");
    try {
      const res = await fetch(`${API_BASE}/api/automation/policy-packs`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
          "X-Workspace-ID": WORKSPACE_ID,
        },
        body: JSON.stringify(policyForm),
      });
      const data = await res.json();
      if (!res.ok) {
        setPolicyStatus(data.error || "Failed to save policy pack.");
        return;
      }
      setPolicyStatus("Policy pack saved.");
      await loadPolicyPacks();
      await loadPolicyAudit();
    } catch (err) {
      setPolicyStatus(err.message || "Failed to save policy pack.");
    }
  }

  function field(key, label, type = "text", rows) {
    return (
      <label key={key}>
        {label}
        {rows ? (
          <textarea rows={rows} value={form[key] || ""} onChange={(e) => setForm((p) => ({ ...p, [key]: e.target.value }))} />
        ) : type === "checkbox" ? (
          <label className="check" style={{ marginTop: "4px" }}>
            <input type="checkbox" checked={!!form[key]} onChange={(e) => setForm((p) => ({ ...p, [key]: e.target.checked }))} />
            {label}
          </label>
        ) : (
          <input type={type} value={form[key] || ""} onChange={(e) => setForm((p) => ({ ...p, [key]: e.target.value }))} />
        )}
      </label>
    );
  }

  return (
    <div className="page">
      <header>
        <h1>⚙️ Settings</h1>
        <p>Manage bug bounty program configurations</p>
      </header>

      {/* Program list */}
      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h2 style={{ margin: 0 }}>Bug Bounty Programs</h2>
          <button onClick={openNew}>+ New Program</button>
        </div>

        {programs.length === 0 && (
          <p className="meta">No programs configured. Add one to pre-fill scan settings.</p>
        )}

        <ul className="findings" style={{ marginTop: "0.5rem" }}>
          {programs.map((p, i) => (
            <li key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "8px" }}>
              <div>
                <strong>{p.name}</strong>
                {p.description && <p style={{ margin: "2px 0", color: "#555", fontSize: "0.85rem" }}>{p.description}</p>}
                {p.allowedTargets && (
                  <p style={{ margin: "2px 0", fontSize: "0.8rem" }}>
                    <b>Targets:</b> {p.allowedTargets}
                  </p>
                )}
                {p.excludeHosts && (
                  <p style={{ margin: "2px 0", fontSize: "0.8rem" }}>
                    <b>Excluded:</b> {p.excludeHosts}
                  </p>
                )}
                {p.allowDestructive && (
                  <span style={{ fontSize: "0.75rem", background: "#dc2626", color: "#fff", padding: "1px 6px", borderRadius: "999px" }}>
                    destructive ok
                  </span>
                )}
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                <button onClick={() => openEdit(i)} style={{ fontSize: "0.8rem", padding: "0.3rem 0.7rem" }}>Edit</button>
                <button
                  onClick={() => handleDelete(i)}
                  style={{ fontSize: "0.8rem", padding: "0.3rem 0.7rem", background: "#7f1d1d" }}
                >
                  Delete
                </button>
              </div>
            </li>
          ))}
        </ul>
      </section>

      {/* Edit / create form */}
      {editing !== null && (
        <section className="card">
          <h2>{editing === "new" ? "New Program" : `Edit: ${programs[editing]?.name}`}</h2>
          <form onSubmit={(e) => { e.preventDefault(); handleSave(); }}>
            {field("name", "Program Name *")}
            {field("description", "Description", "text")}
            {field("allowedTargets", "Allowed Targets (comma-separated)", "text")}
            {field("excludeHosts", "Excluded Hosts (comma-separated)", "text")}
            {field("excludePaths", "Excluded Paths (comma-separated)", "text")}
            {field("programRules", "Program Rules (one per line)", "text", 4)}
            <label className="check">
              <input type="checkbox" checked={!!form.allowDestructive}
                onChange={(e) => setForm((p) => ({ ...p, allowDestructive: e.target.checked }))} />
              Allow destructive checks (SQLMap, Nikto active scanning)
            </label>
            {field("notes", "Private Notes", "text", 3)}
            <div style={{ display: "flex", gap: "0.75rem" }}>
              <button type="submit">💾 Save</button>
              <button type="button" onClick={() => setEditing(null)}
                style={{ background: "rgba(0,0,0,0.25)", color: "#000" }}>
                Cancel
              </button>
            </div>
          </form>
        </section>
      )}

      {/* Info section */}
      <section className="card">
        <h2>Local AI Configuration</h2>
        <p className="meta">
          The system uses a local Ollama instance (<code>phi3:mini</code> by default) for AI summaries and triage.
          No external API key is required. The model is downloaded automatically on first start.
        </p>
        <p className="meta">
          The neural agent learner (<code>agents</code> service) learns from each completed scan and automatically
          improves agent spawn decisions over time.
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.6rem", marginTop: "0.75rem" }}>
          <label>Summary model
            <input value={aiConfig.summaryModel || ""} onChange={(e) => setAIConfig((p) => ({ ...p, summaryModel: e.target.value }))} />
          </label>
          <label>Triage model
            <input value={aiConfig.triageModel || ""} onChange={(e) => setAIConfig((p) => ({ ...p, triageModel: e.target.value }))} />
          </label>
          <label>Planner model
            <input value={aiConfig.plannerModel || ""} onChange={(e) => setAIConfig((p) => ({ ...p, plannerModel: e.target.value }))} />
          </label>
          <label>Temperature
            <input value={aiConfig.temperature || ""} onChange={(e) => setAIConfig((p) => ({ ...p, temperature: e.target.value }))} />
          </label>
          <label>Planner temperature
            <input value={aiConfig.plannerTemperature || ""} onChange={(e) => setAIConfig((p) => ({ ...p, plannerTemperature: e.target.value }))} />
          </label>
          <label>Max tokens
            <input value={aiConfig.maxTokens || ""} onChange={(e) => setAIConfig((p) => ({ ...p, maxTokens: e.target.value }))} />
          </label>
          <label>Top P
            <input value={aiConfig.topP || ""} onChange={(e) => setAIConfig((p) => ({ ...p, topP: e.target.value }))} />
          </label>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: "0.6rem", marginTop: "0.75rem" }}>
          <label>Summary system prompt
            <textarea
              rows={3}
              value={aiConfig.summarySystemPrompt || ""}
              onChange={(e) => setAIConfig((p) => ({ ...p, summarySystemPrompt: e.target.value }))}
            />
          </label>
          <label>Summary user prompt template
            <textarea
              rows={5}
              value={aiConfig.summaryUserPromptTemplate || ""}
              onChange={(e) => setAIConfig((p) => ({ ...p, summaryUserPromptTemplate: e.target.value }))}
            />
          </label>
          <label>Planner system prompt
            <textarea
              rows={3}
              value={aiConfig.plannerSystemPrompt || ""}
              onChange={(e) => setAIConfig((p) => ({ ...p, plannerSystemPrompt: e.target.value }))}
            />
          </label>
          <label>Planner instruction template
            <textarea
              rows={4}
              value={aiConfig.plannerInstructionTemplate || ""}
              onChange={(e) => setAIConfig((p) => ({ ...p, plannerInstructionTemplate: e.target.value }))}
            />
          </label>
        </div>
        <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.75rem" }}>
          <button type="button" onClick={saveAIConfig}>Save local AI preferences</button>
          <button type="button" onClick={resetAIConfig}>Reset AI defaults</button>
          <button type="button" onClick={loadDatasetPreview}>Load enrichment dataset preview</button>
        </div>
        <p className="meta">These preferences are saved locally in your browser for operator workflows.</p>
        {aiConfigStatus && <p className="meta">{aiConfigStatus}</p>}
        {datasetError && <p className="error">{datasetError}</p>}
        {datasetPreview.length > 0 && <pre className="summary">{JSON.stringify(datasetPreview, null, 2)}</pre>}
      </section>

      <section className="card">
        <h2>AI Enrichment Data Feed</h2>
        <p className="meta">
          Feed analyst outcomes into the enrichment loop by posting finding feedback labels.
        </p>
        <form onSubmit={submitEnrichmentFeedback}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.6rem" }}>
            <label>Scan ID
              <input value={feedForm.scanId} onChange={(e) => setFeedForm((p) => ({ ...p, scanId: e.target.value }))} />
            </label>
            <label>Finding ID
              <input value={feedForm.findingId} onChange={(e) => setFeedForm((p) => ({ ...p, findingId: e.target.value }))} />
            </label>
            <label>Outcome
              <select value={feedForm.outcome} onChange={(e) => setFeedForm((p) => ({ ...p, outcome: e.target.value }))}>
                <option value="accepted">accepted</option>
                <option value="rejected">rejected</option>
                <option value="duplicate">duplicate</option>
                <option value="informative">informative</option>
              </select>
            </label>
            <label>Payout USD
              <input value={feedForm.payoutUsd} onChange={(e) => setFeedForm((p) => ({ ...p, payoutUsd: e.target.value }))} />
            </label>
          </div>
          <label>Analyst Notes
            <textarea rows={3} value={feedForm.notes} onChange={(e) => setFeedForm((p) => ({ ...p, notes: e.target.value }))} />
          </label>
          <button type="submit">Submit enrichment feedback</button>
        </form>
        {feedStatus && <p className="meta">{feedStatus}</p>}
      </section>

      <section className="card">
        <h2>Automation Policy Governance</h2>
        <p className="meta">Manage per-workspace automation policy packs and audit changes.</p>
        <form onSubmit={savePolicyPack}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.6rem" }}>
            <label>Pack name
              <input value={policyForm.name} onChange={(e) => setPolicyForm((p) => ({ ...p, name: e.target.value }))} />
            </label>
            <label>Strategy version
              <input type="number" value={policyForm.strategyVersion} onChange={(e) => setPolicyForm((p) => ({ ...p, strategyVersion: Number(e.target.value || 1) }))} />
            </label>
            <label>Canary percent
              <input type="number" value={policyForm.canaryPercent} onChange={(e) => setPolicyForm((p) => ({ ...p, canaryPercent: Number(e.target.value || 0) }))} />
            </label>
            <label>Automation mode
              <select value={policyForm.automationMode} onChange={(e) => setPolicyForm((p) => ({ ...p, automationMode: e.target.value }))}>
                <option value="safe">safe</option>
                <option value="autonomous">autonomous</option>
                <option value="aggressive">aggressive</option>
              </select>
            </label>
          </div>
          <button type="submit">Save policy pack</button>
        </form>
        {policyStatus && <p className="meta">{policyStatus}</p>}
        {policyPacks.length > 0 && <pre className="summary">{JSON.stringify(policyPacks, null, 2)}</pre>}
        {policyAudit.length > 0 && <pre className="summary">{JSON.stringify(policyAudit.slice(0, 10), null, 2)}</pre>}
      </section>
    </div>
  );
}
