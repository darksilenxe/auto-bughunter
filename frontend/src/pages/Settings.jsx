import { useState } from "react";
import { useScan } from "../context/ScanContext";

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

export default function Settings() {
  const { programs, savePrograms } = useScan();
  const [editing, setEditing] = useState(null); // null | index | "new"
  const [form, setForm] = useState(EMPTY_PROGRAM);

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
      </section>
    </div>
  );
}
