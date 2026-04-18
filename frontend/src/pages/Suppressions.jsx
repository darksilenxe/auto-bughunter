import { useEffect, useMemo, useState } from "react";
import { API_BASE } from "../context/ScanContext";

/**
 * Suppressions — manage baseline / noise-reduction rules. Lists active
 * suppression rules for an optional target host and lets analysts create
 * new rules. Wraps GET/POST /api/suppressions.
 */
export default function Suppressions() {
  const [target, setTarget] = useState("");
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [draft, setDraft] = useState({
    target: "",
    findingId: "",
    category: "",
    title: "",
    reason: "",
    expiresAt: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [submitMsg, setSubmitMsg] = useState("");

  const queryURL = useMemo(() => {
    const t = target.trim();
    return `${API_BASE}/api/suppressions${t ? `?target=${encodeURIComponent(t)}` : ""}`;
  }, [target]);

  async function load() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch(queryURL);
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error || `HTTP ${res.status}`);
        setRules([]);
      } else {
        const data = await res.json();
        setRules(data.rules || []);
      }
    } catch (err) {
      setError(err.message);
      setRules([]);
    }
    setLoading(false);
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(e) {
    e.preventDefault();
    setSubmitting(true);
    setSubmitMsg("");
    try {
      const body = {
        target: draft.target.trim(),
        findingId: draft.findingId.trim(),
        category: draft.category.trim(),
        title: draft.title.trim(),
        reason: draft.reason.trim(),
      };
      if (draft.expiresAt.trim()) {
        const d = new Date(draft.expiresAt);
        if (!isNaN(d.getTime())) body.expiresAt = d.toISOString();
      }
      const res = await fetch(`${API_BASE}/api/suppressions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setSubmitMsg(`Error: ${data.error || `HTTP ${res.status}`}`);
      } else {
        setSubmitMsg(`Created rule ${data.id}`);
        setDraft({ target: "", findingId: "", category: "", title: "", reason: "", expiresAt: "" });
        load();
      }
    } catch (err) {
      setSubmitMsg(`Error: ${err.message}`);
    }
    setSubmitting(false);
  }

  return (
    <div className="page">
      <header>
        <h1>🔕 Suppressions</h1>
        <p>Baseline and noise-reduction rules. Matching findings are dropped from new scan results.</p>
      </header>

      <section className="card">
        <h2>Active rules</h2>
        <div style={{ display: "flex", gap: "10px", alignItems: "center", marginBottom: "12px" }}>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Filter by target host (optional)"
            style={{ flex: 1, padding: "8px 10px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.2)", background: "rgba(0,0,0,0.25)", color: "#fff" }}
          />
          <button onClick={load} disabled={loading} className="btn">{loading ? "Loading…" : "Reload"}</button>
        </div>
        {error && <p style={{ color: "#fca5a5" }}>Error: {error}</p>}
        {!error && rules.length === 0 && <p className="meta">No active suppression rules.</p>}
        {rules.length > 0 && (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid rgba(255,255,255,0.15)" }}>
                <th style={{ padding: "8px" }}>Target</th>
                <th style={{ padding: "8px" }}>Category</th>
                <th style={{ padding: "8px" }}>Title</th>
                <th style={{ padding: "8px" }}>Finding ID</th>
                <th style={{ padding: "8px" }}>Reason</th>
                <th style={{ padding: "8px" }}>Created</th>
                <th style={{ padding: "8px" }}>Expires</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                  <td style={{ padding: "8px" }}>{r.target || <em>(global)</em>}</td>
                  <td style={{ padding: "8px" }}>{r.category || "—"}</td>
                  <td style={{ padding: "8px" }}>{r.title || "—"}</td>
                  <td style={{ padding: "8px", fontFamily: "monospace", fontSize: "0.8rem" }}>{r.findingId || "—"}</td>
                  <td style={{ padding: "8px" }}>{r.reason || "—"}</td>
                  <td style={{ padding: "8px" }}>{r.createdAt ? new Date(r.createdAt).toLocaleString() : "—"}</td>
                  <td style={{ padding: "8px" }}>{r.expiresAt ? new Date(r.expiresAt).toLocaleString() : "never"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <h2>Create rule</h2>
        <p className="meta" style={{ marginTop: 0 }}>
          At least one of <code>findingId</code>, <code>category</code> or <code>title</code> is required.
          Leave <code>target</code> blank to apply globally.
        </p>
        <form onSubmit={submit} style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "10px" }}>
          {[
            ["target", "Target host (optional)"],
            ["findingId", "Finding ID"],
            ["category", "Category (e.g. headers)"],
            ["title", "Finding title"],
            ["reason", "Reason / context"],
            ["expiresAt", "Expires at (ISO date, optional)"],
          ].map(([k, label]) => (
            <label key={k} style={{ display: "flex", flexDirection: "column", gap: "4px", fontSize: "0.85rem" }}>
              {label}
              <input
                type={k === "expiresAt" ? "datetime-local" : "text"}
                value={draft[k]}
                onChange={(e) => setDraft({ ...draft, [k]: e.target.value })}
                style={{ padding: "8px 10px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.2)", background: "rgba(0,0,0,0.25)", color: "#fff" }}
              />
            </label>
          ))}
          <div style={{ gridColumn: "1 / -1", display: "flex", gap: "10px", alignItems: "center" }}>
            <button type="submit" disabled={submitting} className="btn">{submitting ? "Saving…" : "Create suppression"}</button>
            {submitMsg && <span style={{ fontSize: "0.85rem" }}>{submitMsg}</span>}
          </div>
        </form>
      </section>
    </div>
  );
}
