import { useEffect, useState } from "react";
import { API_BASE, getAPIKey, getWorkspaceID, useScan } from "../context/ScanContext";

const OUTCOME_COLORS = {
  confirmed: "#47d7ac",
  signal: "#59d0ff",
  no_signal: "#7c8aa5",
};

export default function ProbeCoverage() {
  const { scanId, job } = useScan();
  const [probes, setProbes] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [outcomeFilter, setOutcomeFilter] = useState("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    setError("");
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    fetch(`${API_BASE}/api/scan/${encodeURIComponent(scanId)}/probes?workspaceId=${encodeURIComponent(workspaceID)}`, {
      headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceID },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => setProbes(Array.isArray(data) ? data : (data.probes || [])))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [scanId]);

  const categories = ["all", ...Array.from(new Set(probes.map((p) => p.category).filter(Boolean))).sort()];
  const outcomes = ["all", ...Array.from(new Set(probes.map((p) => p.outcome).filter(Boolean))).sort()];

  const filtered = probes.filter((p) => {
    if (categoryFilter !== "all" && p.category !== categoryFilter) return false;
    if (outcomeFilter !== "all" && p.outcome !== outcomeFilter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        (p.endpoint || "").toLowerCase().includes(q) ||
        (p.paramName || "").toLowerCase().includes(q) ||
        (p.category || "").toLowerCase().includes(q) ||
        (p.observation || "").toLowerCase().includes(q)
      );
    }
    return true;
  });

  const stats = probes.reduce((acc, p) => {
    acc.total++;
    acc[p.outcome] = (acc[p.outcome] || 0) + 1;
    return acc;
  }, { total: 0 });

  return (
    <div className="page page--wide">
      <header>
        <div className="eyebrow">Coverage intelligence</div>
        <h1>Probe coverage map</h1>
        <p>Every probe record for the active scan — endpoint, category, payload, and outcome. Understand what was tested and what was skipped.</p>
      </header>

      {!scanId ? (
        <section className="card empty-state">
          <div style={{ fontSize: "2rem", marginBottom: 12 }}>◎</div>
          No scan loaded. Start or load a scan to view probe coverage.
        </section>
      ) : (
        <>
          <section className="hero-panel">
            <div className="metrics-grid">
              <article className="stat-card">
                <span className="stat-card__label">Total probes</span>
                <div className="stat-card__value">{stats.total}</div>
                <div className="stat-card__hint">Probe records across all categories.</div>
              </article>
              <article className="stat-card">
                <span className="stat-card__label">Confirmed</span>
                <div className="stat-card__value" style={{ color: "#47d7ac" }}>{stats.confirmed || 0}</div>
                <div className="stat-card__hint">Probes that yielded confirmed findings.</div>
              </article>
              <article className="stat-card">
                <span className="stat-card__label">Signal</span>
                <div className="stat-card__value" style={{ color: "#59d0ff" }}>{stats.signal || 0}</div>
                <div className="stat-card__hint">Probes with a partial positive response.</div>
              </article>
              <article className="stat-card">
                <span className="stat-card__label">No signal</span>
                <div className="stat-card__value" style={{ color: "#7c8aa5" }}>{stats.no_signal || 0}</div>
                <div className="stat-card__hint">Probes that returned no actionable response.</div>
              </article>
            </div>
          </section>

          <section className="card">
            <div className="toolbar" style={{ alignItems: "flex-start", marginBottom: 14 }}>
              <div>
                <h2>Probe records</h2>
                <p className="meta">Filter by category or outcome to identify coverage gaps.</p>
              </div>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search endpoint, param, observation…"
                style={{ maxWidth: 300 }}
              />
            </div>

            <div className="filter-row" style={{ marginBottom: 10 }}>
              <span className="meta" style={{ alignSelf: "center" }}>Category:</span>
              {categories.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  className={`filter-chip ${categoryFilter === cat ? "is-active" : ""}`}
                  onClick={() => setCategoryFilter(cat)}
                >
                  {cat === "all" ? `All (${probes.length})` : `${cat} (${probes.filter((p) => p.category === cat).length})`}
                </button>
              ))}
            </div>

            <div className="filter-row" style={{ marginBottom: 14 }}>
              <span className="meta" style={{ alignSelf: "center" }}>Outcome:</span>
              {outcomes.map((out) => (
                <button
                  key={out}
                  type="button"
                  className={`filter-chip ${outcomeFilter === out ? "is-active" : ""}`}
                  onClick={() => setOutcomeFilter(out)}
                >
                  {out === "all" ? "All" : out}
                </button>
              ))}
            </div>

            {loading ? (
              <div className="empty-state">Loading probe records…</div>
            ) : error ? (
              <div className="empty-state error">{error}</div>
            ) : filtered.length === 0 ? (
              <div className="empty-state">
                <div style={{ fontSize: "2rem", marginBottom: 10 }}>◎</div>
                {probes.length === 0 ? "No probe records available for this scan." : "No probes match the current filters."}
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Category</th>
                      <th>Endpoint</th>
                      <th>Parameter</th>
                      <th>Payload hash</th>
                      <th>Outcome</th>
                      <th>Status code</th>
                      <th>Observation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((p, idx) => (
                      <tr key={p.id || idx} style={job?.status === "running" && !p.confirmed ? { opacity: 0.8 } : undefined}>
                        <td><span className="chip chip--muted">{p.category || "—"}</span></td>
                        <td style={{ wordBreak: "break-all", maxWidth: 220 }}><span className="meta">{p.endpoint || "—"}</span></td>
                        <td>{p.paramName || "—"}</td>
                        <td><code style={{ fontSize: "0.76rem", color: "#7c8aa5" }}>{p.payloadHash ? p.payloadHash.slice(0, 12) + "…" : "—"}</code></td>
                        <td>
                          <span style={{ color: OUTCOME_COLORS[p.outcome] || "#aaa", fontWeight: 700, fontSize: "0.8rem" }}>
                            {p.outcome || "—"}
                          </span>
                        </td>
                        <td>{p.statusCode || "—"}</td>
                        <td style={{ maxWidth: 260, color: "var(--ink-soft)", fontSize: "0.84rem" }}>{p.observation || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
