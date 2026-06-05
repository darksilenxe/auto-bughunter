import { useMemo, useState } from "react";
import { useScan } from "../context/ScanContext";

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
const SEV_COLOR = { high: "#ff5f7a", medium: "#ffad66", low: "#ffd966", info: "#8aa0bf" };

function parseDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "unknown";
  }
}

function parsePath(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return "/";
  }
}

function pathPrefix(path, depth) {
  const parts = path.split("/").filter(Boolean);
  return "/" + parts.slice(0, depth).join("/");
}

export default function SurfaceMap() {
  const { job } = useScan();
  const [expandedDomains, setExpandedDomains] = useState(new Set());
  const [expandedPaths, setExpandedPaths] = useState(new Set());
  const [sevFilter, setSevFilter] = useState("all");

  const findings = job?.findings || [];

  // Build domain → path-prefix → [findings] tree
  const tree = useMemo(() => {
    const domainMap = {};
    for (const f of findings) {
      if (!f.affectedUrl) continue;
      const domain = parseDomain(f.affectedUrl);
      const path = parsePath(f.affectedUrl);
      const prefix = pathPrefix(path, 2) || "/";
      if (!domainMap[domain]) domainMap[domain] = {};
      if (!domainMap[domain][prefix]) domainMap[domain][prefix] = [];
      domainMap[domain][prefix].push(f);
    }
    return domainMap;
  }, [findings]);

  const domains = Object.keys(tree).sort();

  const toggleDomain = (d) => setExpandedDomains((prev) => {
    const next = new Set(prev);
    if (next.has(d)) next.delete(d); else next.add(d);
    return next;
  });

  const togglePath = (key) => setExpandedPaths((prev) => {
    const next = new Set(prev);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });

  if (!job) {
    return (
      <div className="page">
        <header>
          <h1>Target surface map</h1>
          <p>Discovered endpoints grouped by domain and path prefix, annotated with finding severity.</p>
        </header>
        <section className="card empty-state">
          <div style={{ fontSize: "2rem", marginBottom: 12 }}>⛓</div>
          No scan loaded. Start or load a scan to explore the target surface.
        </section>
      </div>
    );
  }

  const totalEndpoints = Object.values(tree).reduce((acc, paths) => acc + Object.keys(paths).length, 0);

  const allSevFindings = findings.filter((f) => f.affectedUrl);
  const sevCounts = allSevFindings.reduce((acc, f) => {
    const s = f.severity || "info";
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="page page--wide">
      <header>
        <div className="eyebrow">Attack surface</div>
        <h1>Target surface map</h1>
        <p>
          Endpoints discovered on <strong>{job.target}</strong> grouped by domain and path prefix, with severity annotations.
        </p>
      </header>

      <section className="hero-panel">
        <div className="metrics-grid">
          <article className="stat-card">
            <span className="stat-card__label">Domains</span>
            <div className="stat-card__value">{domains.length}</div>
            <div className="stat-card__hint">Distinct host/domain targets with findings.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Path groups</span>
            <div className="stat-card__value">{totalEndpoints}</div>
            <div className="stat-card__hint">Unique path prefixes with at least one finding.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">High severity</span>
            <div className="stat-card__value" style={{ color: SEV_COLOR.high }}>{sevCounts.high || 0}</div>
            <div className="stat-card__hint">Findings with a mapped URL and high severity.</div>
          </article>
          <article className="stat-card">
            <span className="stat-card__label">Total mapped</span>
            <div className="stat-card__value">{allSevFindings.length}</div>
            <div className="stat-card__hint">Findings with a resolved affectedUrl.</div>
          </article>
        </div>
      </section>

      <section className="card">
        <div className="toolbar" style={{ marginBottom: 14 }}>
          <div>
            <h2>Endpoint tree</h2>
            <p className="meta">Click a domain or path group to expand. Filter by severity.</p>
          </div>
          <div className="filter-row">
            {["all", "high", "medium", "low", "info"].map((s) => (
              <button
                key={s}
                type="button"
                className={`filter-chip ${sevFilter === s ? "is-active" : ""}`}
                onClick={() => setSevFilter(s)}
              >
                {s === "all" ? `All (${allSevFindings.length})` : `${s} (${sevCounts[s] || 0})`}
              </button>
            ))}
          </div>
        </div>

        {domains.length === 0 ? (
          <div className="empty-state">
            <div style={{ fontSize: "2rem", marginBottom: 10 }}>⛓</div>
            No findings with URL information are available yet.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {domains.map((domain) => {
              const pathMap = tree[domain];
              const isExpanded = expandedDomains.has(domain);
              const allDomainFindings = Object.values(pathMap).flat();
              const highestSev = allDomainFindings.sort((a, b) =>
                (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4)
              )[0]?.severity || "info";

              return (
                <div key={domain} className="surface" style={{ padding: 0, overflow: "hidden" }}>
                  {/* Domain header */}
                  <button
                    type="button"
                    onClick={() => toggleDomain(domain)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 12,
                      width: "100%",
                      padding: "14px 16px",
                      textAlign: "left",
                      background: "transparent",
                      color: "var(--ink)",
                      fontWeight: 700,
                      fontSize: "0.95rem",
                      borderRadius: 0,
                      boxShadow: "none",
                    }}
                  >
                    <span style={{ color: isExpanded ? "var(--accent)" : "var(--ink-soft)", transition: "color 0.15s" }}>
                      {isExpanded ? "▾" : "▸"}
                    </span>
                    <span>{domain}</span>
                    <span className={`severity-badge ${highestSev}`} style={{ marginLeft: "auto" }}>{highestSev.toUpperCase()}</span>
                    <span className="chip chip--muted">{allDomainFindings.length} findings</span>
                    <span className="chip chip--muted">{Object.keys(pathMap).length} paths</span>
                  </button>

                  {isExpanded && (
                    <div style={{ borderTop: "1px solid var(--border)", padding: "8px 16px 12px" }}>
                      {Object.entries(pathMap)
                        .sort(([, a], [, b]) => b.length - a.length)
                        .map(([prefix, pathFindings]) => {
                          const pathKey = `${domain}::${prefix}`;
                          const isPathExpanded = expandedPaths.has(pathKey);
                          const filteredPF = sevFilter === "all" ? pathFindings : pathFindings.filter((f) => f.severity === sevFilter);
                          if (sevFilter !== "all" && filteredPF.length === 0) return null;
                          const topSev = filteredPF.sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4))[0]?.severity || "info";

                          return (
                            <div key={prefix} style={{ marginBottom: 6 }}>
                              <button
                                type="button"
                                onClick={() => togglePath(pathKey)}
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: 10,
                                  width: "100%",
                                  padding: "8px 10px",
                                  textAlign: "left",
                                  background: isPathExpanded ? "rgba(89,208,255,0.05)" : "transparent",
                                  color: "var(--ink-soft)",
                                  fontWeight: 600,
                                  fontSize: "0.87rem",
                                  borderRadius: 10,
                                  boxShadow: "none",
                                }}
                              >
                                <span style={{ color: isPathExpanded ? "var(--accent)" : "#555", fontFamily: "monospace" }}>
                                  {isPathExpanded ? "▾" : "▸"}
                                </span>
                                <code style={{ color: "var(--ink-soft)", fontSize: "0.85rem" }}>{prefix}</code>
                                <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: SEV_COLOR[topSev], marginLeft: 4 }} />
                                <span className="meta" style={{ marginLeft: "auto" }}>{filteredPF.length} finding{filteredPF.length !== 1 ? "s" : ""}</span>
                              </button>

                              {isPathExpanded && (
                                <div style={{ paddingLeft: 28, marginTop: 6, display: "flex", flexDirection: "column", gap: 6 }}>
                                  {filteredPF.map((f, fi) => (
                                    <div key={f.id || fi} style={{ display: "flex", gap: 10, alignItems: "flex-start", padding: "6px 10px", background: "rgba(255,255,255,0.025)", borderRadius: 10, border: "1px solid var(--border)" }}>
                                      <span className={`severity-badge ${f.severity || "info"}`} style={{ flexShrink: 0 }}>{(f.severity || "info").toUpperCase()}</span>
                                      <div>
                                        <div style={{ fontWeight: 700, fontSize: "0.87rem" }}>{f.title}</div>
                                        <div className="meta">{f.affectedUrl}</div>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          );
                        })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
