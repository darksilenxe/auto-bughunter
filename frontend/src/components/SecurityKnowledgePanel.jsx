function formatScore(score) {
  if (typeof score !== "number" || Number.isNaN(score) || score <= 0) return null;
  return score.toFixed(2);
}

function MetaBadge({ children }) {
  if (!children) return null;
  return <span className="knowledge-badge">{children}</span>;
}

export default function SecurityKnowledgePanel({ knowledge }) {
  if (!knowledge) return null;

  const references = knowledge.references || [];
  const suggestedActions = knowledge.suggestedActions || [];

  return (
    <section className="card">
      <h2>Security Knowledge</h2>
      <p className="meta">
        Curated references retrieved from the security-knowledge sidecar for this scan.
      </p>

      {(knowledge.stage || knowledge.query || knowledge.curationMode || knowledge.licenseNotice) && (
        <div className="knowledge-overview">
          {knowledge.stage && <p><b>Stage:</b> {knowledge.stage}</p>}
          {knowledge.query && <p><b>Query:</b> {knowledge.query}</p>}
          {knowledge.curationMode && <p><b>Curation mode:</b> {knowledge.curationMode}</p>}
          {knowledge.licenseNotice && <p><b>License notice:</b> {knowledge.licenseNotice}</p>}
        </div>
      )}

      {suggestedActions.length > 0 && (
        <>
          <h3>Knowledge-driven Actions</h3>
          <ul className="findings">
            {suggestedActions.map((action, index) => (
              <li key={`${action}-${index}`}>
                <p>{action}</p>
              </li>
            ))}
          </ul>
        </>
      )}

      <h3>References {references.length > 0 ? `(${references.length})` : ""}</h3>
      {references.length === 0 ? (
        <p className="meta">No curated references were attached to this scan.</p>
      ) : (
        <div className="knowledge-list">
          {references.map((ref, index) => (
            <article className="knowledge-reference" key={ref.id || `${ref.title}-${index}`}>
              <div className="knowledge-header">
                <div>
                  <h4>{ref.title || "Untitled reference"}</h4>
                  <div className="knowledge-badges">
                    <MetaBadge>{ref.sourceType}</MetaBadge>
                    <MetaBadge>{ref.topic}</MetaBadge>
                    <MetaBadge>{ref.vulnerabilityClass}</MetaBadge>
                    <MetaBadge>{ref.technique}</MetaBadge>
                    <MetaBadge>{ref.license}</MetaBadge>
                    <MetaBadge>{formatScore(ref.score) ? `score ${formatScore(ref.score)}` : ""}</MetaBadge>
                  </div>
                </div>
                {ref.url && (
                  <a href={ref.url} target="_blank" rel="noreferrer" className="knowledge-link">
                    Open source ↗
                  </a>
                )}
              </div>
              {ref.passage && <p className="knowledge-passage">{ref.passage}</p>}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
