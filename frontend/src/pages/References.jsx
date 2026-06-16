import { WEB_VULNERABILITY_COVERAGE } from "../lib/webVulnerabilityCoverage";

const KNOWLEDGE_HUBS = [
  { label: "HackTricks Web Methodology", url: "https://hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology" },
  { label: "OWASP Web Security Testing Guide", url: "https://owasp.org/www-project-web-security-testing-guide/" },
  { label: "OWASP Top 10", url: "https://owasp.org/www-project-top-ten/" },
  { label: "OWASP API Security Top 10", url: "https://owasp.org/www-project-api-security/" },
  { label: "PortSwigger Academy (All Topics)", url: "https://portswigger.net/web-security/all-topics" },
  { label: "PayloadsAllTheThings", url: "https://github.com/swisskyrepo/PayloadsAllTheThings" },
];

export default function References() {
  return (
    <div className="page">
      <header>
        <h1>📚 References</h1>
        <p>Web vulnerability coverage matrix with practical testing methods and source references.</p>
      </header>

      <div style={{ display: "grid", gap: "1.25rem" }}>
        <section className="card">
          <h2 style={{ marginTop: 0, marginBottom: "0.6rem", fontSize: "1.05rem", fontWeight: 700 }}>Core Methodology Hubs</h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
            {KNOWLEDGE_HUBS.map(({ label, url }) => (
              <a
                key={url}
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: "inline-block",
                  padding: "0.3rem 0.8rem",
                  background: "rgba(124,58,237,0.15)",
                  border: "1.5px solid rgba(124,58,237,0.35)",
                  borderRadius: "999px",
                  color: "#c4b5fd",
                  fontSize: "0.82rem",
                  textDecoration: "none",
                  transition: "background 0.15s, border-color 0.15s",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(124,58,237,0.35)";
                  e.currentTarget.style.borderColor = "rgba(124,58,237,0.7)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "rgba(124,58,237,0.15)";
                  e.currentTarget.style.borderColor = "rgba(124,58,237,0.35)";
                }}
              >
                {label} ↗
              </a>
            ))}
          </div>
        </section>

        {WEB_VULNERABILITY_COVERAGE.map((item) => (
          <section key={item.id} className="card">
            <h2 style={{ marginTop: 0, marginBottom: "0.35rem", fontSize: "1.02rem", fontWeight: 700 }}>
              {item.title}
            </h2>
            <p className="meta" style={{ marginTop: 0, marginBottom: "0.6rem" }}>
              Detection methods:
            </p>
            <ul style={{ marginTop: 0, marginBottom: "0.8rem", paddingLeft: "1.2rem" }}>
              {item.methods.map((method) => (
                <li key={method} style={{ marginBottom: "0.2rem" }}>{method}</li>
              ))}
            </ul>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
              {item.references.map(({ label, url }) => (
                <a
                  key={url}
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "inline-block",
                    padding: "0.3rem 0.8rem",
                    background: "rgba(124,58,237,0.15)",
                    border: "1.5px solid rgba(124,58,237,0.35)",
                    borderRadius: "999px",
                    color: "#c4b5fd",
                    fontSize: "0.82rem",
                    textDecoration: "none",
                    transition: "background 0.15s, border-color 0.15s",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "rgba(124,58,237,0.35)";
                    e.currentTarget.style.borderColor = "rgba(124,58,237,0.7)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "rgba(124,58,237,0.15)";
                    e.currentTarget.style.borderColor = "rgba(124,58,237,0.35)";
                  }}
                >
                  {label} ↗
                </a>
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
