const SECTIONS = [
  {
    title: "HackTricks — Web Application Hacking",
    icon: "🎩",
    description: "Comprehensive techniques for web app pentesting, from injection to business logic flaws.",
    resources: [
      { label: "Web Application Pentesting (index)", url: "https://book.hacktricks.xyz/pentesting-web/web-vulnerabilities-methodology" },
      { label: "XSS — Cross-Site Scripting", url: "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting" },
      { label: "SQL Injection", url: "https://book.hacktricks.xyz/pentesting-web/sql-injection" },
      { label: "CSRF — Cross-Site Request Forgery", url: "https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery" },
      { label: "SSRF — Server-Side Request Forgery", url: "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery" },
      { label: "XXE — XML External Entities", url: "https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity" },
      { label: "Command Injection / RCE", url: "https://book.hacktricks.xyz/pentesting-web/command-injection" },
      { label: "File Inclusion / Path Traversal", url: "https://book.hacktricks.xyz/pentesting-web/file-inclusion" },
      { label: "IDOR / Broken Object-Level Auth", url: "https://book.hacktricks.xyz/pentesting-web/idor" },
      { label: "Open Redirect", url: "https://book.hacktricks.xyz/pentesting-web/open-redirect" },
      { label: "HTTP Request Smuggling", url: "https://book.hacktricks.xyz/pentesting-web/http-request-smuggling" },
      { label: "SSTI — Server-Side Template Injection", url: "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection" },
      { label: "Clickjacking", url: "https://book.hacktricks.xyz/pentesting-web/clickjacking" },
      { label: "WebSocket Attacks", url: "https://book.hacktricks.xyz/pentesting-web/websocket-attacks" },
      { label: "Broken Access Control", url: "https://book.hacktricks.xyz/pentesting-web/broken-access-control" },
    ],
  },
  {
    title: "HackTricks — Authentication & Session",
    icon: "🔐",
    description: "Login bypass, session hijacking, JWT attacks, OAuth flaws, and password reset weaknesses.",
    resources: [
      { label: "Login / Auth Bypass", url: "https://book.hacktricks.xyz/pentesting-web/login-bypass" },
      { label: "JWT Attacks", url: "https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens" },
      { label: "OAuth Flaws", url: "https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover" },
      { label: "Password Reset Flaws", url: "https://book.hacktricks.xyz/pentesting-web/reset-password" },
      { label: "2FA / OTP Bypass", url: "https://book.hacktricks.xyz/pentesting-web/2fa-bypass" },
      { label: "Cookie Attacks", url: "https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies" },
    ],
  },
  {
    title: "HackTricks — API Security",
    icon: "📡",
    description: "REST and GraphQL API attack surface: enumeration, mass assignment, rate-limit bypass.",
    resources: [
      { label: "API Keys Leaks & Attacks", url: "https://book.hacktricks.xyz/pentesting-web/api-keys" },
      { label: "GraphQL Attacks", url: "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql" },
      { label: "Mass Assignment", url: "https://book.hacktricks.xyz/pentesting-web/mass-assignment" },
      { label: "Rate Limit Bypass", url: "https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass" },
    ],
  },
  {
    title: "OWASP Testing Guide",
    icon: "🔓",
    description: "The definitive open-source guide for web application security testing methodology.",
    resources: [
      { label: "OWASP WSTG (latest)", url: "https://owasp.org/www-project-web-security-testing-guide/" },
      { label: "OWASP Top 10 (2021)", url: "https://owasp.org/www-project-top-ten/" },
      { label: "OWASP API Security Top 10", url: "https://owasp.org/www-project-api-security/" },
      { label: "OWASP Cheat Sheet Series", url: "https://cheatsheetseries.owasp.org/" },
    ],
  },
  {
    title: "PortSwigger Web Security Academy",
    icon: "🕸️",
    description: "Free interactive labs and in-depth learning content from the makers of Burp Suite.",
    resources: [
      { label: "Web Security Academy (all topics)", url: "https://portswigger.net/web-security/all-topics" },
      { label: "SQL Injection", url: "https://portswigger.net/web-security/sql-injection" },
      { label: "XSS", url: "https://portswigger.net/web-security/cross-site-scripting" },
      { label: "CSRF", url: "https://portswigger.net/web-security/csrf" },
      { label: "SSRF", url: "https://portswigger.net/web-security/ssrf" },
      { label: "XXE", url: "https://portswigger.net/web-security/xxe" },
      { label: "Access Control & IDOR", url: "https://portswigger.net/web-security/access-control" },
      { label: "Business Logic Vulnerabilities", url: "https://portswigger.net/web-security/logic-flaws" },
      { label: "OAuth 2.0 Vulnerabilities", url: "https://portswigger.net/web-security/oauth" },
      { label: "JWT Attacks", url: "https://portswigger.net/web-security/jwt" },
      { label: "HTTP Request Smuggling", url: "https://portswigger.net/web-security/request-smuggling" },
    ],
  },
  {
    title: "PayloadsAllTheThings",
    icon: "💣",
    description: "Open-source payload and bypass collection for every class of web vulnerability.",
    resources: [
      { label: "Repository (GitHub)", url: "https://github.com/swisskyrepo/PayloadsAllTheThings" },
      { label: "SQL Injection Payloads", url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection" },
      { label: "XSS Payloads", url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection" },
      { label: "SSRF Payloads", url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery" },
      { label: "XXE Payloads", url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection" },
      { label: "SSTI Payloads", url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection" },
      { label: "Command Injection", url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection" },
      { label: "Path Traversal", url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal" },
      { label: "Open Redirect", url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect" },
    ],
  },
  {
    title: "HackTricks — Cloud & Infrastructure",
    icon: "☁️",
    description: "Cloud misconfigs (AWS, GCP, Azure) and container / Kubernetes attack paths.",
    resources: [
      { label: "AWS Pentesting", url: "https://cloud.hacktricks.xyz/pentesting-cloud/aws-security" },
      { label: "GCP Pentesting", url: "https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security" },
      { label: "Azure Pentesting", url: "https://cloud.hacktricks.xyz/pentesting-cloud/azure-security" },
      { label: "Kubernetes Pentesting", url: "https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security" },
    ],
  },
];

export default function References() {
  return (
    <div className="page">
      <header>
        <h1>📚 References</h1>
        <p>Curated pentesting reference material — all links open in a new tab.</p>
      </header>

      <div style={{ display: "grid", gap: "1.25rem" }}>
        {SECTIONS.map((section) => (
          <section key={section.title} className="card">
            <h2 style={{ marginTop: 0, marginBottom: "0.35rem", fontSize: "1.1rem", fontWeight: 700 }}>
              {section.icon} {section.title}
            </h2>
            <p className="meta" style={{ marginTop: 0, marginBottom: "1rem" }}>
              {section.description}
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
              {section.resources.map(({ label, url }) => (
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
