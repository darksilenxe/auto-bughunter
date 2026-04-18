import { useState } from "react";
import { API_BASE } from "../context/ScanContext";

/**
 * Catalog of every API endpoint exposed by the backend. Each entry describes
 * the method, path, a short description, and (optionally) a sample JSON body
 * for POST endpoints. `pathParam` indicates the path segment that should be
 * substituted with a user-provided value (e.g. {id}).
 */
const ENDPOINTS = [
  {
    group: "Health & Discovery",
    items: [
      {
        method: "GET",
        path: "/api/health",
        description: "Liveness probe. Exempt from API token auth and rate limiting.",
      },
      {
        method: "GET",
        path: "/api/ready",
        description: "Readiness probe — verifies dependent subsystems (DB) are reachable. Exempt from auth/rate limit.",
      },
      {
        method: "GET",
        path: "/api/openapi.json",
        description: "OpenAPI 3.1 specification of the public HTTP surface. Exempt from auth/rate limit.",
      },
      {
        method: "GET",
        path: "/api/tools/health",
        description: "Returns scanner toolchain readiness (binary presence by category).",
      },
      {
        method: "GET",
        path: "/metrics",
        description: "Prometheus-format counters: HTTP requests, scans, findings, webhooks, rate-limit/auth rejections.",
      },
    ],
  },
  {
    group: "Scans",
    items: [
      {
        method: "POST",
        path: "/api/scan",
        description: "Create a scan. authProfile (headers/cookies/basic auth) is required.",
        sampleBody: {
          target: "https://example.com",
          idempotencyKey: "scan-example-001",
          authProfile: { headers: { Authorization: "Bearer ******" } },
          options: {},
        },
      },
      {
        method: "GET",
        path: "/api/scan/{id}",
        description: "Get full scan job state, findings, telemetry, dashboard, and automated report.",
        pathParam: "id",
        pathParamLabel: "Scan ID",
      },
      {
        method: "GET",
        path: "/api/scan/{id}/events",
        description: "Server-Sent Events stream of scan progress (open in a new tab).",
        pathParam: "id",
        pathParamLabel: "Scan ID",
        openInNewTab: true,
      },
      {
        method: "GET",
        path: "/api/scan/{id}/sarif",
        description: "Download findings as SARIF v2.1.0 (for GitHub code scanning, etc.).",
        pathParam: "id",
        pathParamLabel: "Scan ID",
        download: (id) => `scan-${id}.sarif.json`,
      },
      {
        method: "GET",
        path: "/api/report/{id}",
        description: "Download the PDF scan report.",
        pathParam: "id",
        pathParamLabel: "Scan ID",
        download: (id) => `scan-report-${id}.pdf`,
      },
      {
        method: "GET",
        path: "/api/scans",
        description: "List recent completed scans (lightweight summaries).",
      },
    ],
  },
  {
    group: "Proxy",
    items: [
      {
        method: "GET",
        path: "/api/proxy/requests",
        description: "List captured proxy requests.",
      },
      {
        method: "GET",
        path: "/api/proxy/requests/{id}",
        description: "Get a single captured proxy request by ID.",
        pathParam: "id",
        pathParamLabel: "Proxy Request ID",
      },
      {
        method: "POST",
        path: "/api/proxy/replay",
        description: "Replay a captured proxy request (optionally with scope validation).",
        sampleBody: {
          method: "GET",
          url: "https://example.com/api/me",
          headers: {},
          body: "",
        },
      },
    ],
  },
  {
    group: "Feedback & Suppressions",
    items: [
      {
        method: "POST",
        path: "/api/feedback",
        description: "Store bug bounty outcome labels for a finding.",
        sampleBody: {
          scanId: "scan-uuid",
          findingId: "finding-id",
          category: "headers",
          title: "Missing security header",
          programName: "Example Program",
          outcome: "accepted",
          payoutUsd: 150.0,
          notes: "Accepted by triager",
        },
      },
      {
        method: "POST",
        path: "/api/finding-verification",
        description: "Submit manual exploitability verification (confirmed/rejected) for a finding.",
        sampleBody: {
          scanId: "scan-uuid",
          findingId: "finding-id",
          status: "confirmed",
          verifiedBy: "analyst@example.com",
          notes: "Reproduced via manual check.",
        },
      },
      {
        method: "POST",
        path: "/api/suppressions",
        description: "Create a baseline/noise-reduction rule (optional target scope and expiry).",
        sampleBody: {
          target: "example.com",
          category: "headers",
          title: "Missing X-Frame-Options",
          reason: "Tracked separately in JIRA-1234",
        },
      },
      {
        method: "GET",
        path: "/api/suppressions",
        description: "List active suppression rules (optionally scoped to a target host).",
        queryParams: [{ name: "target", placeholder: "example.com" }],
      },
    ],
  },
  {
    group: "Automation",
    items: [
      {
        method: "POST",
        path: "/api/automation/event",
        description: "Queue an event-driven scan (deploy, dependency_change, config_change, new_asset).",
        sampleBody: {
          eventType: "deploy",
          target: "https://example.com",
        },
      },
      {
        method: "GET",
        path: "/api/automation/report",
        description: "Executive automation report: scan trends, feedback metrics, open ticket counts.",
      },
      {
        method: "GET",
        path: "/api/automation/tickets",
        description: "Open auto-managed remediation tickets (optional ?target=).",
        queryParams: [{ name: "target", placeholder: "example.com" }],
      },
    ],
  },
  {
    group: "ML",
    items: [
      {
        method: "GET",
        path: "/api/ml/engagements",
        description: "Sanitized, pseudonymized engagement dataset for offline/shadow ML training.",
        queryParams: [{ name: "limit", placeholder: "100" }],
      },
      {
        method: "GET",
        path: "/api/ml/agent-weights",
        description: "Returns weights from the agent learner service (if configured).",
      },
    ],
  },
];

const METHOD_COLORS = {
  GET: "#166534",
  POST: "#7f1d1d",
  DELETE: "#991b1b",
};

function buildURL(path, pathParamValue, queryValues) {
  let url = API_BASE + path;
  if (path.includes("{") && pathParamValue) {
    url = url.replace(/\{[^}]+\}/, encodeURIComponent(pathParamValue));
  }
  const qs = Object.entries(queryValues || {})
    .filter(([, v]) => v !== undefined && v !== null && String(v).length > 0)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
  if (qs) {
    url += (url.includes("?") ? "&" : "?") + qs;
  }
  return url;
}

function EndpointCard({ endpoint }) {
  const [pathValue, setPathValue] = useState("");
  const [queryValues, setQueryValues] = useState({});
  const [body, setBody] = useState(
    endpoint.sampleBody ? JSON.stringify(endpoint.sampleBody, null, 2) : ""
  );
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const needsPathParam = !!endpoint.pathParam;
  const canBuildURL = !needsPathParam || pathValue.trim() !== "";

  const url = canBuildURL ? buildURL(endpoint.path, pathValue.trim(), queryValues) : null;

  async function invoke() {
    if (!url) return;
    setLoading(true);
    setError("");
    setResponse(null);
    try {
      const opts = { method: endpoint.method, headers: {} };
      if (endpoint.method === "POST") {
        opts.headers["Content-Type"] = "application/json";
        if (body.trim()) {
          // Validate JSON before sending; surface parse errors clearly.
          try {
            JSON.parse(body);
          } catch (e) {
            throw new Error("Invalid JSON body: " + e.message);
          }
          opts.body = body;
        } else {
          opts.body = "{}";
        }
      }
      const res = await fetch(url, opts);
      const contentType = res.headers.get("content-type") || "";
      let data;
      if (contentType.includes("application/json") || contentType.includes("application/sarif+json")) {
        data = await res.json();
      } else {
        data = await res.text();
      }
      setResponse({ status: res.status, contentType, data });
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card" style={{ marginBottom: "1rem" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
        <span
          style={{
            background: METHOD_COLORS[endpoint.method] || "#374151",
            color: "#fff",
            padding: "3px 10px",
            borderRadius: "6px",
            fontSize: "0.75rem",
            fontWeight: 700,
            letterSpacing: "0.05em",
          }}
        >
          {endpoint.method}
        </span>
        <code style={{ fontSize: "0.95rem", fontWeight: 600 }}>{endpoint.path}</code>
      </div>
      <p className="meta" style={{ margin: "0.5rem 0 1rem" }}>{endpoint.description}</p>

      {needsPathParam && (
        <div style={{ marginBottom: "0.75rem" }}>
          <label style={{ display: "block", fontSize: "0.8rem", marginBottom: "0.25rem" }}>
            {endpoint.pathParamLabel || endpoint.pathParam}
          </label>
          <input
            type="text"
            value={pathValue}
            onChange={(e) => setPathValue(e.target.value)}
            placeholder={endpoint.pathParam}
            style={{ width: "100%", padding: "0.4rem 0.6rem", fontFamily: "monospace" }}
          />
        </div>
      )}

      {(endpoint.queryParams || []).map((q) => (
        <div key={q.name} style={{ marginBottom: "0.75rem" }}>
          <label style={{ display: "block", fontSize: "0.8rem", marginBottom: "0.25rem" }}>
            ?{q.name}
          </label>
          <input
            type="text"
            value={queryValues[q.name] || ""}
            onChange={(e) => setQueryValues({ ...queryValues, [q.name]: e.target.value })}
            placeholder={q.placeholder || ""}
            style={{ width: "100%", padding: "0.4rem 0.6rem", fontFamily: "monospace" }}
          />
        </div>
      ))}

      {endpoint.method === "POST" && (
        <div style={{ marginBottom: "0.75rem" }}>
          <label style={{ display: "block", fontSize: "0.8rem", marginBottom: "0.25rem" }}>
            Request body (JSON)
          </label>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows={Math.min(14, Math.max(6, body.split("\n").length))}
            style={{
              width: "100%",
              padding: "0.5rem",
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
              fontSize: "0.82rem",
            }}
          />
        </div>
      )}

      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", alignItems: "center" }}>
        <button
          onClick={invoke}
          disabled={!canBuildURL || loading}
          style={{
            background: METHOD_COLORS[endpoint.method] || "#374151",
            color: "#fff",
            border: "none",
            padding: "0.5rem 1rem",
            borderRadius: "6px",
            fontWeight: 700,
            cursor: canBuildURL && !loading ? "pointer" : "not-allowed",
            opacity: canBuildURL && !loading ? 1 : 0.5,
          }}
        >
          {loading ? "Sending…" : `Send ${endpoint.method}`}
        </button>
        {endpoint.method === "GET" && url && (
          <>
            <a href={url} target="_blank" rel="noreferrer" style={{ fontSize: "0.85rem" }}>
              Open in new tab
            </a>
            {endpoint.download && (
              <a
                href={url}
                download={endpoint.download(pathValue.trim())}
                style={{ fontSize: "0.85rem" }}
              >
                Download
              </a>
            )}
          </>
        )}
        {url && (
          <code style={{ fontSize: "0.78rem", color: "#555", wordBreak: "break-all" }}>{url}</code>
        )}
      </div>

      {error && (
        <pre
          style={{
            marginTop: "0.75rem",
            background: "#fef2f2",
            color: "#7f1d1d",
            padding: "0.75rem",
            borderRadius: "6px",
            fontSize: "0.82rem",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}
        >
          {error}
        </pre>
      )}

      {response && (
        <div style={{ marginTop: "0.75rem" }}>
          <div style={{ fontSize: "0.8rem", marginBottom: "0.25rem" }}>
            Status: <strong>{response.status}</strong>
            {response.contentType && (
              <span style={{ color: "#666", marginLeft: "0.5rem" }}>
                ({response.contentType})
              </span>
            )}
          </div>
          <pre
            style={{
              background: "#0b1020",
              color: "#e2e8f0",
              padding: "0.75rem",
              borderRadius: "6px",
              fontSize: "0.78rem",
              maxHeight: "320px",
              overflow: "auto",
            }}
          >
            {typeof response.data === "string"
              ? response.data
              : JSON.stringify(response.data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function ApiExplorer() {
  return (
    <div className="page">
      <header>
        <h1>🔌 API Explorer</h1>
        <p>
          Discover and invoke every backend endpoint. Base URL: <code>{API_BASE}</code>
        </p>
      </header>

      <section className="card" style={{ marginBottom: "1rem" }}>
        <p className="meta" style={{ margin: 0 }}>
          If <code>API_TOKEN</code> is set on the backend, requests from this UI are
          unauthenticated and will receive <strong>401 Unauthorized</strong> for protected
          routes. Use a curl/HTTP client with an{" "}
          <code>Authorization: Bearer &lt;token&gt;</code> header in that case. The{" "}
          <code>/api/health</code> and <code>/metrics</code> endpoints are always exempt.
        </p>
      </section>

      {ENDPOINTS.map((group) => (
        <section key={group.group} style={{ marginBottom: "1.5rem" }}>
          <h2 style={{ color: "#fff", margin: "0 0 0.5rem" }}>{group.group}</h2>
          {group.items.map((ep) => (
            <EndpointCard key={`${ep.method} ${ep.path}`} endpoint={ep} />
          ))}
        </section>
      ))}
    </div>
  );
}
