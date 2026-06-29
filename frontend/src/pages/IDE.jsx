import { useCallback, useRef, useState } from "react";
import { API_BASE, getAPIKey, getWorkspaceID } from "../context/ScanContext";

const LANGUAGES = [
  "Python 3",
  "Bash",
  "JavaScript",
  "Go",
  "Ruby",
  "Perl",
  "PowerShell",
  "PHP",
  "Java",
  "C",
];

const TEMPLATES = [
  {
    label: "SSRF probe",
    prompt:
      "Write a script that probes a URL for SSRF by injecting a callback URL into common parameters (url, redirect, next, src, dest) and checking for out-of-band DNS/HTTP hits.",
    language: "Python 3",
  },
  {
    label: "SQL injection tester",
    prompt:
      "Write a script that tests a parameterised URL for boolean-based SQL injection by appending payloads like ' AND 1=1-- and ' AND 1=2-- and comparing response lengths.",
    language: "Python 3",
  },
  {
    label: "JWT none-alg PoC",
    prompt:
      "Write a PoC that takes a JWT token, strips the signature, sets the algorithm to 'none', and sends the modified token to a target endpoint to test for none-algorithm acceptance.",
    language: "Python 3",
  },
  {
    label: "Reflected XSS finder",
    prompt:
      "Write a script that crawls a target URL, discovers query parameters, and injects a unique XSS polyglot into each one, then checks if the payload appears unescaped in the response.",
    language: "Python 3",
  },
  {
    label: "IDOR enumerator",
    prompt:
      "Write a script that iterates numeric IDs from 1 to 200 on a given API endpoint and reports any responses that return data belonging to a different user account (based on a reference response).",
    language: "Python 3",
  },
  {
    label: "Open redirect scanner",
    prompt:
      "Write a script that tests a list of common open-redirect parameters (redirect, next, url, return_to, goto) for external-URL redirection on a given base URL.",
    language: "Python 3",
  },
];

export default function IDE() {
  const [prompt, setPrompt] = useState("");
  const [language, setLanguage] = useState("Python 3");
  const [context, setContext] = useState("");
  const [code, setCode] = useState("");
  const [model, setModel] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const outputRef = useRef(null);

  const handleGenerate = useCallback(async () => {
    if (!prompt.trim()) return;
    setError(null);
    setCode("");
    setModel("");
    setLoading(true);
    try {
      const apiKey = getAPIKey();
      const workspaceID = getWorkspaceID();
      const res = await fetch(`${API_BASE}/api/ide/generate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey,
          "X-Workspace-ID": workspaceID,
        },
        body: JSON.stringify({
          prompt: prompt.trim(),
          language,
          context: context.trim(),
          workspaceId: workspaceID,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setCode(data.code || "");
      setModel(data.model || "");
      setTimeout(() => outputRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [prompt, language, context]);

  const handleCopy = useCallback(() => {
    if (!code) return;
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }, [code]);

  const applyTemplate = (tpl) => {
    setPrompt(tpl.prompt);
    setLanguage(tpl.language);
  };

  return (
    <div style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1.25rem", height: "100%", boxSizing: "border-box" }}>
      {/* Header */}
      <div>
        <h2 style={{ color: "#e2e8f0", margin: 0, fontSize: "1.1rem", letterSpacing: ".04em" }}>
          ⌥ PoC IDE
        </h2>
        <p style={{ color: "#64748b", fontSize: ".82rem", margin: "4px 0 0" }}>
          Generate PoC and exploit code with CodeLlama — no scan required.
          {model && (
            <span style={{ color: "#334155", marginLeft: ".5rem" }}>
              model: <span style={{ color: "#475569", fontFamily: "monospace" }}>{model}</span>
            </span>
          )}
        </p>
      </div>

      {/* Quick-start templates */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: ".45rem" }}>
        {TEMPLATES.map((tpl) => (
          <button
            key={tpl.label}
            onClick={() => applyTemplate(tpl)}
            disabled={loading}
            style={{
              background: "#0f172a",
              border: "1px solid #1e293b",
              borderRadius: "4px",
              color: "#94a3b8",
              fontSize: ".75rem",
              padding: ".3rem .7rem",
              cursor: loading ? "default" : "pointer",
              letterSpacing: ".02em",
            }}
          >
            {tpl.label}
          </button>
        ))}
      </div>

      {/* Input panel */}
      <div style={{
        background: "#0f172a",
        border: "1px solid #1e293b",
        borderRadius: "8px",
        padding: "1rem",
        display: "grid",
        gap: ".75rem",
        gridTemplateColumns: "1fr auto",
      }}>
        {/* Prompt — full width */}
        <div style={{ gridColumn: "1 / -1", display: "flex", flexDirection: "column", gap: ".35rem" }}>
          <label style={{ color: "#94a3b8", fontSize: ".78rem", letterSpacing: ".04em" }}>
            PROMPT
          </label>
          <textarea
            rows={4}
            placeholder="Describe the PoC or exploit script you want to generate…"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            disabled={loading}
            style={{
              background: "#1e293b",
              border: "1px solid #334155",
              borderRadius: "5px",
              color: "#e2e8f0",
              padding: ".5rem .7rem",
              fontSize: ".88rem",
              fontFamily: "inherit",
              resize: "vertical",
              outline: "none",
            }}
          />
        </div>

        {/* Language */}
        <div style={{ display: "flex", flexDirection: "column", gap: ".35rem" }}>
          <label style={{ color: "#94a3b8", fontSize: ".78rem", letterSpacing: ".04em" }}>
            LANGUAGE
          </label>
          <select
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            disabled={loading}
            style={{
              background: "#1e293b",
              border: "1px solid #334155",
              borderRadius: "5px",
              color: "#e2e8f0",
              padding: ".45rem .6rem",
              fontSize: ".88rem",
              minWidth: "140px",
            }}
          >
            {LANGUAGES.map((l) => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
        </div>

        {/* Context — full width */}
        <div style={{ gridColumn: "1 / -1", display: "flex", flexDirection: "column", gap: ".35rem" }}>
          <label style={{ color: "#94a3b8", fontSize: ".78rem", letterSpacing: ".04em" }}>
            CONTEXT <span style={{ color: "#475569" }}>(optional — paste a finding, HTTP request, or notes)</span>
          </label>
          <textarea
            rows={3}
            placeholder="Paste relevant details: endpoint, request/response, finding description…"
            value={context}
            onChange={(e) => setContext(e.target.value)}
            disabled={loading}
            style={{
              background: "#1e293b",
              border: "1px solid #334155",
              borderRadius: "5px",
              color: "#e2e8f0",
              padding: ".5rem .7rem",
              fontSize: ".82rem",
              fontFamily: "monospace",
              resize: "vertical",
              outline: "none",
            }}
          />
        </div>

        {/* Actions */}
        <div style={{ gridColumn: "1 / -1", display: "flex", gap: ".75rem", alignItems: "center" }}>
          <button
            onClick={handleGenerate}
            disabled={loading || !prompt.trim()}
            style={{
              background: loading ? "#334155" : "#3b82f6",
              border: "none",
              borderRadius: "5px",
              color: "#fff",
              padding: ".5rem 1.3rem",
              fontWeight: 600,
              fontSize: ".88rem",
              cursor: loading || !prompt.trim() ? "default" : "pointer",
              letterSpacing: ".03em",
            }}
          >
            {loading ? "Generating…" : "⌥ Generate Code"}
          </button>
          {error && (
            <span style={{ color: "#f87171", fontSize: ".82rem" }}>{error}</span>
          )}
        </div>
      </div>

      {/* Output */}
      {(code || loading) && (
        <div
          ref={outputRef}
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            background: "#0a0f1a",
            border: "1px solid #1e293b",
            borderRadius: "8px",
            overflow: "hidden",
            minHeight: "280px",
          }}
        >
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: ".5rem .75rem",
            borderBottom: "1px solid #1e293b",
            background: "#0f172a",
          }}>
            <span style={{ color: "#475569", fontSize: ".75rem", letterSpacing: ".04em", fontFamily: "monospace" }}>
              {language}
            </span>
            {code && (
              <button
                onClick={handleCopy}
                style={{
                  background: "transparent",
                  border: "1px solid #334155",
                  borderRadius: "4px",
                  color: copied ? "#4dff91" : "#94a3b8",
                  fontSize: ".75rem",
                  padding: ".2rem .6rem",
                  cursor: "pointer",
                }}
              >
                {copied ? "✓ Copied" : "⎘ Copy"}
              </button>
            )}
          </div>
          <pre style={{
            flex: 1,
            margin: 0,
            padding: ".75rem",
            overflowY: "auto",
            color: "#e2e8f0",
            fontSize: ".83rem",
            fontFamily: "monospace",
            lineHeight: 1.55,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}>
            {loading && !code ? (
              <span style={{ color: "#334155" }}>● Generating…</span>
            ) : (
              code
            )}
          </pre>
        </div>
      )}
    </div>
  );
}
