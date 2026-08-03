import { useEffect, useState } from "react";
import { API_BASE, API_KEY, WORKSPACE_ID } from "../context/ScanContext";

function getQueryParam(name) {
  return new URLSearchParams(window.location.search).get(name) || "";
}

export default function ProxyBrowserPopout() {
  const proxyHost = getQueryParam("proxyHost") || "127.0.0.1";
  const proxyPort = getQueryParam("proxyPort") || "8081";
  const mitmEnabled = getQueryParam("mitm") === "1";

  const [url, setUrl] = useState("https://");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [iframeSrc, setIframeSrc] = useState(null);
  const [lastFetchedUrl, setLastFetchedUrl] = useState("");
  const [caDownloaded, setCaDownloaded] = useState(false);
  const [showSetup, setShowSetup] = useState(true);

  const proxyURL = `${proxyHost}:${proxyPort}`;

  const chromiumCmd = mitmEnabled
    ? `chromium --proxy-server="http://${proxyURL}" --ignore-certificate-errors-spki-list=<fingerprint>`
    : `chromium --proxy-server="http://${proxyURL}"`;

  async function downloadCA() {
    try {
      const res = await fetch(`${API_BASE}/api/proxy/ca-certificate`, {
        headers: { "X-API-Key": API_KEY, "X-Workspace-ID": WORKSPACE_ID },
      });
      if (!res.ok) return;
      const blob = await res.blob();
      const objectURL = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectURL;
      anchor.download = "auto-bughunter-proxy-ca.pem";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectURL);
      setCaDownloaded(true);
    } catch {
      /* ignore */
    }
  }

  async function navigate(targetUrl) {
    const trimmed = targetUrl.trim();
    if (!trimmed || trimmed === "https://" || trimmed === "http://") {
      setError("Enter a URL to browse.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const tokenRes = await fetch(`${API_BASE}/api/proxy/browse-token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
          "X-Workspace-ID": WORKSPACE_ID,
        },
        body: JSON.stringify({ url: trimmed }),
      });
      const tokenData = await tokenRes.json().catch(() => ({}));
      if (!tokenRes.ok || !tokenData.token) {
        throw new Error(tokenData.error || "Failed to create browse token.");
      }
      const browseUrl =
        `${API_BASE}/api/proxy/browse` +
        `?url=${encodeURIComponent(trimmed)}` +
        `&browse_token=${encodeURIComponent(tokenData.token)}`;
      setIframeSrc(browseUrl);
      setLastFetchedUrl(trimmed);
      setShowSetup(false);
    } catch (err) {
      setLoading(false);
      setError(err.message || "Failed to load page.");
    }
  }

  function handleKeyDown(e) {
    if (e.key === "Enter") navigate(url);
  }

  useEffect(() => {
    document.title = "Proxy Browser — Auto Bughunter";
  }, []);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        background: "var(--bg-color, #0d0d0d)",
        color: "var(--text-color, #e0e0e0)",
        fontFamily: "var(--font-sans, system-ui, sans-serif)",
      }}
    >
      {/* Toolbar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "8px 12px",
          background: "rgba(0,0,0,0.4)",
          borderBottom: "1px solid var(--border, #333)",
          flexShrink: 0,
        }}
      >
        <span
          style={{
            fontSize: "0.8rem",
            fontWeight: 700,
            color: "var(--accent, #4db8ff)",
            letterSpacing: "0.06em",
            flexShrink: 0,
            whiteSpace: "nowrap",
          }}
        >
          ⬡ PROXY BROWSER
        </span>
        <span
          style={{
            fontSize: "0.75rem",
            color: "#666",
            background: "#111",
            border: "1px solid #333",
            borderRadius: 4,
            padding: "2px 8px",
            fontFamily: "monospace",
            flexShrink: 0,
          }}
        >
          ⇄ {proxyURL}
        </span>
        {mitmEnabled && (
          <span
            style={{
              fontSize: "0.75rem",
              color: "#4dff91",
              background: "rgba(77,255,145,0.08)",
              border: "1px solid rgba(77,255,145,0.3)",
              borderRadius: 4,
              padding: "2px 8px",
              flexShrink: 0,
            }}
          >
            🔒 HTTPS intercept
          </span>
        )}
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="https://example.com"
          spellCheck={false}
          style={{
            flex: 1,
            fontFamily: "monospace",
            fontSize: "0.9rem",
            background: "#111",
            border: "1px solid #333",
            borderRadius: 6,
            color: "#e0e0e0",
            padding: "5px 10px",
          }}
        />
        <button
          type="button"
          onClick={() => navigate(url)}
          disabled={loading}
          style={{ flexShrink: 0, minWidth: 56 }}
        >
          {loading ? "…" : "Go"}
        </button>
        {iframeSrc && (
          <button
            type="button"
            className="button-secondary"
            style={{ flexShrink: 0 }}
            onClick={() => navigate(url)}
            disabled={loading}
          >
            ↺
          </button>
        )}
        <button
          type="button"
          className="button-secondary"
          style={{ flexShrink: 0, fontSize: "0.75rem" }}
          onClick={() => setShowSetup((p) => !p)}
        >
          {showSetup ? "Hide setup" : "Setup"}
        </button>
        {window.opener && (
          <button
            type="button"
            className="button-secondary"
            style={{ flexShrink: 0, fontSize: "0.75rem" }}
            onClick={() => window.close()}
          >
            ✕ Close
          </button>
        )}
      </div>

      {error && (
        <div style={{ padding: "6px 12px", background: "#1a0000", borderBottom: "1px solid #500" }}>
          <p className="error" style={{ margin: 0, fontSize: "0.85rem" }}>{error}</p>
        </div>
      )}

      {/* Setup panel */}
      {showSetup && (
        <div
          style={{
            padding: "16px",
            borderBottom: "1px solid var(--border, #333)",
            background: "rgba(0,0,0,0.2)",
            flexShrink: 0,
          }}
        >
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            {/* CA cert card */}
            {mitmEnabled && (
              <div
                style={{
                  flex: "1 1 260px",
                  background: "var(--surface-color, #1a1a1a)",
                  border: "1px solid var(--border, #333)",
                  borderRadius: 8,
                  padding: "14px 16px",
                }}
              >
                <div style={{ fontWeight: 700, marginBottom: 6, fontSize: "0.9rem" }}>
                  {caDownloaded ? "✅ CA certificate downloaded" : "🔒 Install CA certificate"}
                </div>
                <p className="meta" style={{ marginTop: 0, marginBottom: 10, fontSize: "0.8rem" }}>
                  Install the proxy CA once so HTTPS sites are intercepted without certificate warnings.
                  This browser window already trusts it via the recording transport.
                </p>
                <div className="button-row">
                  <button type="button" className="button-secondary" style={{ fontSize: "0.8rem" }} onClick={downloadCA}>
                    ⬇ Download CA (.pem)
                  </button>
                </div>
                <pre
                  style={{
                    marginTop: 10,
                    background: "#000",
                    border: "1px solid #222",
                    borderRadius: 4,
                    padding: "8px 10px",
                    fontSize: "0.75rem",
                    color: "#aaa",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                  }}
                >{`# macOS
open auto-bughunter-proxy-ca.pem
# → Keychain Access → "Always Trust"

# Linux
sudo cp auto-bughunter-proxy-ca.pem /usr/local/share/ca-certificates/
sudo update-ca-certificates`}</pre>
              </div>
            )}

            {/* Chromium launch card */}
            <div
              style={{
                flex: "1 1 260px",
                background: "var(--surface-color, #1a1a1a)",
                border: "1px solid var(--border, #333)",
                borderRadius: 8,
                padding: "14px 16px",
              }}
            >
              <div style={{ fontWeight: 700, marginBottom: 6, fontSize: "0.9rem" }}>
                🌐 Launch real Chromium with proxy
              </div>
              <p className="meta" style={{ marginTop: 0, marginBottom: 10, fontSize: "0.8rem" }}>
                Run Chromium pre-configured with the intercepting proxy. All traffic is captured in HTTP history.
              </p>
              <pre
                style={{
                  background: "#000",
                  border: "1px solid #222",
                  borderRadius: 4,
                  padding: "8px 10px",
                  fontSize: "0.75rem",
                  color: "#4db8ff",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  margin: 0,
                }}
              >{`chromium \\
  --proxy-server="http://${proxyURL}" \\
  --user-data-dir=/tmp/ab-proxy-profile \\
  --ignore-certificate-errors`}</pre>
            </div>

            {/* How this browser works */}
            <div
              style={{
                flex: "1 1 220px",
                background: "var(--surface-color, #1a1a1a)",
                border: "1px solid var(--border, #333)",
                borderRadius: 8,
                padding: "14px 16px",
              }}
            >
              <div style={{ fontWeight: 700, marginBottom: 6, fontSize: "0.9rem" }}>ℹ️ How this works</div>
              <p className="meta" style={{ marginTop: 0, fontSize: "0.8rem" }}>
                Traffic in this window routes through the backend recording transport — every request appears in
                <strong> HTTP history</strong> and is passively scanned. HTTPS is already handled server-side
                so no CA installation is required for this embedded browser.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Browser viewport — fills remaining space */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {iframeSrc ? (
          <iframe
            key={iframeSrc}
            src={iframeSrc}
            title={`Proxy browser — ${lastFetchedUrl}`}
            sandbox="allow-scripts allow-forms allow-popups"
            onLoad={() => setLoading(false)}
            onError={() => {
              setLoading(false);
              setError("Failed to load page.");
            }}
            style={{ flex: 1, width: "100%", border: "none", background: "#fff" }}
          />
        ) : (
          <div
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 12,
              color: "#555",
            }}
          >
            <div style={{ fontSize: "3rem" }}>⬡</div>
            <p style={{ margin: 0, fontSize: "1rem" }}>Enter a URL above and click <strong>Go</strong></p>
            <p className="meta" style={{ margin: 0 }}>
              Traffic is captured in HTTP history and passively scanned for vulnerabilities.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
