import { Component } from "react";

/**
 * ErrorBoundary catches unhandled JavaScript errors anywhere in the child
 * component tree and renders a fallback UI instead of crashing the whole app.
 *
 * React error boundaries must be class components because no hooks equivalent
 * for componentDidCatch / getDerivedStateFromError exists yet.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, message: "" };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, message: String(error?.message || error || "Unknown error") };
  }

  componentDidCatch(error, info) {
    // Log to console so developers can inspect the stack in the browser devtools.
    console.error("[ErrorBoundary] Uncaught error:", error, info?.componentStack);
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flexDirection: "column",
        gap: "16px",
        padding: "32px",
        background: "var(--bg-body, #06101a)",
        color: "var(--ink, #edf6ff)",
        textAlign: "center",
      }}>
        <div style={{ fontSize: "2.4rem" }}>⚠</div>
        <h2 style={{ margin: 0, fontWeight: 700 }}>Something went wrong</h2>
        <p style={{ margin: 0, color: "var(--ink-muted, #7c8aa5)", maxWidth: 480 }}>
          An unexpected error occurred in this view. Try navigating to another page or
          refreshing the browser.
        </p>
        {this.state.message && (
          <pre style={{
            margin: 0,
            padding: "8px 14px",
            background: "rgba(255,95,122,0.08)",
            border: "1px solid rgba(255,95,122,0.25)",
            borderRadius: "8px",
            fontSize: "0.74rem",
            color: "var(--sev-high, #ff5f7a)",
            maxWidth: "600px",
            overflowX: "auto",
            textAlign: "left",
          }}>
            {this.state.message}
          </pre>
        )}
        <button
          type="button"
          onClick={() => { this.setState({ hasError: false, message: "" }); window.location.href = "/"; }}
          style={{
            marginTop: "8px",
            padding: "8px 20px",
            background: "rgba(89,208,255,0.12)",
            border: "1px solid rgba(89,208,255,0.35)",
            borderRadius: "8px",
            color: "var(--accent, #59d0ff)",
            cursor: "pointer",
            fontWeight: 600,
            fontSize: "0.9rem",
          }}
        >
          Return to dashboard
        </button>
      </div>
    );
  }
}
