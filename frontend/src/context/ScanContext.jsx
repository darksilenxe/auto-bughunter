import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { isAbortError, useAbortable } from "../lib/useAbortable";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8080";
// Security: API keys are read from localStorage (set via Settings UI) only.
// VITE_API_KEY is intentionally NOT honored here because Vite inlines
// `import.meta.env.*` literals into the production JS bundle at build time,
// which would publish the operator's API key to every browser that downloads
// the app. Dev-time auth should rely on BOOTSTRAP_ADMIN_API_KEY pasted into
// the Settings UI, not a build-time env var.
const API_KEY = (typeof localStorage !== "undefined" && localStorage.getItem("api_key")) || "";
const WORKSPACE_ID = import.meta.env.VITE_WORKSPACE_ID || "default";
export { API_BASE, API_KEY, WORKSPACE_ID };

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  // ── Active scan state ───────────────────────────────────────────────
  const [scanId, setScanId] = useState("");
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Per-call AbortController registry; every still-in-flight controller is
  // aborted automatically when the provider unmounts so no `setState` runs on
  // a torn-down tree.
  const newController = useAbortable();

  // ── Live events (SSE) ───────────────────────────────────────────────
  const [liveEvents, setLiveEvents] = useState([]);
  const sseRef = useRef(null);

  // ── Screenshots captured during scan ────────────────────────────────
  const [screenshots, setScreenshots] = useState([]); // [{url, b64, agentName}]

  // ── Scan history ────────────────────────────────────────────────────
  const [scanHistory, setScanHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  // ── Bug-bounty programs (persisted in localStorage) ─────────────────
  const [programs, setPrograms] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("bb_programs") || "[]");
    } catch {
      return [];
    }
  });

  const savePrograms = useCallback((progs) => {
    setPrograms(progs);
    localStorage.setItem("bb_programs", JSON.stringify(progs));
  }, []);

  // ── Start SSE stream ─────────────────────────────────────────────────
  const startEventStream = useCallback((id) => {
    if (sseRef.current) sseRef.current.close();
    setLiveEvents([]);
    setScreenshots([]);
    const es = new EventSource(`${API_BASE}/api/scan/${id}/events?workspaceId=${encodeURIComponent(WORKSPACE_ID)}`);
    es.onmessage = (e) => {
      try {
        const evt = JSON.parse(e.data);
        setLiveEvents((prev) => [...prev, evt]);
        if (evt.type === "screenshot" && evt.screenshot) {
          setScreenshots((prev) => [
            ...prev,
            { b64: evt.screenshot, message: evt.message || "", agentName: evt.agentName || "scanner" },
          ]);
        }
      } catch { /* ignore */ }
    };
    es.onerror = () => es.close();
    sseRef.current = es;
  }, []);

  // Close SSE when scan ends
  useEffect(() => {
    if (job?.status === "completed" || job?.status === "failed" || job?.status === "cancelled") {
      sseRef.current?.close();
      sseRef.current = null;
    }
  }, [job?.status]);

  useEffect(() => () => sseRef.current?.close(), []);

  // ── Poll scan status ──────────────────────────────────────────────────
  // Fetches a single status snapshot and returns true when the job has
  // reached a terminal state (completed / failed / cancelled).
  const fetchJobStatus = useCallback(async (id) => {
    const ac = newController();
    try {
      const res = await fetch(`${API_BASE}/api/scan/${id}?workspaceId=${encodeURIComponent(WORKSPACE_ID)}`, {
        headers: { "X-API-Key": API_KEY, "X-Workspace-ID": WORKSPACE_ID },
        signal: ac.signal,
      });
      if (ac.signal.aborted) return false;
      if (!res.ok) return false;
      const data = await res.json();
      if (ac.signal.aborted) return false;
      setJob(data);
      return data.status === "completed" || data.status === "failed" || data.status === "cancelled";
    } catch (err) {
      if (isAbortError(err)) return true; // stop polling loops on unmount
      return false;
    }
  }, [newController]);

  // Ref for the background interval so we can cancel it on unmount.
  const bgPollRef = useRef(null);

  const clearBackgroundPoll = useCallback(() => {
    if (bgPollRef.current) {
      clearTimeout(bgPollRef.current);
      bgPollRef.current = null;
    }
  }, []);

  const scheduleBackgroundPoll = useCallback((id) => {
    const tick = async () => {
      const terminal = await fetchJobStatus(id);
      if (terminal) {
        clearBackgroundPoll();
        return;
      }
      bgPollRef.current = setTimeout(tick, 30000);
    };
    bgPollRef.current = setTimeout(tick, 30000);
  }, [clearBackgroundPoll, fetchJobStatus]);

  const pollScan = useCallback(async (id) => {
    // Cancel any existing background interval from a previous scan before
    // starting a new active-poll loop, preventing interval leaks on re-use.
    clearBackgroundPoll();

    // Active phase: poll every 5 s for up to 10 min while the loading
    // indicator is shown.
    const maxAttempts = 120;
    let done = false;
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, 5000));
      done = await fetchJobStatus(id);
      if (done) break;
    }
    setLoading(false);

    // Background phase: if the scan is still running after the active-poll
    // window (e.g. a very long scan), keep checking every 30 s so the UI
    // eventually reflects the terminal state without a manual refresh.
    if (!done) {
      scheduleBackgroundPoll(id);
    }
  }, [clearBackgroundPoll, fetchJobStatus, scheduleBackgroundPoll]);

  // Clean up the background interval on unmount.
  useEffect(() => () => clearBackgroundPoll(), [clearBackgroundPoll]);

  // ── Stop a running scan ───────────────────────────────────────────────
  const stopScan = useCallback(async (id) => {
    const targetId = id || scanId;
    if (!targetId) return;
    const ac = newController();
    try {
      await fetch(`${API_BASE}/api/scan/${encodeURIComponent(targetId)}/stop`, {
        method: "POST",
        headers: { "X-API-Key": API_KEY, "X-Workspace-ID": WORKSPACE_ID },
        signal: ac.signal,
      });
    } catch (err) {
      if (isAbortError(err)) return;
      /* ignore */
    }
  }, [scanId, newController]);

  // ── Start a scan ──────────────────────────────────────────────────────
  const startScan = useCallback(async (payload) => {
    setLoading(true);
    setError("");
    setJob(null);
    setLiveEvents([]);
    setScreenshots([]);
    const ac = newController();
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": API_KEY, "X-Workspace-ID": WORKSPACE_ID },
        body: JSON.stringify(payload),
        signal: ac.signal,
      });
      const data = await res.json();
      if (ac.signal.aborted) return;
      if (!res.ok) { setError(data.error || "Scan failed"); setLoading(false); return; }
      setScanId(data.id);
      startEventStream(data.id);
      await pollScan(data.id);
    } catch (err) {
      if (isAbortError(err)) return;
      setError(err.message);
      setLoading(false);
    }
  }, [startEventStream, pollScan, newController]);

  // ── Load scan history ─────────────────────────────────────────────────
  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    const ac = newController();
    try {
      const res = await fetch(`${API_BASE}/api/scans?workspaceId=${encodeURIComponent(WORKSPACE_ID)}`, {
        headers: { "X-API-Key": API_KEY, "X-Workspace-ID": WORKSPACE_ID },
        signal: ac.signal,
      });
      if (ac.signal.aborted) return;
      if (res.ok) {
        const data = await res.json();
        if (ac.signal.aborted) return;
        setScanHistory(data.scans || []);
      }
    } catch (err) {
      if (isAbortError(err)) return;
      /* ignore */
    } finally {
      if (!ac.signal.aborted) setHistoryLoading(false);
    }
  }, [newController]);

  return (
    <ScanContext.Provider value={{
      scanId, job, loading, error,
      liveEvents, screenshots,
      scanHistory, historyLoading,
      programs, savePrograms,
      startScan, stopScan, loadHistory,
    }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  return useContext(ScanContext);
}
