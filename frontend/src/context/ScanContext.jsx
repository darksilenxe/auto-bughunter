import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8080";
const API_KEY = localStorage.getItem("api_key") || import.meta.env.VITE_API_KEY || "";
const WORKSPACE_ID = import.meta.env.VITE_WORKSPACE_ID || "default";
export { API_BASE, API_KEY, WORKSPACE_ID };
export function getAPIKey() {
  return localStorage.getItem("api_key") || import.meta.env.VITE_API_KEY || "";
}
export function getWorkspaceID() {
  return import.meta.env.VITE_WORKSPACE_ID || "default";
}

const ScanContext = createContext(null);
const ACTIVE_SCAN_STATUSES = new Set(["running", "finalizing"]);
const TERMINAL_SCAN_STATUSES = new Set(["completed", "failed", "cancelled"]);

function normalizeScanStatus(status) {
  return String(status || "").trim().toLowerCase();
}

function mergeJobSnapshot(prev, next) {
  if (!next) return prev;
  if (!prev) return next;
  const prevStatus = normalizeScanStatus(prev.status);
  const nextStatus = normalizeScanStatus(next.status);
  if (TERMINAL_SCAN_STATUSES.has(prevStatus) && nextStatus && !TERMINAL_SCAN_STATUSES.has(nextStatus)) {
    return {
      ...next,
      status: prev.status,
      completedAt: prev.completedAt || next.completedAt,
    };
  }
  return next;
}

export function ScanProvider({ children }) {
  // ── Active scan state ───────────────────────────────────────────────
  const [scanId, setScanId] = useState("");
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

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

  const updateJobSnapshot = useCallback((updater) => {
    setJob((prev) => mergeJobSnapshot(prev, typeof updater === "function" ? updater(prev) : updater));
  }, []);

  // Ref for the background interval so we can cancel it on unmount.
  const bgPollRef = useRef(null);
  // Ref tracking the currently-active poll generation. Incremented whenever
  // a new scan starts or a historical scan is loaded so any in-flight active
  // polling loop for a previous scan stops mutating state.
  const pollGenRef = useRef(0);

  const cancelActivePolling = useCallback(() => {
    pollGenRef.current += 1;
    if (bgPollRef.current) {
      clearInterval(bgPollRef.current);
      bgPollRef.current = null;
    }
  }, []);

  // ── Start SSE stream ─────────────────────────────────────────────────
  const startEventStream = useCallback((id) => {
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    if (sseRef.current) sseRef.current.close();
    setLiveEvents([]);
    setScreenshots([]);
    const es = new EventSource(`${API_BASE}/api/scan/${id}/events?api_key=${encodeURIComponent(apiKey)}&workspaceId=${encodeURIComponent(workspaceID)}`);
    es.onmessage = (e) => {
      try {
        const evt = JSON.parse(e.data);
        const message = String(evt?.message || "");
        if (/^scan completed:/i.test(message)) {
          cancelActivePolling();
          updateJobSnapshot((prev) => ({ ...(prev || {}), status: "completed" }));
          setLoading(false);
        } else if (/^scan cancelled/i.test(message)) {
          cancelActivePolling();
          updateJobSnapshot((prev) => ({ ...(prev || {}), status: "cancelled" }));
          setLoading(false);
        } else if (/^scan failed:/i.test(message)) {
          cancelActivePolling();
          updateJobSnapshot((prev) => ({ ...(prev || {}), status: "failed" }));
          setLoading(false);
        }
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
  }, [cancelActivePolling, updateJobSnapshot]);

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
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    try {
      const res = await fetch(`${API_BASE}/api/scan/${id}?workspaceId=${encodeURIComponent(workspaceID)}`, {
        headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceID },
      });
      if (!res.ok) return false;
      const data = await res.json();
      updateJobSnapshot(data);
      return TERMINAL_SCAN_STATUSES.has(normalizeScanStatus(data.status));
    } catch {
      return false;
    }
  }, [updateJobSnapshot]);

  const pollScan = useCallback(async (id) => {
    // Invalidate any previous poll loop and clear background interval.
    cancelActivePolling();
    const myGen = pollGenRef.current;

    // Active phase: poll every 5 s for up to 10 min while the loading
    // indicator is shown.
    const maxAttempts = 120;
    let done = false;
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, 5000));
      if (pollGenRef.current !== myGen) return; // superseded by a new scan
      done = await fetchJobStatus(id);
      if (done) break;
    }
    if (pollGenRef.current !== myGen) return;
    setLoading(false);

    // Background phase: if the scan is still running after the active-poll
    // window (e.g. a very long scan), keep checking every 30 s so the UI
    // eventually reflects the terminal state without a manual refresh.
    if (!done) {
      bgPollRef.current = setInterval(async () => {
        if (pollGenRef.current !== myGen) {
          clearInterval(bgPollRef.current);
          bgPollRef.current = null;
          return;
        }
        const terminal = await fetchJobStatus(id);
        if (terminal) {
          clearInterval(bgPollRef.current);
          bgPollRef.current = null;
        }
      }, 30000);
    }
  }, [fetchJobStatus, cancelActivePolling]);

  // Clean up the background interval on unmount.
  useEffect(() => () => {
    cancelActivePolling();
  }, [cancelActivePolling, updateJobSnapshot]);

  // ── Stop a running scan ───────────────────────────────────────────────
  const stopScan = useCallback(async (id) => {
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    const targetId = id || scanId;
    if (!targetId) return;
    try {
      await fetch(`${API_BASE}/api/scan/${encodeURIComponent(targetId)}/stop`, {
        method: "POST",
        headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceID },
      });
    } catch { /* ignore */ }
  }, [scanId]);

  // ── Start a scan ──────────────────────────────────────────────────────
  const startScan = useCallback(async (payload) => {
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    setLoading(true);
    setError("");
    setJob(null);
    setLiveEvents([]);
    setScreenshots([]);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey, "X-Workspace-ID": workspaceID },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || "Scan failed"); setLoading(false); return; }
      setScanId(data.id);
      startEventStream(data.id);
      await pollScan(data.id);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }, [startEventStream, pollScan]);

  // ── Load scan history ─────────────────────────────────────────────────
  const loadHistory = useCallback(async () => {
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    setHistoryLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scans?workspaceId=${encodeURIComponent(workspaceID)}`, {
        headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceID },
      });
      if (res.ok) setScanHistory((await res.json()).scans || []);
    } catch { /* ignore */ }
    setHistoryLoading(false);
  }, []);

  // ── Load a specific past scan by ID ───────────────────────────────────
  // Closes any active SSE stream and replaces the current job with the
  // fetched scan so that Findings, Reports, and Attack Graph all reflect
  // the selected historical engagement.
  const loadScan = useCallback(async (id) => {
    const apiKey = getAPIKey();
    const workspaceID = getWorkspaceID();
    if (sseRef.current) { sseRef.current.close(); sseRef.current = null; }
    // Cancel any active polling loops so they cannot overwrite the loaded
    // historical scan with a later status from a previous live scan.
    cancelActivePolling();
    try {
      const res = await fetch(
        `${API_BASE}/api/scan/${encodeURIComponent(id)}?workspaceId=${encodeURIComponent(workspaceID)}`,
        { headers: { "X-API-Key": apiKey, "X-Workspace-ID": workspaceID } },
      );
      if (!res.ok) return false;
      const data = await res.json();
      setScanId(data.id);
      updateJobSnapshot(data);
      setLiveEvents([]);
      setScreenshots([]);
      setLoading(false);
      setError("");
      return true;
    } catch (err) {
      console.error("[ScanContext] loadScan failed:", err);
      return false;
    }
  }, [cancelActivePolling]);

  return (
    <ScanContext.Provider value={{
      scanId, job, loading, error,
      liveEvents, screenshots,
      scanHistory, historyLoading,
      programs, savePrograms,
      startScan, stopScan, loadHistory, loadScan,
      isScanActive: loading || ACTIVE_SCAN_STATUSES.has(String(job?.status || "").toLowerCase()),
    }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  return useContext(ScanContext);
}
