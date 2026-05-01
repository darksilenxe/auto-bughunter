/**
 * useAbortable — small hook that hands out per-call AbortController instances
 * and aborts every still-in-flight one when the owning component unmounts.
 *
 * Returns a function. Each invocation produces a fresh AbortController that is
 * registered with the hook; pass `controller.signal` to `fetch` (or check
 * `controller.signal.aborted` before calling setState) to make an asynchronous
 * call cancellable.
 *
 * Usage:
 *   const newController = useAbortable();
 *
 *   async function load() {
 *     const ac = newController();
 *     try {
 *       const res = await fetch(url, { signal: ac.signal });
 *       if (ac.signal.aborted) return;
 *       const data = await res.json();
 *       if (ac.signal.aborted) return;
 *       setData(data);
 *     } catch (err) {
 *       if (err.name === "AbortError") return;
 *       setError(err.message);
 *     }
 *   }
 *
 * Aborted controllers are dropped from the internal set automatically so the
 * registry does not grow without bound across long-lived components.
 */
import { useCallback, useEffect, useRef } from "react";

export function useAbortable() {
  const controllersRef = useRef(null);
  if (controllersRef.current === null) {
    controllersRef.current = new Set();
  }

  useEffect(() => {
    const set = controllersRef.current;
    return () => {
      for (const ac of set) {
        try { ac.abort(); } catch { /* noop */ }
      }
      set.clear();
    };
  }, []);

  return useCallback(() => {
    const set = controllersRef.current;
    const ac = new AbortController();
    set.add(ac);
    ac.signal.addEventListener("abort", () => set.delete(ac), { once: true });
    return ac;
  }, []);
}

/**
 * isAbortError reports whether `err` is the rejection produced when the fetch
 * `AbortSignal` fires. Treat such errors as "the caller is gone, nothing to
 * do" — never surface them as user-facing failures.
 */
const ABORT_ERR_CODE = 20; // DOMException.ABORT_ERR

export function isAbortError(err) {
  return Boolean(err) && (err.name === "AbortError" || err.code === ABORT_ERR_CODE);
}
