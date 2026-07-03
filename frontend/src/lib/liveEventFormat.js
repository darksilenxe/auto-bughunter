import { useEffect, useRef } from "react";

/**
 * Shared helpers for rendering SSE scan-event streams.
 *
 * Both `LiveFeed` (the full AI activity stream) and `AttackGraph`'s
 * `ActivityLog` panel render the same underlying `events` array coming from
 * the scan SSE feed. Icon glyphs and color palettes differ intentionally
 * between the two (LiveFeed uses the dashboard's severity palette;
 * AttackGraph reuses the node/severity palette of its own graph so the log
 * matches the graph next to it), but the logic for turning an event object
 * into human-readable text was duplicated. That extraction lives here.
 */

/**
 * Auto-scrolls a scrollable container to the bottom whenever `events`
 * changes. Returns a ref to attach to the scrollable element.
 */
export function useAutoScrollToLatest(events) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [events]);
  return ref;
}

/**
 * Derives the display text (and any agent-name prefix / screenshot payload)
 * for a single live scan event, independent of icon/color styling.
 *
 * Returns:
 *   {
 *     agentName:  string | undefined  — agent that emitted the event, if any
 *     primary:    string               — main line of text to display
 *     screenshot: string | null        — base64 screenshot payload, if any
 *   }
 */
export function formatLiveEventText(evt) {
  switch (evt.type) {
    case "finding":
      return {
        agentName: undefined,
        primary: `[${evt.severity?.toUpperCase() || "INFO"}] ${evt.findingTitle || ""}`,
        screenshot: null,
      };
    case "command":
      return {
        agentName: evt.agentName,
        primary: `$ ${evt.command || evt.message || ""}`,
        screenshot: null,
      };
    case "command_result": {
      const firstLine = evt.output
        ? evt.output.split("\n").filter(Boolean)[0] || "(no output)"
        : "(no output)";
      return {
        agentName: evt.agentName,
        primary: evt.command ? `${evt.command} → ${firstLine}` : firstLine,
        screenshot: null,
      };
    }
    case "screenshot":
      return {
        agentName: undefined,
        primary: evt.message || "Screenshot captured",
        screenshot: evt.screenshot || null,
      };
    default:
      return {
        agentName: evt.agentName,
        primary: evt.message || "",
        screenshot: null,
      };
  }
}
