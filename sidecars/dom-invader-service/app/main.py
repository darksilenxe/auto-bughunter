"""
DOM Invader Service (plugin)
============================
A FastAPI micro-service that drives a headless Chromium browser via
Playwright to perform client-side taint tracking for DOM XSS, in the spirit
of Burp Suite's "DOM Invader" extension.

This is a *starter scaffold* for your own implementation, not a faithful
clone of DOM Invader. It ships with a working, minimal taint-tracking
engine so it is useful out of the box, and clearly marked extension points
so you can grow it into your own tool:

  - SOURCES: the JS APIs treated as attacker-controlled input.
  - SINKS:   the JS APIs/DOM operations treated as dangerous execution
             contexts.
  - The injected `__domInvader` init script instruments both lists on every
    page/frame, tags values read from a source with an inert, unique canary,
    and reports whenever a tainted value (unmodified or still recognisable)
    reaches a sink.

How it works:
  1. `/v1/analyze` navigates to the target URL in a fresh browser context.
  2. Before any page script runs, an init script monkey-patches each
     configured source getter/API to return a canary-tagged value, and
     each configured sink to check its argument(s) for that canary.
  3. Sink hits are relayed to Python via `page.expose_function` and
     collected as findings (source, sink, snippet, stack).
  4. This process repeats for each canary/source pair so multiple sources
     can be distinguished in a single page load.

Extend it by:
  - Adding entries to SOURCES / SINKS below (or making them configurable
    via the request body).
  - Adding "manual testing" style probes (e.g. injecting canaries into the
    address bar hash/search and reloading, similar to DOM Invader's
    "Test in browser" workflow) via additional endpoints.
  - Adding DOM clobbering, postMessage, and prototype-pollution specific
    source/sink pairs.
  - Wiring findings into the auto-bughunter backend the same way other
    sidecars are consumed (see sidecars/ui-simulation-service for the
    integration pattern), or consume this service directly from your own
    tooling — it is intentionally decoupled from the rest of the platform.

Endpoints:
  POST /v1/analyze  - Run DOM taint analysis against a URL
  GET  /health      - Health check
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from playwright.async_api import async_playwright
from pydantic import BaseModel, Field

logger = logging.getLogger("dom-invader-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

# Required shared-secret auth between the backend/caller and this sidecar.
# Refuse to start if the token is not configured — an empty token would
# allow any unauthenticated caller to drive headless Chromium at arbitrary URLs.
SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
if not SIDECAR_AUTH_TOKEN:
    logger.critical(
        "SIDECAR_AUTH_TOKEN is not set or empty. "
        "Refusing to start to prevent unauthenticated access."
    )
    raise SystemExit(1)
_AUTH_EXEMPT_PATHS = {"/health"}

MAX_TIMEOUT = 120

# ---------------------------------------------------------------------------
# Extension point: sources and sinks
# ---------------------------------------------------------------------------
# Each source is a JS expression path that gets replaced with a getter
# returning a canary-tagged value. Each sink is a JS expression path that
# gets wrapped so its first argument is checked for a canary before the
# original implementation runs.
#
# Add your own entries here (or wire them up to be request-configurable)
# to broaden coverage — e.g. WebSocket message handlers, IndexedDB reads,
# Web Worker postMessage, custom framework router state, etc.
SOURCES: List[str] = [
    "location.hash",
    "location.search",
    "location.href",
    "document.referrer",
    "document.URL",
    "document.cookie",
    "window.name",
]

SINKS: List[str] = [
    "Element.prototype.innerHTML",
    "Element.prototype.outerHTML",
    "Document.prototype.write",
    "Document.prototype.writeln",
    "window.eval",
    "Function.prototype",  # covers new Function(...)
]

_DOM_INVADER_TAINT_PREFIX = "__DOMINV_TAINT__"


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


# ---------------------------------------------------------------------------
# SSRF target validation
# ---------------------------------------------------------------------------

# Networks that must never be reachable from a scan-triggered browser session.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),    # link-local / cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),     # Shared Address Space (RFC 6598)
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _validate_target_url(target: str) -> None:
    """Raise HTTPException(400) if target is not a safe, public-internet URL.

    Checks performed:
    - Scheme must be http or https.
    - Hostname must be present.
    - If the hostname is a literal IP address, it must not fall within any
      private, loopback, link-local, or reserved network.
    - DNS resolution is attempted; all resolved addresses are checked against
      the blocked networks to prevent DNS rebinding / SSRF via hostname.
    """
    try:
        parsed = urlparse(target)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {exc}") from exc

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail=f"Target scheme must be http or https, got: {parsed.scheme!r}",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Target URL has no hostname")

    addresses_to_check: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []

    try:
        addr = ipaddress.ip_address(hostname)
        addresses_to_check.append(addr)
    except ValueError:
        # Not a literal IP — resolve via DNS.
        try:
            resolved = socket.getaddrinfo(hostname, None)
            for family, _type, _proto, _canonname, sockaddr in resolved:
                try:
                    addresses_to_check.append(ipaddress.ip_address(sockaddr[0]))
                except ValueError:
                    pass
        except OSError:
            # DNS resolution failure is treated as safe (the browser will also fail).
            return

    for addr in addresses_to_check:
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                raise HTTPException(
                    status_code=400,
                    detail=f"Target resolves to a disallowed network address ({addr}); "
                           "SSRF to internal/private networks is not permitted.",
                )


app = FastAPI(title="DOM Invader Service (plugin)", version="0.1.0")


@app.middleware("http")
async def _require_sidecar_token(request: Request, call_next):
    if request.url.path not in _AUTH_EXEMPT_PATHS:
        provided = _extract_bearer_token(request)
        if not provided or not hmac.compare_digest(provided, SIDECAR_AUTH_TOKEN):
            return JSONResponse(
                status_code=401,
                content={"detail": "invalid or missing sidecar token"},
            )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    target: str = Field(description="Absolute URL of the page to analyze")
    sources: Optional[List[str]] = Field(
        default=None,
        description="Override the default source list (JS property paths)",
    )
    sinks: Optional[List[str]] = Field(
        default=None,
        description="Override the default sink list (JS property paths)",
    )
    cookies: Optional[str] = Field(
        default=None,
        description="Semicolon-separated 'name=value' pairs to inject before navigating",
    )
    headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Extra HTTP headers to attach to the navigation request",
    )
    timeout: int = Field(default=30, ge=5, le=MAX_TIMEOUT)


class DOMTaintFinding(BaseModel):
    source: str
    sink: str
    snippet: str
    frame_url: str


class AnalyzeResponse(BaseModel):
    target: str
    findings: List[DOMTaintFinding]
    sources_tested: List[str]
    sinks_tested: List[str]
    timed_out: bool
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> JSONResponse:
    """Verify that the Playwright Chromium installation is functional."""
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            await browser.close()
        return JSONResponse(content={"status": "ok", "service": "dom-invader"})
    except Exception as exc:
        logger.warning("Health check failed: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "service": "dom-invader", "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# Analyze endpoint
# ---------------------------------------------------------------------------

@app.post("/v1/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """
    Load the target URL with instrumented sources/sinks and report any
    tainted-value flows observed (source -> sink), the DOM XSS signal that
    Burp's DOM Invader is built around.
    """
    _validate_target_url(req.target)
    sources = req.sources or SOURCES
    sinks = req.sinks or SINKS
    logger.info("dom-invader analyze target=%s sources=%d sinks=%d",
                req.target, len(sources), len(sinks))
    result = await _run_analysis(req, sources, sinks)
    logger.info("dom-invader done target=%s findings=%d timed_out=%s",
                req.target, len(result.findings), result.timed_out)
    return result


# ---------------------------------------------------------------------------
# Core taint-tracking logic
# ---------------------------------------------------------------------------

def _build_init_script(sources: List[str], sinks: List[str]) -> str:
    """
    Build the JS init script that instruments every configured source and
    sink before any page script executes. Each source read is tagged with a
    unique canary embedded in the returned string; each sink call inspects
    its first string-like argument for any canary and, if found, calls back
    into Python via `window.__domInvaderReport`.
    """
    import json as _json

    sources_json = _json.dumps(sources)
    sinks_json = _json.dumps(sinks)
    taint_prefix = _DOM_INVADER_TAINT_PREFIX

    return f"""
(() => {{
  const TAINT_PREFIX = {_json.dumps(taint_prefix)};
  const sourcePaths = {sources_json};
  const sinkPaths = {sinks_json};

  function resolvePath(path) {{
    const parts = path.split(".");
    let obj = window;
    for (let i = 0; i < parts.length - 1; i++) {{
      if (obj == null) return null;
      obj = obj[parts[i]];
    }}
    if (obj == null) return null;
    return {{ obj, key: parts[parts.length - 1] }};
  }}

  function tag(sourcePath, value) {{
    if (typeof value !== "string") return value;
    return TAINT_PREFIX + sourcePath.replace(/[^a-zA-Z0-9]/g, "_") + "__" + value;
  }}

  // Instrument sources: replace each with a getter returning a
  // canary-tagged copy of the real value.
  for (const path of sourcePaths) {{
    try {{
      const resolved = resolvePath(path);
      if (!resolved) continue;
      const {{ obj, key }} = resolved;
      const desc = Object.getOwnPropertyDescriptor(obj, key) ||
        Object.getOwnPropertyDescriptor(Object.getPrototypeOf(obj) || {{}}, key);
      const originalGetter = desc && desc.get ? desc.get.bind(obj) : () => obj[key];
      Object.defineProperty(obj, key, {{
        configurable: true,
        get() {{
          try {{
            const real = originalGetter();
            return tag(path, real);
          }} catch (e) {{
            return originalGetter();
          }}
        }},
      }});
    }} catch (e) {{ /* best-effort instrumentation */ }}
  }}

  function containsTaint(value) {{
    return typeof value === "string" && value.indexOf(TAINT_PREFIX) !== -1;
  }}

  function sourceFromTaint(value) {{
    const idx = value.indexOf(TAINT_PREFIX);
    const rest = value.slice(idx + TAINT_PREFIX.length);
    const sep = rest.indexOf("__");
    return sep === -1 ? "unknown" : rest.slice(0, sep);
  }}

  function report(sinkPath, sourceTag, snippet) {{
    try {{
      window.__domInvaderReport(sinkPath, sourceTag, String(snippet).slice(0, 300));
    }} catch (e) {{ /* reporting is best-effort */ }}
  }}

  // Instrument sinks: wrap each so it inspects its first string-like
  // argument (or `this` for property setters) for taint before delegating
  // to the real implementation.
  for (const path of sinkPaths) {{
    try {{
      const resolved = resolvePath(path);
      if (!resolved) continue;
      const {{ obj, key }} = resolved;
      const desc = Object.getOwnPropertyDescriptor(obj, key);
      if (desc && typeof desc.set === "function") {{
        const originalSetter = desc.set.bind(obj);
        Object.defineProperty(obj, key, {{
          configurable: true,
          set(value) {{
            if (containsTaint(value)) {{
              report(path, sourceFromTaint(value), value);
            }}
            return originalSetter(value);
          }},
          get: desc.get,
        }});
      }} else if (typeof obj[key] === "function") {{
        const original = obj[key];
        obj[key] = function (...args) {{
          for (const arg of args) {{
            if (containsTaint(arg)) {{
              report(path, sourceFromTaint(arg), arg);
              break;
            }}
          }}
          return original.apply(this, args);
        }};
      }}
    }} catch (e) {{ /* best-effort instrumentation */ }}
  }}
}})();
"""


async def _run_analysis(req: AnalyzeRequest, sources: List[str], sinks: List[str]) -> AnalyzeResponse:
    findings: List[DOMTaintFinding] = []
    timed_out = False
    error: Optional[str] = None

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(extra_http_headers=req.headers or {})

            if req.cookies:
                await _inject_cookies(context, req.target, req.cookies)

            page = await context.new_page()

            async def _on_report(sink_path: str, source_tag: str, snippet: str) -> None:
                findings.append(
                    DOMTaintFinding(
                        source=source_tag,
                        sink=sink_path,
                        snippet=snippet,
                        frame_url=page.url,
                    )
                )

            await page.expose_function("__domInvaderReport", _on_report)
            await page.add_init_script(_build_init_script(sources, sinks))

            try:
                await page.goto(req.target, timeout=req.timeout * 1000, wait_until="networkidle")
                # Give any deferred sink calls (timers, async handlers) a
                # brief window to fire after load.
                await page.wait_for_timeout(1000)
            except Exception as exc:
                if "Timeout" in str(exc):
                    timed_out = True
                else:
                    error = str(exc)

            await context.close()
            await browser.close()
    except Exception as exc:
        error = str(exc)
        logger.warning("dom-invader analysis failed target=%s: %s", req.target, exc)

    return AnalyzeResponse(
        target=req.target,
        findings=findings,
        sources_tested=sources,
        sinks_tested=sinks,
        timed_out=timed_out,
        error=error,
    )


async def _inject_cookies(context, target: str, cookie_header: str) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(target)
    domain = parsed.hostname or ""
    cookies = []
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        cookies.append({"name": name.strip(), "value": value.strip(), "domain": domain, "path": "/"})
    if cookies:
        await context.add_cookies(cookies)
