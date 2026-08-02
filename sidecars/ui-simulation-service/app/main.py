"""
UI Simulation Service
=====================
A FastAPI micro-service that drives a headless Chromium browser via Playwright
to simulate human interaction with a target web application.  It navigates all
discoverable pages, clicks interactive elements (buttons, tabs, nav links, menu
items), fills forms with realistic dummy data, scrolls, and records every
network request generated during the session.

The collected endpoint set is returned to the caller so the auto-bughunter
backend can feed it into subsequent active probes as additional attack surface.

Endpoints:
  POST /v1/simulate  - Run a human-simulation session against a URL
  GET  /health       - Health check
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import logging
import os
import random
import re
import socket
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from playwright.async_api import (
    BrowserContext,
    Page,
    Playwright,
    Request as PWRequest,
    async_playwright,
)
from pydantic import BaseModel, Field

logger = logging.getLogger("ui-simulation-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

# Required shared-secret auth between the backend and this sidecar.
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

# Maximum per-session execution time (seconds)
MAX_TIMEOUT = 300

# Human-like interaction timing (seconds)
_MIN_PAUSE = 0.4
_MAX_PAUSE = 1.8
_SCROLL_PAUSE = 0.6
_TYPE_DELAY_MS = 80  # milliseconds per character

# Caps to keep runtimes bounded
_MAX_PAGES = 12
_MAX_CLICKS_PER_PAGE = 20
_MAX_FORMS_PER_PAGE = 3
_MAX_DEPTH = 3

# Realistic dummy values for common form field types
_DUMMY_VALUES: Dict[str, str] = {
    "email": "tester@example.com",
    "password": "T3stP@ss!",
    "username": "testuser",
    "name": "Test User",
    "firstname": "Test",
    "first_name": "Test",
    "lastname": "User",
    "last_name": "User",
    "phone": "555-0100",
    "tel": "555-0100",
    "address": "123 Test Street",
    "city": "Testville",
    "zip": "12345",
    "postcode": "12345",
    "country": "US",
    "message": "This is a test message for security scanning purposes.",
    "comment": "Security scan comment.",
    "search": "test",
    "query": "test",
    "q": "test",
    "url": "https://example.com",
    "website": "https://example.com",
}


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

    # Collect IP addresses to check: literal IP + DNS-resolved addresses.
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


app = FastAPI(title="UI Simulation Service", version="1.0.0")


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

class LoginStep(BaseModel):
    """A single automated login action (mirrors the frontend LoginStep type)."""
    action: str = Field(description="'navigate', 'click', 'type', or 'wait'")
    selector: Optional[str] = None
    value: Optional[str] = None
    url: Optional[str] = None


class SimulateRequest(BaseModel):
    target: str = Field(description="Absolute URL of the target web application")
    login_steps: List[LoginStep] = Field(
        default_factory=list,
        description="Optional ordered login sequence to execute before crawling",
    )
    cookies: Optional[str] = Field(
        default=None,
        description="Semicolon-separated 'name=value' pairs to inject before navigating",
    )
    headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Extra HTTP headers to attach to every request",
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="Override the browser User-Agent string",
    )
    max_pages: int = Field(default=8, ge=1, le=_MAX_PAGES)
    max_depth: int = Field(default=2, ge=1, le=_MAX_DEPTH)
    timeout: int = Field(default=120, ge=10, le=MAX_TIMEOUT)


class DiscoveredEndpoint(BaseModel):
    url: str
    method: str


class SimulateResponse(BaseModel):
    target: str
    pages_visited: int
    clicks_performed: int
    forms_filled: int
    discovered_endpoints: List[DiscoveredEndpoint]
    actions_log: List[str]
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
        return JSONResponse(content={"status": "ok", "service": "ui-simulation"})
    except Exception as exc:
        logger.warning("Health check failed: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "service": "ui-simulation", "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# Simulation endpoint
# ---------------------------------------------------------------------------

@app.post("/v1/simulate", response_model=SimulateResponse)
async def simulate(req: SimulateRequest) -> SimulateResponse:
    """
    Drive a headless Chromium browser through the target web application in a
    human-like manner: navigate pages, click interactive elements, fill and
    submit forms, scroll content, and collect all network endpoints seen.
    """
    _validate_target_url(req.target)
    logger.info("ui-simulation start target=%s max_pages=%d timeout=%ds",
                req.target, req.max_pages, req.timeout)
    result = await _run_simulation(req)
    logger.info(
        "ui-simulation done target=%s pages=%d clicks=%d forms=%d endpoints=%d timed_out=%s",
        req.target, result.pages_visited, result.clicks_performed,
        result.forms_filled, len(result.discovered_endpoints), result.timed_out,
    )
    return result


# ---------------------------------------------------------------------------
# Core simulation logic
# ---------------------------------------------------------------------------

def _is_same_origin(base: str, url: str) -> bool:
    """Return True when url shares the scheme+host(+port) of base."""
    try:
        b = urlparse(base)
        u = urlparse(url)
        return b.scheme == u.scheme and b.netloc == u.netloc
    except Exception:
        return False


def _normalise_url(base: str, href: str) -> Optional[str]:
    """Resolve href relative to base; return None for non-HTTP schemes."""
    try:
        full = urljoin(base, href.strip())
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            return None
        # Drop fragments — they don't represent distinct server resources
        return parsed._replace(fragment="").geturl()
    except Exception:
        return None


def _dummy_value_for(name: str, input_type: str) -> str:
    """Pick a realistic dummy value for a form field."""
    name_lower = (name or "").lower().replace("-", "_").replace(" ", "_")
    for key, val in _DUMMY_VALUES.items():
        if key in name_lower:
            return val
    # Fallback by input type
    if input_type in ("email",):
        return _DUMMY_VALUES["email"]
    if input_type in ("password",):
        return _DUMMY_VALUES["password"]
    if input_type in ("tel", "phone"):
        return _DUMMY_VALUES["tel"]
    if input_type in ("url",):
        return _DUMMY_VALUES["url"]
    if input_type in ("number", "range"):
        return "42"
    if input_type == "date":
        return "2024-01-15"
    return "test"


async def _human_pause(min_s: float = _MIN_PAUSE, max_s: float = _MAX_PAUSE) -> None:
    """Sleep for a random human-like interval."""
    await asyncio.sleep(random.uniform(min_s, max_s))


async def _scroll_page(page: Page) -> None:
    """Scroll down the page gradually to simulate a human reading it."""
    try:
        viewport_height = await page.evaluate("window.innerHeight")
        total_height = await page.evaluate("document.body.scrollHeight")
        steps = max(1, min(5, total_height // max(1, viewport_height)))
        for i in range(steps):
            scroll_to = int((total_height / steps) * (i + 1))
            await page.evaluate(f"window.scrollTo(0, {scroll_to})")
            await asyncio.sleep(_SCROLL_PAUSE * random.uniform(0.6, 1.4))
        # Scroll back to top
        await page.evaluate("window.scrollTo(0, 0)")
    except Exception:
        pass


async def _fill_and_submit_forms(page: Page, log: List[str]) -> int:
    """Fill visible forms with dummy data and optionally submit them.

    Returns the number of forms filled.
    """
    filled = 0
    try:
        form_count = await page.evaluate("document.querySelectorAll('form').length")
        limit = min(int(form_count), _MAX_FORMS_PER_PAGE)
        for idx in range(limit):
            try:
                form_selector = f"form:nth-of-type({idx + 1})"
                # Gather inputs within the form
                inputs = await page.query_selector_all(
                    f"{form_selector} input:not([type='hidden']):not([type='submit'])"
                    f":not([type='button']):not([type='checkbox']):not([type='radio'])"
                    f":not([type='file']):not([type='reset']):not([disabled])"
                )
                typed_any = False
                for inp in inputs:
                    try:
                        inp_type = (await inp.get_attribute("type") or "text").lower()
                        if inp_type in ("hidden", "submit", "button", "file", "reset"):
                            continue
                        inp_name = await inp.get_attribute("name") or await inp.get_attribute("id") or ""
                        val = _dummy_value_for(inp_name, inp_type)
                        await inp.fill(val)
                        await asyncio.sleep(_TYPE_DELAY_MS / 1000 * random.uniform(0.5, 1.5))
                        typed_any = True
                    except Exception:
                        pass

                # Check select elements
                selects = await page.query_selector_all(
                    f"{form_selector} select:not([disabled])"
                )
                for sel in selects:
                    try:
                        options = await sel.query_selector_all("option:not([disabled])")
                        if len(options) > 1:
                            # Choose the second option to avoid "please select" defaults
                            val = await options[1].get_attribute("value") or ""
                            if val:
                                await sel.select_option(value=val)
                    except Exception:
                        pass

                if typed_any:
                    filled += 1
                    log.append(f"Filled form #{idx + 1} on {page.url}")
                    await _human_pause(0.3, 0.8)
                    # Do NOT submit — submitting may trigger destructive server-side
                    # actions. We only fill to exercise JS validation and surface
                    # hidden endpoint calls; submit is intentionally skipped.
            except Exception as exc:
                logger.debug("Form fill error (form %d): %s", idx, exc)
    except Exception as exc:
        logger.debug("Form discovery error: %s", exc)
    return filled


async def _click_interactive_elements(
    page: Page,
    log: List[str],
    target_origin: str,
) -> int:
    """Click buttons, tabs, nav links, and menu items.

    Returns the number of successful clicks.
    """
    clicks = 0
    # Selectors ordered from least-destructive to most-destructive
    CLICK_SELECTORS = [
        # Navigation and tab bar items
        "nav a",
        "[role='tab']",
        "[role='menuitem']",
        ".tab",
        ".nav-item a",
        ".nav-link",
        "[data-tab]",
        "[data-page]",
        # Accordion / expand panels
        "[data-toggle='collapse']",
        "[aria-expanded='false']",
        ".accordion-header",
        ".collapsible",
        # Buttons that don't look like submit/delete/danger
        "button:not([type='submit']):not([class*='delete']):not([class*='danger'])"
        ":not([class*='remove']):not([class*='logout']):not([disabled])",
        # Generic anchor links within the same origin
        f"a[href]:not([href^='javascript']):not([href^='mailto'])",
    ]

    already_clicked: set[str] = set()

    for selector in CLICK_SELECTORS:
        if clicks >= _MAX_CLICKS_PER_PAGE:
            break
        try:
            elements = await page.query_selector_all(selector)
            random.shuffle(elements)
            for el in elements:
                if clicks >= _MAX_CLICKS_PER_PAGE:
                    break
                try:
                    is_visible = await el.is_visible()
                    if not is_visible:
                        continue
                    # For links: only follow same-origin hrefs
                    href = await el.get_attribute("href")
                    if href and not href.startswith(("#", "javascript", "mailto", "tel")):
                        resolved = _normalise_url(page.url, href)
                        if resolved and not _is_same_origin(target_origin, resolved):
                            continue

                    # Deduplicate by text content + tag
                    tag = await el.evaluate("el => el.tagName.toLowerCase()")
                    text = (await el.inner_text()).strip()[:60]
                    dedup_key = f"{tag}:{text}"
                    if dedup_key in already_clicked:
                        continue
                    already_clicked.add(dedup_key)

                    await el.scroll_into_view_if_needed()
                    await _human_pause(0.2, 0.6)

                    # Use a short timeout so a stale overlay doesn't block us
                    try:
                        await el.click(timeout=3000)
                    except Exception:
                        continue

                    clicks += 1
                    log.append(f"Clicked <{tag}> '{text}' on {page.url}")
                    await _human_pause(0.4, 1.2)

                    # After navigating away, break out of the inner loop and
                    # let the outer crawl pick up the new page URL.
                    if page.url and not _is_same_origin(target_origin, page.url):
                        await page.go_back(wait_until="domcontentloaded", timeout=5000)
                        await _human_pause(0.3, 0.7)
                        break
                except Exception as exc:
                    logger.debug("Click error on selector '%s': %s", selector, exc)
        except Exception as exc:
            logger.debug("Selector error '%s': %s", selector, exc)

    return clicks


def _record_request(
    pw_request: PWRequest,
    endpoints: List[DiscoveredEndpoint],
    seen: set[str],
    target_origin: str,
) -> None:
    """Append a newly seen endpoint to the discovered list."""
    url = pw_request.url
    method = pw_request.method.upper()
    # Only record XHR/Fetch or navigation requests to the target origin
    resource_type = pw_request.resource_type
    if resource_type not in ("xhr", "fetch", "document"):
        return
    if not _is_same_origin(target_origin, url):
        return
    key = f"{method}:{url.split('?')[0]}"  # deduplicate ignoring query params
    if key in seen:
        return
    seen.add(key)
    endpoints.append(DiscoveredEndpoint(url=url, method=method))


async def _execute_login_steps(
    page: Page,
    steps: List[LoginStep],
    log: List[str],
) -> None:
    """Execute an ordered set of login automation steps."""
    for step in steps:
        try:
            if step.action == "navigate" and step.url:
                await page.goto(step.url, wait_until="domcontentloaded", timeout=15000)
                log.append(f"Login: navigated to {step.url}")
            elif step.action == "click" and step.selector:
                await page.click(step.selector, timeout=5000)
                log.append(f"Login: clicked '{step.selector}'")
            elif step.action == "type" and step.selector and step.value:
                await page.fill(step.selector, step.value)
                log.append(f"Login: typed into '{step.selector}'")
            elif step.action == "wait":
                delay = float(step.value or "1")
                await asyncio.sleep(min(delay, 5.0))
                log.append(f"Login: waited {delay}s")
            await _human_pause(0.2, 0.5)
        except Exception as exc:
            logger.warning("Login step '%s' failed: %s", step.action, exc)
            log.append(f"Login: step '{step.action}' failed: {exc}")


async def _run_simulation(req: SimulateRequest) -> SimulateResponse:
    """Main simulation driver — returns a populated SimulateResponse."""
    discovered_endpoints: List[DiscoveredEndpoint] = []
    seen_endpoints: set[str] = set()
    actions_log: List[str] = []
    pages_visited = 0
    clicks_performed = 0
    forms_filled = 0
    timed_out = False
    error: Optional[str] = None

    target_origin = req.target

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            ctx_options: dict = {
                "ignore_https_errors": True,
            }
            if req.user_agent:
                ctx_options["user_agent"] = req.user_agent
            if req.headers:
                ctx_options["extra_http_headers"] = req.headers

            context: BrowserContext = await browser.new_context(**ctx_options)

            # Inject cookies if supplied
            if req.cookies:
                parsed = urlparse(req.target)
                cookie_domain = parsed.hostname or ""
                for pair in req.cookies.split(";"):
                    pair = pair.strip()
                    if "=" not in pair:
                        continue
                    name, _, value = pair.partition("=")
                    try:
                        await context.add_cookies([{
                            "name": name.strip(),
                            "value": value.strip(),
                            "domain": cookie_domain,
                            "path": "/",
                        }])
                    except Exception:
                        pass

            page: Page = await context.new_page()

            # Record all network requests
            page.on(
                "request",
                lambda r: _record_request(r, discovered_endpoints, seen_endpoints, target_origin),
            )

            # Navigate to target with overall timeout guard
            deadline = time.monotonic() + req.timeout

            try:
                await page.goto(req.target, wait_until="domcontentloaded", timeout=20000)
                actions_log.append(f"Navigated to {req.target}")
            except Exception as exc:
                logger.warning("Initial navigation failed: %s", exc)
                error = f"Initial navigation failed: {exc}"
                await browser.close()
                return SimulateResponse(
                    target=req.target,
                    pages_visited=0,
                    clicks_performed=0,
                    forms_filled=0,
                    discovered_endpoints=discovered_endpoints,
                    actions_log=actions_log,
                    timed_out=False,
                    error=error,
                )

            # Execute login steps before starting the crawl
            if req.login_steps:
                await _execute_login_steps(page, req.login_steps, actions_log)

            # BFS crawl queue: (url, depth)
            visited_urls: set[str] = {req.target}
            queue: List[tuple[str, int]] = [(page.url, 0)]

            while queue and pages_visited < req.max_pages:
                if time.monotonic() > deadline:
                    timed_out = True
                    actions_log.append("Simulation timed out")
                    break

                current_url, depth = queue.pop(0)

                # Navigate to the page (skip if already there)
                try:
                    if page.url != current_url:
                        await page.goto(current_url, wait_until="domcontentloaded", timeout=15000)
                        await _human_pause(0.5, 1.0)
                except Exception as exc:
                    logger.debug("Navigate to %s failed: %s", current_url, exc)
                    continue

                pages_visited += 1
                actions_log.append(f"Visiting page {pages_visited}: {page.url}")

                # Scroll to trigger lazy-loaded content
                await _scroll_page(page)

                # Fill visible forms (without submitting)
                ff = await _fill_and_submit_forms(page, actions_log)
                forms_filled += ff

                # Click interactive elements
                cp = await _click_interactive_elements(page, actions_log, target_origin)
                clicks_performed += cp

                # Collect links for BFS if we haven't reached max depth
                if depth < req.max_depth:
                    try:
                        links = await page.evaluate(
                            """Array.from(document.querySelectorAll('a[href]'))
                               .map(a => a.href)
                               .filter(h => h && !h.startsWith('javascript') && !h.startsWith('mailto'))
                               .slice(0, 50)"""
                        )
                        for link in links:
                            norm = _normalise_url(req.target, link)
                            if norm and _is_same_origin(target_origin, norm) and norm not in visited_urls:
                                visited_urls.add(norm)
                                queue.append((norm, depth + 1))
                    except Exception:
                        pass

            await browser.close()

    except asyncio.TimeoutError:
        timed_out = True
        error = "Simulation exceeded overall timeout"
    except Exception as exc:
        logger.error("Simulation error: %s", exc, exc_info=True)
        error = str(exc)

    return SimulateResponse(
        target=req.target,
        pages_visited=pages_visited,
        clicks_performed=clicks_performed,
        forms_filled=forms_filled,
        discovered_endpoints=discovered_endpoints,
        actions_log=actions_log,
        timed_out=timed_out,
        error=error,
    )
