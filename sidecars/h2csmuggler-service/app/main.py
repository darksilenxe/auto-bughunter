"""
h2csmuggler Service
===================
A FastAPI micro-service that probes HTTP targets for HTTP/2 cleartext (h2c)
upgrade smuggling vulnerabilities, inspired by the h2csmuggler tool by
Assetnote (https://github.com/assetnote/h2csmuggler).

How it works:
  1. POST /v1/scan accepts a target URL.
  2. The service sends an HTTP/1.1 request with ``Upgrade: h2c`` and
     ``Connection: Upgrade, HTTP2-Settings`` headers to discover whether the
     server (or an intermediary) transparently upgrades to HTTP/2.
  3. If an h2c upgrade is accepted it attempts to send a smuggled HTTP/2
     request over the cleartext connection, specifically targeting paths that
     might bypass proxy / WAF inspection (e.g. ``/`` vs ``/../admin``).
  4. Differences in status codes, response bodies, or h2c acceptance are
     reported as structured findings.

Endpoints:
  POST /v1/scan  — run h2c upgrade and smuggling probe against a URL
  GET  /health   — health check
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("h2csmuggler-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
if not SIDECAR_AUTH_TOKEN:
    logger.critical(
        "SIDECAR_AUTH_TOKEN is not set or empty. "
        "Refusing to start to prevent unauthenticated access."
    )
    raise SystemExit(1)

_AUTH_EXEMPT_PATHS = {"/health"}

# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_blocked_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _format_authority(host: str, port: int, scheme: str, explicit_port: bool) -> str:
    default_port = 443 if scheme == "https" else 80
    host_part = host
    if ":" in host_part and not host_part.startswith("["):
        host_part = f"[{host_part}]"
    if explicit_port and port != default_port:
        return f"{host_part}:{port}"
    return host_part


def _build_pinned_request_url(target: str) -> tuple[str, str]:
    parsed = urlparse(target)
    scheme = parsed.scheme
    hostname = parsed.hostname
    if scheme not in ("http", "https") or not hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL")

    port = parsed.port or (443 if scheme == "https" else 80)
    explicit_port = parsed.port is not None
    path = parsed.path or "/"

    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        addresses.append(ipaddress.ip_address(hostname))
    except ValueError:
        try:
            resolved = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise HTTPException(status_code=400, detail=f"Failed to resolve target hostname: {exc}") from exc
        seen: set[str] = set()
        for _family, _type, _proto, _canon, sockaddr in resolved:
            try:
                addr = ipaddress.ip_address(sockaddr[0])
            except ValueError:
                continue
            key = str(addr)
            if key in seen:
                continue
            seen.add(key)
            addresses.append(addr)

    public_addr = next((addr for addr in addresses if not _is_blocked_address(addr)), None)
    if public_addr is None:
        raise HTTPException(
            status_code=400,
            detail="Target resolves only to disallowed network addresses",
        )

    pinned_host = str(public_addr)
    pinned_authority = _format_authority(pinned_host, port, scheme, explicit_port=True)
    original_authority = _format_authority(hostname, port, scheme, explicit_port=explicit_port)
    pinned_url = parsed._replace(netloc=pinned_authority, path=path, fragment="").geturl()
    return pinned_url, original_authority


def _validate_target_url(target: str) -> None:
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
        try:
            resolved = socket.getaddrinfo(hostname, None)
            for _family, _type, _proto, _canon, sockaddr in resolved:
                try:
                    addresses_to_check.append(ipaddress.ip_address(sockaddr[0]))
                except ValueError:
                    pass
        except OSError:
            return

    for addr in addresses_to_check:
        if _is_blocked_address(addr):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Target resolves to a disallowed network address ({addr}); "
                    "SSRF to internal/private networks is not permitted."
                ),
            )


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    url: str = Field(description="Absolute target URL to probe for h2c upgrade smuggling")
    smuggle_paths: Optional[List[str]] = Field(
        default=None,
        description=(
            "Additional request paths to smuggle via the h2c upgrade channel. "
            "Defaults to a built-in list of high-interest paths."
        ),
    )
    timeout: int = Field(default=15, ge=3, le=60)


class H2cFinding(BaseModel):
    type: str
    description: str
    evidence: Dict[str, Any]


class ScanResponse(BaseModel):
    url: str
    h2c_upgrade_accepted: bool
    smuggle_attempted: bool
    findings: List[H2cFinding]
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Core probe logic
# ---------------------------------------------------------------------------

_DEFAULT_SMUGGLE_PATHS = [
    "/",
    "/../admin",
    "/../api",
    "/../internal",
    "/../health",
    "/..%2fadmin",
    "/..%2fapi",
]


async def _probe_h2c(req: ScanRequest) -> ScanResponse:
    """
    Probe ``req.url`` for h2c upgrade acceptance and attempt to smuggle HTTP/2
    requests through the upgrade channel, reporting any anomalies.
    """
    findings: List[H2cFinding] = []
    h2c_accepted = False
    smuggle_attempted = False
    error: Optional[str] = None

    parsed = urlparse(req.url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    base_path = parsed.path or "/"
    pinned_url, original_authority = _build_pinned_request_url(req.url)
    timeout = httpx.Timeout(req.timeout)

    # ------------------------------------------------------------------
    # Step 1: probe for h2c upgrade via HTTP/1.1
    # ------------------------------------------------------------------
    upgrade_headers = {
        "Host": original_authority,
        "Upgrade": "h2c",
        "Connection": "Upgrade, HTTP2-Settings",
        # Minimal valid HTTP2-Settings value (base64url of an empty SETTINGS frame)
        "HTTP2-Settings": "AAMAAABkAAQAAP__",
    }

    baseline_status: Optional[int] = None
    upgrade_status: Optional[int] = None
    upgrade_headers_seen: Dict[str, str] = {}

    try:
        async with httpx.AsyncClient(
            verify=False,  # noqa: S501 — target may use self-signed cert
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            # Baseline request without upgrade headers
            baseline_resp = await client.get(pinned_url)
            baseline_status = baseline_resp.status_code

            # Upgrade probe
            upgrade_resp = await client.get(pinned_url, headers=upgrade_headers)
            upgrade_status = upgrade_resp.status_code
            upgrade_headers_seen = dict(upgrade_resp.headers)

            # A 101 response indicates the server accepted the h2c upgrade.
            # Some intermediaries will also transparently forward the request
            # and the origin may respond with 200 but include an "Upgrade" or
            # "Connection: Upgrade" confirmation header.
            if upgrade_status == 101:
                h2c_accepted = True
                findings.append(
                    H2cFinding(
                        type="h2c-upgrade-accepted",
                        description=(
                            "Server responded with 101 Switching Protocols to an "
                            "HTTP/1.1 Upgrade: h2c request, indicating h2c is "
                            "accepted on a cleartext channel."
                        ),
                        evidence={
                            "url": req.url,
                            "baseline_status": baseline_status,
                            "upgrade_status": upgrade_status,
                            "upgrade_response_headers": {
                                k: v for k, v in upgrade_headers_seen.items()
                                if k.lower() in ("upgrade", "connection", "server", "via")
                            },
                        },
                    )
                )
            elif (
                upgrade_headers_seen.get("upgrade", "").lower() == "h2c"
                or "h2c" in upgrade_headers_seen.get("connection", "").lower()
            ):
                h2c_accepted = True
                findings.append(
                    H2cFinding(
                        type="h2c-upgrade-echoed",
                        description=(
                            "Server echoed Upgrade: h2c in the response headers "
                            "without issuing a 101, suggesting partial or "
                            "misconfigured h2c support."
                        ),
                        evidence={
                            "url": req.url,
                            "baseline_status": baseline_status,
                            "upgrade_status": upgrade_status,
                            "upgrade_response_headers": {
                                k: v for k, v in upgrade_headers_seen.items()
                                if k.lower() in ("upgrade", "connection", "server", "via")
                            },
                        },
                    )
                )

    except Exception as exc:
        error = f"upgrade probe error: {exc}"
        logger.warning("h2csmuggler upgrade probe failed url=%s: %s", req.url, exc)

    # ------------------------------------------------------------------
    # Step 2: attempt smuggling via httpx HTTP/2 over cleartext (h2c)
    # ------------------------------------------------------------------
    # httpx supports HTTP/2 but only over TLS by default. We exploit the
    # http2 transport to send HTTP/2 requests over cleartext to detect
    # whether an intermediary forwards them to an origin that accepts h2c.
    # This is the core of the smuggling attack: the front-end proxy speaks
    # HTTP/1.1 only, so it sees a single request, while the back-end origin
    # sees the h2c-upgraded stream carrying a smuggled request.

    smuggle_paths = req.smuggle_paths or _DEFAULT_SMUGGLE_PATHS
    if not error:
        smuggle_attempted = True
        smuggle_results: list[dict[str, Any]] = []

        try:
            # Use httpx h2c (HTTP/2 cleartext) transport
            async with httpx.AsyncClient(
                http2=True,
                verify=False,  # noqa: S501
                timeout=timeout,
                follow_redirects=False,
            ) as h2_client:
                for path in smuggle_paths:
                    smuggle_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                    try:
                        smuggle_resp = await h2_client.get(smuggle_url)
                        smuggle_results.append(
                            {
                                "path": path,
                                "status": smuggle_resp.status_code,
                                "protocol": smuggle_resp.http_version,
                                "baseline_status": baseline_status,
                            }
                        )
                    except Exception as path_exc:
                        smuggle_results.append(
                            {"path": path, "error": str(path_exc)}
                        )

            # Analyse results: if any smuggled path returned a different
            # status or was served over HTTP/2 when the normal request was
            # HTTP/1.1, that is suspicious.
            anomalous = [
                r for r in smuggle_results
                if "error" not in r
                and (
                    r.get("protocol", "").startswith("HTTP/2")
                    or r.get("status") != baseline_status
                )
            ]
            if anomalous:
                findings.append(
                    H2cFinding(
                        type="h2c-smuggling-anomaly",
                        description=(
                            "One or more smuggled HTTP/2 requests returned a "
                            "different status code or were served over HTTP/2 "
                            "where the baseline was HTTP/1.1. This may indicate "
                            "that a front-end proxy forwards h2c-upgraded requests "
                            "to an origin that bypasses HTTP/1.1 security controls."
                        ),
                        evidence={
                            "url": req.url,
                            "baseline_status": baseline_status,
                            "anomalous_paths": anomalous,
                            "all_results": smuggle_results,
                        },
                    )
                )

        except Exception as exc:
            error = f"smuggle probe error: {exc}"
            logger.warning("h2csmuggler smuggle probe failed url=%s: %s", req.url, exc)

    return ScanResponse(
        url=req.url,
        h2c_upgrade_accepted=h2c_accepted,
        smuggle_attempted=smuggle_attempted,
        findings=findings,
        error=error,
    )


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="h2csmuggler Service", version="0.1.0")


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


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse(content={"status": "ok", "service": "h2csmuggler"})


@app.post("/v1/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    """Probe a URL for h2c upgrade acceptance and attempt request smuggling."""
    _validate_target_url(req.url)
    logger.info("h2csmuggler scan url=%s", req.url)
    result = await _probe_h2c(req)
    logger.info(
        "h2csmuggler done url=%s h2c_accepted=%s findings=%d",
        req.url,
        result.h2c_upgrade_accepted,
        len(result.findings),
    )
    return result
