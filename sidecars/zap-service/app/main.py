"""
ZAP Baseline HTTP Wrapper Service
===================================
HTTP service that wraps the zap-baseline.py CLI tool, eliminating the need
for Docker socket access. The backend communicates via HTTP instead of
`docker compose exec`.

Endpoints:
  POST /v1/execute - Execute zap-baseline.py with provided arguments
  GET  /health     - Health check
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import subprocess
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

logger = logging.getLogger("zap-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

# Required shared-secret auth between the backend and this sidecar.
# Refuse to start if the token is not configured — an empty token would
# allow any unauthenticated caller to drive zap-baseline.py with arbitrary argv.
SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
if not SIDECAR_AUTH_TOKEN:
    logger.critical(
        "SIDECAR_AUTH_TOKEN is not set or empty. "
        "Refusing to start to prevent unauthenticated access."
    )
    raise SystemExit(1)
_AUTH_EXEMPT_PATHS = {"/health"}

# zap-baseline.py ships inside the zaproxy image at a well-known path.
# Prefer the versioned path, fall back to the plain name on $PATH.
_ZAP_BASELINE = "/zap/zap-baseline.py"

# Maximum execution timeout (seconds) — ZAP baseline can be slow
MAX_TIMEOUT = 600  # 10 minutes
_ZAP_FLAGS_WITH_VALUE = {"-t", "-m"}
_ZAP_FLAGS_NO_VALUE = {"-I"}
_NUMERIC_RE = re.compile(r"^[0-9]+$")


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


app = FastAPI(title="ZAP Baseline HTTP Wrapper", version="1.0.0")


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


class ExecuteRequest(BaseModel):
    """Request to execute zap-baseline.py with specific arguments."""
    args: List[str] = Field(
        default_factory=list,
        description="Command-line arguments to pass to zap-baseline.py"
    )
    timeout: int = Field(
        default=300,
        ge=1,
        le=MAX_TIMEOUT,
        description="Execution timeout in seconds (max 600)"
    )


class ExecuteResponse(BaseModel):
    """Response from zap-baseline.py execution."""
    stdout: str = Field(description="Standard output from zap-baseline.py")
    stderr: str = Field(description="Standard error from zap-baseline.py")
    exit_code: int = Field(description="Exit code from zap-baseline.py process")
    timed_out: bool = Field(description="Whether execution timed out")
    error: Optional[str] = Field(default=None, description="Error message if execution failed")


def _is_safe_url(raw: str) -> bool:
    parsed = urlparse(raw)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _validate_zap_args(args: List[str]) -> Optional[str]:
    if not args:
        return "No arguments provided"
    i = 0
    while i < len(args):
        arg = args[i]
        if any(dangerous in arg for dangerous in [";", "&&", "||", "|", "`", "$("]):
            return "Invalid argument: potentially dangerous characters detected"
        if arg in _ZAP_FLAGS_NO_VALUE:
            i += 1
            continue
        if arg in _ZAP_FLAGS_WITH_VALUE:
            if i + 1 >= len(args):
                return f"Missing value for {arg}"
            value = args[i + 1].strip()
            if not value:
                return f"Missing value for {arg}"
            if any(dangerous in value for dangerous in [";", "&&", "||", "|", "`", "$("]):
                return "Invalid argument value: potentially dangerous characters detected"
            if arg == "-t" and not _is_safe_url(value):
                return "Invalid URL for -t"
            if arg == "-m" and not _NUMERIC_RE.match(value):
                return "Invalid value for -m"
            i += 2
            continue
        return f"Unsupported argument: {arg}"
    return None


@app.get("/health")
def health() -> Response:
    """Health check endpoint."""
    if os.path.isfile(_ZAP_BASELINE):
        return JSONResponse(content={
            "status": "ok",
            "service": "zap-baseline-http-wrapper",
            "zap_baseline": _ZAP_BASELINE,
        })
    return JSONResponse(
        status_code=503,
        content={
            "status": "degraded",
            "service": "zap-baseline-http-wrapper",
            "error": f"zap-baseline.py not found at {_ZAP_BASELINE}",
        },
    )


@app.post("/v1/execute", response_model=ExecuteResponse)
def execute_zap_baseline(req: ExecuteRequest) -> ExecuteResponse:
    """
    Execute zap-baseline.py with the provided arguments.

    This endpoint runs zap-baseline.py in a subprocess and returns stdout,
    stderr, and exit code. It enforces a timeout to prevent runaway processes.

    Example request:
    ```json
    {
      "args": ["-t", "https://example.com", "-m", "1", "-I"],
      "timeout": 300
    }
    ```
    """
    logger.info(f"Executing zap-baseline.py with args: {req.args}")

    err = _validate_zap_args(req.args)
    if err:
        return ExecuteResponse(
            stdout="",
            stderr="",
            exit_code=1,
            timed_out=False,
            error=err,
        )

    try:
        result = subprocess.run(
            [_ZAP_BASELINE] + req.args,
            capture_output=True,
            text=True,
            timeout=req.timeout
        )

        logger.info(f"zap-baseline.py completed with exit code {result.returncode}")

        return ExecuteResponse(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.returncode,
            timed_out=False,
            error=None
        )

    except subprocess.TimeoutExpired as e:
        logger.warning(f"zap-baseline.py timed out after {req.timeout}s")
        # When text=True is set, stdout/stderr on TimeoutExpired are already
        # decoded strings (or None); no .decode() call is needed.
        return ExecuteResponse(
            stdout=e.stdout if e.stdout else "",
            stderr=e.stderr if e.stderr else "",
            exit_code=-1,
            timed_out=True,
            error=f"Execution timed out after {req.timeout} seconds"
        )

    except Exception as e:
        logger.error(f"zap-baseline.py execution failed: {e}")
        return ExecuteResponse(
            stdout="",
            stderr="",
            exit_code=-1,
            timed_out=False,
            error=str(e)
        )
