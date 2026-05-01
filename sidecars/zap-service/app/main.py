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
import subprocess  # nosec B404
from typing import List, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

logger = logging.getLogger("zap-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

# Optional shared-secret auth between the backend and this sidecar
SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
_AUTH_EXEMPT_PATHS = {"/health"}

# zap-baseline.py ships inside the zaproxy image at a well-known path.
# Prefer the versioned path, fall back to the plain name on $PATH.
_ZAP_BASELINE = "/zap/zap-baseline.py"

# Maximum execution timeout (seconds) — ZAP baseline can be slow
MAX_TIMEOUT = 600  # 10 minutes


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
    if SIDECAR_AUTH_TOKEN and request.url.path not in _AUTH_EXEMPT_PATHS:
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


_ALLOWED_FLAGS_WITH_VALUE = {
    "-t", "-m", "-d", "-P", "-c", "-u", "-g", "-r", "-w", "-x", "-J", "-z", "-n", "-p", "-j", "-T"
}
_ALLOWED_BOOLEAN_FLAGS = {"-I", "-a"}


def _validate_and_normalize_args(args: List[str]) -> Tuple[Optional[List[str]], Optional[str]]:
    validated: List[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token in _ALLOWED_BOOLEAN_FLAGS:
            validated.append(token)
            i += 1
            continue
        if token in _ALLOWED_FLAGS_WITH_VALUE:
            if i + 1 >= len(args):
                return None, f"Missing value for argument: {token}"
            value = args[i + 1]
            if value.startswith("-"):
                return None, f"Invalid value for argument: {token}"
            validated.extend([token, value])
            i += 2
            continue
        return None, f"Unsupported argument: {token}"
    return validated, None


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

    validated_args, validation_error = _validate_and_normalize_args(req.args)
    if validation_error:
        return ExecuteResponse(
            stdout="",
            stderr="",
            exit_code=1,
            timed_out=False,
            error=validation_error
        )

    try:
        result = subprocess.run(  # nosemgrep - args validated against allowlist
            [_ZAP_BASELINE] + validated_args,
            capture_output=True,
            text=True,
            timeout=req.timeout,
            shell=False,
            check=False,
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
