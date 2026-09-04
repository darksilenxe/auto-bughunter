"""
Nuclei HTTP Wrapper Service
============================
HTTP service that wraps the nuclei CLI tool, eliminating the need for
Docker socket access. The backend communicates via HTTP instead of
`docker compose exec`.

Endpoints:
  POST /v1/execute - Execute nuclei with provided arguments
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

logger = logging.getLogger("nuclei-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

# Required shared-secret auth between the backend and this sidecar.
# Refuse to start if the token is not configured — an empty token would
# allow any unauthenticated caller to drive nuclei with arbitrary argv.
SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
if not SIDECAR_AUTH_TOKEN:
    logger.critical(
        "SIDECAR_AUTH_TOKEN is not set or empty. "
        "Refusing to start to prevent unauthenticated access."
    )
    raise SystemExit(1)
_AUTH_EXEMPT_PATHS = {"/health"}

# Maximum execution timeout (seconds)
MAX_TIMEOUT = 600  # 10 minutes
_NUCLEI_FLAGS_WITH_VALUE = {"-u", "-severity", "-proxy"}
_NUCLEI_FLAGS_NO_VALUE = {"-silent"}
_NUCLEI_SEVERITY_RE = re.compile(r"^(info|low|medium|high|critical)(,(info|low|medium|high|critical))*$", re.IGNORECASE)


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


app = FastAPI(title="Nuclei HTTP Wrapper", version="1.0.0")


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
    """Request to execute nuclei with specific arguments."""
    args: List[str] = Field(
        default_factory=list,
        description="Command-line arguments to pass to nuclei"
    )
    timeout: int = Field(
        default=300,
        ge=1,
        le=MAX_TIMEOUT,
        description="Execution timeout in seconds (max 600)"
    )


class ExecuteResponse(BaseModel):
    """Response from nuclei execution."""
    stdout: str = Field(description="Standard output from nuclei")
    stderr: str = Field(description="Standard error from nuclei")
    exit_code: int = Field(description="Exit code from nuclei process")
    timed_out: bool = Field(description="Whether execution timed out")
    error: Optional[str] = Field(default=None, description="Error message if execution failed")


def _is_safe_url(raw: str) -> bool:
    parsed = urlparse(raw)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _validate_nuclei_args(args: List[str]) -> Optional[str]:
    if not args:
        return "No arguments provided"
    i = 0
    while i < len(args):
        arg = args[i]
        if any(dangerous in arg for dangerous in [";", "&&", "||", "|", "`", "$("]):
            return "Invalid argument: potentially dangerous characters detected"
        if arg in _NUCLEI_FLAGS_NO_VALUE:
            i += 1
            continue
        if arg in _NUCLEI_FLAGS_WITH_VALUE:
            if i + 1 >= len(args):
                return f"Missing value for {arg}"
            value = args[i + 1].strip()
            if not value:
                return f"Missing value for {arg}"
            if any(dangerous in value for dangerous in [";", "&&", "||", "|", "`", "$("]):
                return "Invalid argument value: potentially dangerous characters detected"
            if arg in {"-u", "-proxy"} and not _is_safe_url(value):
                return f"Invalid URL for {arg}"
            if arg == "-severity" and not _NUCLEI_SEVERITY_RE.match(value):
                return "Invalid value for -severity"
            i += 2
            continue
        return f"Unsupported argument: {arg}"
    return None


@app.get("/health")
def health() -> Response:
    """Health check endpoint."""
    # Verify nuclei binary is available
    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        version = result.stdout.strip() if result.returncode == 0 else "unknown"
        return JSONResponse(content={
            "status": "ok",
            "service": "nuclei-http-wrapper",
            "nuclei_version": version,
        })
    except Exception as e:
        logger.warning(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "service": "nuclei-http-wrapper",
                "error": "nuclei binary not found or failed to execute",
            },
        )


@app.post("/v1/execute", response_model=ExecuteResponse)
def execute_nuclei(req: ExecuteRequest) -> ExecuteResponse:
    """
    Execute nuclei with the provided arguments.

    This endpoint runs nuclei in a subprocess and returns stdout, stderr,
    and exit code. It enforces a timeout to prevent runaway processes.

    Example request:
    ```json
    {
      "args": ["-u", "https://example.com", "-severity", "medium,high,critical", "-silent"],
      "timeout": 300
    }
    ```
    """
    logger.info(f"Executing nuclei with args: {req.args}")

    err = _validate_nuclei_args(req.args)
    if err:
        return ExecuteResponse(
            stdout="",
            stderr="",
            exit_code=1,
            timed_out=False,
            error=err,
        )

    try:
        # Execute nuclei
        result = subprocess.run(
            ["nuclei"] + req.args,
            capture_output=True,
            text=True,
            timeout=req.timeout
        )

        logger.info(f"Nuclei execution completed with exit code {result.returncode}")

        return ExecuteResponse(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.returncode,
            timed_out=False,
            error=None
        )

    except subprocess.TimeoutExpired as e:
        logger.warning(f"Nuclei execution timed out after {req.timeout}s")
        return ExecuteResponse(
            stdout=e.stdout.decode() if e.stdout else "",
            stderr=e.stderr.decode() if e.stderr else "",
            exit_code=-1,
            timed_out=True,
            error=f"Execution timed out after {req.timeout} seconds"
        )

    except Exception as e:
        logger.error(f"Nuclei execution failed: {e}")
        return ExecuteResponse(
            stdout="",
            stderr="",
            exit_code=-1,
            timed_out=False,
            error=str(e)
        )
