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
import shutil
import subprocess  # nosec B404
from typing import List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

logger = logging.getLogger("nuclei-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

# Optional shared-secret auth between the backend and this sidecar
SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
_AUTH_EXEMPT_PATHS = {"/health"}

# Maximum execution timeout (seconds)
MAX_TIMEOUT = 600  # 10 minutes


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


app = FastAPI(title="Nuclei HTTP Wrapper", version="1.0.0")


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _resolve_nuclei_binary() -> str:
    binary = shutil.which("nuclei")
    if not binary:
        raise FileNotFoundError("nuclei binary not found in PATH")
    return binary


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


@app.get("/health")
def health() -> Response:
    """Health check endpoint."""
    # Verify nuclei binary is available
    try:
        binary = _resolve_nuclei_binary()
        result = subprocess.run(  # nosemgrep - binary is resolved with shutil.which
            [binary, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
            check=False,
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

    # Strict allowlist validation for nuclei arguments
    allowed_flags_no_value = {
        "-silent",
        "-json",
        "-nc",
        "-no-interactsh",
    }
    allowed_flags_with_value = {
        "-u",
        "-l",
        "-t",
        "-severity",
        "-timeout",
        "-rl",
        "-c",
        "-bulk-size",
    }

    sanitized_args: List[str] = []
    i = 0
    while i < len(req.args):
        arg = req.args[i]

        if arg in allowed_flags_no_value:
            sanitized_args.append(arg)
            i += 1
            continue

        if arg in allowed_flags_with_value:
            if i + 1 >= len(req.args):
                return ExecuteResponse(
                    stdout="",
                    stderr="",
                    exit_code=1,
                    timed_out=False,
                    error=f"Invalid argument: missing value for {arg}"
                )

            value = req.args[i + 1]

            # Basic value sanity checks
            if not value or len(value) > 2048 or "\x00" in value or "\n" in value or "\r" in value:
                return ExecuteResponse(
                    stdout="",
                    stderr="",
                    exit_code=1,
                    timed_out=False,
                    error=f"Invalid value for {arg}"
                )

            # Extra restriction for file/path-like options
            if arg in {"-l", "-t"} and ".." in value:
                return ExecuteResponse(
                    stdout="",
                    stderr="",
                    exit_code=1,
                    timed_out=False,
                    error=f"Invalid value for {arg}: path traversal detected"
                )

            sanitized_args.extend([arg, value])
            i += 2
            continue

        return ExecuteResponse(
            stdout="",
            stderr="",
            exit_code=1,
            timed_out=False,
            error=f"Invalid argument: {arg} is not allowed"
        )

    try:
        binary = _resolve_nuclei_binary()
        # Execute nuclei with validated arguments
        result = subprocess.run(  # nosemgrep - args validated against allowlist
            [binary] + sanitized_args,
            capture_output=True,
            text=True,
            timeout=req.timeout,
            shell=False,
            check=False,
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
            stdout=_coerce_output(e.stdout),
            stderr=_coerce_output(e.stderr),
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
