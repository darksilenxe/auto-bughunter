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
from urllib.parse import urlparse

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
MAX_RATE_LIMIT = 1000
MAX_CONCURRENCY = 200
MAX_BULK_SIZE = 200
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}


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


def _normalize_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("invalid URL")
    return parsed.geturl()


def _normalize_severity(value: str) -> str:
    parts = [p.strip().lower() for p in value.split(",") if p.strip()]
    if not parts:
        raise ValueError("severity must be non-empty")
    for part in parts:
        if part not in ALLOWED_SEVERITIES:
            raise ValueError("unsupported severity value")
    return ",".join(parts)


def _normalize_int(value: str, *, minimum: int, maximum: int) -> str:
    value = value.strip()
    if not value.isdigit():
        raise ValueError("value must be numeric")
    number = int(value)
    if number < minimum or number > maximum:
        raise ValueError("value outside allowed range")
    return str(number)


def _normalize_path(value: str) -> str:
    value = value.strip()
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("invalid path")
    if not os.path.isabs(value):
        raise ValueError("path must be absolute")
    normalized = os.path.normpath(value)
    prefixes: list[str] = []
    configured_prefixes = os.getenv("NUCLEI_ALLOWED_PATH_PREFIXES", "")
    if configured_prefixes:
        prefixes.extend([p.strip() for p in configured_prefixes.split(",") if p.strip()])
    shared_tmp = os.getenv("SHARED_TMP_DIR", "").strip()
    if shared_tmp:
        prefixes.append(shared_tmp)
    if not prefixes:
        raise ValueError("no allowed path prefixes configured")
    for prefix in prefixes:
        prefix = os.path.normpath(prefix)
        if normalized == prefix or normalized.startswith(prefix + os.sep):
            return normalized
    raise ValueError("path is outside allowed prefixes")


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
        result = subprocess.run(  # nosec B603 - nosemgrep - binary is resolved with shutil.which
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
            if not value or len(value) > 2048:
                return ExecuteResponse(
                    stdout="",
                    stderr="",
                    exit_code=1,
                    timed_out=False,
                    error=f"Invalid value for {arg}"
                )

            try:
                if arg == "-u":
                    value = _normalize_url(value)
                elif arg == "-severity":
                    value = _normalize_severity(value)
                elif arg == "-timeout":
                    value = _normalize_int(value, minimum=1, maximum=MAX_TIMEOUT)
                elif arg == "-rl":
                    value = _normalize_int(value, minimum=1, maximum=MAX_RATE_LIMIT)
                elif arg == "-c":
                    value = _normalize_int(value, minimum=1, maximum=MAX_CONCURRENCY)
                elif arg == "-bulk-size":
                    value = _normalize_int(value, minimum=1, maximum=MAX_BULK_SIZE)
                elif arg in {"-l", "-t"}:
                    value = _normalize_path(value)
                else:
                    if "\x00" in value or "\n" in value or "\r" in value:
                        raise ValueError("invalid value")
            except ValueError as exc:
                return ExecuteResponse(
                    stdout="",
                    stderr="",
                    exit_code=1,
                    timed_out=False,
                    error=f"Invalid value for {arg}: {exc}"
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
        # lgtm [py/command-line-injection] args are strictly allowlisted, normalized, and shell=False.
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
