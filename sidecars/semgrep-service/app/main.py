"""
Semgrep SAST HTTP Wrapper Service
===================================
HTTP service that wraps the semgrep CLI tool for static application security
testing (SAST). The backend submits source-code snippets and receives
structured findings without needing Docker socket access.

Endpoints:
  POST /v1/scan  - Scan a code snippet with semgrep
  GET  /health   - Health check
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("semgrep-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

# Required shared-secret auth between the backend and this sidecar.
# Refuse to start if the token is not configured — an empty token would
# allow any unauthenticated caller to scan arbitrary code snippets.
SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
if not SIDECAR_AUTH_TOKEN:
    logger.critical(
        "SIDECAR_AUTH_TOKEN is not set or empty. "
        "Refusing to start to prevent unauthenticated access."
    )
    raise SystemExit(1)
_AUTH_EXEMPT_PATHS = {"/health"}

# Maximum execution timeout (seconds)
MAX_TIMEOUT = 300  # 5 minutes

# Semgrep binary path
_SEMGREP_BIN = os.getenv("SEMGREP_BINARY", "semgrep")

# Extension map for supported languages
_LANG_EXTENSIONS: dict[str, str] = {
    "js": ".js",
    "javascript": ".js",
    "ts": ".ts",
    "typescript": ".ts",
    "jsx": ".jsx",
    "tsx": ".tsx",
    "py": ".py",
    "python": ".py",
    "go": ".go",
    "java": ".java",
    "rb": ".rb",
    "ruby": ".rb",
    "php": ".php",
    "cs": ".cs",
    "csharp": ".cs",
    "c": ".c",
    "cpp": ".cpp",
    "html": ".html",
}


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


app = FastAPI(title="Semgrep SAST HTTP Wrapper", version="1.0.0")


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


class SemgrepScanRequest(BaseModel):
    snippet: str = Field(description="Source-code fragment to analyse")
    language: str = Field(default="js", description="Language hint for semgrep")
    timeout: int = Field(default=60, ge=1, le=MAX_TIMEOUT, description="Execution timeout in seconds")


class SemgrepFinding(BaseModel):
    ruleId: str
    message: str
    severity: str
    line: int
    language: str


class SemgrepScanResponse(BaseModel):
    findings: List[SemgrepFinding]
    timedOut: bool
    error: Optional[str] = None


@app.get("/health")
def health() -> JSONResponse:
    """Health check — verifies the semgrep binary is available."""
    try:
        result = subprocess.run(
            [_SEMGREP_BIN, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = result.stdout.strip() or result.stderr.strip() or "unknown"
        return JSONResponse(content={
            "status": "ok",
            "service": "semgrep-sast-wrapper",
            "semgrep_version": version,
        })
    except Exception as exc:
        logger.warning("Health check failed: %s", exc)
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "service": "semgrep-sast-wrapper",
                "error": "semgrep binary not found or failed to execute",
            },
        )


@app.post("/v1/scan", response_model=SemgrepScanResponse)
def scan_snippet(req: SemgrepScanRequest) -> SemgrepScanResponse:
    """
    Scan a source-code snippet with ``semgrep --config=auto``.

    The snippet is written to a temporary file with an appropriate extension
    for the requested language, semgrep runs on it, and the JSON output is
    parsed and returned as structured findings.

    Example request::

        {
          "snippet": "eval(userInput)",
          "language": "js",
          "timeout": 60
        }
    """
    snippet = req.snippet.strip()
    if not snippet:
        return SemgrepScanResponse(findings=[], timedOut=False)

    lang = req.language.strip().lower() or "js"
    ext = _LANG_EXTENSIONS.get(lang, ".txt")

    logger.info("semgrep scan language=%s snippet_len=%d", lang, len(snippet))

    with tempfile.TemporaryDirectory(prefix="semgrep-") as tmpdir:
        src_file = Path(tmpdir) / f"snippet{ext}"
        src_file.write_text(snippet, encoding="utf-8")

        cmd = [
            _SEMGREP_BIN,
            "--config=auto",
            "--json",
            "--no-git-ignore",
            "--quiet",
            str(src_file),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=req.timeout,
                cwd=tmpdir,
            )
        except subprocess.TimeoutExpired:
            logger.warning("semgrep timed out after %ds", req.timeout)
            return SemgrepScanResponse(findings=[], timedOut=True)
        except Exception as exc:
            logger.error("semgrep execution failed: %s", exc)
            return SemgrepScanResponse(findings=[], timedOut=False, error=str(exc))

        findings = _parse_semgrep_json(result.stdout, lang)
        logger.info("semgrep completed exit_code=%d findings=%d", result.returncode, len(findings))
        return SemgrepScanResponse(findings=findings, timedOut=False)


def _parse_semgrep_json(output: str, language: str) -> List[SemgrepFinding]:
    """Parse semgrep --json output into SemgrepFinding list."""
    output = output.strip()
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse semgrep JSON: %s", exc)
        return []

    results = data.get("results") or []
    findings: List[SemgrepFinding] = []
    seen: set[str] = set()
    for item in results:
        check_id = str(item.get("check_id") or "unknown")
        message = str(item.get("extra", {}).get("message") or "")
        severity = str(item.get("extra", {}).get("severity") or "INFO")
        start = (item.get("start") or {})
        line = int(start.get("line") or 0)
        detected_lang = str(item.get("extra", {}).get("metadata", {}).get("language") or language)

        dedup_key = f"{check_id}:{line}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        findings.append(SemgrepFinding(
            ruleId=check_id,
            message=message,
            severity=severity,
            line=line,
            language=detected_lang,
        ))
    return findings
