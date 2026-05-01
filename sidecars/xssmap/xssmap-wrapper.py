#!/usr/bin/env python3
"""
xssmap CLI wrapper.

The auto-bughunter backend invokes this wrapper with a stable contract:

    xssmap scan --url <target> --output json
                [--max-payloads N] [--model M] [--ollama-url URL]

Upstream XSSMap (https://github.com/secdec/xssmap) ships its own CLI; we
keep this wrapper as the single seam so the backend doesn't have to track
upstream flag changes. The wrapper:

  1. Locates the cloned XSSMap source under $XSSMAP_HOME/src.
  2. Tries a few known invocation shapes (entry script, module, console
     script) until one succeeds.
  3. Streams XSSMap's stdout to a parser that emits a JSON document of the
     form documented in backend/internal/scanner/integrations.go::xssmapResult.

If XSSMap cannot be located or no invocation succeeds, the wrapper prints
``{"vulnerabilities":[]}`` to stdout and exits non-zero on stderr so the
backend can still parse a sane document while surfacing the failure.

Environment variables:
  XSSMAP_HOME       - root of the XSSMap install (default /opt/xssmap)
  XSSMAP_OLLAMA_URL - Ollama HTTP base URL (default http://ollama:11434)
  OLLAMA_MODEL      - Default model when --model is not provided
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# Conservative regex that captures URL/parameter/payload triples from a wide
# variety of XSSMap stdout formats (table rows, "[+] FOUND" lines, etc.). We
# parse output line-by-line because XSSMap's exact format may change between
# releases — the auto-bughunter backend will re-parse the JSON we emit, so as
# long as we surface a recognisable triple per finding the integration works.
_TRIPLE_RE = re.compile(
    r"(?P<type>reflected|stored|dom)\s*xss[^\n]*?"
    r"url[=:\s]+(?P<url>https?://\S+)[^\n]*?"
    r"(?:param(?:eter)?|input)[=:\s]+(?P<param>[\w\-\[\]\.]+)[^\n]*?"
    r"payload[=:\s]+(?P<payload>.+?)\s*$",
    re.IGNORECASE,
)

_MAX_TIMEOUT_SECONDS = 600
_MAX_PAYLOADS = 500
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _has_invalid_chars(value: str) -> bool:
    return any(ch in value for ch in ("\r", "\n", "\x00"))


def _validate_url(value: str, label: str) -> str:
    value = value.strip()
    if not value or _has_invalid_chars(value):
        raise ValueError(f"{label} contains invalid characters")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{label} must be an http(s) URL")
    return value


def _validate_model(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) > 128 or not _MODEL_RE.match(value):
        raise ValueError("model must be 1-128 chars (letters, numbers, ., _, :, -)")
    return value


def _validate_max_payloads(value: int | None) -> int | None:
    if value is None:
        return None
    if value <= 0 or value > _MAX_PAYLOADS:
        raise ValueError(f"max-payloads must be between 1 and {_MAX_PAYLOADS}")
    return value


def _validate_timeout(value: int) -> int:
    if value <= 0 or value > _MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be between 1 and {_MAX_TIMEOUT_SECONDS} seconds")
    return value


def _fail(message: str, output: str) -> int:
    sys.stderr.write(f"xssmap wrapper: {message}\n")
    if output == "json":
        json.dump({"vulnerabilities": []}, sys.stdout)
        sys.stdout.write("\n")
    return 2


def _candidate_invocations(src: Path, target: str, max_payloads: int | None,
                           model: str | None, ollama_url: str) -> list[list[str]]:
    """Build a prioritised list of candidate command lines to try."""
    common: list[str] = []
    if max_payloads is not None:
        common += ["--max-payloads", str(max_payloads)]
    if model:
        common += ["--model", model]
    if ollama_url:
        common += ["--ollama-url", ollama_url]

    invocations: list[list[str]] = []
    # 1) Project-provided entry script (most XSSMap forks ship `xssmap.py`).
    script = src / "xssmap.py"
    if script.is_file():
        invocations.append(["python3", str(script), "-u", target] + common)
    # 2) Console-script style entry-point installed by `pip install .`.
    invocations.append(["xssmap", "-u", target] + common)
    # 3) `python -m xssmap` style.
    invocations.append(["python3", "-m", "xssmap", "-u", target] + common)
    return invocations


def _parse_stdout(raw: str) -> list[dict[str, Any]]:
    """Best-effort extraction of XSS findings from XSSMap's stdout."""
    # Fast path: XSSMap forks that already emit JSON.
    stripped = raw.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            doc = json.loads(stripped)
            if isinstance(doc, dict) and "vulnerabilities" in doc:
                return list(doc.get("vulnerabilities") or [])
            if isinstance(doc, list):
                return doc
        except json.JSONDecodeError:
            pass

    findings: list[dict[str, Any]] = []
    for match in _TRIPLE_RE.finditer(raw):
        findings.append({
            "url": match.group("url"),
            "parameter": match.group("param"),
            "payload": match.group("payload").strip().strip("'\""),
            "type": match.group("type").lower(),
            "evidence": match.group(0)[:200],
            "severity": "medium",
        })
    return findings


def _run(cmd: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(prog="xssmap")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="run an XSS scan against a single URL")
    scan.add_argument("--url", required=True)
    scan.add_argument("--output", default="json", choices=["json", "text"])
    scan.add_argument("--max-payloads", type=int, default=None)
    scan.add_argument("--model", default=None)
    scan.add_argument("--ollama-url", default=None)
    scan.add_argument("--timeout", type=int,
                      default=int(os.environ.get("XSSMAP_TIMEOUT_SECONDS", "120")))
    args = parser.parse_args()

    try:
        target = _validate_url(args.url, "target URL")
        args.max_payloads = _validate_max_payloads(args.max_payloads)
        args.timeout = _validate_timeout(args.timeout)
    except ValueError as exc:
        return _fail(str(exc), args.output)

    home = Path(os.environ.get("XSSMAP_HOME", "/opt/xssmap"))
    src = home / "src"
    ollama_url = (args.ollama_url
                  or os.environ.get("XSSMAP_OLLAMA_URL")
                  or "http://ollama:11434")
    model = args.model or os.environ.get("OLLAMA_MODEL") or ""
    try:
        ollama_url = _validate_url(ollama_url, "Ollama URL") if ollama_url else ""
        model = _validate_model(model)
    except ValueError as exc:
        return _fail(str(exc), args.output)

    invocations = _candidate_invocations(src, target, args.max_payloads,
                                         model, ollama_url)

    last_err = "no invocation attempted"
    for cmd in invocations:
        try:
            cp = _run(cmd, cwd=src if src.is_dir() else home, timeout=args.timeout)
        except FileNotFoundError as exc:
            last_err = f"{cmd[0]}: {exc}"
            continue
        except subprocess.TimeoutExpired:
            last_err = f"timeout after {args.timeout}s running {cmd[0]}"
            continue
        if cp.returncode == 0 or cp.stdout.strip():
            findings = _parse_stdout(cp.stdout)
            if args.output == "json":
                json.dump({"vulnerabilities": findings}, sys.stdout)
                sys.stdout.write("\n")
            else:
                sys.stdout.write(cp.stdout)
            return cp.returncode
        last_err = (cp.stderr or cp.stdout or "non-zero exit").strip()[:500]

    # All invocations failed — emit an empty JSON document so the backend can
    # still parse the contract, while surfacing the underlying error on
    # stderr.
    sys.stderr.write(f"xssmap wrapper: {last_err}\n")
    json.dump({"vulnerabilities": []}, sys.stdout)
    sys.stdout.write("\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
