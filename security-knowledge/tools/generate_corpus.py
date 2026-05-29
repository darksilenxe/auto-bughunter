#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVICE_ROOT = REPO_ROOT / "security-knowledge"
DEFAULT_SOURCE_PATH = SERVICE_ROOT / "sources" / "corpus_sources.json"
DEFAULT_CORPUS_PATH = SERVICE_ROOT / "data" / "corpus.json"
DEFAULT_REVIEW_PATH = SERVICE_ROOT / "data" / "corpus.review.json"
DEFAULT_WEBSITE_TEXT_PATH = SERVICE_ROOT / "data" / "website_text.json"
USER_AGENT = "auto-bughunter-security-knowledge/1.0"
PASSAGE_PREFIX = "Curated note:"
PASSAGE_MAX_LENGTH = 320
WEBSITE_TEXT_MAX_LENGTH = 12000
LOW_CONFIDENCE_MIN_WORDS = 120
# Maximum length of full-text body stored on a corpus document. Full-text
# ingestion is ON by default (owner sign-off; disable with --no-full-text) and
# only ever applies to entries explicitly flagged with "fullText": true.
FULL_TEXT_MAX_LENGTH = WEBSITE_TEXT_MAX_LENGTH


class CorpusGenerationError(Exception):
    pass


class PlainTextHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._ignored_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._ignored_depth += 1
            return
        if tag in {"p", "br", "li", "section", "article", "div", "h1", "h2", "h3", "h4"}:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1
            return
        if tag in {"p", "br", "li", "section", "article", "div", "h1", "h2", "h3", "h4"}:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        text = " ".join(data.split())
        if text:
            self._parts.append(text)

    def text(self) -> str:
        lines = [" ".join(line.split()) for line in "".join(self._parts).splitlines()]
        cleaned = "\n".join(line for line in lines if line)
        return cleaned.strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_space(value: str) -> str:
    return " ".join((value or "").split())


def normalize_keywords(keywords: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for keyword in keywords or []:
        candidate = normalize_space(str(keyword)).lower()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def required_string(entry: dict[str, Any], field: str) -> str:
    value = normalize_space(str(entry.get(field, "")))
    if not value:
        raise CorpusGenerationError(f"missing required field: {field}")
    return value


def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise CorpusGenerationError(f"invalid url: {url}")


def token_set(*values: str) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        for token in normalize_space(value).lower().replace("/", " ").replace("-", " ").split():
            if token:
                tokens.add(token)
    return tokens


def similarity(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    overlap = len(a & b)
    return overlap / len(a | b)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: Any) -> None:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def extract_plain_text(body: bytes, content_type: str) -> str:
    if "html" in content_type:
        parser = PlainTextHTMLParser()
        parser.feed(body.decode("utf-8", errors="ignore"))
        return parser.text()
    return normalize_space(body.decode("utf-8", errors="ignore"))


def fetch_url_text(url: str, timeout: int) -> tuple[str, str]:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - allowlisted curated URLs only
        content_type = response.headers.get("Content-Type", "text/plain")
        body = response.read()
    return extract_plain_text(body, content_type), content_type


def load_sources(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise CorpusGenerationError("source file must be a JSON object")
    payload.setdefault("allowlists", {})
    payload.setdefault("entries", [])
    if not isinstance(payload["entries"], list):
        raise CorpusGenerationError("entries must be a JSON array")
    return payload


def fetch_website_texts(source_path: Path, output_path: Path, timeout: int = 20) -> dict[str, Any]:
    payload = load_sources(source_path)
    results: list[dict[str, Any]] = []
    for entry in payload["entries"]:
        if not entry.get("websiteImport", {}).get("enabled", True):
            continue
        record = {
            "id": entry.get("id"),
            "title": entry.get("title"),
            "url": entry.get("url"),
            "sourceType": entry.get("sourceType"),
            "license": entry.get("license"),
            "fetchedAt": utc_now(),
            "text": "",
            "excerpt": "",
            "contentType": "",
            "wordCount": 0,
            "textHashSha256": "",
            "confidence": "low",
            "flags": [],
            "error": "",
        }
        try:
            url = required_string(entry, "url")
            validate_url(url)
            text, content_type = fetch_url_text(url, timeout)
            bounded_text = text[:WEBSITE_TEXT_MAX_LENGTH]
            excerpt = bounded_text[:800]
            words = len(bounded_text.split())
            flags: list[str] = []
            if len(text) > WEBSITE_TEXT_MAX_LENGTH:
                flags.append("text-truncated")
            if words < LOW_CONFIDENCE_MIN_WORDS:
                flags.append("low-word-count")
            title = normalize_space(str(entry.get("title", ""))).lower()
            if title and title not in bounded_text.lower():
                flags.append("title-not-found")
            confidence = "high" if not flags or flags == ["text-truncated"] else "low"
            record.update(
                {
                    "contentType": content_type,
                    "text": bounded_text,
                    "excerpt": excerpt,
                    "wordCount": words,
                    "textHashSha256": hashlib.sha256(bounded_text.encode("utf-8")).hexdigest(),
                    "confidence": confidence,
                    "flags": flags,
                }
            )
        except Exception as exc:  # noqa: BLE001
            record["flags"] = ["fetch-failed"]
            record["error"] = str(exc)
        results.append(record)
    output = {
        "version": 1,
        "generatedAt": utc_now(),
        "source": str(source_path),
        "entries": results,
    }
    write_json(output_path, output)
    return output


def build_corpus(source_path: Path, output_path: Path, review_path: Path, website_text_path: Path | None = None, allow_full_text: bool = True) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    payload = load_sources(source_path)
    allowlists = payload.get("allowlists") or {}
    allowed_source_types = set(allowlists.get("sourceTypes") or [])
    allowed_licenses = set(allowlists.get("licenses") or [])
    website_text_entries: dict[str, dict[str, Any]] = {}
    if website_text_path and website_text_path.exists():
        for item in load_json(website_text_path).get("entries", []):
            website_text_entries[str(item.get("id"))] = item

    review_exceptions: list[dict[str, str]] = []
    corpus: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    accepted_fingerprints: list[tuple[str, set[str], dict[str, Any]]] = []

    for raw_entry in payload["entries"]:
        try:
            entry = {
                "id": required_string(raw_entry, "id"),
                "title": required_string(raw_entry, "title"),
                "url": required_string(raw_entry, "url"),
                "sourceType": required_string(raw_entry, "sourceType"),
                "license": required_string(raw_entry, "license"),
                "topic": required_string(raw_entry, "topic"),
                "vulnerabilityClass": required_string(raw_entry, "vulnerabilityClass"),
                "technique": required_string(raw_entry, "technique"),
                "keywords": normalize_keywords(list(raw_entry.get("keywords") or [])),
                "passage": required_string(raw_entry, "passage"),
            }
            validate_url(entry["url"])
            if entry["sourceType"] not in allowed_source_types:
                raise CorpusGenerationError(f"sourceType not allowlisted: {entry['sourceType']}")
            if entry["license"] not in allowed_licenses:
                raise CorpusGenerationError(f"license not allowlisted: {entry['license']}")
            if entry["id"] in seen_ids:
                raise CorpusGenerationError(f"duplicate id: {entry['id']}")
            if len(entry["passage"]) > PASSAGE_MAX_LENGTH:
                raise CorpusGenerationError(f"passage too long: {entry['id']}")
            if not entry["passage"].startswith(PASSAGE_PREFIX):
                review_exceptions.append(
                    {
                        "level": "warning",
                        "id": entry["id"],
                        "type": "policy-style",
                        "message": "passage should start with 'Curated note:'",
                    }
                )

            fingerprint = token_set(
                entry["title"],
                entry["topic"],
                entry["vulnerabilityClass"],
                entry["technique"],
                entry["passage"],
            )
            duplicate_of = None
            for existing_id, existing_fingerprint, existing_entry in accepted_fingerprints:
                same_class = existing_entry["vulnerabilityClass"] == entry["vulnerabilityClass"]
                same_technique = existing_entry["technique"] == entry["technique"]
                if same_class and same_technique and similarity(fingerprint, existing_fingerprint) >= 0.72:
                    duplicate_of = existing_id
                    break
            if duplicate_of:
                review_exceptions.append(
                    {
                        "level": "warning",
                        "id": entry["id"],
                        "type": "duplicate-cluster",
                        "message": f"near-duplicate of {duplicate_of}; skipped from generated corpus",
                    }
                )
                continue

            website_text = website_text_entries.get(entry["id"])
            if website_text:
                if website_text.get("error"):
                    review_exceptions.append(
                        {
                            "level": "warning",
                            "id": entry["id"],
                            "type": "website-import-failed",
                            "message": website_text["error"],
                        }
                    )
                elif website_text.get("confidence") == "low":
                    flags = ", ".join(website_text.get("flags") or []) or "low confidence"
                    review_exceptions.append(
                        {
                            "level": "warning",
                            "id": entry["id"],
                            "type": "website-import-low-confidence",
                            "message": flags,
                        }
                    )

            # Full-text ingestion is ON by default (the repository owner has
            # signed off on mirroring HackTricks / PayloadsAllTheThings bodies
            # into the corpus) and applies to entries flagged "fullText": true.
            # It can be disabled for hermetic/offline builds with --no-full-text.
            # The fetched body is stored in a separate "content" field; the short
            # curated "passage" is always retained, and source URL / license
            # attribution stay on the document so provenance is never lost.
            wants_full_text = bool(raw_entry.get("fullText"))
            if allow_full_text and wants_full_text:
                if website_text and website_text.get("text") and not website_text.get("error"):
                    body = str(website_text["text"])[:FULL_TEXT_MAX_LENGTH]
                    entry["content"] = body
                    entry["contentSource"] = "website-import"
                    entry["contentRetrievedAt"] = website_text.get("fetchedAt", "")
                    entry["contentHashSha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
                else:
                    review_exceptions.append(
                        {
                            "level": "warning",
                            "id": entry["id"],
                            "type": "full-text-missing",
                            "message": "fullText requested but no website text available; run fetch-web-text first",
                        }
                    )
            elif wants_full_text and not allow_full_text:
                review_exceptions.append(
                    {
                        "level": "info",
                        "id": entry["id"],
                        "type": "full-text-skipped",
                        "message": "fullText entry stored as curated note only; full-text ingestion disabled via --no-full-text",
                    }
                )

            seen_ids.add(entry["id"])
            corpus.append(entry)
            accepted_fingerprints.append((entry["id"], fingerprint, entry))
        except CorpusGenerationError as exc:
            review_exceptions.append(
                {
                    "level": "error",
                    "id": str(raw_entry.get("id", "")),
                    "type": "validation",
                    "message": str(exc),
                }
            )

    corpus.sort(key=lambda item: item["id"])
    review = {
        "generatedAt": utc_now(),
        "phase": payload.get("phase", "phase-1"),
        "summary": {
            "sourceEntries": len(payload["entries"]),
            "acceptedEntries": len(corpus),
            "warnings": sum(1 for item in review_exceptions if item["level"] == "warning"),
            "errors": sum(1 for item in review_exceptions if item["level"] == "error"),
        },
        "exceptions": review_exceptions,
    }
    write_json(output_path, corpus)
    write_json(review_path, review)
    return corpus, review


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate and review the curated security knowledge corpus.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch_parser = subparsers.add_parser("fetch-web-text", help="Fetch plain text from website sources into JSON.")
    fetch_parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCE_PATH)
    fetch_parser.add_argument("--output", type=Path, default=DEFAULT_WEBSITE_TEXT_PATH)
    fetch_parser.add_argument("--timeout", type=int, default=20)

    build_parser = subparsers.add_parser("build", help="Build data/corpus.json and a review report.")
    build_parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCE_PATH)
    build_parser.add_argument("--output", type=Path, default=DEFAULT_CORPUS_PATH)
    build_parser.add_argument("--review-output", type=Path, default=DEFAULT_REVIEW_PATH)
    build_parser.add_argument("--website-text", type=Path, default=DEFAULT_WEBSITE_TEXT_PATH)
    build_parser.add_argument(
        "--allow-full-text",
        dest="allow_full_text",
        action="store_true",
        default=True,
        help=(
            "Mirror fetched full-text bodies into the corpus 'content' field for "
            "entries flagged \"fullText\": true. ON by default (owner sign-off). "
            "Source URL and license attribution are always retained."
        ),
    )
    build_parser.add_argument(
        "--no-full-text",
        dest="allow_full_text",
        action="store_false",
        help=(
            "Disable full-text ingestion for hermetic/offline builds; fullText "
            "entries are stored as curated notes only (no network fetch mirrored)."
        ),
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.command == "fetch-web-text":
        fetch_website_texts(args.sources.resolve(), args.output.resolve(), args.timeout)
        return 0
    if args.command == "build":
        website_text = args.website_text.resolve()
        build_corpus(
            args.sources.resolve(),
            args.output.resolve(),
            args.review_output.resolve(),
            website_text if website_text.exists() else None,
            allow_full_text=args.allow_full_text,
        )
        return 0
    raise AssertionError(f"unexpected command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
