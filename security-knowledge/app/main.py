from __future__ import annotations

import hmac
import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


logger = logging.getLogger("security-knowledge")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
_AUTH_EXEMPT_PATHS = {"/health"}
CORPUS_PATH = Path(os.getenv("KNOWLEDGE_CORPUS_PATH", "/app/data/corpus.json"))


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def normalize(text: str) -> str:
    return " ".join((text or "").lower().split())


def tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9_.:/-]+", normalize(text))


class FindingInput(BaseModel):
    category: str = ""
    severity: str = "info"
    title: str = ""
    description: str = ""
    recommendation: str = ""


class RetrieveRequest(BaseModel):
    query: str = ""
    stage: str = "general"
    findings: List[FindingInput] = Field(default_factory=list)
    attackPaths: List[str] = Field(default_factory=list)
    limit: int = 5


class KnowledgeReference(BaseModel):
    id: str
    title: str
    url: str
    sourceType: str
    license: str
    topic: str
    vulnerabilityClass: str
    technique: str
    passage: str
    content: str = ""
    score: float


class RetrieveResponse(BaseModel):
    query: str
    stage: str
    curationMode: str
    licenseNotice: str
    suggestedActions: List[str]
    references: List[KnowledgeReference]


class CorpusDocument(BaseModel):
    id: str
    title: str
    url: str
    sourceType: str
    license: str
    topic: str
    vulnerabilityClass: str
    technique: str
    keywords: List[str] = Field(default_factory=list)
    passage: str
    content: str = ""


def _load_corpus() -> List[CorpusDocument]:
    if not CORPUS_PATH.exists():
        logger.warning("knowledge corpus not found: %s", CORPUS_PATH)
        return []
    with CORPUS_PATH.open() as f:
        raw = json.load(f)
    docs = [CorpusDocument.model_validate(item) for item in raw]
    logger.info("Loaded %d curated knowledge documents", len(docs))
    return docs


def _request_keywords(req: RetrieveRequest) -> List[str]:
    tokens = tokenize(req.query + " " + req.stage)
    for finding in req.findings:
        tokens.extend(tokenize(f"{finding.category} {finding.title} {finding.description} {finding.recommendation}"))
    for path in req.attackPaths:
        tokens.extend(tokenize(path))
    return tokens


def _score_document(doc: CorpusDocument, req: RetrieveRequest) -> float:
    score = 0.0
    request_tokens = _request_keywords(req)
    request_set = set(request_tokens)
    doc_tokens = set(tokenize(" ".join([
        doc.title,
        doc.topic,
        doc.vulnerabilityClass,
        doc.technique,
        doc.passage,
        doc.content,
        " ".join(doc.keywords),
    ])))

    overlap = len(request_set & doc_tokens)
    score += overlap * 0.12

    stage = normalize(req.stage)
    if stage and stage in normalize(f"{doc.topic} {doc.technique} {doc.vulnerabilityClass}"):
        score += 0.35

    for finding in req.findings:
        combined = normalize(f"{finding.category} {finding.title} {finding.description} {finding.recommendation}")
        if doc.vulnerabilityClass and normalize(doc.vulnerabilityClass) in combined:
            score += 0.45
        if doc.technique and normalize(doc.technique) in combined:
            score += 0.35
        if doc.topic and normalize(doc.topic) in combined:
            score += 0.25

    for keyword in doc.keywords:
        if normalize(keyword) in " ".join(request_tokens):
            score += 0.15

    if req.attackPaths and any(normalize(doc.technique) in normalize(path) for path in req.attackPaths):
        score += 0.3

    return round(score, 4)


def _suggested_actions(references: List[KnowledgeReference]) -> List[str]:
    actions: List[str] = []
    seen = set()
    for ref in references:
        for candidate in [
            f"Review {ref.topic} guidance from {ref.title} before validating similar findings.",
            f"Use {ref.title} as a citation when documenting remediation for {ref.vulnerabilityClass}.",
        ]:
            key = candidate.lower()
            if key in seen:
                continue
            seen.add(key)
            actions.append(candidate)
            if len(actions) >= 4:
                return actions
    return actions


CORPUS = _load_corpus()
# Maximum number of full-text characters returned per reference. Full bodies are
# stored in the corpus but bounded in responses to keep AI prompt payloads sane.
RESPONSE_CONTENT_MAX_LENGTH = 4000
LICENSE_NOTICE = (
    "Curated notes only: this service stores short manually-authored summaries with source URLs. "
    "Confirm third-party content rights before importing article bodies or training data."
)

app = FastAPI(title="Auto Bughunter Security Knowledge", version="0.1.0")


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


@app.get("/health")
def health() -> Dict[str, str]:
    return {
        "status": "ok",
        "mode": "curated-retrieval",
        "documents": str(len(CORPUS)),
        "curationMode": "manual-short-notes",
    }


@app.post("/v1/retrieve", response_model=RetrieveResponse)
def retrieve(req: RetrieveRequest) -> RetrieveResponse:
    limit = req.limit if req.limit > 0 else 5
    scored = []
    for doc in CORPUS:
        score = _score_document(doc, req)
        if score <= 0:
            continue
        scored.append(
            KnowledgeReference(
                id=doc.id,
                title=doc.title,
                url=doc.url,
                sourceType=doc.sourceType,
                license=doc.license,
                topic=doc.topic,
                vulnerabilityClass=doc.vulnerabilityClass,
                technique=doc.technique,
                passage=doc.passage,
                content=doc.content[:RESPONSE_CONTENT_MAX_LENGTH],
                score=round(score, 2),
            )
        )
    scored.sort(key=lambda item: (-item.score, item.title.lower()))
    refs = scored[:limit]
    return RetrieveResponse(
        query=req.query,
        stage=req.stage,
        curationMode="manual-short-notes",
        licenseNotice=LICENSE_NOTICE,
        suggestedActions=_suggested_actions(refs),
        references=refs,
    )
