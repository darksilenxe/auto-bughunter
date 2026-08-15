"""
LangChain Service
=================
A FastAPI micro-service that exposes three LangChain-powered endpoints
to the Auto Bughunter backend:

  POST /v1/rag-retrieve   – BM25 retrieval over a security-knowledge corpus,
                             with optional LLM-augmented QA when an AI
                             provider is configured.

  POST /v1/tool-chain     – LangChain structured-output pipeline that
                             produces a prioritised list of planned tool
                             calls for a given pentest task.

  POST /v1/pentest-graph  – LangGraph stateful multi-step reasoning graph
                             that iterates over hypotheses and returns
                             actionable recommendations.

The service is opt-in: set USE_LANGCHAIN_SERVICE=true and
LANGCHAIN_SERVICE_URL=https://langchain-service:8099 in the backend
environment to activate it.  All LLM-dependent endpoints degrade
gracefully to an empty/error response when AI_API_BASE is unset.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


logger = logging.getLogger("langchain-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
_AUTH_EXEMPT_PATHS = {"/health"}

AI_API_BASE = os.getenv("AI_API_BASE", "").strip()
AI_API_KEY = os.getenv("AI_API_KEY", "not-set").strip()
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini").strip()

# Optionally load the security-knowledge corpus for RAG bootstrap
CORPUS_PATH = Path(os.getenv("KNOWLEDGE_CORPUS_PATH", "/app/data/corpus.json"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def _build_llm():
    """Return a ChatOpenAI instance wired to the operator-configured provider."""
    from langchain_openai import ChatOpenAI  # type: ignore[import-untyped]

    return ChatOpenAI(
        model=AI_MODEL,
        base_url=AI_API_BASE or None,
        api_key=AI_API_KEY,
        temperature=0.0,
    )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="LangChain Service", version="1.0.0")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if SIDECAR_AUTH_TOKEN and request.url.path not in _AUTH_EXEMPT_PATHS:
        token = _extract_bearer_token(request)
        if not hmac.compare_digest(token, SIDECAR_AUTH_TOKEN):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)


@app.get("/health")
async def health():
    return {"status": "ok", "llm_configured": bool(AI_API_BASE)}


# ---------------------------------------------------------------------------
# /v1/rag-retrieve
# ---------------------------------------------------------------------------

class RagDocument(BaseModel):
    id: str = ""
    title: str = ""
    content: str = ""
    topic: str = ""
    technique: str = ""
    url: str = ""


class RagRetrieveRequest(BaseModel):
    query: str
    documents: List[RagDocument] = Field(default_factory=list)
    limit: int = 5
    use_llm: bool = False


class RagResult(BaseModel):
    id: str
    title: str
    content: str
    score: float
    url: str = ""


class RagRetrieveResponse(BaseModel):
    query: str
    results: List[RagResult]
    answer: str = ""


@app.post("/v1/rag-retrieve", response_model=RagRetrieveResponse)
async def rag_retrieve(req: RagRetrieveRequest):
    """
    Keyword BM25 retrieval over a set of security-knowledge documents.

    If *use_llm* is true and AI_API_BASE is configured, the retrieved
    passages are fed into a RetrievalQA chain that synthesises a short
    answer; otherwise only the ranked passages are returned.
    """
    from langchain_community.retrievers import BM25Retriever  # type: ignore[import-untyped]
    from langchain_core.documents import Document  # type: ignore[import-untyped]

    docs: List[Document] = []

    for d in req.documents:
        text = f"{d.title}\n{d.content}".strip()
        if text:
            docs.append(Document(
                page_content=text,
                metadata={"id": d.id, "title": d.title, "url": d.url},
            ))

    # Fall back to the on-disk corpus when no inline documents are provided.
    if not docs and CORPUS_PATH.exists():
        try:
            with open(CORPUS_PATH) as fh:
                corpus = json.load(fh)
            for entry in corpus:
                text = (
                    f"{entry.get('title', '')}\n"
                    f"{entry.get('content', entry.get('passage', ''))}"
                ).strip()
                if text:
                    docs.append(Document(
                        page_content=text,
                        metadata={
                            "id": entry.get("id", ""),
                            "title": entry.get("title", ""),
                            "url": entry.get("url", ""),
                        },
                    ))
        except Exception:
            logger.exception("failed to load corpus from %s", CORPUS_PATH)

    if not docs:
        return RagRetrieveResponse(query=req.query, results=[])

    retriever = BM25Retriever.from_documents(docs, k=req.limit)
    retrieved = retriever.invoke(req.query)

    results = [
        RagResult(
            id=doc.metadata.get("id", f"doc-{i}"),
            title=doc.metadata.get("title", ""),
            content=doc.page_content,
            score=1.0 / (i + 1),
            url=doc.metadata.get("url", ""),
        )
        for i, doc in enumerate(retrieved)
    ]

    answer = ""
    if req.use_llm and AI_API_BASE:
        try:
            from langchain.chains import RetrievalQA  # type: ignore[import-untyped]

            llm = _build_llm()
            qa_chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)
            result = qa_chain.invoke({"query": req.query})
            answer = result.get("result", "")
        except Exception:
            logger.exception("LLM QA chain error")

    return RagRetrieveResponse(query=req.query, results=results, answer=answer)


# ---------------------------------------------------------------------------
# /v1/tool-chain
# ---------------------------------------------------------------------------

class ToolDef(BaseModel):
    name: str
    description: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ToolChainRequest(BaseModel):
    task: str
    tools: List[ToolDef] = Field(default_factory=list)
    context: str = ""
    max_steps: int = 5


class PlannedAction(BaseModel):
    tool: str
    reasoning: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ToolChainResponse(BaseModel):
    task: str
    planned_actions: List[PlannedAction]
    summary: str = ""
    error: str = ""


# Pydantic schema used for LLM structured output
class _PentestPlan(BaseModel):
    planned_actions: List[PlannedAction] = Field(default_factory=list)
    summary: str = ""


@app.post("/v1/tool-chain", response_model=ToolChainResponse)
async def tool_chain(req: ToolChainRequest):
    """
    Use LangChain structured output to produce a prioritised list of
    planned tool calls for the given pentest task.

    The caller supplies the available tool catalogue; the LLM reasons
    about which tools to invoke and in what order, returning structured
    JSON that the Go backend can execute directly.
    """
    if not AI_API_BASE:
        return ToolChainResponse(
            task=req.task,
            planned_actions=[],
            error="LLM not configured: AI_API_BASE is unset",
        )

    try:
        from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore[import-untyped]

        tool_catalogue = "\n".join(
            f"- {t.name}: {t.description}" for t in req.tools
        ) or "(no tools provided)"

        system_prompt = (
            "You are an expert penetration tester. "
            "Given a task and a catalogue of available tools, produce a minimal "
            "ordered plan of tool invocations needed to accomplish the task. "
            "For each step include the tool name, your reasoning, and any "
            "key parameters. Limit the plan to at most "
            f"{req.max_steps} steps."
        )
        human_prompt = (
            f"Task: {req.task}\n\n"
            f"Context: {req.context or 'Standard web application security assessment.'}\n\n"
            f"Available tools:\n{tool_catalogue}"
        )

        llm = _build_llm()
        structured_llm = llm.with_structured_output(_PentestPlan)
        plan: _PentestPlan = structured_llm.invoke(
            [SystemMessage(content=system_prompt), HumanMessage(content=human_prompt)]
        )

        return ToolChainResponse(
            task=req.task,
            planned_actions=plan.planned_actions[: req.max_steps],
            summary=plan.summary,
        )

    except Exception:
        logger.exception("tool-chain error")
        return ToolChainResponse(task=req.task, planned_actions=[], error="internal error")


# ---------------------------------------------------------------------------
# /v1/pentest-graph
# ---------------------------------------------------------------------------

class PentestGraphRequest(BaseModel):
    target: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    context: str = ""
    max_iterations: int = 3


class PentestGraphResponse(BaseModel):
    target: str
    reasoning_steps: List[str]
    recommendations: List[str]
    error: str = ""


@app.post("/v1/pentest-graph", response_model=PentestGraphResponse)
async def pentest_graph(req: PentestGraphRequest):
    """
    LangGraph stateful multi-step reasoning graph.

    The graph iterates between a *plan* node (which generates the next
    security hypothesis) and a *summarise* node (which turns all
    hypotheses into actionable recommendations).  The Go backend can call
    this endpoint to augment the ``pentest_loop`` agent's reasoning with
    LangChain-native chain-of-thought.
    """
    if not AI_API_BASE:
        return PentestGraphResponse(
            target=req.target,
            reasoning_steps=[],
            recommendations=[],
            error="LLM not configured: AI_API_BASE is unset",
        )

    try:
        from typing import TypedDict

        from langchain_core.messages import HumanMessage  # type: ignore[import-untyped]
        from langgraph.graph import END, StateGraph  # type: ignore[import-untyped]

        llm = _build_llm()

        class _State(TypedDict):
            target: str
            findings_summary: str
            context: str
            steps: List[str]
            recommendations: List[str]
            iteration: int
            max_iterations: int

        def plan_node(state: _State) -> _State:
            prompt = (
                f"You are a security analyst.\n"
                f"Target: {state['target']}\n"
                f"Known findings: {state['findings_summary']}\n"
                f"Context: {state['context']}\n\n"
                f"Iteration {state['iteration'] + 1} of {state['max_iterations']}.\n"
                f"Identify the single most important security hypothesis to investigate next. "
                f"Be concise (2-3 sentences)."
            )
            response = llm.invoke([HumanMessage(content=prompt)])
            step = f"[Iteration {state['iteration'] + 1}] {response.content.strip()}"
            return {**state, "steps": state["steps"] + [step], "iteration": state["iteration"] + 1}

        def summarise_node(state: _State) -> _State:
            all_steps = "\n".join(state["steps"])
            prompt = (
                f"You are a security analyst summarising a pentest reasoning session.\n"
                f"Target: {state['target']}\n"
                f"Reasoning steps:\n{all_steps}\n\n"
                f"Provide a prioritised list of actionable recommendations. "
                f"Format each recommendation as a bullet starting with '- '."
            )
            response = llm.invoke([HumanMessage(content=prompt)])
            recs = [
                line.lstrip("- ").strip()
                for line in response.content.split("\n")
                if line.strip().startswith("-")
            ]
            return {**state, "recommendations": recs}

        def _route(state: _State) -> str:
            return "summarise" if state["iteration"] >= state["max_iterations"] else "plan"

        graph: StateGraph = StateGraph(_State)
        graph.add_node("plan", plan_node)
        graph.add_node("summarise", summarise_node)
        graph.set_entry_point("plan")
        graph.add_conditional_edges("plan", _route, {"plan": "plan", "summarise": "summarise"})
        graph.add_edge("summarise", END)
        compiled = graph.compile()

        findings_summary = "; ".join(
            f"{f.get('category', 'unknown')} ({f.get('severity', 'info')}): {f.get('title', '')}"
            for f in req.findings
        ) or "No prior findings."

        initial: _State = {
            "target": req.target,
            "findings_summary": findings_summary,
            "context": req.context or "Standard web application security assessment.",
            "steps": [],
            "recommendations": [],
            "iteration": 0,
            "max_iterations": max(1, req.max_iterations),
        }

        final = compiled.invoke(initial)
        return PentestGraphResponse(
            target=req.target,
            reasoning_steps=final["steps"],
            recommendations=final["recommendations"],
        )

    except Exception:
        logger.exception("pentest-graph error")
        return PentestGraphResponse(
            target=req.target,
            reasoning_steps=[],
            recommendations=[],
            error="internal error",
        )
