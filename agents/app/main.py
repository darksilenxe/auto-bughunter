"""
Autonomous Agent Learner Service
=================================
A FastAPI micro-service that implements an online Q-learning model for
autonomous agent spawn recommendations.  Every completed scan teaches the
model which agent sequences produced high-value findings, and future spawn
requests use the learned Q-table to augment the static orchestration rules.

The model is persisted to /data/agent_weights.json so that it survives
container restarts and accumulates knowledge over time.
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
from typing import Dict, List, Optional

import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel, Field

logger = logging.getLogger("agents-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

WEIGHTS_PATH = os.getenv("WEIGHTS_PATH", "/data/agent_weights.json")

# ---------------------------------------------------------------------------
# Known agents (ordered by pipeline stage)
# ---------------------------------------------------------------------------
KNOWN_AGENTS: List[str] = [
    "reconnaissance",
    "scanning",
    "input_validation",
    "information_disclosure",
    "access_control",
    "api_security",
    "cors_redirect",
    "wordlist",
    "analysis",
    "ml_triage",
    "attack_path",
    "false_positive_review",
    "remediation_planner",
    "reporting",
]

AGENT_INDEX: Dict[str, int] = {a: i for i, a in enumerate(KNOWN_AGENTS)}

# ---------------------------------------------------------------------------
# Q-learning model
# ---------------------------------------------------------------------------

class QLearner:
    """
    Simple tabular Q-learning model.

    State  = (source_agent_index, context_flags)  where context_flags is a
              6-bit integer summarising the scan context:
              bit0 = has_high_finding
              bit1 = has_sql
              bit2 = has_wordpress
              bit3 = has_xss
              bit4 = has_api
              bit5 = has_forms

    Action = target_agent_index

    Q(s, a) is initialised to 0.5 (neutral) and updated after each scan
    with a standard TD(0) update:
        Q(s,a) ← Q(s,a) + α * (r - Q(s,a))
    """

    ALPHA = 0.15   # learning rate
    NUM_AGENTS = len(KNOWN_AGENTS)
    NUM_CONTEXT_FLAGS = 64  # 2^6

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Q[source_idx][ctx_flags][target_idx] = value in [0, 1]
        self._q: np.ndarray = np.full(
            (self.NUM_AGENTS, self.NUM_CONTEXT_FLAGS, self.NUM_AGENTS),
            0.5,
            dtype=np.float32,
        )
        self._update_count: int = 0
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def recommend(
        self,
        source_agent: str,
        context_flags: int,
        top_k: int = 3,
        threshold: float = 0.6,
    ) -> List[str]:
        """Return up to top_k agents with Q > threshold, sorted descending."""
        src = AGENT_INDEX.get(source_agent)
        if src is None:
            return []
        ctx = context_flags & 0x3F  # clamp to 6 bits
        with self._lock:
            q_row = self._q[src, ctx, :].copy()
        # Mask out the source agent itself and agents that come before it
        # in the pipeline (avoid circular spawning).
        candidates = []
        for tgt_idx, q_val in enumerate(q_row):
            tgt_name = KNOWN_AGENTS[tgt_idx]
            if tgt_name == source_agent:
                continue
            if q_val >= threshold:
                candidates.append((tgt_name, float(q_val)))
        candidates.sort(key=lambda x: -x[1])
        return [name for name, _ in candidates[:top_k]]

    def learn(
        self,
        source_agent: str,
        target_agent: str,
        context_flags: int,
        reward: float,
    ) -> None:
        """Update Q-value for a (source, context, target) transition."""
        src = AGENT_INDEX.get(source_agent)
        tgt = AGENT_INDEX.get(target_agent)
        if src is None or tgt is None:
            return
        ctx = context_flags & 0x3F
        reward = float(np.clip(reward, 0.0, 1.0))
        with self._lock:
            old = float(self._q[src, ctx, tgt])
            self._q[src, ctx, tgt] = old + self.ALPHA * (reward - old)
            self._update_count += 1
        # Persist every 50 updates to avoid excessive disk I/O.
        if self._update_count % 50 == 0:
            self._save()

    def weights_summary(self) -> Dict:
        with self._lock:
            q_copy = self._q.copy()
        # Summarise: for each source agent return the top 3 targets overall
        summary = {}
        for src_idx, src_name in enumerate(KNOWN_AGENTS):
            q_flat = q_copy[src_idx].mean(axis=0)  # average over context
            top_targets = sorted(
                [(KNOWN_AGENTS[i], round(float(v), 3)) for i, v in enumerate(q_flat)
                 if KNOWN_AGENTS[i] != src_name],
                key=lambda x: -x[1],
            )[:5]
            summary[src_name] = top_targets
        return {"agents": KNOWN_AGENTS, "topTransitions": summary, "updateCount": self._update_count}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(WEIGHTS_PATH) or ".", exist_ok=True)
            with self._lock:
                data = {
                    "q": self._q.tolist(),
                    "updateCount": self._update_count,
                    "savedAt": time.time(),
                }
            with open(WEIGHTS_PATH, "w") as f:
                json.dump(data, f)
            logger.info("Saved agent weights to %s (updates=%d)", WEIGHTS_PATH, self._update_count)
        except Exception as exc:
            logger.warning("Failed to save weights: %s", exc)

    def _load(self) -> None:
        if not os.path.exists(WEIGHTS_PATH):
            return
        try:
            with open(WEIGHTS_PATH) as f:
                data = json.load(f)
            q_loaded = np.array(data["q"], dtype=np.float32)
            if q_loaded.shape == self._q.shape:
                with self._lock:
                    self._q = q_loaded
                    self._update_count = int(data.get("updateCount", 0))
                logger.info("Loaded agent weights from %s (updates=%d)", WEIGHTS_PATH, self._update_count)
        except Exception as exc:
            logger.warning("Failed to load weights: %s", exc)


learner = QLearner()

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="Auto Bughunter Agent Learner", version="1.0.0")


# ---- Request / Response models ----------------------------------------

class SpawnRequest(BaseModel):
    sourceAgent: str
    findings: List[dict] = Field(default_factory=list)
    topK: int = 3
    threshold: float = 0.6


class SpawnResponse(BaseModel):
    recommended: List[str]
    contextFlags: int


class LearnRequest(BaseModel):
    """
    Sent by the backend after a scan completes so the model can update
    its Q-values based on which agents were spawned and what value they
    produced.
    """
    scanId: str = ""
    agentSequence: List[str] = Field(default_factory=list)
    findings: List[dict] = Field(default_factory=list)
    highCount: int = 0
    mediumCount: int = 0
    lowCount: int = 0
    durationMs: int = 0


class LearnResponse(BaseModel):
    updated: int
    message: str


# ---- Helpers -----------------------------------------------------------

def compute_context_flags(findings: List[dict]) -> int:
    """Encode scan context into a 6-bit integer for use as Q-table state."""
    flags = 0
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        title = str(f.get("title", "")).lower()
        cat = str(f.get("category", "")).lower()
        ev = str(f.get("evidence", "")).lower()
        combined = f"{title} {cat} {ev}"
        if sev == "high":
            flags |= 1 << 0
        if "sql" in combined or "inject" in combined:
            flags |= 1 << 1
        if "wordpress" in combined or "wp-" in combined:
            flags |= 1 << 2
        if "xss" in combined or "script" in combined:
            flags |= 1 << 3
        if "api" in cat or "graphql" in combined:
            flags |= 1 << 4
        if "form" in combined or "csrf" in combined:
            flags |= 1 << 5
    return flags


def compute_reward(agent_name: str, findings: List[dict], high: int, medium: int) -> float:
    """
    Compute a normalised [0,1] reward for spawning agent_name given the
    overall scan outcome.

    High findings are weighted more heavily; agents that produce findings
    closely related to their specialty get a bonus.
    """
    base = math.tanh(high * 0.4 + medium * 0.15)  # tanh keeps it in (0,1)
    # Speciality bonus: reward more if the agent's category matches findings
    specialty_hits = 0
    for f in findings:
        cat = str(f.get("category", "")).lower()
        title = str(f.get("title", "")).lower()
        combined = f"{cat} {title}"
        if agent_name == "input_validation" and ("input" in combined or "sql" in combined or "xss" in combined):
            specialty_hits += 1
        elif agent_name == "access_control" and ("access" in combined or "idor" in combined or "auth" in combined):
            specialty_hits += 1
        elif agent_name == "api_security" and ("api" in combined or "graphql" in combined):
            specialty_hits += 1
        elif agent_name == "cors_redirect" and ("cors" in combined or "redirect" in combined):
            specialty_hits += 1
        elif agent_name == "ml_triage" and str(f.get("severity", "")).lower() == "high":
            specialty_hits += 1
        elif agent_name == "attack_path" and str(f.get("severity", "")).lower() in ("high", "medium"):
            specialty_hits += 1
    bonus = math.tanh(specialty_hits * 0.3)
    return float(np.clip(0.6 * base + 0.4 * bonus, 0.0, 1.0))


# ---- Endpoints ---------------------------------------------------------

@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "updateCount": learner._update_count,
        "weightsPath": WEIGHTS_PATH,
    }


@app.post("/v1/spawn", response_model=SpawnResponse)
def spawn(req: SpawnRequest) -> SpawnResponse:
    """Return recommended agents to spawn after `sourceAgent` completes."""
    ctx = compute_context_flags(req.findings)
    recommended = learner.recommend(
        source_agent=req.sourceAgent,
        context_flags=ctx,
        top_k=req.topK,
        threshold=req.threshold,
    )
    return SpawnResponse(recommended=recommended, contextFlags=ctx)


@app.post("/v1/learn", response_model=LearnResponse)
def learn(req: LearnRequest) -> LearnResponse:
    """
    Update Q-values from a completed scan.
    The agent sequence tells us which (source→target) transitions occurred;
    the reward is derived from finding counts.
    """
    ctx = compute_context_flags(req.findings)
    updated = 0
    seq = req.agentSequence
    for i in range(len(seq) - 1):
        src = seq[i]
        tgt = seq[i + 1]
        reward = compute_reward(tgt, req.findings, req.highCount, req.mediumCount)
        learner.learn(
            source_agent=src,
            target_agent=tgt,
            context_flags=ctx,
            reward=reward,
        )
        updated += 1
    # Persist after learning batch
    learner._save()
    return LearnResponse(
        updated=updated,
        message=f"Updated {updated} Q-value(s) for scan {req.scanId}",
    )


@app.get("/v1/weights")
def get_weights() -> dict:
    """Return a human-readable summary of the current learned weights."""
    return learner.weights_summary()
