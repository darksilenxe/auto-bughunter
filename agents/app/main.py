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
    "dynamic_commands",
    "tool_builder",
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
# FastAPI app  (must be defined before any @app.route decorators below)
# ---------------------------------------------------------------------------

app = FastAPI(title="Auto Bughunter Agent Learner", version="1.0.0")

# ---------------------------------------------------------------------------
# Command generation catalogue
# ---------------------------------------------------------------------------

# Maps finding signal → (binary, arg_template, rationale)
COMMAND_RULES: List[tuple] = [
    # (signal_fn, binary, args_factory, rationale)
]

def _has(findings: List[dict], field: str, substr: str) -> bool:
    for f in findings:
        val = str(f.get(field, "")).lower()
        if substr in val:
            return True
    return False

def _target_host(target: str) -> str:
    from urllib.parse import urlparse
    try:
        return urlparse(target).hostname or target
    except Exception:
        return target


class GenerateCommandRequest(BaseModel):
    agentName: str = "agent"
    target: str
    findings: List[dict] = Field(default_factory=list)
    maxCommands: int = 5


class GeneratedCommand(BaseModel):
    binary: str
    args: List[str]
    rationale: str
    generatedBy: str
    timeoutSeconds: int = 60


class GenerateCommandResponse(BaseModel):
    commands: List[GeneratedCommand]


class BuildToolRequest(BaseModel):
    agentName: str = "agent"
    target: str
    taskDescription: str
    findings: List[dict] = Field(default_factory=list)


class BuiltTool(BaseModel):
    name: str
    language: str
    code: str
    rationale: str


class BuildToolResponse(BaseModel):
    tool: BuiltTool


@app.post("/v1/generate-command", response_model=GenerateCommandResponse)
def generate_command(req: GenerateCommandRequest) -> GenerateCommandResponse:
    """
    Return a list of tailored pen testing commands based on the current
    findings context.  All commands target only the authorised scan target.
    """
    findings = req.findings
    target = req.target.rstrip("/")
    host = _target_host(target)
    agent_name = req.agentName
    commands: List[GeneratedCommand] = []

    # SQL injection
    if _has(findings, "category", "injection") or _has(findings, "title", "sql"):
        param_url = next(
            (str(f.get("evidence", "")).split()[0] for f in findings
             if "?" in str(f.get("evidence", "")) and host in str(f.get("evidence", ""))),
            f"{target}?id=1",
        )
        commands.append(GeneratedCommand(
            binary="sqlmap",
            args=["-u", param_url, "--batch", "--level=2", "--risk=1",
                  "--output-dir=/tmp/auto-bughunter/sqlmap"],
            rationale="SQL injection indicators detected; probing with sqlmap (safe level/risk)",
            generatedBy=agent_name,
            timeoutSeconds=180,
        ))

    # XSS
    if _has(findings, "title", "xss") or _has(findings, "title", "cross-site"):
        param_url = next(
            (str(f.get("evidence", "")).split()[0] for f in findings
             if "?" in str(f.get("evidence", "")) and host in str(f.get("evidence", ""))),
            f"{target}?q=test",
        )
        commands.append(GeneratedCommand(
            binary="dalfox",
            args=["url", param_url, "--silence", "--no-color"],
            rationale="XSS indicators found; confirming with dalfox",
            generatedBy=agent_name,
            timeoutSeconds=120,
        ))

    # WordPress
    if _has(findings, "evidence", "wordpress") or _has(findings, "evidence", "wp-content"):
        commands.append(GeneratedCommand(
            binary="wpscan",
            args=["--url", target, "--enumerate", "vp,vt,u", "--no-banner"],
            rationale="WordPress detected; enumerating plugins, themes, users",
            generatedBy=agent_name,
            timeoutSeconds=120,
        ))

    # Subdomain/host enumeration
    if _has(findings, "category", "reconnaissance"):
        commands.append(GeneratedCommand(
            binary="subfinder",
            args=["-d", host, "-silent"],
            rationale="Running subdomain enumeration to expand attack surface",
            generatedBy=agent_name,
            timeoutSeconds=60,
        ))

    # Directory fuzzing
    if _has(findings, "title", "form") or _has(findings, "evidence", "forms="):
        commands.append(GeneratedCommand(
            binary="ffuf",
            args=["-u", f"{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt",
                  "-t", "20", "-mc", "200,204,301,302,307,401,403", "-s"],
            rationale="Forms discovered; fuzzing for additional endpoints",
            generatedBy=agent_name,
            timeoutSeconds=90,
        ))

    # WAF detection (fallback)
    if not commands:
        commands.append(GeneratedCommand(
            binary="wafw00f",
            args=[target, "--no-colors"],
            rationale="No specific indicators; detecting WAF to adapt attack strategy",
            generatedBy=agent_name,
            timeoutSeconds=30,
        ))

    return GenerateCommandResponse(commands=commands[: req.maxCommands])


@app.post("/v1/build-tool", response_model=BuildToolResponse)
def build_tool(req: BuildToolRequest) -> BuildToolResponse:
    """
    Generate a self-contained Python tool script for a specialised task.
    The script outputs JSON-lines findings to stdout.
    """
    desc = req.taskDescription.lower()
    target = req.target
    agent_name = req.agentName

    # Pick the right template based on the task description.
    if any(k in desc for k in ("jwt", "token", "bearer")):
        tool = _build_jwt_tool(target, agent_name)
    elif any(k in desc for k in ("graphql", "introspection")):
        tool = _build_graphql_tool(target, agent_name)
    elif any(k in desc for k in ("redirect", "open redirect")):
        tool = _build_redirect_tool(target, agent_name)
    elif any(k in desc for k in ("header", "csp", "hsts")):
        tool = _build_header_tool(target, agent_name)
    else:
        tool = _build_generic_probe(target, agent_name, req.taskDescription)

    return BuildToolResponse(tool=tool)


def _build_jwt_tool(target: str, agent_name: str) -> BuiltTool:
    return BuiltTool(
        name="jwt_probe",
        language="python3",
        rationale="Detect JWT algorithm confusion, none-alg, and weak-secret vulnerabilities",
        code=f"""#!/usr/bin/env python3
import sys, json, base64, urllib.request, urllib.error
target = "{target}"
def _b64pad(s): return s + '=' * (-len(s) % 4)
def emit(f): print(json.dumps(f), flush=True)
try:
    req = urllib.request.Request(target)
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read().decode('utf-8', errors='replace')
        headers = dict(r.headers)
except Exception:
    sys.exit(0)
tokens = []
for h, v in headers.items():
    for part in v.split():
        if part.startswith('eyJ') and part.count('.') == 2:
            tokens.append(('header:' + h, part))
for tok in body.split():
    if tok.startswith('eyJ') and tok.count('.') == 2:
        tokens.append(('body', tok))
for src, tok in tokens[:3]:
    parts = tok.split('.')
    try: hdr = json.loads(base64.b64decode(_b64pad(parts[0])).decode())
    except: hdr = {{}}
    alg = hdr.get('alg', 'unknown')
    if alg.lower() in ('none', 'null'):
        emit({{"id":"jwt-none","category":"access_control","severity":"high",
               "title":"JWT none-algorithm","description":"Signature bypass possible.",
               "evidence":f"alg={{alg}} source={{src}}","recommendation":"Reject alg=none tokens."}})
    elif alg in ('HS256','HS384','HS512'):
        emit({{"id":"jwt-symmetric","category":"access_control","severity":"medium",
               "title":f"JWT symmetric algorithm ({{alg}})",
               "description":"Symmetric JWT may be brute-forced if secret is weak.",
               "evidence":f"alg={{alg}} source={{src}}","recommendation":"Use RS256/ES256."}})
""",
    )


def _build_graphql_tool(target: str, agent_name: str) -> BuiltTool:
    return BuiltTool(
        name="graphql_probe",
        language="python3",
        rationale="Probe GraphQL introspection and batch query abuse",
        code=f"""#!/usr/bin/env python3
import sys, json, urllib.request, urllib.error
target = "{target}"
def post(url, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={{'Content-Type':'application/json'}})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode()), r.status
    except Exception as e:
        return {{}}, 0
def emit(f): print(json.dumps(f), flush=True)
for ep in [target.rstrip('/')+p for p in ['/graphql','/api/graphql','/v1/graphql','/query']]:
    data, status = post(ep, {{'query':'query{{__schema{{types{{name}}}}}}'}})
    if status == 200 and '__schema' in str(data):
        types = [t.get('name') for t in data.get('data',{{}}).get('__schema',{{}}).get('types',[])]
        emit({{"id":"graphql-introspection","category":"information_disclosure","severity":"medium",
               "title":"GraphQL introspection enabled",
               "description":f"Schema exposed at {{ep}}.",
               "evidence":f"endpoint={{ep}} types={{len(types)}}",
               "recommendation":"Disable introspection in production."}})
        break
""",
    )


def _build_redirect_tool(target: str, agent_name: str) -> BuiltTool:
    return BuiltTool(
        name="redirect_probe",
        language="python3",
        rationale="Probe for open redirect vulnerabilities",
        code=f"""#!/usr/bin/env python3
import sys, json, urllib.request, urllib.error, urllib.parse
target = "{target}"
canary = 'https://evil.example.com'
def emit(f): print(json.dumps(f), flush=True)
for param in ['?next=','?redirect=','?url=','?return=','?goto=']:
    probe = target.rstrip('/') + '/' + param + urllib.parse.quote(canary)
    req = urllib.request.Request(probe)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            loc = r.headers.get('Location','')
    except urllib.error.HTTPError as e:
        loc = e.headers.get('Location','')
    except Exception:
        continue
    if 'evil.example.com' in loc:
        emit({{"id":f"redirect-{{param[:10]}}","category":"cors_redirect","severity":"medium",
               "title":"Open redirect","description":f"Parameter {{param}} accepts arbitrary redirect.",
               "evidence":f"probe={{probe}} location={{loc}}",
               "recommendation":"Validate redirect destinations against allowlist."}})
""",
    )


def _build_header_tool(target: str, agent_name: str) -> BuiltTool:
    return BuiltTool(
        name="header_probe",
        language="python3",
        rationale="Check for missing or weak security headers",
        code=f"""#!/usr/bin/env python3
import sys, json, urllib.request
target = "{target}"
def emit(f): print(json.dumps(f), flush=True)
try:
    with urllib.request.urlopen(urllib.request.Request(target), timeout=10) as r:
        headers = {{k.lower(): v for k,v in r.headers.items()}}
except Exception:
    sys.exit(0)
checks = [
    ('content-security-policy','missing-csp','medium','Missing CSP header','No Content-Security-Policy.','Add a strict CSP.'),
    ('strict-transport-security','missing-hsts','medium','Missing HSTS header','No HSTS; downgrade attacks possible.','Add HSTS with max-age>=31536000.'),
    ('x-frame-options','missing-xfo','low','Missing X-Frame-Options','Clickjacking possible.','Set X-Frame-Options: DENY.'),
    ('x-content-type-options','missing-xcto','low','Missing X-Content-Type-Options','MIME sniffing possible.','Set nosniff.'),
]
for hdr, fid, sev, title, desc, rec in checks:
    if hdr not in headers:
        emit({{"id":fid,"category":"headers","severity":sev,"title":title,
               "description":desc,"evidence":f"header '{{hdr}}' absent","recommendation":rec}})
""",
    )


def _build_generic_probe(target: str, agent_name: str, description: str) -> BuiltTool:
    """Fallback: generate a simple connectivity + header check."""
    return BuiltTool(
        name="generic_probe",
        language="python3",
        rationale=f"Generic probe for: {description}",
        code=f"""#!/usr/bin/env python3
import sys, json, urllib.request
target = "{target}"
def emit(f): print(json.dumps(f), flush=True)
try:
    with urllib.request.urlopen(urllib.request.Request(target), timeout=10) as r:
        headers = {{k.lower(): v for k,v in r.headers.items()}}
        server = headers.get('server','unknown')
        powered = headers.get('x-powered-by','')
        emit({{"id":"generic-info","category":"reconnaissance","severity":"info",
               "title":"Server technology fingerprint",
               "description":f"Server header reveals technology stack.",
               "evidence":f"server={{server}} x-powered-by={{powered}}",
               "recommendation":"Remove or genericise Server and X-Powered-By headers."}})
except Exception as e:
    emit({{"id":"probe-error","category":"reconnaissance","severity":"info",
           "title":"Probe connectivity issue",
           "description":str(e),"evidence":target,"recommendation":"Verify target is reachable."}})
""",
    )

# ---------------------------------------------------------------------------
# Request / Response models for spawn / learn endpoints
# ---------------------------------------------------------------------------

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
