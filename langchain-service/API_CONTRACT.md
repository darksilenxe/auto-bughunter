# LangChain Service — API Contract

Base URL (default): `https://langchain-service:8099`

Every request (except `GET /health`) must include:
```
Authorization: ******
```

---

## GET /health

Response:

```json
{
  "status": "ok",
  "llm_configured": true
}
```

`llm_configured` is `true` when `AI_API_BASE` is set in the container environment.

---

## POST /v1/rag-retrieve

BM25 keyword retrieval over a set of security-knowledge documents.  When
`use_llm` is `true` and an LLM provider is configured, retrieved passages are
fed into a RetrievalQA chain that synthesises a short answer.

Request:

```json
{
  "query": "SQL injection UNION-based extraction",
  "documents": [
    {
      "id": "sqli-001",
      "title": "SQL Injection Techniques",
      "content": "UNION-based extraction allows...",
      "topic": "injection",
      "technique": "sqli",
      "url": "https://example.com/sqli"
    }
  ],
  "limit": 5,
  "use_llm": false
}
```

`documents` may be omitted; when empty the service falls back to the
on-disk corpus at `KNOWLEDGE_CORPUS_PATH` (default `/app/data/corpus.json`).

Response:

```json
{
  "query": "SQL injection UNION-based extraction",
  "results": [
    {
      "id": "sqli-001",
      "title": "SQL Injection Techniques",
      "content": "UNION-based extraction allows...",
      "score": 1.0,
      "url": "https://example.com/sqli"
    }
  ],
  "answer": ""
}
```

`answer` is populated only when `use_llm` is `true` and a provider is configured.

---

## POST /v1/tool-chain

LangChain structured-output pipeline.  Given a pentest task and a catalogue of
available tools, the LLM produces a prioritised, ordered plan of tool calls.
The Go backend can execute the planned actions directly.

Request:

```json
{
  "task": "Enumerate all API endpoints and check for IDOR on /api/v1/users/{id}",
  "tools": [
    {"name": "ffuf", "description": "Fuzz HTTP endpoints with a wordlist"},
    {"name": "httpx", "description": "HTTP probe and fingerprinter"},
    {"name": "nuclei", "description": "Template-based vulnerability scanner"}
  ],
  "context": "Target is a REST API with JWT authentication",
  "max_steps": 5
}
```

Response:

```json
{
  "task": "Enumerate all API endpoints...",
  "planned_actions": [
    {
      "tool": "ffuf",
      "reasoning": "Discover hidden API routes before probing for IDOR",
      "parameters": {"wordlist": "api-endpoints.txt", "target": "/api/v1/FUZZ"}
    },
    {
      "tool": "nuclei",
      "reasoning": "Run IDOR-specific templates against discovered routes",
      "parameters": {"templates": "idor", "target": "https://target/api/v1/users"}
    }
  ],
  "summary": "Enumerate routes with ffuf then verify IDOR with nuclei.",
  "error": ""
}
```

`error` is non-empty when the LLM is not configured or an internal error occurs.

---

## POST /v1/pentest-graph

LangGraph stateful multi-step reasoning graph.  The graph iterates over
security hypotheses (configurable iterations) and returns a prioritised
recommendation list.  Intended to augment the `pentest_loop` agent.

Request:

```json
{
  "target": "https://app.example.com",
  "findings": [
    {
      "category": "xss",
      "severity": "medium",
      "title": "Reflected XSS in search parameter"
    }
  ],
  "context": "E-commerce application, authenticated user session available",
  "max_iterations": 3
}
```

Response:

```json
{
  "target": "https://app.example.com",
  "reasoning_steps": [
    "[Iteration 1] The existing XSS finding suggests insufficient output encoding...",
    "[Iteration 2] Given weak encoding, stored XSS in user-profile fields is likely...",
    "[Iteration 3] Check for CSP bypass opportunities given the XSS surface..."
  ],
  "recommendations": [
    "Test all user-controlled fields for stored XSS using blind payloads",
    "Audit Content-Security-Policy header for unsafe-inline directives",
    "Verify session cookie flags (HttpOnly, Secure) to assess XSS impact"
  ],
  "error": ""
}
```

`error` is non-empty when the LLM is not configured or an internal error occurs.
