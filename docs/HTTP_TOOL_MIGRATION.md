# HTTP Tool Service Migration Guide

This guide explains how to migrate CLI tool sidecars from Docker socket exec mode to HTTP wrapper services.

## Overview

The HTTP wrapper pattern eliminates the Docker socket requirement by exposing CLI tools via HTTP endpoints instead of using `docker compose exec`. This provides better security, scalability, and orchestration flexibility.

## Benefits

- **No Docker socket access required** - Eliminates root-equivalent host access
- **Better security isolation** - Each service runs in its own container with clear boundaries
- **Orchestration agnostic** - Works with Kubernetes, Docker Swarm, or any container platform
- **Easier to scale** - HTTP services can be scaled horizontally
- **Simpler testing** - Services can be tested independently via HTTP
- **Authentication support** - Built-in token-based auth via `SIDECAR_AUTH_TOKEN`

## Architecture

### Before (Exec Mode)
```
Backend Container
  ├─ Docker Socket Mount (/var/run/docker.sock)
  ├─ Shim Scripts (/usr/local/bin/nuclei)
  └─ exec.Command → docker compose exec -T nuclei nuclei ...
       └─ Nuclei Container
```

### After (HTTP Mode)
```
Backend Container
  └─ HTTP Client (toolclient.NucleiClient)
       └─ HTTP POST → http://nuclei-service:8093/v1/execute
            └─ Nuclei Service Container
                 └─ subprocess.run(['nuclei', ...])
```

## Creating a New HTTP Wrapper Service

Follow these steps to wrap a CLI tool:

### 1. Create Service Directory Structure

```bash
sidecars/<tool>-service/
├── Dockerfile
├── requirements.txt
└── app/
    └── main.py
```

### 2. Dockerfile Template

```dockerfile
# Use official tool image as source
FROM <official-tool-image>:<version> AS tool-binary

# Build HTTP wrapper on Python slim
FROM python:3.11-slim

# Copy tool binary from official image
COPY --from=tool-binary /usr/local/bin/<tool> /usr/local/bin/<tool>

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy service code
COPY app/ ./app/

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:<port>/health', timeout=2).raise_for_status()"

# Run service
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "<port>"]
```

### 3. requirements.txt

```
fastapi==0.115.0
uvicorn[standard]==0.30.6
pydantic==2.9.2
```

### 4. FastAPI Service Template (app/main.py)

```python
"""
<Tool> HTTP Wrapper Service
"""
import hmac
import logging
import os
import subprocess
from typing import List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("<tool>-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
_AUTH_EXEMPT_PATHS = {"/health"}
MAX_TIMEOUT = 600  # 10 minutes

def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()

app = FastAPI(title="<Tool> HTTP Wrapper", version="1.0.0")

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
    args: List[str] = Field(default_factory=list)
    timeout: int = Field(default=300, ge=1, le=MAX_TIMEOUT)

class ExecuteResponse(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    error: Optional[str] = None

@app.get("/health")
def health() -> dict:
    try:
        result = subprocess.run(
            ["<tool>", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        version = result.stdout.strip() if result.returncode == 0 else "unknown"
        return {
            "status": "ok",
            "service": "<tool>-http-wrapper",
            "tool_version": version
        }
    except Exception as e:
        return {
            "status": "degraded",
            "service": "<tool>-http-wrapper",
            "error": str(e)
        }

@app.post("/v1/execute", response_model=ExecuteResponse)
def execute_tool(req: ExecuteRequest) -> ExecuteResponse:
    logger.info(f"Executing <tool> with args: {req.args}")

    # Basic argument validation
    for arg in req.args:
        if any(dangerous in arg for dangerous in [";", "&&", "||", "|", "`", "$("]):
            return ExecuteResponse(
                stdout="",
                stderr="",
                exit_code=1,
                timed_out=False,
                error="Invalid argument: potentially dangerous characters detected"
            )

    try:
        result = subprocess.run(
            ["<tool>"] + req.args,
            capture_output=True,
            text=True,
            timeout=req.timeout
        )

        return ExecuteResponse(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.returncode,
            timed_out=False,
            error=None
        )

    except subprocess.TimeoutExpired as e:
        return ExecuteResponse(
            stdout=e.stdout.decode() if e.stdout else "",
            stderr=e.stderr.decode() if e.stderr else "",
            exit_code=-1,
            timed_out=True,
            error=f"Execution timed out after {req.timeout} seconds"
        )

    except Exception as e:
        return ExecuteResponse(
            stdout="",
            stderr="",
            exit_code=-1,
            timed_out=False,
            error=str(e)
        )
```

### 5. Backend HTTP Client (backend/internal/toolclient/<tool>.go)

```go
package toolclient

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "time"
)

type <Tool>Client struct {
    baseURL    string
    authToken  string
    httpClient *http.Client
}

func New<Tool>Client() *<Tool>Client {
    baseURL := os.Getenv("<TOOL>_SERVICE_URL")
    if baseURL == "" {
        baseURL = "http://<tool>-service:<port>"
    }

    return &<Tool>Client{
        baseURL:   baseURL,
        authToken: os.Getenv("SIDECAR_AUTH_TOKEN"),
        httpClient: &http.Client{
            Timeout: 15 * time.Minute,
        },
    }
}

type ExecuteRequest struct {
    Args    []string `json:"args"`
    Timeout int      `json:"timeout"`
}

type ExecuteResponse struct {
    Stdout   string `json:"stdout"`
    Stderr   string `json:"stderr"`
    ExitCode int    `json:"exit_code"`
    TimedOut bool   `json:"timed_out"`
    Error    string `json:"error,omitempty"`
}

func (c *<Tool>Client) Execute(ctx context.Context, args []string, timeout int) (*ExecuteResponse, error) {
    reqBody := ExecuteRequest{
        Args:    args,
        Timeout: timeout,
    }

    jsonData, err := json.Marshal(reqBody)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/execute", bytes.NewReader(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Content-Type", "application/json")
    if c.authToken != "" {
        req.Header.Set("Authorization", "Bearer "+c.authToken)
    }

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to execute request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("service returned status %d: %s", resp.StatusCode, string(body))
    }

    var result ExecuteResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return &result, nil
}

func (c *<Tool>Client) IsAvailable(ctx context.Context) bool {
    req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
    if err != nil {
        return false
    }

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return false
    }
    defer resp.Body.Close()

    return resp.StatusCode == http.StatusOK
}
```

### 6. Update Integration Code

Modify the scanner integration to support both HTTP and exec modes:

```go
func (s *Service) run<Tool>(ctx context.Context, target string) []model.Finding {
    if useHTTPMode := os.Getenv("USE_HTTP_TOOL_SERVICES"); useHTTPMode == "true" || useHTTPMode == "1" {
        return s.run<Tool>HTTP(ctx, target)
    }
    return s.run<Tool>Exec(ctx, target)
}

func (s *Service) run<Tool>HTTP(ctx context.Context, target string) []model.Finding {
    client := toolclient.New<Tool>Client()

    if !client.IsAvailable(ctx) {
        return []model.Finding{{
            ID:             "<tool>-service-unavailable",
            Category:       "integration",
            Severity:       model.SeverityLow,
            Title:          "<Tool> HTTP service unavailable",
            Description:    "<Tool> HTTP wrapper service is not reachable.",
            Evidence:       "service_url=" + os.Getenv("<TOOL>_SERVICE_URL"),
            Recommendation: "Ensure <tool>-service container is running and healthy.",
        }}
    }

    timeoutSecs := int(s.cfg.IntegrationTimeout.Seconds())
    args := []string{/* tool-specific args */}

    result, err := client.Execute(ctx, args, timeoutSecs)
    if err != nil {
        return []model.Finding{{
            ID:             "<tool>-http-error",
            Category:       "integration",
            Severity:       model.SeverityLow,
            Title:          "<Tool> HTTP service error",
            Description:    "Failed to execute <tool> via HTTP service.",
            Evidence:       err.Error(),
            Recommendation: "Check <tool>-service logs and retry.",
        }}
    }

    // Process result.Stdout, result.Stderr, result.ExitCode
    // Return appropriate findings
}

func (s *Service) run<Tool>Exec(ctx context.Context, target string) []model.Finding {
    // Existing exec.Command implementation
}
```

### 7. Update docker-compose.yml

Add the new service:

```yaml
  <tool>-service:
    build:
      context: ./sidecars/<tool>-service
    environment:
      SIDECAR_AUTH_TOKEN: ${SIDECAR_AUTH_TOKEN:-}
      LOG_LEVEL: ${<TOOL>_SERVICE_LOG_LEVEL:-INFO}
    ports:
      - "<port>:<port>"
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "python -c 'import requests; requests.get(\"http://localhost:<port>/health\", timeout=2).raise_for_status()' || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

Add to backend dependencies:

```yaml
  backend:
    depends_on:
      <tool>-service:
        condition: service_healthy
```

### 8. Update .env.example

```bash
# HTTP wrapper service URL for <tool>
<TOOL>_SERVICE_URL=http://<tool>-service:<port>
```

## Testing

1. **Build and start services:**
   ```bash
   docker compose build <tool>-service
   docker compose up -d <tool>-service
   ```

2. **Test health endpoint:**
   ```bash
   curl http://localhost:<port>/health
   ```

3. **Test execution:**
   ```bash
   curl -X POST http://localhost:<port>/v1/execute \
     -H "Content-Type: application/json" \
     -d '{"args": ["--version"], "timeout": 30}'
   ```

4. **Enable HTTP mode:**
   ```bash
   echo "USE_HTTP_TOOL_SERVICES=true" >> .env
   docker compose restart backend
   ```

5. **Run a scan and verify the tool is called via HTTP**

## Migration Checklist

For each tool to migrate:

- [ ] Create `sidecars/<tool>-service/` directory
- [ ] Write Dockerfile with multi-stage build
- [ ] Implement FastAPI service with `/health` and `/v1/execute`
- [ ] Create Go HTTP client in `backend/internal/toolclient/`
- [ ] Update scanner integration to support both modes
- [ ] Add service to docker-compose.yml
- [ ] Add environment variables to .env.example
- [ ] Test HTTP mode with real scans
- [ ] Document any tool-specific considerations

## Priority Order

Recommended migration order based on usage and security impact:

1. **nuclei** ✅ (Complete)
2. **zap** - OWASP ZAP baseline scanner
3. **sqlmap** - SQL injection testing
4. **ffuf** - Web fuzzing
5. **gobuster** - Directory brute-forcing
6. **nikto** - Web server scanner
7. **wpscan** - WordPress scanner
8. **projectdiscovery tools** - subfinder, httpx, etc.

## Security Considerations

- Always validate input arguments to prevent command injection
- Use `subprocess.run()` with list arguments (not shell=True)
- Implement timeout limits to prevent resource exhaustion
- Use `SIDECAR_AUTH_TOKEN` for production deployments
- Consider rate limiting for public-facing deployments

## Troubleshooting

**Service won't start:**
- Check logs: `docker compose logs <tool>-service`
- Verify Dockerfile builds: `docker compose build <tool>-service`
- Check port conflicts: `docker compose ps`

**Backend can't reach service:**
- Verify service is healthy: `docker compose ps`
- Check network connectivity: `docker compose exec backend ping <tool>-service`
- Verify environment variable: `echo $<TOOL>_SERVICE_URL`

**Authentication errors:**
- Ensure `SIDECAR_AUTH_TOKEN` is set consistently across services
- Check token format (should be bearer token)

## Performance Comparison

HTTP mode vs Exec mode:

| Metric | Exec Mode | HTTP Mode |
|--------|-----------|-----------|
| Latency | ~100ms (docker exec overhead) | ~10ms (HTTP overhead) |
| Security | Root-equivalent socket access | No privileged access |
| Scalability | Single host only | Horizontal scaling |
| Orchestration | Docker Compose only | Any platform |

## Next Steps

Once all tools are migrated:

1. Set `USE_HTTP_TOOL_SERVICES=true` as default
2. Remove Docker socket mounts from docker-compose.yml
3. Remove docker-cli from backend Dockerfile
4. Remove shim scripts from backend/scripts/shims/
5. Update documentation to recommend HTTP mode
6. Archive exec mode code for reference
