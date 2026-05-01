# ZAP HTTP wrapper service
# Exposes zap-baseline.py via HTTP endpoints to eliminate Docker socket requirement

FROM zaproxy/zap-stable:2.17.0

USER root

# Install pip and HTTP service dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /zap-service
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY app/ ./app/

# Switch back to the non-root `zap` user shipped by the upstream zaproxy
# image. We needed root only to install pip and copy app code; the runtime
# itself drops privileges. (Dockerfile last-user-is-root / DL3002.)
RUN chown -R zap:zap /zap-service
USER zap

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8094/health', timeout=5)"

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8094"]
