# Nuclei HTTP wrapper service
# Exposes nuclei via HTTP endpoints to eliminate Docker socket requirement

FROM projectdiscovery/nuclei:v3.8.0 AS nuclei-binary

FROM python:3.11-slim

# Copy nuclei binary from official image
COPY --from=nuclei-binary /usr/local/bin/nuclei /usr/local/bin/nuclei

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy service code
COPY app/ ./app/

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8093/health', timeout=2).raise_for_status()"

# Run service
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8093"]
