FROM python:3.12-slim

# Install system dependencies required by Playwright's Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Install Playwright Chromium browser and its OS-level dependencies.
# --with-deps installs the necessary system libraries (libnss3, etc.) so the
# browser runs inside the slim Python image without a full desktop environment.
RUN playwright install chromium --with-deps

COPY app /app/app

EXPOSE 8096

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8096"]
