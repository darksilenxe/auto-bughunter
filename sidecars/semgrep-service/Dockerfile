FROM python:3.12-slim

# Install semgrep and service dependencies.
# semgrep is installed via pip so its version tracks the official release cadence.
RUN pip install --no-cache-dir semgrep==1.90.0

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

EXPOSE 8095

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8095"]
