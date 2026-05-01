FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

# Run as non-root user for least privilege.
RUN groupadd --system --gid 1001 appuser \
 && useradd  --system --uid 1001 --gid appuser --no-create-home --shell /sbin/nologin appuser \
 && chown -R appuser:appuser /app
USER appuser

EXPOSE 8090

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
