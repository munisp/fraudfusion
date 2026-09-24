# kg-qa — analyst KG question-answering service (FastAPI, :8300).
# Endpoints: /v1/kgqa/ask, /v1/kgqa/health, /v1/kg/refresh.
# Serves from FalkorDB (FALKORDB_URL) or Neo4j (NEO4J_URI) when reachable,
# else in-memory from the parquet KG store at KG_DIR (fallback mode).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8300 \
    KG_DIR=/data/kg \
    LAKEHOUSE_DIR=/data/lakehouse \
    PYTHONPATH=/app

WORKDIR /app
COPY services/python/kg-qa/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
# The service imports intelligence.kg_pipeline for /v1/kg/refresh.
COPY intelligence /app/intelligence
COPY services/python/kg-qa/app /app/app

RUN groupadd --system app && useradd --system --gid app app \
    && mkdir -p /data && chown -R app:app /data
USER app:app

EXPOSE 8300
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8300')+'/v1/kgqa/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8300"]
