# account-takeover-detector — login-pattern anomaly detection (takeover,
# session hijacking, impossible travel, credential stuffing, device trust)
# with hybrid ONNX + rule scoring. PostgreSQL-only (asyncpg); Keycloak
# bearer auth with role + tenant binding.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8092

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY main.py /app/

# The ONNX artifact is injected at runtime (volume or image layer) at
# ATO_ARTIFACT_DIR; without it the service honestly runs rule_fallback.
RUN groupadd --system app && useradd --system --gid app app
USER app:app

EXPOSE 8092
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8092')+'/health')" || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8092"]
