# backoffice-api — operator console backend (FastAPI, :8087).
# Implements /api/v1/backoffice/* + /api/v1/auth/* consumed by
# implementations/backoffice-ui. Fail-closed Keycloak JWKS auth, tenant-scoped,
# every mutation written to the hash-chained backoffice_audit_ledger.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8087 \
    BACKOFFICE_DB=/app/data/backoffice.db

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app /app/app

RUN groupadd --system app && useradd --system --gid app app \
    && mkdir -p /app/data && chown -R app:app /app
USER app:app

EXPOSE 8087
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8087')+'/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8087"]
