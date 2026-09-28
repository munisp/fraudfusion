# webhook-service — tenant webhook endpoint management + signed delivery
# pipeline (FastAPI, :8088). Signing scheme: X-FraudFusion-Signature
# t=<unix>,v1=<hex hmac-sha256> over "<t>.<body>" (see app/signing.py).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8088 \
    WEBHOOK_DB_PATH=/app/data/webhooks.db

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app /app/app

RUN groupadd --system app && useradd --system --gid app app \
    && mkdir -p /app/data && chown -R app:app /app
USER app:app

EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8088')+'/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088"]
