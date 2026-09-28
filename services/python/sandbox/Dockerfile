# sandbox — FraudFusion developer sandbox (FastAPI, :8091).
# Deterministic synthetic mirrors of the data-plane endpoints; no real
# verification occurs, no credentials required (any ffk_test_* key).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8091

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app /app/app

RUN groupadd --system app && useradd --system --gid app app \
    && chown -R app:app /app
USER app:app

EXPOSE 8091
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8091')+'/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091"]
