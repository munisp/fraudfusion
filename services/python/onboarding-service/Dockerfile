# onboarding-service — tenant/developer onboarding backend (FastAPI, :8085).
# Implements /api/v1/onboarding/* consumed by ml-onboarding-portal, plus the
# staff dual-control approval workflow under /api/v1/onboarding/admin/*.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8085 \
    ONBOARDING_DB_PATH=/app/data/onboarding.db

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app /app/app

RUN groupadd --system app && useradd --system --gid app app \
    && mkdir -p /app/data && chown -R app:app /app
USER app:app

EXPOSE 8085
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8085')+'/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8085"]
