# intel-service — National Fraud Intelligence API (FastAPI, :8500).
# Serves ml/artifacts/national_intelligence/v1 (hierarchical Bayesian
# posteriors). Fail-closed: /health is 503 when the artifact is absent.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8500 \
    INTEL_ARTIFACT_DIR=/artifacts/national_intelligence/v1 \
    INTEL_SUPPRESS_MIN_N=30

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app /app/app

RUN groupadd --system app && useradd --system --gid app app \
    && mkdir -p /artifacts && chown -R app:app /artifacts
USER app:app

EXPOSE 8500
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8500')+'/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8500"]
