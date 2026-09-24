# land-verification-service — landlord/property document verification
# (Keycloak bearer auth, SQLite/Postgres persistence, PDF reports).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8002 \
    LAND_VERIFY_REPORT_DIR=/app/reports_out

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY api /app/api
COPY models /app/models
COPY reports /app/reports

RUN groupadd --system app && useradd --system --gid app app \
    && mkdir -p /app/data /app/reports_out \
    && chown -R app:app /app
USER app:app

EXPOSE 8002
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8002')+'/health')" || exit 1

CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8002"]
