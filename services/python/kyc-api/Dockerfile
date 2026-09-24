# kyc-api — KYC/KYB verification backend (FastAPI, :8086).
# Implements /api/v1/kyc/*, /api/v1/biometric/*, /api/v1/document/*,
# /api/v1/screening/*, /api/v1/credit-bureau/*, /api/v1/risk/* consumed by
# frontend/kyc-frontend.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8086 \
    KYC_DB_PATH=/app/data/kyc.db \
    WATCHLIST_PATH=/app/data/watchlist.json

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app /app/app
COPY data/watchlist.json /app/data/watchlist.json

RUN groupadd --system app && useradd --system --gid app app \
    && mkdir -p /app/data && chown -R app:app /app
USER app:app

EXPOSE 8086
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8086')+'/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8086"]
