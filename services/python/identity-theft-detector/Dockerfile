# identity-theft-detector — FastAPI fraud detector (Keycloak fail-closed auth, Postgres persistence).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8089

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app/

RUN groupadd --system app && useradd --system --gid app app \
    && chown -R app:app /app
USER app:app

EXPOSE 8089
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('PORT','8089')+'/health')" || exit 1

CMD ["python", "/app/main.py"]
