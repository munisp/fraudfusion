FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt requirements.lock .
# Reproducible builds: install the lock (pip-compile output), not the floors.
RUN pip install --no-cache-dir -r requirements.lock
COPY app ./app

ENV PORT=8400
EXPOSE 8400
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
