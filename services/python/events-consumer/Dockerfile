# events-consumer — consumes the fraudfusion-events topic into Postgres
# events_archive + events_aggregates_weekly. Source is dependency-injected:
# KafkaSource (kafka-python) or FileTailSource (lakehouse jsonl), selected by
# EVENTS_SOURCE=kafka|filetail|auto and reported honestly in /health (:8090).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HEALTH_PORT=8090 \
    EVENTS_DB=/app/data/events.db

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY consumer.py /app/consumer.py

RUN groupadd --system app && useradd --system --gid app app \
    && mkdir -p /app/data && chown -R app:app /app
USER app:app

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://localhost:'+os.environ.get('HEALTH_PORT','8090')+'/health')" || exit 1

CMD ["python", "consumer.py"]
