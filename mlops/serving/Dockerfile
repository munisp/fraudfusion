# AML ML inference service — serves ml/artifacts/fraud_net/v1/model.onnx (+vocab.json, preprocess.npz)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8100

WORKDIR /app

COPY mlops/serving/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY mlops/serving/aml_service.py /app/aml_service.py

# Model artifacts are mounted at runtime: -v $(pwd)/ml:/app/ml:ro
# or override AML_MODEL_PATH.
EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8100/health')" || exit 1

CMD ["uvicorn", "aml_service:app", "--host", "0.0.0.0", "--port", "8100", "--workers", "4", "--loop", "uvloop", "--http", "httptools"]
