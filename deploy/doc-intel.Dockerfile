# Document intelligence engine image (Round 16).
# Core engine (cv2 forensics, metadata, checksums, fingerprints) + PaddleOCR
# backend. Docling and the ollama VLM are reached over HTTP / lazy import.
FROM python:3.12-slim

# OpenCV runtime deps (headless build still needs libGL on some base images).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/doc-verification
COPY services/python/doc-verification/requirements.txt services/python/doc-verification/requirements.lock ./
# Reproducible builds: install the lock (pip-compile output), not the floors.
RUN pip install --no-cache-dir -r requirements.lock

# Heavy OCR backend (Round 16 rollout item 1). PaddlePaddle CPU wheel;
# for CUDA use the paddlepaddle-gpu wheel matching your driver.
RUN pip install --no-cache-dir paddlepaddle paddleocr

# Optional PDF layout backend (Round 16 rollout item 3). First use
# downloads models from HuggingFace — in network-restricted deployments
# the adapter reports status="unavailable" honestly.
# RUN pip install --no-cache-dir docling

COPY services/python/doc-verification/ .

ENV PYTHONUNBUFFERED=1
EXPOSE 8090
CMD ["python", "-m", "uvicorn", "doc_intelligence:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8090"]
