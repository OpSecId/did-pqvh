# did-pqvh HTTP API (FastAPI + uvicorn)
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Optional: WebVH-style alsoKnownAs on GET /resolve (see README).
# ENV DID_PQVH_WEBVH_HOSTNAME=wallets.example.com

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

EXPOSE 8000

# Bind all interfaces for container networking; disable dev reload.
CMD ["uvicorn", "did_pqvh.api:app", "--host", "0.0.0.0", "--port", "8000"]
