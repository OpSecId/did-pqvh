# did-pqvh HTTP API (FastAPI + uvicorn)
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Optional: WebVH-style alsoKnownAs on GET /resolve (see README).
# ENV DID_PQVH_WEBVH_HOSTNAME=wallets.example.com
# Optional: expose /keys CRUD in OpenAPI (default off).
# ENV KEY_MANAGEMENT=true
# Optional: Askar SQLite per SCID (see README); mount a volume on DID_PQVH_WALLET_DIR.
# ENV DID_PQVH_WALLET_DIR=/wallets
# ENV DID_PQVH_ASKAR_PASS_KEY=<raw key from Store.generate_raw_key()>

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

EXPOSE 8000

# Bind all interfaces for container networking; disable dev reload.
CMD ["uvicorn", "did_pqvh.api:app", "--host", "0.0.0.0", "--port", "8000"]
