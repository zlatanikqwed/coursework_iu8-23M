FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
COPY pyproject.toml .
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir \
        fastapi>=0.110.0 \
        uvicorn[standard]>=0.29.0 && \
    pip install --no-cache-dir --only-binary=:all: -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir .

FROM python:3.11-slim AS runtime

LABEL maintainer="llm-pentest"
LABEL description="LLM Pentest Tool - автоматизированный пентест LLM"
LABEL version="0.1.0"

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY src/ ./src/
COPY config.yaml .
COPY payloads/ ./payloads/

RUN mkdir -p reports data && \
    useradd --no-create-home --shell /bin/false appuser && \
    chown -R appuser:appuser /app

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV LITELLM_LOCAL_MODEL_COST_MAP=True

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "llm_pentest.api:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--log-level", "info"]