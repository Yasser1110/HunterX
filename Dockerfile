FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HUNTERX_BASE=/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl ca-certificates git openssl procps dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY hunterx ./hunterx
COPY pyproject.toml README.md ./
RUN pip install .

COPY templates ./templates
COPY wordlists ./wordlists

VOLUME ["/app/config", "/app/data", "/app/reports", "/app/wordlists", "/app/log"]

ENTRYPOINT ["hunterx"]