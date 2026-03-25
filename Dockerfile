# ---- Build stage ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---- Runtime stage (distroless-style slim) ----
FROM python:3.12-slim AS runtime

# Security: non-root user
RUN groupadd --gid 1001 auditor \
    && useradd --uid 1001 --gid auditor --shell /bin/sh --create-home auditor

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY src/ ./src/
COPY pyproject.toml .

# Remove write permissions on app files
RUN chown -R auditor:auditor /app \
    && chmod -R 555 /app/src

USER auditor

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

EXPOSE 8000

# No shell in CMD for reduced attack surface
CMD ["python", "-m", "uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
