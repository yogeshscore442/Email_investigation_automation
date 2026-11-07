# ==============================================================================
# PhishScope SOC - Backend Production Dockerfile
# Hardened, unprivileged container running Gunicorn WSGI server.
# ==============================================================================
FROM python:3.10-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies into virtualenv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir gunicorn && \
    pip install --no-cache-dir -r requirements.txt

# Final runtime image
FROM python:3.10-slim AS runtime

WORKDIR /app

# Install minimal runtime libraries (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user
RUN groupadd -g 1000 socgroup && \
    useradd -u 1000 -g socgroup -s /bin/bash -m socuser

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source code
COPY --chown=socuser:socgroup . .

# Create persistent storage directories with correct ownership
RUN mkdir -p /app/data/storage /app/data/samples /app/data/backups && \
    chown -R socuser:socgroup /app/data

USER socuser

EXPOSE 5000

ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:5000/api/health || exit 1

CMD ["gunicorn", "--workers=4", "--bind=0.0.0.0:5000", "--timeout=60", "--access-logfile=-", "--error-logfile=-", "run:app"]

