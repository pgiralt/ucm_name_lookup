# ---------------------------------------------------------------------------
# UCM Name Lookup CURRI Service – Docker Image
# ---------------------------------------------------------------------------
# Multi-stage build using a slim Python base image.  Gunicorn serves the
# Flask application in production mode.
#
# Build:
#   docker build -t ucm-name-lookup .
#
# Run (HTTP):
#   docker run -p 80:80 \
#       -v /path/to/phone_directory.csv:/app/phone_directory.csv:ro \
#       ucm-name-lookup
#
# Run (HTTPS – mount your TLS certificate and key):
#   docker run -p 443:443 \
#       -v /path/to/phone_directory.csv:/app/phone_directory.csv:ro \
#       -v /path/to/server.crt:/app/certs/server.crt:ro \
#       -v /path/to/server.key:/app/certs/server.key:ro \
#       -e GUNICORN_CMD_ARGS="--certfile=/app/certs/server.crt --keyfile=/app/certs/server.key --bind=0.0.0.0:443" \
#       ucm-name-lookup
#
# Run (HTTPS + mTLS – also mount the UCM CA certificate):
#   docker run -p 443:443 \
#       -v /path/to/phone_directory.csv:/app/phone_directory.csv:ro \
#       -v /path/to/server.crt:/app/certs/server.crt:ro \
#       -v /path/to/server.key:/app/certs/server.key:ro \
#       -v /path/to/CallManager.pem:/app/certs/ca.pem:ro \
#       -e GUNICORN_CMD_ARGS="--certfile=/app/certs/server.crt --keyfile=/app/certs/server.key --ca-certs=/app/certs/ca.pem --cert-reqs=2 --bind=0.0.0.0:443" \
#       ucm-name-lookup
#
# Run (with custom config – define clusters, IP allow-lists, etc.):
#   docker run -p 80:80 \
#       -v /path/to/config.yaml:/app/config.yaml:ro \
#       -v /path/to/phone_directory.csv:/app/phone_directory.csv:ro \
#       ucm-name-lookup
# ---------------------------------------------------------------------------

# ---- Stage 1: Build dependencies ----
FROM python:3.12-slim@sha256:ccc7089399c8bb65dd1fb3ed6d55efa538a3f5e7fca3f5988ac3b5b87e593bf0 AS builder

WORKDIR /build

# Install dependencies into a virtual environment so we can copy them cleanly.
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt

# ---- Stage 2: Runtime image ----
FROM python:3.12-slim@sha256:ccc7089399c8bb65dd1fb3ed6d55efa538a3f5e7fca3f5988ac3b5b87e593bf0

# Prevent Python from writing .pyc files and enable unbuffered output
# so that log messages appear immediately in `docker logs`.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy the virtual environment from the builder stage.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create a non-root user to run the application.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --no-create-home appuser

WORKDIR /app

# Copy application code, Gunicorn config, and default configuration.
COPY main.py gunicorn.conf.py healthcheck.py ./
COPY config.yaml.example config.yaml

# Copy the sample phone directory. In production, mount your own CSV
# and config.yaml over these files via Docker volumes or bind mounts.
COPY phone_directory.csv .

# Create log directory (writable by appuser for rotating log files).
RUN mkdir -p /app/logs && chown appuser:appuser /app/logs

# Switch to non-root user.
USER appuser

# Expose HTTP and HTTPS ports. gunicorn.conf.py auto-selects the port
# based on whether TLS certificates are present (80 = HTTP, 443 = HTTPS).
EXPOSE 80 443

# Health-check: auto-detects HTTP vs HTTPS from config.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python healthcheck.py || exit 1

# Start Gunicorn. All settings (workers, bind, TLS) are in gunicorn.conf.py
# which is auto-loaded from the working directory. TLS and mTLS are enabled
# automatically when certificate files are present.
#
# gunicorn.conf.py defaults: 4 workers × 4 threads = 16 concurrent connections.
# Adjust workers × threads to match the UCM service parameter
# "External Call Control Maximum Connection Count to PDP" (max 20).
# Override any setting at runtime via the GUNICORN_CMD_ARGS env var.
CMD ["gunicorn", "main:app"]
