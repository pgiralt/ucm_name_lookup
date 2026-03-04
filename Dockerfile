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
# ---------------------------------------------------------------------------

# ---- Stage 1: Build dependencies ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Install dependencies into a virtual environment so we can copy them cleanly.
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---- Stage 2: Runtime image ----
FROM python:3.12-slim

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

# Copy application code.
COPY main.py .

# Copy the sample phone directory.  In production, mount your own CSV
# over this file via a Docker volume or bind mount.
COPY phone_directory.csv .

# Switch to non-root user.
USER appuser

# Expose the default HTTP port.  Override with GUNICORN_CMD_ARGS for HTTPS.
EXPOSE 80

# Health-check: hit the /health endpoint every 30 seconds.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:80/health')" || exit 1

# Start Gunicorn with gthread workers bound to port 80.
# gthread prevents bare TCP connections (e.g. network probes) from
# tying up an entire worker process – only one thread is blocked.
# The default 4 workers × 4 threads = 16 concurrent connections.
# Adjust workers × threads to match the UCM service parameter
# "External Call Control Maximum Connection Count to PDP" (max 20).
# Override any of these at runtime via the GUNICORN_CMD_ARGS env var.
CMD ["gunicorn", \
     "--workers=4", \
     "--threads=4", \
     "--worker-class=gthread", \
     "--bind=0.0.0.0:80", \
     "--worker-tmp-dir=/dev/shm", \
     "--timeout=30", \
     "--access-logfile=-", \
     "--error-logfile=-", \
     "main:app"]
