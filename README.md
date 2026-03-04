# UCM Name Lookup Service

A CURRI (Cisco Unified Routing Rules Interface) server that provides phone number to display name lookup for Cisco Unified Communications Manager (UCM).

## How It Works

1. At startup, the service loads a CSV file mapping phone numbers to display names into an in-memory dictionary for fast lookups.
2. UCM sends XACML XML POST requests to the `/curri` endpoint whenever a call matches a configured External Call Control (ECC) profile.
3. The service parses the calling party number from the XACML request and looks it up in the directory.
4. The service responds with an XACML Permit/Continue response:
   - **Name found**: includes a `<modify callingname="..."/>` CIXML directive so UCM updates the caller display name on the receiving phone.
   - **Name not found**: returns a simple Continue with no modification.
   - **Calls are never rejected** — the service always returns a Permit/Continue decision.

## Prerequisites

- Python 3.10+
- pip

## Installation

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

All configuration is done via environment variables:

| Variable | Default | Description |
|---|---|---|
| `CSV_FILE_PATH` | `phone_directory.csv` | Path to the phone directory CSV file |
| `FLASK_HOST` | `0.0.0.0` | Host to bind to (dev server only) |
| `FLASK_PORT` | `5000` | Port to bind to (dev server only) |
| `TLS_CERT_FILE` | *(none)* | Path to TLS certificate (dev server HTTPS) |
| `TLS_KEY_FILE` | *(none)* | Path to TLS private key (dev server HTTPS) |
| `LOG_LEVEL` | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR |

## CSV File Format

The phone directory CSV must have a header row with at least these columns:

| Column | Required | Description |
|---|---|---|
| `phone_number` | Yes | The phone number or prefix (e.g. `+12125551212` or `+1212`) |
| `display_name` | Yes | The name to display (e.g. `Alice Johnson`) |
| `match_type` | No | `exact` (default) or `prefix` |

```csv
phone_number,display_name,match_type
+12125551001,Alice Johnson,exact
+12125551002,Bob Smith,exact
+1212,New York City,prefix
+1312,Chicago,prefix
+1415,San Francisco,prefix
```

**Matching behaviour:**
- **`exact`** (default when column is absent) — the incoming calling number must match the full normalized phone number.
- **`prefix`** — any incoming number whose digits *start with* the normalized prefix will match.
- Exact matches are always evaluated first. Prefix matching is only attempted when no exact match is found, and the **longest** matching prefix wins.

The `match_type` column is optional. If it is omitted entirely, every row is treated as an exact match, preserving backward compatibility with existing CSV files.

**Important**: Phone numbers are normalized to digits only (stripping `+`, `-`, `()`, `.`, spaces) for matching. Ensure your CSV numbers include the country code if UCM sends numbers in E.164 format (e.g., `+12125551212`).

## Running

### Development

```bash
python main.py
```

The server starts on `http://0.0.0.0:5000` by default.

### Production (Gunicorn)

The service uses `gthread` (threaded) workers so that idle or stalled TCP connections (such as network health probes) only block a single thread instead of an entire worker process. The default configuration of 4 workers × 4 threads provides 16 concurrent connections.

**HTTP:**
```bash
gunicorn -w 4 --threads 4 --worker-class gthread \
    -b 0.0.0.0:80 main:app
```

**HTTPS:**
```bash
gunicorn -w 4 --threads 4 --worker-class gthread \
    -b 0.0.0.0:443 \
    --certfile=/path/to/server.crt \
    --keyfile=/path/to/server.key \
    main:app
```

> **Tuning:** The total thread count (`workers × threads`) should be set to match the **External Call Control Maximum Connection Count to PDP** service parameter in UCM (found under **System > Service Parameters > Cisco CallManager**). This parameter controls how many simultaneous connections UCM opens toward the service and has a maximum value of 20. For example, to support the maximum of 20 connections, use `-w 5 --threads 4` or `-w 4 --threads 5`.

### Docker

**Build the image:**
```bash
docker build -t ucm-name-lookup .
```

**Run (HTTP):**
```bash
docker run -p 80:80 \
    -v /path/to/phone_directory.csv:/app/phone_directory.csv:ro \
    ucm-name-lookup
```

**Run (HTTPS):**
```bash
docker run -p 443:443 \
    -v /path/to/phone_directory.csv:/app/phone_directory.csv:ro \
    -v /path/to/server.crt:/app/certs/server.crt:ro \
    -v /path/to/server.key:/app/certs/server.key:ro \
    -e GUNICORN_CMD_ARGS="--certfile=/app/certs/server.crt --keyfile=/app/certs/server.key --bind=0.0.0.0:443" \
    ucm-name-lookup
```

The container runs Gunicorn with 4 gthread workers (4 threads each, 16 total) as a non-root user. The worker temporary directory is set to `/dev/shm` (shared memory) to prevent false worker timeouts caused by slow I/O on Docker's overlay filesystem. Override Gunicorn settings at runtime via the `GUNICORN_CMD_ARGS` environment variable. A built-in Docker `HEALTHCHECK` polls `/health` every 30 seconds.

### Docker Compose

A `docker-compose.yml` is included for convenience:

```yaml
services:
  ucm-name-lookup:
    build: .
    container_name: ucm-name-lookup
    ports:
      - "5015:80"
    volumes:
      - ./phone_directory.csv:/app/phone_directory.csv:ro
    environment:
      - LOG_LEVEL=INFO
    restart: unless-stopped
```

**Start the service:**
```bash
docker compose up -d
```

**View logs:**
```bash
docker compose logs -f
```

**Rebuild after code changes:**
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

By default the compose file maps host port **5015** to the container's port 80. To change the host port, edit the `ports` mapping (e.g., `"80:80"` to listen on port 80).

To enable HTTPS via Docker Compose, mount your TLS certificate and key and override the Gunicorn bind address:

```yaml
services:
  ucm-name-lookup:
    build: .
    container_name: ucm-name-lookup
    ports:
      - "443:443"
    volumes:
      - ./phone_directory.csv:/app/phone_directory.csv:ro
      - ./certs/server.crt:/app/certs/server.crt:ro
      - ./certs/server.key:/app/certs/server.key:ro
    environment:
      - LOG_LEVEL=INFO
      - GUNICORN_CMD_ARGS=--certfile=/app/certs/server.crt --keyfile=/app/certs/server.key --bind=0.0.0.0:443
    restart: unless-stopped
```

## UCM Configuration

1. In Cisco Unified CM Administration, navigate to **Call Routing > External Call Control Profile**.
2. Create a new profile with the **Primary Route Server URI** set to:
   ```
   http(s)://<server-ip>:<port>/curri
   ```
3. Set the **Routing Request Timer** appropriately (e.g., 2000 ms).
4. Set **Call Treatment on Failures** to continue routing normally.
5. Apply the ECC profile to the desired Directory Numbers, Translation Patterns, or Route Patterns that should trigger name lookups.

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/curri` | CURRI XACML endpoint for UCM ECC requests |
| `HEAD` | `/curri` | Keepalive probe — returns `200 OK` (used by UCM to check service availability) |
| `GET` | `/health` | Health check — returns JSON with service status and directory entry count |

## Testing with curl

```bash
# Health check
curl http://localhost:5000/health

# Simulate a CURRI request
curl -X POST http://localhost:5000/curri \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<Request xmlns="urn:oasis:names:tc:xacml:2.0:context:schema:os">
  <Subject SubjectCategory="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
    <Attribute AttributeId="urn:Cisco:uc:1.0:callingnumber" DataType="http://www.w3.org/2001/XMLSchema#string">
      <AttributeValue>+12125551001</AttributeValue>
    </Attribute>
    <Attribute AttributeId="urn:Cisco:uc:1.0:callednumber" DataType="http://www.w3.org/2001/XMLSchema#string">
      <AttributeValue>+12125559999</AttributeValue>
    </Attribute>
  </Subject>
</Request>'
```

## License

Internal use.
