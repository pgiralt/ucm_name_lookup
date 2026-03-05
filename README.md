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
| `TLS_CA_FILE` | *(none)* | Path to CA certificate for mutual TLS client verification (dev server) |
| `ALLOWED_IPS` | *(none)* | Comma-separated IP addresses/CIDRs allowed to reach `/curri` |
| `TLS_ALLOWED_SUBJECTS` | *(none)* | Comma-separated CN/SAN values expected in client certificates |
| `LOG_LEVEL` | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR |

## Authentication & Security

The CURRI protocol relies on **mutual TLS (mTLS)** for authentication — this is the only authentication mechanism defined by the Cisco External Call Control interface. When HTTPS is configured, UCM and the route server mutually authenticate by exchanging and verifying certificates during the TLS handshake.

### Mutual TLS (mTLS)

mTLS ensures that **only UCM servers presenting a trusted certificate** can connect to the `/curri` endpoint. Setup requires certificate exchange between UCM and this service:

1. **Export UCM's certificate** — In *Cisco Unified OS Administration > Security > Certificate Management*, download the `CallManager.pem` certificate. This is the CA certificate the route server will use to verify UCM.
2. **Import this service's certificate into UCM** — Upload the route server's TLS certificate into UCM's `CallManager-trust` store. Repeat for every UCM node in the cluster.
3. **Configure this service** with the UCM CA certificate:

**Development server:**
```bash
export TLS_CERT_FILE=server.crt
export TLS_KEY_FILE=server.key
export TLS_CA_FILE=CallManager.pem
python main.py
```

**Production (Gunicorn):**
```bash
gunicorn -w 4 --threads 4 --worker-class gthread \
    -b 0.0.0.0:443 \
    --certfile=server.crt \
    --keyfile=server.key \
    --ca-certs=CallManager.pem \
    --cert-reqs=2 \
    main:app
```

The `--cert-reqs=2` flag tells Gunicorn to **require** a valid client certificate (equivalent to `ssl.CERT_REQUIRED`). Connections without a valid certificate signed by the specified CA are rejected at the TLS layer before reaching the application.

> **Note:** If your UCM cluster has multiple nodes with different certificates, you can concatenate all `CallManager.pem` files into a single CA bundle file.

**Docker:**
```bash
docker run -p 443:443 \
    -v /path/to/phone_directory.csv:/app/phone_directory.csv:ro \
    -v /path/to/server.crt:/app/certs/server.crt:ro \
    -v /path/to/server.key:/app/certs/server.key:ro \
    -v /path/to/CallManager.pem:/app/certs/ca.pem:ro \
    -e GUNICORN_CMD_ARGS="--certfile=/app/certs/server.crt --keyfile=/app/certs/server.key --ca-certs=/app/certs/ca.pem --cert-reqs=2 --bind=0.0.0.0:443" \
    ucm-name-lookup
```

**Docker Compose (mTLS):**
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
      - ./certs/CallManager.pem:/app/certs/ca.pem:ro
    environment:
      - LOG_LEVEL=INFO
      - GUNICORN_CMD_ARGS=--certfile=/app/certs/server.crt --keyfile=/app/certs/server.key --ca-certs=/app/certs/ca.pem --cert-reqs=2 --bind=0.0.0.0:443
    restart: unless-stopped
```

### Certificate Subject Validation (CN/SAN)

Verifying that a client certificate is signed by a trusted CA is **not sufficient on its own** — many unrelated hosts may hold certificates signed by the same well-known CA. To ensure that only your specific UCM servers are accepted, set `TLS_ALLOWED_SUBJECTS` to a comma-separated list of expected Common Name (CN) and/or Subject Alternative Name (SAN) values.

When configured, the application extracts the CN and SAN fields from the connecting client's certificate and checks that **at least one** matches an entry in the allow-list. Requests from clients whose certificate does not match are rejected with HTTP 403.

- Comparison is **case-insensitive**
- Both DNS SANs and IP Address SANs are checked
- The `/health` endpoint is **exempt**
- If the peer certificate is not accessible (e.g. TLS terminated by a reverse proxy without forwarding cert info), the request is **denied** (fail-closed)

```bash
# Allow the UCM publisher and two subscribers
export TLS_ALLOWED_SUBJECTS="cucm-pub.example.com,cucm-sub1.example.com,cucm-sub2.example.com"
```

**Docker Compose (mTLS + subject validation):**
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
      - ./certs/CallManager.pem:/app/certs/ca.pem:ro
    environment:
      - LOG_LEVEL=INFO
      - TLS_ALLOWED_SUBJECTS=cucm-pub.example.com,cucm-sub1.example.com,cucm-sub2.example.com
      - GUNICORN_CMD_ARGS=--certfile=/app/certs/server.crt --keyfile=/app/certs/server.key --ca-certs=/app/certs/ca.pem --cert-reqs=2 --bind=0.0.0.0:443
    restart: unless-stopped
```

> **Tip:** To find the CN/SAN values of your UCM certificates, run:
> ```bash
> openssl x509 -text -noout -in CallManager.pem | grep -E 'Subject:|DNS:|IP Address:'
> ```

### IP Allow-List (Defense-in-Depth)

As an additional layer of security, you can restrict which IP addresses are permitted to reach the `/curri` endpoint using the `ALLOWED_IPS` environment variable. This is especially useful when mTLS is not feasible or as a supplementary control.

- Accepts individual IPs and CIDR notation
- Multiple entries are comma-separated
- The `/health` endpoint is **exempt** so load-balancer and Docker health checks continue to work
- When `ALLOWED_IPS` is not set, all IPs are allowed (no filtering)

```bash
# Allow two specific UCM nodes and a /24 subnet
export ALLOWED_IPS="10.1.1.10,10.1.1.11,10.1.2.0/24"
python main.py
```

**Docker Compose example:**
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
      - ALLOWED_IPS=10.1.1.10,10.1.1.11,10.1.2.0/24
    restart: unless-stopped
```

> **Recommendation:** For maximum security, use **all three** controls together:
> 1. **mTLS** — verifies the certificate chain (CA trust)
> 2. **`TLS_ALLOWED_SUBJECTS`** — verifies the certificate identity (CN/SAN pinning)
> 3. **`ALLOWED_IPS`** — restricts by network address (defense-in-depth)

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

**Matching behavior:**
- **`exact`** (default when column is absent) — the incoming calling number must match the full normalized phone number.
- **`prefix`** — any incoming number whose digits *start with* the normalized prefix will match.
- Exact matches are always evaluated first. Prefix matching is only attempted when no exact match is found, and the **longest** matching prefix wins.

The `match_type` column is optional. If it is omitted entirely, every row is treated as an exact match, preserving backward compatibility with existing CSV files.

**Important**: Phone numbers are normalized by stripping formatting characters (`-`, `()`, `.`, spaces) while preserving a leading `+` for E.164 compatibility. Ensure your CSV numbers include the country code if UCM sends numbers in E.164 format (e.g., `+12125551212`).

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
