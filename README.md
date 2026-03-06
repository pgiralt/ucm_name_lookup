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
- OpenSSL CLI (`openssl`) — required by `setup_certs.sh` for certificate generation

## Installation

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create your local configuration from the example
cp config.yaml.example config.yaml
```

## Configuration

Non-sensitive settings are defined in a **YAML configuration file** (`config.yaml` by default). The repository ships a `config.yaml.example` template — copy it to `config.yaml` and customize for your environment. The `config.yaml` file is gitignored so local changes won't conflict with upstream updates.

```bash
cp config.yaml.example config.yaml
```

| Setting | Default | Description |
|---|---|---|
| `csv_file_path` | `phone_directory.csv` | Path to the phone directory CSV file |
| `log_level` | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR |
| `flask_host` | `0.0.0.0` | Host to bind to (dev server only) |
| `flask_port` | `5000` | Port to bind to (dev server only) |
| `tls_cert_file` | *(none)* | Path to TLS certificate (dev server HTTPS) |
| `tls_key_file` | *(none)* | Path to TLS private key (dev server HTTPS) |
| `clusters` | `{}` | UCM cluster definitions (see below) |
| `ca_bundle_path` | *(none)* | When set, auto-generates a combined CA bundle from all cluster `ca_file` entries at startup |

Two environment variables are still supported:

| Variable | Description |
|---|---|
| `CONFIG_FILE` | Path to the YAML configuration file (default: `config.yaml`) |
| `LOG_LEVEL` | Overrides the `log_level` value in the config file when set |

## Multi-Cluster Support

The `clusters` section in `config.yaml` lets you define access rules for one or more UCM clusters. Each cluster can independently specify:

- **`allowed_ips`** — IP addresses and/or CIDR networks permitted to connect
- **`ca_file`** — path to the CA certificate (PEM) that signed the cluster's client certificates
- **`allowed_subjects`** — expected CN and/or SAN values in client certificates

A request is authorized if it matches **at least one** cluster. Matching a cluster means satisfying **all** of its defined rules. Rules that are omitted for a cluster are not enforced for that cluster.

```yaml
clusters:
  headquarters:
    allowed_ips:
      - 10.1.1.10
      - 10.1.1.11
      - 10.1.2.0/24
    ca_file: certs/hq-CallManager.pem
    allowed_subjects:
      - cucm-pub.example.com
      - cucm-sub1.example.com
      - cucm-sub2.example.com

  branch-office:
    allowed_ips:
      - 10.2.1.0/24
    ca_file: certs/branch-CallManager.pem
    allowed_subjects:
      - cucm-branch.example.com
```

When **no clusters** are defined, IP filtering and certificate subject validation are disabled — all clients are accepted (same behavior as a fresh install).

> **Tip:** To find the CN/SAN values of your UCM certificates, run:
> ```bash
> openssl x509 -text -noout -in CallManager.pem | grep -E 'Subject:|DNS:|IP Address:'
> ```

## Authentication & Security

The CURRI protocol relies on **mutual TLS (mTLS)** for authentication — this is the only authentication mechanism defined by the Cisco External Call Control interface. When HTTPS is configured, UCM and the route server mutually authenticate by exchanging and verifying certificates during the TLS handshake.

### mTLS Setup Guide

mTLS ensures that **only UCM servers presenting a trusted certificate** can connect to the `/curri` endpoint. The setup requires exchanging certificates between UCM and this service. A helper script (`setup_certs.sh`) automates the server-side certificate generation.

#### Step 1 — Generate the server certificate

The `setup_certs.sh` script offers two modes. Choose the one that fits your environment:

**Option A — Self-signed certificate** (simplest; good for labs and standalone deployments):

```bash
./setup_certs.sh --hostname curri.example.com
```

This generates `certs/server.key` and `certs/server.crt`. The certificate can be uploaded directly to UCM.

**Option B — Certificate Signing Request** (for CA-signed certificates in enterprise environments):

```bash
./setup_certs.sh --hostname curri.example.com --mode csr
```

This generates `certs/server.key` and `certs/server.csr`. Submit the CSR to your Certificate Authority. When you receive the signed certificate, save it as `certs/server.crt`.

Both options accept these flags:

| Flag | Default | Description |
|---|---|---|
| `--hostname` | *(required)* | FQDN or IP address for the certificate CN and SAN |
| `--mode` | `selfsigned` | `selfsigned` or `csr` |
| `--out-dir` | `certs` | Output directory for generated files |
| `--days` | `365` | Certificate validity (self-signed only) |
| `--key-type` | `ecdsa` | `ecdsa` (P-256) or `rsa` (2048-bit) |

> **Tip:** If your UCM references the server by IP address, pass the IP as the hostname:
> ```bash
> ./setup_certs.sh --hostname 10.1.1.50
> ```
> The script auto-detects IP addresses and sets the SAN accordingly.

#### Step 2 — Export UCM's CA certificate

Each UCM cluster has its own CA certificate that signs client certificates presented during mTLS.

1. Open **Cisco Unified OS Administration** on the UCM publisher.
2. Navigate to **Security > Certificate Management**.
3. Click **Find**, then download the **CallManager.pem** certificate.
4. Save it to your `certs/` directory with a descriptive name:
   ```bash
   # Example for a single cluster
   cp ~/Downloads/CallManager.pem certs/ucm-CallManager.pem

   # Example with multiple clusters
   cp ~/Downloads/CallManager-HQ.pem  certs/hq-CallManager.pem
   cp ~/Downloads/CallManager-BR.pem  certs/branch-CallManager.pem
   ```

#### Step 3 — Upload the server certificate to UCM

Upload this service's TLS certificate (`certs/server.crt`) into UCM so it trusts connections from this server:

1. Open **Cisco Unified OS Administration** on each UCM node.
2. Navigate to **Security > Certificate Management > Upload Certificate**.
3. Set **Certificate Purpose** to **CallManager-trust**.
4. Upload `certs/server.crt`.
5. **Repeat for every UCM node** in the cluster (publisher and all subscribers).
6. Restart the **Cisco CallManager** service on each node for the change to take effect.

#### Step 4 — Configure config.yaml

Enable TLS and define your cluster(s) in `config.yaml`:

```yaml
# Server TLS certificate (dev server; Gunicorn uses CLI args instead)
tls_cert_file: certs/server.crt
tls_key_file: certs/server.key

# Auto-generate a combined CA bundle for Gunicorn's --ca-certs
ca_bundle_path: certs/ca-bundle.pem

# Cluster definitions
clusters:
  headquarters:
    allowed_ips:
      - 10.1.1.10
      - 10.1.1.11
    ca_file: certs/hq-CallManager.pem
    allowed_subjects:
      - cucm-pub.example.com
      - cucm-sub1.example.com
```

#### Step 5 — Start the service

**Development server** (reads TLS and cluster settings from `config.yaml`):
```bash
python main.py
```

**Production (Gunicorn):** The included `gunicorn.conf.py` **automatically detects** TLS certificates and configures Gunicorn accordingly:

- If `certs/server.crt` and `certs/server.key` exist → HTTPS on port 443
- If `ca_bundle_path` is set and cluster CA files exist → mTLS enabled (client cert required)
- Otherwise → plain HTTP on port 80

The CA bundle is generated automatically before Gunicorn binds, so no manual `--ca-certs` flag is needed.

```bash
# Just run Gunicorn — gunicorn.conf.py handles the rest:
gunicorn main:app
```

Override any setting via the `GUNICORN_CMD_ARGS` environment variable or by passing explicit CLI flags.

> **Note:** If you prefer to manage TLS manually, you can pass explicit flags that override `gunicorn.conf.py`:
> ```bash
> gunicorn --certfile=certs/server.crt --keyfile=certs/server.key \
>     --ca-certs=certs/ca-bundle.pem --cert-reqs=2 \
>     -b 0.0.0.0:443 main:app
> ```

**Docker Compose (mTLS):**

TLS and mTLS are enabled automatically when the `certs/` directory contains the server certificate, key, and cluster CA files. Set `ca_bundle_path` to a writable path (e.g., `/tmp/ca-bundle.pem`) in `config.yaml` so the auto-generated bundle can be written inside the container.

```yaml
services:
  ucm-name-lookup:
    build: .
    container_name: ucm-name-lookup
    ports:
      - "443:443"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./phone_directory.csv:/app/phone_directory.csv:ro
      - ./certs:/app/certs:ro
    restart: unless-stopped
```

No `GUNICORN_CMD_ARGS` needed — `gunicorn.conf.py` reads `config.yaml` and auto-configures everything.

### TLS Chain Validation

Gunicorn uses `CERT_REQUIRED` when a CA bundle is present, so OpenSSL validates the full certificate chain at the TLS handshake. If the client certificate does not chain to a trusted root in the CA bundle, the connection is rejected before the request reaches the application. No application-layer chain verification is needed.

> **Important:** The `ca_file` must be the **root CA certificate** (`CA:TRUE`) that anchors the client certificate chain. If a leaf/identity certificate is detected at startup, the application exits with an error. For self-signed UCM clusters, this is typically the `CallManager.pem` certificate exported from UCM OS Administration under **Security > Certificate Management**. For UCM clusters using certificates signed by a public or enterprise CA, provide the root CA certificate (e.g. the IdenTrust root for HydrantID-signed certificates).

#### Multi-cluster trust boundary limitation

When multiple clusters define **different** `ca_file` entries, all root CA certificates are combined into a single CA bundle for Gunicorn. This means the TLS layer accepts any client certificate that chains to *any* root in the bundle — it cannot distinguish which root a given connection was validated against. A client certificate signed by cluster B's root CA will pass the TLS handshake even when matching against cluster A's rules.

In practice, `allowed_subjects` and `allowed_ips` provide effective cluster isolation because different clusters have distinct server hostnames and IP addresses. However, if two clusters have **overlapping `allowed_subjects` and different root CAs**, there is no application-layer defense to enforce per-cluster CA trust boundaries. Python's `ssl` module does not expose the verified certificate chain.

If strict per-cluster CA isolation is required with overlapping subjects, run **separate service instances** (one per trust boundary) with independent CA bundles.

### Certificate Subject Validation (CN/SAN)

Verifying that a client certificate is signed by a trusted CA is **not sufficient on its own** — many unrelated hosts may hold certificates signed by the same CA. The `allowed_subjects` list in each cluster definition ensures that only your specific UCM servers are accepted.

When configured, the application extracts the CN and SAN fields from the connecting client's certificate and checks that **at least one** matches an entry in the cluster's `allowed_subjects` list. Requests from clients whose certificate does not match any cluster are rejected with HTTP 403.

- Comparison is **case-insensitive**
- Both DNS SANs and IP Address SANs are checked
- The `/health` endpoint is **restricted to localhost** when clusters are defined
- If the peer certificate is not accessible (e.g. TLS terminated by a reverse proxy without forwarding cert info), the request is **denied** (fail-closed)

### IP Allow-List (Defense-in-Depth)

The `allowed_ips` list in each cluster definition restricts which IP addresses are permitted to reach the `/curri` endpoint. This is especially useful when mTLS is not feasible or as a supplementary control.

- Accepts individual IPs and CIDR notation
- The `/health` endpoint is **restricted to localhost** (127.0.0.1 / ::1) when clusters are defined, so only the in-container Docker health check can reach it
- When no clusters define `allowed_ips`, all IPs are allowed (no filtering)

> **Recommendation:** For maximum security, define **all three** controls in each cluster:
> 1. **`ca_file`** — verifies the certificate chain (CA trust)
> 2. **`allowed_subjects`** — verifies the certificate identity (CN/SAN pinning)
> 3. **`allowed_ips`** — restricts by network address (defense-in-depth)

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

`gunicorn.conf.py` auto-detects TLS when cert files are present at `certs/server.crt` and `certs/server.key`. Use `--user` to match the UID that owns the key file (the key is `chmod 600`):

```bash
docker run -p 443:443 \
    --user "$(id -u):$(id -g)" \
    -v /path/to/config.yaml:/app/config.yaml:ro \
    -v /path/to/phone_directory.csv:/app/phone_directory.csv:ro \
    -v /path/to/certs:/app/certs:ro \
    ucm-name-lookup
```

The container runs Gunicorn with 4 gthread workers (4 threads each, 16 total). The worker temporary directory is set to `/dev/shm` (shared memory) to prevent false worker timeouts caused by slow I/O on Docker's overlay filesystem. Override Gunicorn settings at runtime via the `GUNICORN_CMD_ARGS` environment variable. A built-in Docker `HEALTHCHECK` runs every 30 seconds — it probes `/health` over HTTP(S) when mTLS is not active, or verifies Gunicorn worker processes are alive via `/proc` when mTLS is enabled (since `CERT_REQUIRED` prevents connections without a client certificate).

### Docker Compose

A `docker-compose.yml` is included for convenience:

```yaml
services:
  ucm-name-lookup:
    build: .
    container_name: ucm-name-lookup
    ports:
      - "80:80"
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

The example above maps host port 80 to the container's port 80 (HTTP). When TLS is enabled, use `443:443` instead — see the HTTPS example below.

To enable HTTPS via Docker Compose, mount the `certs/` directory. `gunicorn.conf.py` auto-detects the cert/key and switches to HTTPS on port 443:

```yaml
services:
  ucm-name-lookup:
    build: .
    container_name: ucm-name-lookup
    user: "${DOCKER_UID:-1000}:${DOCKER_GID:-1000}"
    ports:
      - "443:443"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./phone_directory.csv:/app/phone_directory.csv:ro
      - ./certs:/app/certs:ro
    restart: unless-stopped
```

**Private key permissions:** The `server.key` file is created with `chmod 600` (owner-only read) for security. The container must run as the UID that owns the key file. Two approaches:

1. **Match the container UID to the file owner** (recommended) — set `DOCKER_UID` and `DOCKER_GID` in a `.env` file next to `docker-compose.yml`:
   ```
   DOCKER_UID=1000
   DOCKER_GID=1000
   ```
   Use `id -u` and `id -g` on your deployment server to find the correct values for the user that owns the cert files.

2. **Change file ownership to match the default container user** — the Dockerfile creates `appuser` with uid 1000:
   ```bash
   sudo chown 1000:1000 certs/server.key certs/server.crt
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
| `GET` | `/health` | Health check — returns JSON with service status and directory entry count. **Localhost only** when clusters are defined |

## Troubleshooting TLS / mTLS

When diagnosing certificate verification errors such as `unable to get local issuer certificate`, set `LOG_LEVEL` to `DEBUG` to enable detailed TLS diagnostics:

```bash
# Via environment variable
LOG_LEVEL=DEBUG docker compose up

# Or in config.yaml
log_level: DEBUG
```

At **DEBUG** level the service logs:

- **Startup (Gunicorn and dev server):** the TLS configuration (cert, key, CA bundle path, cert_reqs mode) and the full details of every certificate in the CA trust store — subject, issuer, serial number, and validity dates. Both CA and leaf certificates in the bundle are listed.
- **Per-request:** the connecting client's certificate details — subject, issuer, serial, validity, and SANs — plus the cluster-matching decisions (IP check, subject check, issuer/identity check).

This makes it easy to spot mismatches between the client certificate's issuer and the CAs in the trust store.

> **Tip:** You can also inspect certificates directly with OpenSSL:
> ```bash
> # View the CA bundle contents
> openssl crl2pkcs7 -nocrl -certfile /tmp/ca-bundle.pem | \
>   openssl pkcs7 -print_certs -noout
>
> # View a single certificate
> openssl x509 -text -noout -in certs/server.crt
>
> # Test the TLS handshake with a client cert
> openssl s_client -connect localhost:443 \
>   -cert client.crt -key client.key -CAfile ca.pem
> ```

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
