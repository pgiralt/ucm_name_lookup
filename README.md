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

## Quick Start

Get the service running in under two minutes:

```bash
# 1. Clone and install
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.yaml.example config.yaml

# 2. Edit phone_directory.csv with your phone number → display name mappings

# 3a. Run with TLS (recommended — generate certs first)
./setup_certs.sh --hostname localhost
#     Then set tls_cert_file and tls_key_file in config.yaml:
#       tls_cert_file: certs/server.crt
#       tls_key_file: certs/server.key
python main.py

# 3b. Or run without TLS (development only — requires insecure_mode)
#     Uncomment 'insecure_mode: true' in config.yaml, then:
python main.py
```

> **Note:** The service is **secure by default** and will not start without TLS certificates unless `insecure_mode: true` is explicitly set in `config.yaml`. See [Secure by Default](#secure-by-default) for details.

Once running, point a UCM External Call Control profile at the service URL to start testing. See [Production Deployment Checklist](#production-deployment-checklist) when you're ready to deploy with HTTPS and mTLS.

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
| `insecure_mode` | `false` | When `true`, allows the service to start without TLS (see [Secure by Default](#secure-by-default)) |
| `csv_file_path` | `phone_directory.csv` | Path to the phone directory CSV file |
| `log_level` | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR |
| `log_dir` | *(none)* | Directory for rotating log files (see [Logging](#logging)) |
| `log_max_bytes` | `10485760` | Max size in bytes per log file before rotation (10 MB) |
| `log_backup_count` | `5` | Number of rotated log files to keep |
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

### Logging

By default, all log output goes to stdout/stderr (visible via `docker logs`). To also write rotating log files, set `log_dir` in `config.yaml`:

```yaml
log_dir: logs
```

When enabled, three log files are created:

| File | Contents |
|---|---|
| `app.log` | Application log — startup, CURRI requests, lookups, cluster enforcement |
| `access.log` | Gunicorn HTTP access log |
| `error.log` | Gunicorn startup and error log |

Each file rotates at `log_max_bytes` (default 10 MB) and keeps `log_backup_count` backups (default 5). With defaults, maximum disk usage is ~150 MB (3 files × 10 MB × 5 backups + active files). Log rotation uses file locking (`concurrent-log-handler`) so it is safe with Gunicorn's multiple worker processes.

Console output is **always active** alongside file logging so `docker logs` continues to work.

> **Docker:** The `docker-compose.yml` mounts `./logs` into the container. Create the directory on the host or let Docker create it automatically. The `logs/` directory is gitignored.

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

## Secure by Default

The service enforces a **secure by default** posture: it **will not start** unless TLS certificates are properly configured. This ensures that the service never accidentally runs in plaintext HTTP mode in production.

If TLS is not configured (`tls_cert_file`/`tls_key_file` are not set, or the certificate files are missing), the service exits immediately with an error message explaining how to fix it.

For **development and testing only**, you can override this by setting `insecure_mode: true` in `config.yaml`:

```yaml
# WARNING: Development/testing only — never enable in production!
insecure_mode: true
```

When insecure mode is enabled:

- A **prominent warning banner** is printed at startup
- A **security warning is logged every hour** as a persistent reminder
- All traffic is transmitted in **unencrypted plaintext HTTP**

To run the service securely, generate TLS certificates and remove (or set to `false`) the `insecure_mode` setting:

```bash
# Generate a self-signed certificate for development
./setup_certs.sh --hostname localhost

# Configure TLS in config.yaml
# tls_cert_file: certs/server.crt
# tls_key_file: certs/server.key
```

See [mTLS Setup Guide](#mtls-setup-guide) for production certificate setup.

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
| `--key-type` | `ecdsa` | `ecdsa` (P-256) or `rsa` (4096-bit) |

> **Tip:** If your UCM references the server by IP address, pass the IP as the hostname:
> ```bash
> ./setup_certs.sh --hostname 10.1.1.50
> ```
> The script auto-detects IP addresses and sets the SAN accordingly.

#### Step 2 — Obtain the root CA certificate that signed UCM's certificate

This service needs the **root CA certificate** that anchors UCM's client certificate chain. The correct file depends on how your UCM cluster's certificates were signed:

**Self-signed UCM cluster (default):**

When UCM uses its built-in self-signed certificates, `CallManager.pem` *is* the root CA:

1. Open **Cisco Unified OS Administration** on the UCM publisher.
2. Navigate to **Security > Certificate Management**.
3. Click **Find**, then download the **CallManager.pem** certificate.
4. Save it to your `certs/` directory:
   ```bash
   cp ~/Downloads/CallManager.pem certs/ucm-ca.pem
   ```

**CA-signed UCM cluster (enterprise or public CA):**

When UCM's certificates are signed by an enterprise or public Certificate Authority, you need the **root CA certificate** from that CA — not the `CallManager.pem` exported from UCM:

1. Obtain the root CA certificate from your Certificate Authority. For example:
   - **Enterprise CA (Active Directory CS):** Export the root certificate from the CA server or download it from the CA's web enrollment page.
   - **Public CA (e.g., HydrantID, DigiCert):** Download the root certificate from the CA's repository.
2. If there are intermediate CA certificates in the chain, include the full chain (root + intermediates) in a single PEM file.
3. Save the root CA certificate to your `certs/` directory:
   ```bash
   cp ~/Downloads/enterprise-root-ca.pem certs/ucm-ca.pem
   ```

> **How to check:** Open `CallManager.pem` and compare the **Subject** and **Issuer** fields. If they are identical, the certificate is self-signed and can be used directly. If they differ, the **Issuer** identifies the CA that signed it — obtain that CA's root certificate instead.
>
> ```bash
> openssl x509 -in CallManager.pem -noout -subject -issuer
> ```

**Multiple clusters** with different CAs:

```bash
# Each cluster gets its own root CA file
cp ~/Downloads/hq-root-ca.pem     certs/hq-ca.pem
cp ~/Downloads/branch-root-ca.pem certs/branch-ca.pem
```

#### Step 3 — Upload the server certificate to UCM

Upload this service's TLS certificate (`certs/server.crt`) into UCM so it trusts connections from this server:

1. Open **Cisco Unified OS Administration** on the UCM **publisher**.
2. Navigate to **Security > Certificate Management > Upload Certificate**.
3. Set **Certificate Purpose** to **CallManager-trust**.
4. Upload `certs/server.crt`.
5. The publisher automatically distributes trust certificates to all subscriber nodes. No service restart is required.

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

TLS and mTLS are enabled automatically when the `certs/` directory contains the server certificate, key, and cluster CA files. Set `ca_bundle_path` to a writable path (e.g., `/tmp/ca-bundle.pem`) in `config.yaml` so the auto-generated bundle can be written inside the container (since `certs/` is mounted read-only).

```bash
docker compose up -d
```

No `GUNICORN_CMD_ARGS` needed — `gunicorn.conf.py` reads `config.yaml` and auto-configures everything. See [Docker Compose](#docker-compose) for the full `docker-compose.yml` reference.

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

A `docker-compose.yml` is included for convenience. The default configuration runs with HTTPS when certificates are present:

```yaml
services:
  ucm-name-lookup:
    build: .
    container_name: ucm-name-lookup
    user: "${DOCKER_UID:-1000}:${DOCKER_GID:-1000}"
    tmpfs:
      - /tmp
      - /dev/shm
    ports:
      - "443:443"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./phone_directory.csv:/app/phone_directory.csv:ro
      - ./certs:/app/certs:ro
      - ./logs:/app/logs
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "2.0"
    restart: unless-stopped
```

- **`tmpfs`** mounts provide writable scratch space for CA bundle generation (`/tmp`) and Gunicorn worker heartbeats (`/dev/shm`) without writing to the container filesystem.
- **`./logs:/app/logs`** persists rotating log files on the host (requires `log_dir: logs` in `config.yaml`).
- **`deploy.resources.limits`** caps memory and CPU to prevent a runaway process from consuming all host resources. Adjust to match your hardware.
- For HTTP-only (no TLS), change the port to `"80:80"`.
- Copy `.env.example` to `.env` and set `DOCKER_UID`/`DOCKER_GID` to match your cert file owner.

**Start the service:**
```bash
docker compose up -d
```

**View logs:**
```bash
# Console logs
docker compose logs -f

# File logs (when log_dir is configured)
tail -f logs/app.log
```

**Rebuild after code changes:**
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
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

This section covers everything that must be configured on the Cisco Unified Communications Manager side. The steps assume you have already deployed this service and it is reachable from the UCM nodes over the network.

> **Prerequisite:** CURRI / External Call Control requires CUCM 8.5 or later. All examples below use the Cisco Unified CM Administration web interface.

### Step 1 — Certificate exchange (mTLS only)

If you are using mTLS (recommended for production), certificates must be exchanged between UCM and this service before ECC will work. If you are running without TLS (lab/testing), skip to [Step 2](#step-2--create-the-external-call-control-profile).

The full certificate procedure is documented in the [mTLS Setup Guide](#mtls-setup-guide) above. In summary:

1. **Obtain the root CA certificate for your UCM cluster:**
   - **Self-signed UCM (default):** Export **CallManager.pem** from **Cisco Unified OS Administration > Security > Certificate Management** on the publisher. This file is both the UCM identity certificate and the root CA.
   - **CA-signed UCM:** Obtain the **root CA certificate** from the Certificate Authority that signed UCM's certificate (e.g., your enterprise CA or public CA). Do *not* use `CallManager.pem` — it is a leaf certificate, not the trust anchor.
   - Save the root CA certificate into this service's `certs/` directory.
2. **Upload this service's certificate to UCM** — On the UCM **publisher**, go to **Cisco Unified OS Administration > Security > Certificate Management > Upload Certificate**, set **Certificate Purpose** to **CallManager-trust**, and upload `certs/server.crt`. The publisher automatically distributes trust certificates to all subscribers. No service restart is required.
>
> **How to tell if UCM is self-signed or CA-signed:** Run `openssl x509 -in CallManager.pem -noout -subject -issuer`. If Subject and Issuer are identical, it is self-signed. If they differ, the Issuer identifies the CA — obtain that CA's root certificate. See [Step 2 of the mTLS Setup Guide](#step-2--obtain-the-root-ca-certificate-that-signed-ucms-certificate) for details.

### Step 2 — Create the External Call Control profile

1. In **Cisco Unified CM Administration**, navigate to **Call Routing > External Call Control Profile**.
2. Click **Add New**.
3. Configure the profile fields:

| Field | Value | Notes |
|---|---|---|
| **Name** | `Name Lookup` | Descriptive name for this profile |
| **Primary Route Server URI** | `https://<server-fqdn-or-ip>:443/curri` | Use `http://` and port `80` if not using TLS. See note below about hostname matching |
| **Secondary Route Server URI** | *(optional)* | Set this to a second instance for redundancy. Same hostname matching rules apply |
| **Routing Request Timer** | `2000` | Milliseconds UCM waits for a response before treating the request as failed. Increase if the service is on a high-latency link |
| **Call Treatment on Failures** | `Allow` | **Critical:** set this to **Allow** so calls continue normally if the service is unreachable. Setting it to Deny would block calls on failure |
| **Connection Reuse Timer** | `60` | Seconds UCM keeps idle HTTP connections open. The service handles HEAD keepalive probes automatically |

4. Click **Save**.

> **Hostname matching (TLS):** The hostname or IP address in the Route Server URI must match a CN or SAN entry in this service's TLS certificate (`certs/server.crt`). UCM validates the server certificate during the TLS handshake and will reject the connection if the URI does not match. For example, if the certificate was generated with `./setup_certs.sh --hostname 10.1.1.50`, the URI must use `https://10.1.1.50:443/curri`. If it was generated with `--hostname curri.example.com`, the URI must use `https://curri.example.com:443/curri`.

> **Tip — Redundancy:** If you run two instances of this service (e.g., on separate hosts), enter the second instance URL as the **Secondary Route Server URI**. UCM will fail over to the secondary if the primary is unreachable.
>
> A load balancer can also be placed in front of multiple instances, but it **must operate at Layer 4 (TCP passthrough)**. The load balancer must **not** perform SSL termination or inspection — any form of TLS interception will break mTLS because UCM's client certificate will not reach the service, and the service's certificate will not be presented to UCM. Configure the load balancer to forward raw TCP connections without decrypting them.

### Step 3 — Adjust service parameters

Several service parameters control how UCM interacts with External Call Control services. Review and adjust these as needed.

1. Navigate to **System > Service Parameters**.
2. Select a UCM server and choose **Cisco CallManager** as the service.
3. Find the **Clusterwide Parameters (External Call Control)** section:

| Parameter | Default | Recommended | Notes |
|---|---|---|---|
| **Maximum Number of PDP Connections per Node** | `20` | Match Gunicorn workers × threads | This service defaults to 4 workers × 4 threads = 16 concurrent connections. Set this parameter to at least `16` (or whatever you configured in Gunicorn) |
| **PDP Connection Keep Alive Timer** | `30` | `30` | Seconds between HEAD keepalive probes. The service responds to HEAD requests on `/curri` automatically |
| **PDP Retry Timer** | `3` | `3` | Seconds to wait before retrying a failed connection |

4. Click **Save** and confirm the change applies to all nodes.

### Step 4 — Apply the ECC profile to call routing

The ECC profile must be assigned to the call routing elements (patterns) where you want caller name lookups to occur. UCM sends a CURRI request to this service each time a call matches a pattern that has an ECC profile assigned.

Choose one or more of the following depending on your deployment:

#### Option A — Directory Numbers (per-line)

Best for looking up names on specific lines (e.g., receptionist phones, call center agents):

1. Navigate to **Device > Phone**, find the phone, and click the **Directory Number** (line) you want to enable.
2. Scroll to the **External Call Control Profile** drop-down under the **Incoming Calls** section.
3. Select the profile you created in Step 2.
4. Click **Save** and **Apply Config**.

#### Option B — Translation Patterns (recommended for broad coverage)

Best for applying name lookups to a range of numbers without modifying individual DNs:

1. Navigate to **Call Routing > Translation Pattern**.
2. Create a new Translation Pattern (or edit an existing one) that matches the inbound calling number range. For example:
   - **Translation Pattern:** `!` (matches any number) or a specific range like `2XXX`
   - **Partition / Calling Search Space:** configure to match your dial plan
3. Set the **External Call Control Profile** drop-down to the profile you created.
4. Set **Called Party Transformation Mask** and other fields as needed for your dial plan.
5. Click **Save**.

> **Note:** Translation Patterns are evaluated based on calling search spaces and partitions. Ensure the pattern is reachable in the call flow for the calls you want to apply name lookups to.

#### Option C — Route Patterns

Best for applying name lookups to calls leaving the cluster (e.g., outbound calls through a gateway or SIP trunk):

1. Navigate to **Call Routing > Route/Hunt > Route Pattern**.
2. Edit the Route Pattern for the desired destination range.
3. Set the **External Call Control Profile** drop-down to the profile you created.
4. Click **Save**.

#### Option D — SIP Route Patterns

For SIP trunk routing:

1. Navigate to **Call Routing > SIP Route Pattern**.
2. Edit or create the SIP Route Pattern.
3. Set the **External Call Control Profile**.
4. Click **Save**.

### Step 5 — Number format considerations

The phone numbers in your `phone_directory.csv` must match the format that UCM sends in the CURRI request. UCM sends the calling party number as it appears at the point in the call flow where the ECC profile is applied.

- **Before digit manipulation:** If the ECC profile is on a Translation Pattern that runs before calling party transformations, the number will be in its original received format.
- **After digit manipulation:** If transformations (e.g., globalization, E.164 normalization) have already been applied, the number will be in the transformed format.

The service checks the `callingnumber` attribute first, then falls back to `transformedcgpn` (the transformed calling party globalized number). To determine what format UCM is sending:

1. Set `log_level: DEBUG` in `config.yaml`.
2. Place a test call.
3. Check the logs for the parsed XACML attributes:
   ```
   Parsed XACML attribute: urn:Cisco:uc:1.0:callingnumber = +12125551001
   Parsed XACML attribute: urn:Cisco:uc:1.0:transformedcgpn = +12125551001
   ```
4. Use the number format you see in the logs as the format for your CSV entries.

> **Tip:** If UCM sends numbers in E.164 format (e.g., `+12125551212`), include the `+` and country code in your CSV. The service normalizes numbers by stripping formatting characters (`-`, `()`, `.`, spaces) but preserves the leading `+`.

### Step 6 — Verify the integration

After completing the configuration on both sides:

1. **Check the ECC profile status** in UCM:
   - Navigate to **Call Routing > External Call Control Profile** and open your profile.
   - The **PDP Status** should show **Active** for each server. If it shows **Inactive**, UCM cannot reach the service — check network connectivity, TLS certificates, and firewall rules.

2. **Place a test call** from a phone whose call flow passes through a pattern with the ECC profile:
   - Call a number where the calling party is listed in `phone_directory.csv`.
   - The receiving phone should display the name from the CSV instead of (or in addition to) the default caller ID.

3. **Check the service logs** for the CURRI request:
   ```bash
   # Docker
   docker compose logs -f

   # Or file logs (if log_dir is configured)
   tail -f logs/app.log
   ```
   You should see a log entry showing the parsed calling number and the matched display name.

4. **If the name is not updated:**
   - Verify the ECC profile shows **Active** status on the UCM server.
   - Verify the phone number format in the CSV matches what UCM sends (use DEBUG logging).
   - Verify the ECC profile is applied to the correct pattern in the call flow.
   - Check for TLS errors in the service logs and in UCM's RTMT (Real-Time Monitoring Tool) under **Trace & Log Central**.

### UCM troubleshooting tools

- **RTMT (Real-Time Monitoring Tool):** Collect SDL traces with the **External Call Control** filter enabled to see the XACML request/response exchange.
- **Dialed Number Analyzer:** Use **Call Routing > Dialed Number Analyzer** to trace a call through the dial plan and confirm it hits a pattern with the ECC profile.
- **CURRI keepalive:** UCM sends periodic HEAD requests to `/curri` to check if the service is available. If these fail, UCM marks the PDP as inactive. Check network/firewall rules if the status is stuck on Inactive.

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

## Production Deployment Checklist

Use this checklist when moving from a development setup to a production deployment. Each item references the relevant section above for details.

### Security mode

- [ ] Ensure `insecure_mode` is **not set** (or set to `false`) in `config.yaml` — the service must run with TLS in production

### Certificates and mTLS

- [ ] Generate a server certificate with `./setup_certs.sh --hostname <fqdn>` (see [Step 1](#step-1--generate-the-server-certificate))
- [ ] Export each UCM cluster's `CallManager.pem` CA certificate (see [Step 2](#step-2--export-ucms-ca-certificate))
- [ ] Upload `certs/server.crt` to the UCM publisher's **CallManager-trust** store (see [Step 3](#step-3--upload-the-server-certificate-to-ucm))
- [ ] Set `ca_bundle_path` in `config.yaml` (e.g., `/tmp/ca-bundle.pem` for Docker)

### Cluster access control

- [ ] Define at least one cluster in `config.yaml` with all three controls:
  - `ca_file` — path to the cluster's root CA certificate
  - `allowed_subjects` — CN/SAN values of the UCM nodes
  - `allowed_ips` — IP addresses or CIDR ranges of the UCM nodes
- [ ] Verify the CA file is a root certificate (`CA:TRUE`), not a leaf certificate

### Logging

- [ ] Set `log_dir: logs` in `config.yaml` to enable rotating file logs
- [ ] Mount the `./logs` directory in Docker Compose (included by default)
- [ ] Optionally adjust `log_max_bytes` and `log_backup_count` for your disk capacity

### Docker hardening

- [ ] Set `DOCKER_UID` and `DOCKER_GID` in `.env` to match the cert file owner
- [ ] Mount `config.yaml`, `phone_directory.csv`, and `certs/` as read-only (`:ro`)
- [ ] Keep `tmpfs` mounts for `/tmp` and `/dev/shm`
- [ ] Verify the container starts: `docker compose up -d && docker compose logs -f`

### UCM configuration

See [UCM Configuration](#ucm-configuration) for detailed instructions on each step.

- [ ] Obtain the root CA certificate for each UCM cluster — `CallManager.pem` if self-signed, or the CA root cert if CA-signed (mTLS only)
- [ ] Upload `certs/server.crt` to **CallManager-trust** on the UCM publisher (mTLS only)
- [ ] Create an External Call Control profile pointing to `https://<server>:443/curri`
- [ ] Set **Routing Request Timer** (e.g., 2000 ms)
- [ ] Set **Call Treatment on Failures** to **Allow**
- [ ] Set **Maximum Number of PDP Connections per Node** to match Gunicorn workers × threads (default: 16)
- [ ] Apply the ECC profile to the desired Directory Numbers, Translation Patterns, or Route Patterns
- [ ] Verify the phone number format in your CSV matches what UCM sends (use `log_level: DEBUG` to check)

### Verification

- [ ] Confirm health check passes: `curl -k https://localhost:443/health` (or check `docker compose ps`)
- [ ] Confirm ECC profile shows **Active** PDP status in UCM
- [ ] Place a test call through UCM and verify the caller display name is updated
- [ ] Check log files are being written: `ls -la logs/`
- [ ] Set `log_level: DEBUG` temporarily if troubleshooting TLS or number format issues

## License

This project is licensed under the [MIT License](LICENSE).
