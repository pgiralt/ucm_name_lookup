# AGENTS.md — UCM Name Lookup Service

Project context for AI coding agents working on this codebase.

## Overview

A **CURRI** (Cisco Unified Routing Rules Interface) server that provides phone number → display name lookup for **Cisco Unified Communications Manager (UCM)**. UCM sends XACML 2.0 XML POST requests; the service responds with Permit/Continue decisions, optionally modifying the caller display name via embedded CIXML.

**Calls are never rejected** — the service always returns Permit/Continue.

## Tech Stack

- **Language**: Python 3.10+
- **Framework**: Flask (dev server) / Gunicorn (production)
- **XML parsing**: `defusedxml` (XXE-safe) — never use stdlib `xml.etree` directly
- **Config**: YAML via `PyYAML` (`yaml.safe_load` only — never `yaml.load`)
- **Containerization**: Docker (multi-stage build, non-root user) + Docker Compose

## Project Structure

| File | Purpose |
|---|---|
| `main.py` | Single-file application: config loading, cluster enforcement, CSV loading, XACML parsing, CIXML response building, Flask routes, dev server TLS setup |
| `config.yaml` | Non-sensitive configuration: general settings + multi-cluster definitions (gitignored; copy from `config.yaml.example`) |
| `phone_directory.csv` | Phone number → display name mappings (exact and prefix match types) |
| `requirements.txt` | Python dependencies (pinned to major version ranges) |
| `Dockerfile` | Multi-stage production image with Gunicorn |
| `docker-compose.yml` | Development/deployment compose file |
| `setup_certs.sh` | Certificate helper script — generates self-signed certs or CSRs for mTLS setup |
| `gunicorn.conf.py` | Gunicorn config — auto-detects TLS/mTLS from config.yaml, generates CA bundle before bind |
| `healthcheck.py` | Docker HEALTHCHECK script — auto-detects HTTP vs HTTPS |
| `README.md` | Full user-facing documentation |

## Architecture Decisions

### Single-file application (`main.py`)

All application logic lives in `main.py`. This is intentional for simplicity given the service's focused scope. The file is organized in clear sections with separator comments:

1. **Configuration** — YAML loading, global settings, insecure mode flag, PII obfuscation flag and helper
2. **Insecure Mode Warning** — banner constant, hourly warning timer
3. **Cluster Definitions** — `ClusterConfig` dataclass, parsing helpers
4. **CA Bundle Generation** — auto-concatenation of cluster CA files
5. **Client Certificate Helpers** — peer cert extraction, CN/SAN parsing
6. **Flask Application** — `before_request` enforcement hook, routes
7. **Prefix Trie** — efficient longest-prefix phone number matching
8. **CSV Directory Loader** — phone directory ingestion with normalization
9. **XACML Parser** — CURRI request parsing
10. **CIXML Response Builder** — CURRI response construction
11. **Phone Number Lookup** — exact then prefix match strategy
12. **Flask Routes** — `/curri` (POST/HEAD) and `/health` (GET)
13. **Application Startup** — directory loading, secure-by-default enforcement, dev server TLS

### Configuration via YAML (not environment variables)

Non-sensitive settings are in `config.yaml` (gitignored). The repo ships `config.yaml.example` as a template. Only two env vars remain:
- `CONFIG_FILE` — path to the YAML file (default: `config.yaml`)
- `LOG_LEVEL` — overrides the config file value when set

Sensitive values (TLS private keys) are passed via Gunicorn CLI args or mounted files — never in config.

### Multi-cluster access control

The `clusters` section in `config.yaml` supports multiple UCM clusters. Each cluster independently defines:
- **`allowed_ips`** — IP/CIDR allow-list
- **`ca_file`** — path to the cluster's CA certificate (PEM)
- **`allowed_subjects`** — expected CN/SAN values in client certificates

A request must match **at least one** cluster. Matching means passing **all** of that cluster's defined rules.

**Two-layer app enforcement** per cluster (in `_enforce_cluster_access`):
1. IP address check against `allowed_networks`
2. Certificate CN/SAN check against `allowed_subjects`

**TLS-layer chain validation** is handled separately by Gunicorn with `CERT_REQUIRED`. When `ca_file` is set, the client certificate must chain to a trusted root CA in the combined CA bundle — connections that fail chain validation are rejected at the TLS handshake before reaching the application.

The `ca_file` **must** be the root CA certificate (`CA:TRUE`) that anchors the client certificate chain. It can include intermediate CAs in the chain. If a leaf certificate is detected at startup, the application exits with a clear error. The root CA certificate can typically be exported from UCM OS Administration under Security > Certificate Management.

**Multi-cluster trust boundary limitation:** When multiple clusters define different `ca_file` entries, all roots are combined into one CA bundle. The TLS layer cannot distinguish which root validated a given connection. Cluster isolation relies on `allowed_subjects` and `allowed_ips` having no overlap. If strict per-cluster CA isolation with overlapping subjects is needed, run separate service instances.

### Secure by default

The service **refuses to start** without TLS certificates unless `insecure_mode: true` is explicitly set in `config.yaml`. This applies to both the dev server (`main.py`) and production (`gunicorn.conf.py`).

When `insecure_mode` is enabled:
- A prominent ASCII warning banner is printed at startup.
- A security warning is logged every hour via a daemon `threading.Timer`.
- The service runs on plain HTTP.

The `insecure_mode` config value defaults to `false`. The check uses `_config.get("insecure_mode", False) is True` to ensure only an explicit boolean `true` enables it.

### PII obfuscation

When `obfuscate_pii: true` is set in `config.yaml`, phone numbers and display names are replaced with truncated SHA-256 hashes in all log output. The format is `{! <24-char-hex> !}`. The `_obfuscate_pii()` helper returns the original value when disabled or the hash when enabled. This covers CSV loading warnings, XACML attribute parsing, phone number lookup results, the CURRI request processing log line, and the raw XACML body debug log (suppressed entirely when obfuscation is active).

Hashes use HMAC-SHA256 with a per-startup random salt (32 bytes from `secrets.token_bytes`). The salt lives only in memory — never logged or persisted — preventing rainbow-table reversal of the small phone-number keyspace. Hashes are consistent within a process lifetime but not comparable across restarts. In production, `gunicorn.conf.py` generates the salt once in the master process and passes it to workers via the `_PII_SALT` environment variable so all workers produce identical hashes. The dev server generates its own salt locally.

### CA bundle auto-generation

When `ca_bundle_path` is set in config, the app concatenates all unique cluster `ca_file` entries into a single PEM bundle at startup. This file is what Gunicorn's `--ca-certs` should point to.

### Phone number matching

Two strategies, evaluated in order:
1. **Exact match** — O(1) dict lookup
2. **Longest prefix match** — O(m) trie walk (where m = digit length)

Numbers are normalized (strip formatting chars, preserve leading `+`) before lookup.

## Key Protocols

### CURRI / XACML

- UCM sends XACML 2.0 XML with Cisco-specific attribute URNs under `urn:Cisco:uc:1.0:*`
- Key attributes: `callingnumber`, `callednumber`, `transformedcgpn`, `transformedcdpn`
- XACML namespace: `urn:oasis:names:tc:xacml:2.0:context:schema:os`
- Response embeds CIXML inside XACML via HTML entity encoding
- UCM also sends HEAD requests as keepalive probes — always return 200

### mTLS

- Authentication uses mutual TLS — the only auth mechanism in CURRI
- `setup_certs.sh` automates server certificate generation (two modes: self-signed or CSR)
- `gunicorn.conf.py` auto-detects TLS cert/key and CA bundle; generates the CA bundle before Gunicorn binds
- UCM's `CallManager.pem` is the CA cert to trust
- The service's TLS cert must be imported into UCM's `CallManager-trust` store
- Dev server: cluster `ca_file` entries are loaded into the SSLContext directly
- Production: `gunicorn.conf.py` handles CA bundle generation and `--ca-certs` automatically
- Generated certs go in `certs/` (gitignored)
- In Docker, set `ca_bundle_path` to a writable path (e.g., `/tmp/ca-bundle.pem`) since `certs/` is mounted read-only

## Important Conventions

- **Secure by default** — the service will not start without TLS certificates unless `insecure_mode: true` is explicitly set in config. When insecure mode is active, a warning banner is shown at startup and a security warning is logged every hour
- **Never reject calls** — always return Permit/Continue, even on errors or empty input
- **`/health` is localhost-only** when clusters are defined (127.0.0.1 / ::1); unrestricted when no clusters are configured. The Docker health check uses a process-level check (scanning `/proc` for gunicorn workers) when mTLS is active, since `CERT_REQUIRED` prevents HTTP connections without a client cert
- **`defusedxml` for all XML parsing** — prevents XXE attacks
- **`yaml.safe_load` only** — prevents unsafe deserialization
- **No secrets in config.yaml** — TLS keys go through Gunicorn CLI or file mounts
- **PII obfuscation** — when `obfuscate_pii: true` is set, all phone numbers and display names are logged as `{! SHA-256-prefix !}` via the `_obfuscate_pii()` helper. Use this helper for any new log statements that include caller/callee data
- **Logging**: use the `ucm_name_lookup` logger; never log secrets, tokens, or raw cert data
- **File logging**: when `log_dir` is set in config, `ConcurrentRotatingFileHandler` (from `concurrent-log-handler`) writes `app.log`, and Gunicorn's `logconfig_dict` writes `access.log` + `error.log` — all with file-locked rotation safe for multiple Gunicorn workers
- **Security headers**: `@app.after_request` sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'`, and strips the `Server` header
- **Request body limit**: Flask `MAX_CONTENT_LENGTH` is set to 1 MB to prevent oversized payload DoS
- **TLS minimum**: TLSv1.2 enforced in dev server SSLContext
- **`logs/` directory**: gitignored; mounted as a writable volume in Docker Compose
- **`.env` / `.env.example`**: Docker Compose UID/GID variables; `.env` is gitignored
- **Docker image pinning**: Dockerfile uses `python:3.12-slim@sha256:...` digest for reproducible builds

## Development

```bash
# Install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Create local config from the template
cp config.yaml.example config.yaml

# Run dev server (requires TLS by default — secure by default)
# Option A: Generate certs and configure TLS
./setup_certs.sh --hostname localhost
# Set tls_cert_file and tls_key_file in config.yaml
python main.py

# Option B: Run without TLS (dev/testing only)
# Set 'insecure_mode: true' in config.yaml
python main.py

# Run dev server (HTTPS with mTLS — configure clusters in config.yaml first)
# Set tls_cert_file and tls_key_file in config.yaml, plus cluster ca_file entries
python main.py

# Production (gunicorn.conf.py auto-detects TLS/mTLS from config.yaml)
gunicorn main:app

# Docker
docker build -t ucm-name-lookup .
docker compose up
```

## TLS Debug Logging

Set `LOG_LEVEL=DEBUG` (env var or `log_level: DEBUG` in config.yaml) to enable detailed TLS diagnostics:

- **Gunicorn startup:** prints TLS config (cert, key, CA bundle, cert_reqs) and dumps every certificate in the CA trust store (subject, issuer, serial, validity). Both CA and leaf certs are listed.
- **App startup:** `_log_ca_bundle_contents()` parses the CA bundle and logs the same details via the `ucm_name_lookup` logger. `_log_trusted_ca_certs()` dumps the SSLContext trust store for the dev server.
- **Per-request:** `_log_cert_details()` logs the client certificate (subject, issuer, serial, validity, SANs). Cluster-matching decisions (IP, subject, issuer/identity) are also logged at DEBUG.

Helper functions in `main.py`: `_format_cert_name()`, `_log_cert_details()`, `_log_trusted_ca_certs()`, `_log_ca_bundle_contents()`.

## Testing Notes

- No test suite exists yet — this is an area for future development
- Key areas to test: XACML parsing, phone number normalization, prefix trie matching, cluster enforcement logic (IP + subject + CA issuer), CA bundle generation
- The `/health` endpoint is useful for quick smoke tests
- For cluster enforcement testing, use `./setup_certs.sh --hostname localhost` to generate test certs
