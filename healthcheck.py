"""Docker HEALTHCHECK script — verifies the service is running.

Behavior depends on the TLS / mTLS configuration detected from
``config.yaml``:

* **HTTP or HTTPS (no mTLS)** — probes ``/health`` via HTTP(S).
* **HTTPS + leaf-only CA bundle (CERT_OPTIONAL)** — probes ``/health``
  via HTTPS (the TLS handshake succeeds without a client certificate).
* **mTLS with real CA certs (CERT_REQUIRED)** — verifies that Gunicorn
  worker processes are alive via ``/proc``, since the TLS layer rejects
  connections without a client certificate.
"""

import os
import ssl
import sys

import yaml

config_path = os.environ.get("CONFIG_FILE", "config.yaml")
config = {}
if os.path.isfile(config_path):
    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

cert = config.get("tls_cert_file", "certs/server.crt")
key = config.get("tls_key_file", "certs/server.key")
ca_bundle_path = config.get("ca_bundle_path", "")
clusters = config.get("clusters", {})

tls_enabled = os.path.isfile(cert) and os.path.isfile(key)

# Determine if strict mTLS (CERT_REQUIRED) is active. This is only
# the case when the CA bundle contains real CA certificates. When
# the bundle has only leaf certificates, Gunicorn uses CERT_OPTIONAL
# and the HTTP health check works without a client cert.
cert_required = False
if tls_enabled and ca_bundle_path:
    _bundle_exists = os.path.isfile(ca_bundle_path)
    if not _bundle_exists and isinstance(clusters, dict):
        for cdata in clusters.values():
            if isinstance(cdata, dict) and cdata.get("ca_file"):
                if os.path.isfile(cdata["ca_file"]):
                    _bundle_exists = True
                    break
    if _bundle_exists:
        # Check whether the bundle has real CA certs (not just leaves).
        try:
            _ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            _ctx.load_verify_locations(ca_bundle_path)
            cert_required = bool(_ctx.get_ca_certs())
        except (ssl.SSLError, OSError):
            pass


def _check_http():
    """Probe the /health endpoint over HTTP or HTTPS."""
    import urllib.request

    if tls_enabled:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = "https://localhost:443/health"
    else:
        ctx = None
        url = "http://localhost:80/health"

    try:
        urllib.request.urlopen(url, context=ctx, timeout=5)
    except Exception as exc:
        print(f"Health check failed: {exc}", file=sys.stderr)
        sys.exit(1)


def _check_process():
    """Verify at least one Gunicorn worker process is alive via /proc."""
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as f:
                    cmdline = f.read()
                if b"gunicorn" in cmdline:
                    return
            except (OSError, PermissionError):
                continue
    except OSError:
        pass
    print("Health check failed: no gunicorn process found", file=sys.stderr)
    sys.exit(1)


if cert_required:
    _check_process()
else:
    _check_http()
