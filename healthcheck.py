"""Docker HEALTHCHECK script — verifies the service is running.

Behavior depends on the TLS / mTLS configuration detected from
``config.yaml``:

* **HTTP or HTTPS (no mTLS)** — probes ``/health`` via HTTP(S).
* **mTLS (CERT_REQUIRED)** — verifies that Gunicorn worker processes
  are alive via ``/proc``, since the TLS layer rejects connections
  without a valid client certificate.
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
clusters = config.get("clusters", {})

tls_enabled = os.path.isfile(cert) and os.path.isfile(key)

# mTLS is active when TLS is enabled and at least one cluster
# defines a ca_file. In that case Gunicorn uses CERT_REQUIRED
# and the health check cannot connect without a client certificate,
# so we fall back to a process-level check.
mtls_enabled = False
if tls_enabled and isinstance(clusters, dict):
    for cdata in clusters.values():
        if isinstance(cdata, dict) and cdata.get("ca_file"):
            mtls_enabled = True
            break


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


if mtls_enabled:
    _check_process()
else:
    _check_http()
