"""Gunicorn configuration with automatic TLS and mTLS detection.

Reads ``config.yaml`` (or the path in ``CONFIG_FILE``) and:

1. Generates the CA bundle from cluster ``ca_file`` entries so that
   ``--ca-certs`` can reference it before workers start.
2. If a server certificate and key are found, enables HTTPS on port 443.
3. If the CA bundle is available, enables mTLS (client cert required).

When no certificates are detected, Gunicorn binds to port 80 over
plain HTTP — no manual ``GUNICORN_CMD_ARGS`` needed in either case.

Any setting here can be overridden via ``GUNICORN_CMD_ARGS``.
"""

import os
import ssl

import yaml

# ---------------------------------------------------------------------------
# Base Gunicorn settings
# ---------------------------------------------------------------------------

workers = 4
threads = 4
worker_class = "gthread"
bind = "0.0.0.0:80"
worker_tmp_dir = "/dev/shm"
timeout = 30
accesslog = "-"
errorlog = "-"

# ---------------------------------------------------------------------------
# Load application config (same file the app uses at runtime)
# ---------------------------------------------------------------------------

_config_path = os.environ.get("CONFIG_FILE", "config.yaml")
_config = {}
if os.path.isfile(_config_path):
    with open(_config_path, encoding="utf-8") as _f:
        _config = yaml.safe_load(_f) or {}

_cert = _config.get("tls_cert_file", "certs/server.crt")
_key = _config.get("tls_key_file", "certs/server.key")
_bundle_path = _config.get("ca_bundle_path", "")
_clusters = _config.get("clusters", {})

# ---------------------------------------------------------------------------
# Generate CA bundle from cluster CA files
# ---------------------------------------------------------------------------
# This runs before Gunicorn creates its TLS listener, so the bundle
# file is ready for --ca-certs by the time the socket is bound.

if _bundle_path and isinstance(_clusters, dict):
    _seen: set[str] = set()
    _ca_files: list[str] = []
    for _cdata in _clusters.values():
        if isinstance(_cdata, dict):
            _ca = _cdata.get("ca_file")
            if _ca and _ca not in _seen and os.path.isfile(_ca):
                _seen.add(_ca)
                _ca_files.append(_ca)
    if _ca_files:
        try:
            with open(_bundle_path, "w", encoding="utf-8") as _out:
                for _p in _ca_files:
                    with open(_p, encoding="utf-8") as _fh:
                        _c = _fh.read()
                        _out.write(_c)
                        if not _c.endswith("\n"):
                            _out.write("\n")
        except OSError:
            _bundle_path = ""

# ---------------------------------------------------------------------------
# Auto-detect TLS
# ---------------------------------------------------------------------------

if os.path.isfile(_cert) and os.path.isfile(_key):
    certfile = _cert
    keyfile = _key
    bind = "0.0.0.0:443"

    # Enable mTLS if the CA bundle is available.
    if _bundle_path and os.path.isfile(_bundle_path):
        ca_certs = _bundle_path
        cert_reqs = ssl.CERT_REQUIRED
