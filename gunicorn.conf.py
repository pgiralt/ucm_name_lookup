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

_log_level = os.environ.get(
    "LOG_LEVEL", _config.get("log_level", "INFO")
).upper()

if os.path.isfile(_cert) and os.path.isfile(_key):
    certfile = _cert
    keyfile = _key
    bind = "0.0.0.0:443"

    # Enable mTLS if the CA bundle is available.
    # CERT_REQUIRED means all TLS connections must present a valid
    # client certificate signed by a CA in the bundle. The ca_file
    # entries in config.yaml must be CA certificates, not leaf certs.
    if _bundle_path and os.path.isfile(_bundle_path):
        ca_certs = _bundle_path
        cert_reqs = ssl.CERT_REQUIRED

    # --- TLS debug diagnostics (only when LOG_LEVEL=DEBUG) ---
    if _log_level == "DEBUG":
        print("[DEBUG] gunicorn TLS configuration:")
        print(f"  certfile  = {_cert}")
        print(f"  keyfile   = {_key}")
        print(f"  ca_certs  = {_bundle_path or '<none>'}")
        _cr_label = "none (no mTLS)"
        if _bundle_path and os.path.isfile(_bundle_path):
            _cr_label = "CERT_REQUIRED"
        print(f"  cert_reqs = {_cr_label}")
        if _bundle_path and os.path.isfile(_bundle_path):
            try:
                _dbg_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                _dbg_ctx.load_verify_locations(_bundle_path)
                _dbg_ca_list = _dbg_ctx.get_ca_certs()
                print(
                    f"[DEBUG] CA bundle contains "
                    f"{len(_dbg_ca_list)} CA certificate(s):"
                )
                for _i, _ca in enumerate(_dbg_ca_list, 1):
                    _subj_parts = []
                    for _rdn in _ca.get("subject", ()):
                        for _at, _av in _rdn:
                            _subj_parts.append(f"{_at}={_av}")
                    _iss_parts = []
                    for _rdn in _ca.get("issuer", ()):
                        for _at, _av in _rdn:
                            _iss_parts.append(f"{_at}={_av}")
                    print(
                        f"  [{_i}] Subject: "
                        f"{', '.join(_subj_parts) or '<empty>'}"
                    )
                    print(
                        f"       Issuer : "
                        f"{', '.join(_iss_parts) or '<empty>'}"
                    )
                    print(
                        f"       Serial : "
                        f"{_ca.get('serialNumber', '<unknown>')}"
                    )
                    print(
                        f"       Valid  : "
                        f"{_ca.get('notBefore', '?')} → "
                        f"{_ca.get('notAfter', '?')}"
                    )
                # Also check for leaf certs in the bundle
                import re as _re
                with open(_bundle_path, "r", encoding="utf-8") as _bf:
                    _pem = _bf.read()
                _blocks = _re.findall(
                    r"(-----BEGIN CERTIFICATE-----"
                    r".*?"
                    r"-----END CERTIFICATE-----)",
                    _pem,
                    _re.DOTALL,
                )
                import tempfile as _tf
                _leaf_n = 0
                for _blk in _blocks:
                    with _tf.NamedTemporaryFile(
                        mode="w", suffix=".pem", delete=True
                    ) as _tmp:
                        _tmp.write(_blk)
                        _tmp.flush()
                        try:
                            _cd = ssl._ssl._test_decode_cert(
                                _tmp.name
                            )
                            _tc = ssl.SSLContext(
                                ssl.PROTOCOL_TLS_CLIENT
                            )
                            _tc.load_verify_locations(_tmp.name)
                            if _cd and not _tc.get_ca_certs():
                                _leaf_n += 1
                                _sp = []
                                for _r in _cd.get("subject", ()):
                                    for _a, _v in _r:
                                        _sp.append(f"{_a}={_v}")
                                _ip = []
                                for _r in _cd.get("issuer", ()):
                                    for _a, _v in _r:
                                        _ip.append(f"{_a}={_v}")
                                print(
                                    f"  [leaf-{_leaf_n}] Subject: "
                                    f"{', '.join(_sp)}"
                                )
                                print(
                                    f"              Issuer : "
                                    f"{', '.join(_ip)}"
                                )
                        except Exception:
                            pass
                if _leaf_n:
                    print(
                        f"[DEBUG] Bundle also contains "
                        f"{_leaf_n} leaf certificate(s) "
                        f"(not CA — used for identity matching)"
                    )
            except Exception as _exc:
                print(
                    f"[DEBUG] Could not inspect CA bundle: {_exc}"
                )
