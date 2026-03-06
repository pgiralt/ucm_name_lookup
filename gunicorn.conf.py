"""Gunicorn configuration with automatic TLS and mTLS detection.

Reads ``config.yaml`` (or the path in ``CONFIG_FILE``) and:

1. Generates the CA bundle from cluster ``ca_file`` entries so that
   ``--ca-certs`` can reference it before workers start.
2. If a server certificate and key are found, enables HTTPS on port 443.
3. If the CA bundle is available, enables mTLS (client cert required).

When no certificates are detected, the service **refuses to start**
unless ``insecure_mode: true`` is set in the configuration file.
If insecure mode is enabled, Gunicorn binds to port 80 over plain
HTTP with prominent security warnings.

Any setting here can be overridden via ``GUNICORN_CMD_ARGS``.
"""

import os
import ssl
import sys
import threading

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
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# ---------------------------------------------------------------------------
# Load application config (same file the app uses at runtime)
# ---------------------------------------------------------------------------

_config_path = os.environ.get("CONFIG_FILE", "config.yaml")
_config = {}
if os.path.isfile(_config_path):
    with open(_config_path, encoding="utf-8") as _f:
        _config = yaml.safe_load(_f) or {}

# --- Log directory with rotation ---
# When log_dir is set, write Gunicorn access and error logs to rotating
# files there in addition to the console. Uses Python's RotatingFileHandler
# so log files are automatically rotated before they fill the disk.
_log_dir = _config.get("log_dir")
_log_max_bytes = int(_config.get("log_max_bytes", 10 * 1024 * 1024))  # 10 MB
_log_backup_count = int(_config.get("log_backup_count", 5))

if _log_dir:
    os.makedirs(_log_dir, exist_ok=True)
    _access_log_file = os.path.join(_log_dir, "access.log")
    _error_log_file = os.path.join(_log_dir, "error.log")

    logconfig_dict = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "generic": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "access": {
                "format": "%(asctime)s [ACCESS] %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "generic",
                "stream": "ext://sys.stderr",
            },
            "error_file": {
                "class": "concurrent_log_handler.ConcurrentRotatingFileHandler",
                "formatter": "generic",
                "filename": _error_log_file,
                "maxBytes": _log_max_bytes,
                "backupCount": _log_backup_count,
            },
            "access_console": {
                "class": "logging.StreamHandler",
                "formatter": "access",
                "stream": "ext://sys.stdout",
            },
            "access_file": {
                "class": "concurrent_log_handler.ConcurrentRotatingFileHandler",
                "formatter": "access",
                "filename": _access_log_file,
                "maxBytes": _log_max_bytes,
                "backupCount": _log_backup_count,
            },
        },
        "loggers": {
            "gunicorn.error": {
                "level": "INFO",
                "handlers": ["console", "error_file"],
                "propagate": False,
            },
            "gunicorn.access": {
                "level": "INFO",
                "handlers": ["access_console", "access_file"],
                "propagate": False,
            },
        },
        "root": {
            "level": "INFO",
            "handlers": ["console"],
        },
    }

_cert = _config.get("tls_cert_file", "certs/server.crt")
_key = _config.get("tls_key_file", "certs/server.key")
_bundle_path = _config.get("ca_bundle_path", "")
_clusters = _config.get("clusters", {})
_insecure_mode = _config.get("insecure_mode", False) is True

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

_INSECURE_BANNER = (
    "\n"
    "########################################################################\n"
    "#                                                                      #\n"
    "#                    WARNING: INSECURE MODE ENABLED                    #\n"
    "#                                                                      #\n"
    "#  This service is running WITHOUT TLS encryption. All traffic,        #\n"
    "#  including CURRI requests and responses, is transmitted in plain     #\n"
    "#  text and is vulnerable to eavesdropping and tampering.              #\n"
    "#                                                                      #\n"
    "#  This mode is intended for development and testing ONLY.             #\n"
    "#  Do NOT use insecure mode in production.                             #\n"
    "#                                                                      #\n"
    "#  To enable TLS, configure tls_cert_file and tls_key_file in          #\n"
    "#  config.yaml and set insecure_mode to false (or remove it).          #\n"
    "#                                                                      #\n"
    "########################################################################"
)

_INSECURE_HOURLY_MSG = (
    "SECURITY WARNING: This service is running in INSECURE MODE without "
    "TLS encryption. All traffic is unencrypted. Configure TLS certificates "
    "and disable insecure_mode for production use."
)


def _start_insecure_mode_warning() -> None:
    """Start a repeating timer that logs an insecure mode warning every hour."""
    import logging as _logging

    _warn_logger = _logging.getLogger("ucm_name_lookup")

    def _warn_and_reschedule() -> None:
        _warn_logger.warning(_INSECURE_HOURLY_MSG)
        _schedule_next()

    def _schedule_next() -> None:
        _t = threading.Timer(3600, _warn_and_reschedule)
        _t.daemon = True
        _t.start()

    _schedule_next()


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
            except Exception as _exc:
                print(
                    f"[DEBUG] Could not inspect CA bundle: {_exc}"
                )
else:
    # --- Secure by default: require insecure_mode to run without TLS ---
    if not _insecure_mode:
        print(
            "[ERROR] TLS is not configured and insecure_mode is not "
            "enabled. The service requires TLS certificates to start. "
            "Either:\n"
            "  1. Place server certificate and key at the configured paths\n"
            f"     (cert: {_cert}, key: {_key})\n"
            "     (see: ./setup_certs.sh --hostname <your-host>)\n"
            f"  2. Set 'insecure_mode: true' in {_config_path} to allow "
            "plaintext HTTP (development/testing only)",
            file=sys.stderr,
        )
        sys.exit(1)

    # Insecure mode explicitly enabled — warn loudly.
    print(_INSECURE_BANNER, file=sys.stderr)
    print(
        f"[WARNING] {_INSECURE_HOURLY_MSG}",
        file=sys.stderr,
    )
    _start_insecure_mode_warning()
