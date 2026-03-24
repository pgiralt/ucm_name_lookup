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

import errno
import logging
import os
import secrets
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
worker_tmp_dir = "/dev/shm" if os.path.isdir("/dev/shm") else None
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

# --- Require at least one cluster in secure mode ---
if not _insecure_mode and not _clusters:
    print(
        "[ERROR] No clusters defined and insecure_mode is not enabled. "
        "At least one cluster must be configured to restrict access to "
        "trusted UCM servers. Either:\n"
        f"  1. Define one or more clusters in {_config_path} with "
        "allowed_ips, ca_file, and/or allowed_subjects\n"
        f"  2. Set 'insecure_mode: true' in {_config_path} to bypass "
        "this requirement (development/testing only)",
        file=sys.stderr,
    )
    sys.exit(1)

# --- Require ca_bundle_path when clusters define ca_file ---
# Without ca_bundle_path, the CA bundle is never generated and Gunicorn
# cannot enable CERT_REQUIRED — meaning mTLS is silently inactive even
# though clusters expect client certificates.
if not _insecure_mode and isinstance(_clusters, dict):
    _any_ca_file = any(
        isinstance(cdata, dict) and cdata.get("ca_file")
        for cdata in _clusters.values()
    )
    if _any_ca_file and not _bundle_path:
        print(
            "[ERROR] One or more clusters define 'ca_file' but "
            "'ca_bundle_path' is not configured. Gunicorn needs "
            "ca_bundle_path to generate the CA bundle for mTLS "
            "(client certificate verification).\n"
            f"  Add 'ca_bundle_path: certs/ca-bundle.pem' to "
            f"{_config_path}\n"
            "  (In Docker with certs/ mounted read-only, use a "
            "writable path such as /tmp/ca-bundle.pem)",
            file=sys.stderr,
        )
        sys.exit(1)

# --- PII obfuscation salt ---
# Generate the HMAC salt once in the master process and expose it via an
# environment variable so that every forked worker inherits the same value.
# This ensures consistent hashes across all workers for a given run.
if _config.get("obfuscate_pii", False) is True:
    os.environ["_PII_SALT"] = secrets.token_bytes(32).hex()

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
        except OSError as _exc:
            if not _insecure_mode:
                print(
                    f"[ERROR] Failed to generate CA bundle at "
                    f"'{_bundle_path}': {_exc}\n"
                    "  Ensure the path is writable or use a different "
                    "ca_bundle_path.",
                    file=sys.stderr,
                )
                sys.exit(1)
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


if not _insecure_mode and os.path.isfile(_cert) and os.path.isfile(_key):
    certfile = _cert
    keyfile = _key
    bind = "0.0.0.0:443"

    # Enable mTLS if the CA bundle is available.
    # CERT_REQUIRED means all TLS connections must present a valid
    # client certificate signed by a CA in the bundle. The ca_file
    # entries in config.yaml must be CA certificates, not leaf certs.
    _mtls_enabled = False
    if _bundle_path and os.path.isfile(_bundle_path):
        ca_certs = _bundle_path
        cert_reqs = ssl.CERT_REQUIRED
        _mtls_enabled = True

    if _mtls_enabled:
        print(
            "[INFO] Mutual TLS (mTLS) is ENABLED — client certificates "
            "are required for all connections (ca_certs=%s)" % _bundle_path,
            file=sys.stderr,
        )
    else:
        print(
            "[INFO] TLS is enabled but mTLS is NOT active — client "
            "certificates will not be verified. To enable mTLS, "
            "configure ca_bundle_path and cluster ca_file entries "
            "in %s" % _config_path,
            file=sys.stderr,
        )

    # --- TLS handshake failure logging & TLSv1.2 enforcement ---
    # Gunicorn's gthread worker catches TLS errors at DEBUG level in
    # its handle() method, making failures invisible in production.
    #
    # We use three layers of defence to surface these errors:
    #
    #   Layer 1 — ssl_wrap_socket patch (all worker types)
    #     Catches errors during the eager handshake when
    #     do_handshake_on_connect=True.
    #
    #   Layer 2 — enqueue_req wrapper (gthread only)
    #     Prevents unhandled handshake exceptions from crashing the
    #     gthread event-loop thread.
    #
    #   Layer 3 — HTTP parser wrapper (gthread only)
    #     Catches TLS errors during lazy handshakes that happen inside
    #     handle() → next(conn.parser). The wrapper logs at WARNING
    #     before re-raising, so handle() still performs its cleanup.
    #     This is the critical fallback: if do_handshake_on_connect
    #     is not applied for any reason, this layer still catches
    #     the error.
    #
    # All three patches are applied in post_fork where server.log
    # (the Gunicorn Logger) is fully initialised with handlers.
    do_handshake_on_connect = True

    def ssl_context(conf, default_ssl_context_factory):
        ctx = default_ssl_context_factory()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def post_fork(server, worker):
        import gunicorn.sock as _gsock

        # ---- Layer 1: patch gunicorn.sock.ssl_wrap_socket ----------
        _orig_ssl_wrap = _gsock.ssl_wrap_socket

        def _logging_ssl_wrap_socket(sock, conf):
            server.log.debug(
                "ssl_wrap_socket called "
                "(do_handshake_on_connect=%s)",
                conf.do_handshake_on_connect,
            )
            try:
                return _orig_ssl_wrap(sock, conf)
            except ssl.SSLError as exc:
                try:
                    peer = sock.getpeername()
                    peer_str = f"{peer[0]}:{peer[1]}"
                except (OSError, IndexError):
                    peer_str = "<unknown>"
                server.log.warning(
                    "TLS handshake failed from %s: %s", peer_str, exc
                )
                raise
            except OSError as exc:
                try:
                    peer = sock.getpeername()
                    peer_str = f"{peer[0]}:{peer[1]}"
                except (OSError, IndexError):
                    peer_str = "<unknown>"
                server.log.warning(
                    "TLS handshake failed from %s "
                    "(client disconnected — may have rejected the "
                    "server certificate): %s",
                    peer_str, exc,
                )
                raise

        _gsock.ssl_wrap_socket = _logging_ssl_wrap_socket

        # ---- gthread-specific layers (2 & 3) ----------------------
        if not hasattr(worker, "enqueue_req"):
            server.log.info("TLS handshake failure logging enabled")
            return

        # ---- Layer 2: wrap enqueue_req -----------------------------
        _original_enqueue = worker.enqueue_req

        def _safe_enqueue_req(conn):
            try:
                _original_enqueue(conn)
            except (ssl.SSLError, OSError) as exc:
                server.log.debug(
                    "enqueue_req caught %s: %s",
                    type(exc).__name__, exc,
                )
                try:
                    conn.close()
                except Exception:
                    pass
                worker.nr_conns -= 1
            except Exception as exc:
                server.log.warning(
                    "Unexpected error in enqueue_req: %s: %s",
                    type(exc).__name__, exc,
                )
                try:
                    conn.close()
                except Exception:
                    pass
                worker.nr_conns -= 1

        worker.enqueue_req = _safe_enqueue_req

        # ---- Layer 3: wrap TConn's HTTP parser ---------------------
        # The gthread handle() method does:
        #     req = next(conn.parser)
        # If do_handshake_on_connect is not effective, the TLS
        # handshake happens lazily here. handle() catches
        # ssl.SSLError and EnvironmentError at DEBUG level.
        # Our wrapper intercepts them first at WARNING.
        #
        # Additionally, when a client completes the TLS handshake
        # but then disconnects without sending HTTP data (e.g. UCM
        # rejects the server certificate post-handshake), handle()
        # sees StopIteration or SSL_ERROR_EOF and logs at DEBUG.
        # We detect this on the *first* next() call and escalate
        # to WARNING.

        try:
            from gunicorn.http.errors import NoMoreData as _NoMoreData
        except ImportError:
            _NoMoreData = None

        class _TlsLoggingParser:
            """Proxy around Gunicorn's HTTP RequestParser that logs
            TLS errors at WARNING before they reach handle()."""

            __slots__ = ("_parser", "_log", "_client", "_first")

            def __init__(self, parser, log, client):
                self._parser = parser
                self._log = log
                self._client = client
                self._first = True

            def _peer_str(self):
                try:
                    return f"{self._client[0]}:{self._client[1]}"
                except (IndexError, TypeError):
                    return "<unknown>"

            def __next__(self):
                is_first = self._first
                self._first = False
                try:
                    return next(self._parser)
                except ssl.SSLError as exc:
                    if exc.args[0] == ssl.SSL_ERROR_EOF:
                        if is_first:
                            self._log.warning(
                                "Client %s established TLS but "
                                "disconnected without sending "
                                "data (SSL EOF — may have rejected "
                                "the server certificate)",
                                self._peer_str(),
                            )
                    else:
                        self._log.warning(
                            "TLS error from %s: %s",
                            self._peer_str(), exc,
                        )
                    raise
                except StopIteration:
                    if is_first:
                        self._log.warning(
                            "Client %s established TLS but "
                            "disconnected without sending "
                            "data (may have rejected the server "
                            "certificate)",
                            self._peer_str(),
                        )
                    raise
                except OSError as exc:
                    if exc.errno in (
                        errno.ECONNRESET,
                        errno.ENOTCONN,
                        errno.EPIPE,
                    ):
                        self._log.warning(
                            "Client %s disconnected during TLS "
                            "(may have rejected the server "
                            "certificate): %s",
                            self._peer_str(), exc,
                        )
                    raise
                except Exception:
                    if is_first and _NoMoreData is not None:
                        import sys
                        exc_type = sys.exc_info()[0]
                        if issubclass(exc_type, _NoMoreData):
                            self._log.warning(
                                "Client %s established TLS but "
                                "disconnected without sending "
                                "complete data (may have rejected "
                                "the server certificate)",
                                self._peer_str(),
                            )
                    raise

            def __iter__(self):
                return self

            def __getattr__(self, name):
                return getattr(self._parser, name)

        try:
            import gunicorn.workers.gthread as _gthread
        except ImportError:
            _gthread = None

        if _gthread is not None:
            _orig_tconn_init = _gthread.TConn.init

            def _logging_tconn_init(self):
                _orig_tconn_init(self)
                if self.cfg.is_ssl and self.parser is not None:
                    self.parser = _TlsLoggingParser(
                        self.parser, server.log, self.client,
                    )

            _gthread.TConn.init = _logging_tconn_init

        server.log.info(
            "TLS handshake failure logging enabled "
            "(do_handshake_on_connect=%s, parser_wrapper=%s)",
            worker.cfg.do_handshake_on_connect,
            _gthread is not None,
        )

    # --- TLS debug diagnostics (only when LOG_LEVEL=DEBUG) ---
    if _log_level == "DEBUG":
        print("[DEBUG] gunicorn TLS configuration:")
        print(f"  certfile  = {_cert}")
        print(f"  keyfile   = {_key}")
        print(f"  ca_certs  = {_bundle_path or '<none>'}")
        print(f"  cert_reqs = {'CERT_REQUIRED' if _mtls_enabled else 'none (no mTLS)'}")
        print(f"  min_ver   = TLSv1.2")
        if _mtls_enabled:
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
