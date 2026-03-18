"""
UCM Name Lookup Service
=======================

A CURRI (Cisco Unified Routing Rules Interface) server that provides
phone number to display name lookup for Cisco Unified Communications
Manager (UCM).

The service:
    1. Loads a CSV file mapping phone numbers to display names into memory.
    2. Exposes an HTTP/HTTPS POST endpoint that accepts XACML requests from UCM.
    3. Parses the calling party number from the XACML request.
    4. Looks up the display name in the in-memory directory.
    5. Returns an XACML response with a Permit/Continue directive, including
       the display name if found. Calls are NEVER rejected.

CURRI Protocol Reference:
    https://developer.cisco.com/site/curri/

Usage:
    # Development (HTTP only):
    python main.py

    # Production with Gunicorn (HTTP):
    gunicorn -w 4 --threads 4 --worker-class gthread \\
        -b 0.0.0.0:80 main:app

    # Production with Gunicorn (HTTPS):
    gunicorn -w 4 --threads 4 --worker-class gthread \\
        -b 0.0.0.0:443 \\
        --certfile=server.crt --keyfile=server.key main:app

Configuration:
    Non-sensitive settings are defined in a YAML configuration file
    (default: config.yaml). The file supports multiple UCM cluster
    definitions, each with its own IP allow-list, CA certificate, and
    certificate subject validation rules.

    See config.yaml for the full schema and examples.

Environment Variables:
    CONFIG_FILE     - Path to the YAML configuration file
                      (default: config.yaml)
    LOG_LEVEL       - Logging level override: DEBUG, INFO, WARNING, ERROR
                      (overrides the value in config.yaml when set)
"""

import csv
import hashlib
import hmac
import ipaddress
import logging
import logging.handlers
import os
import secrets
import ssl
import sys
import threading
from dataclasses import dataclass, field
from xml.sax.saxutils import escape as xml_escape

from concurrent_log_handler import ConcurrentRotatingFileHandler
import yaml
from defusedxml import ElementTree as ET
from flask import Flask, Response, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Path to the YAML configuration file.
CONFIG_FILE = os.environ.get("CONFIG_FILE", "config.yaml")


def _load_config(config_path: str) -> dict:
    """Load configuration from a YAML file.

    Uses ``yaml.safe_load`` to prevent unsafe deserialization. Returns
    an empty dict when the file does not exist so that the application
    can start with sensible defaults.
    """
    if not os.path.isfile(config_path):
        # Cannot use logger yet — logging is configured after this.
        print(
            f"[WARNING] Config file not found: {config_path} — "
            "using built-in defaults"
        )
        return {}

    with open(config_path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if data is None:
        return {}

    if not isinstance(data, dict):
        print(
            f"[ERROR] Config file {config_path} must contain a YAML "
            "mapping at the top level"
        )
        sys.exit(1)

    return data


_config = _load_config(CONFIG_FILE)

# Path to the CSV file containing phone number -> display name mappings.
CSV_FILE_PATH = _config.get("csv_file_path", "phone_directory.csv")

# Flask development server bind address and port.
FLASK_HOST = _config.get("flask_host", "0.0.0.0")
FLASK_PORT = int(_config.get("flask_port", 5000))

# Optional TLS certificate and key for HTTPS in development mode.
# For production, configure TLS through Gunicorn's --certfile / --keyfile.
TLS_CERT_FILE = _config.get("tls_cert_file")
TLS_KEY_FILE = _config.get("tls_key_file")

# Logging verbosity level. The LOG_LEVEL environment variable, when
# set, takes precedence over the value in the config file.
LOG_LEVEL = os.environ.get(
    "LOG_LEVEL", _config.get("log_level", "INFO")
).upper()

# Insecure mode flag. When True, the application is allowed to run
# without TLS certificates (plain HTTP). When False (the default),
# the application refuses to start unless TLS is properly configured.
INSECURE_MODE = _config.get("insecure_mode", False) is True

# PII obfuscation flag. When True, phone numbers and display names are
# replaced with a salted HMAC-SHA256 hash in log output so that operators
# can correlate identical values without seeing the actual data.
OBFUSCATE_PII = _config.get("obfuscate_pii", False) is True

# Per-startup random salt for PII hashing. In production (Gunicorn),
# the salt is generated once in the master process and passed to workers
# via the _PII_SALT environment variable so all workers produce
# consistent hashes. In development (Flask dev server), a fresh salt
# is generated locally. The salt is never logged or persisted. This
# prevents precomputed rainbow-table attacks against the small keyspace
# of phone numbers. Because the salt changes on every restart, hashes
# from different process lifetimes are not comparable.
_pii_salt_hex = os.environ.get("_PII_SALT", "") if OBFUSCATE_PII else ""
_PII_SALT: bytes = (
    bytes.fromhex(_pii_salt_hex) if _pii_salt_hex
    else secrets.token_bytes(32) if OBFUSCATE_PII
    else b""
)


def _obfuscate_pii(value: str | None) -> str | None:
    """Return a privacy-safe representation of *value* for logging.

    When ``OBFUSCATE_PII`` is enabled, the value is hashed with
    HMAC-SHA256 using a per-startup random salt and the first 24 hex
    characters are returned wrapped in ``{! … !}`` delimiters. This
    allows log readers to recognise when two values are identical
    within the same process lifetime without revealing the underlying
    data.

    The random salt is generated from a CSPRNG at startup and kept
    only in memory. It is never logged or persisted, which prevents
    rainbow-table reversal of hashed phone numbers.

    When obfuscation is disabled the original value is returned unchanged.
    ``None`` and empty strings are passed through as-is.
    """
    if not OBFUSCATE_PII or not value:
        return value
    digest = hmac.new(
        _PII_SALT, value.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:24]
    return f"{{! {digest} !}}"


# Optional directory for rotating log files. When set, the application
# writes log files here in addition to stdout/stderr.
LOG_DIR = _config.get("log_dir")
LOG_MAX_BYTES = int(_config.get("log_max_bytes", 10 * 1024 * 1024))  # 10 MB
LOG_BACKUP_COUNT = int(_config.get("log_backup_count", 5))

# XACML 2.0 namespace used by UCM in CURRI requests.
XACML_NS = "urn:oasis:names:tc:xacml:2.0:context:schema:os"

# Cisco CURRI XACML attribute IDs for call information.
CURRI_ATTR_CALLING_NUMBER = "urn:Cisco:uc:1.0:callingnumber"
CURRI_ATTR_CALLED_NUMBER = "urn:Cisco:uc:1.0:callednumber"
CURRI_ATTR_TRANSFORMED_CGPN = "urn:Cisco:uc:1.0:transformedcgpn"
CURRI_ATTR_TRANSFORMED_CDPN = "urn:Cisco:uc:1.0:transformedcdpn"

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

_log_fmt = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_log_level = getattr(logging, LOG_LEVEL, logging.INFO)

# Console handler (always active — supports `docker logs`).
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_log_fmt)

logging.root.setLevel(_log_level)
logging.root.addHandler(_console_handler)

# Rotating file handler (active when log_dir is configured).
if LOG_DIR:
    os.makedirs(LOG_DIR, exist_ok=True)
    _file_handler = ConcurrentRotatingFileHandler(
        os.path.join(LOG_DIR, "app.log"),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
    )
    _file_handler.setFormatter(_log_fmt)
    logging.root.addHandler(_file_handler)

logger = logging.getLogger("ucm_name_lookup")

# ---------------------------------------------------------------------------
# Insecure Mode Warning
# ---------------------------------------------------------------------------

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

_insecure_mode_timer: threading.Timer | None = None


def _start_insecure_mode_warning() -> None:
    """Start a repeating timer that logs an insecure mode warning every hour.

    The timer runs as a daemon thread so it does not prevent the process
    from exiting.
    """
    global _insecure_mode_timer

    def _warn_and_reschedule() -> None:
        logger.warning(_INSECURE_HOURLY_MSG)
        _schedule_next()

    def _schedule_next() -> None:
        global _insecure_mode_timer
        _insecure_mode_timer = threading.Timer(3600, _warn_and_reschedule)
        _insecure_mode_timer.daemon = True
        _insecure_mode_timer.start()

    _schedule_next()


# ---------------------------------------------------------------------------
# UCM Cluster Definitions
# ---------------------------------------------------------------------------

@dataclass
class ClusterConfig:
    """Access rules for a single UCM cluster.

    A request is authorized by a cluster when **all** of the cluster's
    active rules match:

        * The client IP must fall within at least one network in
          ``allowed_networks``.  An empty list matches **no** IPs.
        * The client certificate must contain at least one CN or SAN
          in ``allowed_subjects``.  An empty set matches **no**
          subjects.

    In **insecure mode only**, when a cluster defines neither
    ``allowed_subjects`` nor ``ca_file``, the certificate subject
    check is skipped and only IP-based access control is enforced.
    In secure mode, every cluster must have certificate
    infrastructure or the service refuses to start.

    Every active rule uses deny-by-default semantics: configuring a
    rule but leaving it empty blocks all traffic for that criterion.
    """

    name: str
    allowed_networks: list[
        ipaddress.IPv4Network | ipaddress.IPv6Network
    ] = field(default_factory=list)
    allowed_subjects: set[str] = field(default_factory=set)
    ca_file: str | None = None


def _validate_ca_cert(
    ca_file: str, cluster_name: str
) -> bool:
    """Validate that a CA file contains a proper CA certificate.

    The file **must** contain a CA certificate (``CA:TRUE``). If a
    leaf certificate is detected instead, an error is logged and the
    application exits — the user must provide the CA certificate that
    signed the UCM's identity certificate, not the identity
    certificate itself.

    Returns ``True`` if the CA cert is valid, ``False`` otherwise.
    The TLS layer (Gunicorn with ``CERT_REQUIRED``) handles full
    chain validation at connection time.

    .. note::

        Leaf-certificate detection uses the private CPython API
        ``ssl._ssl._test_decode_cert``. There is no public Python
        API to decode a PEM certificate without loading it into a
        trust store. If this internal changes in a future CPython
        release the leaf-detection heuristic will need updating.
    """
    # --- Try loading as a CA certificate ---
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(ca_file)
        ca_certs = ctx.get_ca_certs()
        if ca_certs:
            return True
    except (ssl.SSLError, OSError) as exc:
        logger.error(
            "Cluster '%s': failed to load CA file '%s': %s",
            cluster_name,
            ca_file,
            exc,
        )
        return False

    # --- Detect leaf certificate and give a clear error ---
    try:
        cert_dict = ssl._ssl._test_decode_cert(ca_file)  # noqa: SLF001
        if cert_dict and cert_dict.get("subject"):
            logger.error(
                "Cluster '%s': '%s' is a leaf certificate (not a CA). "
                "The ca_file must be the CA certificate that signed "
                "the UCM's identity certificate — not the identity "
                "certificate itself. You can usually export the CA "
                "cert from UCM OS Administration under "
                "Security > Certificate Management.",
                cluster_name,
                ca_file,
            )
            sys.exit(1)
    except (AttributeError, TypeError, ValueError, OSError) as exc:
        logger.warning(
            "Cluster '%s': could not parse certificate '%s': %s",
            cluster_name,
            ca_file,
            exc,
        )

    logger.warning(
        "Cluster '%s': CA file '%s' contained no usable certificates",
        cluster_name,
        ca_file,
    )
    return False


def _parse_network_list(
    entries: list,
    cluster_name: str,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a list of IP / CIDR strings into network objects.

    Invalid entries are logged and skipped.
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in entries:
        entry = str(entry).strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.error(
                "Invalid entry in cluster '%s' allowed_ips, "
                "skipping: '%s'",
                cluster_name,
                entry,
            )
    return networks


def _parse_subject_list(entries: list) -> set[str]:
    """Parse a list of CN / SAN strings into a lower-cased set."""
    subjects: set[str] = set()
    for entry in entries:
        entry = str(entry).strip()
        if entry:
            subjects.add(entry.lower())
    return subjects


def _parse_clusters(raw_clusters: dict) -> list[ClusterConfig]:
    """Build :class:`ClusterConfig` objects from the ``clusters`` mapping
    in the YAML configuration file.

    Each key is a human-readable cluster name; the value is a dict with
    optional keys ``allowed_ips``, ``allowed_subjects``, and ``ca_file``.
    """
    clusters: list[ClusterConfig] = []
    if not raw_clusters:
        return clusters

    if not isinstance(raw_clusters, dict):
        logger.error(
            "'clusters' in config must be a YAML mapping (got %s)",
            type(raw_clusters).__name__,
        )
        sys.exit(1)

    for name, cfg in raw_clusters.items():
        if not isinstance(cfg, dict):
            logger.error(
                "Cluster '%s' must be a YAML mapping (got %s)",
                name,
                type(cfg).__name__,
            )
            sys.exit(1)

        networks = _parse_network_list(
            cfg.get("allowed_ips", []), str(name)
        )
        subjects = _parse_subject_list(
            cfg.get("allowed_subjects", [])
        )
        ca_file = cfg.get("ca_file")
        if ca_file is not None:
            ca_file = str(ca_file)
            if os.path.isfile(ca_file):
                if not _validate_ca_cert(ca_file, str(name)):
                    logger.error(
                        "Cluster '%s': CA file '%s' is not a valid CA "
                        "certificate — aborting startup",
                        name,
                        ca_file,
                    )
                    sys.exit(1)
            else:
                logger.error(
                    "Cluster '%s': CA file not found: %s", name, ca_file
                )
                sys.exit(1)

        clusters.append(
            ClusterConfig(
                name=str(name),
                allowed_networks=networks,
                allowed_subjects=subjects,
                ca_file=ca_file,
            )
        )
    return clusters


CLUSTERS: list[ClusterConfig] = _parse_clusters(
    _config.get("clusters", {})
)

if CLUSTERS:
    for _cl in CLUSTERS:
        _parts: list[str] = []
        if _cl.allowed_networks:
            _parts.append(
                f"{len(_cl.allowed_networks)} network(s): "
                + ", ".join(str(n) for n in _cl.allowed_networks)
            )
        if _cl.allowed_subjects:
            _parts.append(
                f"{len(_cl.allowed_subjects)} subject(s): "
                + ", ".join(sorted(_cl.allowed_subjects))
            )
        if _cl.ca_file:
            _parts.append(f"CA: {_cl.ca_file} (chain validated by TLS layer)")
        # In secure mode, every cluster must have cert infrastructure.
        # IP-only clusters (no allowed_subjects and no ca_file) are
        # only permitted in insecure mode.
        _has_cert_rules = bool(_cl.allowed_subjects) or bool(_cl.ca_file)
        if _cl.allowed_networks and not _has_cert_rules:
            if not INSECURE_MODE:
                logger.error(
                    "Cluster '%s' has allowed_ips but no "
                    "allowed_subjects or ca_file. In secure mode, "
                    "every cluster must define certificate "
                    "infrastructure (allowed_subjects and/or "
                    "ca_file). Either add them or set "
                    "'insecure_mode: true' for IP-only access.",
                    _cl.name,
                )
                sys.exit(1)
        if _parts:
            logger.info("Cluster '%s' — %s", _cl.name, "; ".join(_parts))
        else:
            logger.warning(
                "Cluster '%s' has no allowed_ips or allowed_subjects "
                "— all requests will be denied (deny-by-default)",
                _cl.name,
            )
else:
    if not INSECURE_MODE:
        logger.error(
            "No clusters defined and insecure_mode is not enabled. "
            "At least one cluster must be configured to restrict "
            "access to trusted UCM servers. Either:\n"
            "  1. Define one or more clusters in %s with allowed_ips, "
            "ca_file, and/or allowed_subjects\n"
            "  2. Set 'insecure_mode: true' in %s to bypass this "
            "requirement (development/testing only)",
            CONFIG_FILE,
            CONFIG_FILE,
        )
        sys.exit(1)
    logger.warning(
        "No clusters defined — IP filtering and certificate "
        "subject validation are DISABLED. All clients can reach "
        "the /curri endpoint. Define clusters in %s to restrict access.",
        CONFIG_FILE,
    )

if OBFUSCATE_PII:
    logger.info(
        "PII obfuscation is ENABLED — phone numbers and display names "
        "will appear as SHA-256 hashes in log output"
    )


# ---------------------------------------------------------------------------
# Combined CA Bundle Generation
# ---------------------------------------------------------------------------

def _generate_ca_bundle(
    clusters: list[ClusterConfig], bundle_path: str
) -> None:
    """Concatenate all unique cluster CA files into a single PEM bundle.

    The resulting file can be passed to Gunicorn's ``--ca-certs`` option
    so that the TLS layer trusts client certificates from every
    configured cluster.
    """
    seen: set[str] = set()
    ca_files: list[str] = []
    for cluster in clusters:
        if cluster.ca_file and cluster.ca_file not in seen:
            seen.add(cluster.ca_file)
            ca_files.append(cluster.ca_file)

    if not ca_files:
        logger.info(
            "No cluster defines ca_file — skipping CA bundle generation"
        )
        return

    try:
        with open(bundle_path, "w", encoding="utf-8") as out:
            for ca_path in ca_files:
                with open(ca_path, "r", encoding="utf-8") as ca_fh:
                    contents = ca_fh.read()
                    out.write(contents)
                    if not contents.endswith("\n"):
                        out.write("\n")
        logger.info(
            "Generated combined CA bundle (%d CA file(s)) → %s  "
            "Use this with Gunicorn: --ca-certs=%s --cert-reqs=2",
            len(ca_files),
            bundle_path,
            bundle_path,
        )
    except OSError as exc:
        logger.warning(
            "Could not write CA bundle to '%s': %s  "
            "You can manually concatenate your cluster CA files for "
            "Gunicorn's --ca-certs option.",
            bundle_path,
            exc,
        )


CA_BUNDLE_PATH: str | None = _config.get("ca_bundle_path")
if CA_BUNDLE_PATH and CLUSTERS:
    _generate_ca_bundle(CLUSTERS, CA_BUNDLE_PATH)


# ===========================================================================
# Client Certificate Helpers
# ===========================================================================

def _format_cert_name(name_tuple: tuple | None) -> str:
    """Format a certificate subject or issuer tuple into a readable string.

    Converts the nested-tuple format from :meth:`ssl.SSLSocket.getpeercert`
    into an OpenSSL-style one-line distinguished name, e.g.
    ``CN=server, O=Acme, C=US``.
    """
    if not name_tuple:
        return "<empty>"
    parts: list[str] = []
    for rdn in name_tuple:
        for attr_type, attr_value in rdn:
            parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts) if parts else "<empty>"


def _log_cert_details(cert: dict, label: str = "Client") -> None:
    """Log certificate details at DEBUG level for TLS troubleshooting.

    Outputs subject, issuer, serial number, validity dates, and SAN
    entries. Never logs private key material.
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
    logger.debug(
        "%s certificate details:\n"
        "  Subject : %s\n"
        "  Issuer  : %s\n"
        "  Serial  : %s\n"
        "  Valid   : %s → %s\n"
        "  SANs    : %s",
        label,
        _format_cert_name(cert.get("subject")),
        _format_cert_name(cert.get("issuer")),
        cert.get("serialNumber", "<unknown>"),
        cert.get("notBefore", "<unknown>"),
        cert.get("notAfter", "<unknown>"),
        ", ".join(
            f"{t}={v}" for t, v in cert.get("subjectAltName", ())
        ) or "<none>",
    )


def _log_trusted_ca_certs(ssl_ctx: ssl.SSLContext) -> None:
    """Log the subjects of all CA certificates in the trust store.

    Only produces output at DEBUG level. This helps diagnose
    ``unable to get local issuer certificate`` errors by showing
    exactly which CAs the TLS layer will accept.
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
    ca_certs = ssl_ctx.get_ca_certs()
    if not ca_certs:
        logger.debug("TLS trust store: <empty — no CA certs loaded>")
        return
    logger.debug(
        "TLS trust store contains %d CA certificate(s):", len(ca_certs)
    )
    for idx, ca in enumerate(ca_certs, 1):
        logger.debug(
            "  [%d] Subject: %s\n"
            "       Issuer : %s\n"
            "       Serial : %s\n"
            "       Valid  : %s → %s",
            idx,
            _format_cert_name(ca.get("subject")),
            _format_cert_name(ca.get("issuer")),
            ca.get("serialNumber", "<unknown>"),
            ca.get("notBefore", "<unknown>"),
            ca.get("notAfter", "<unknown>"),
        )


def _log_ca_bundle_contents(bundle_path: str) -> None:
    """Parse a PEM CA bundle and log each certificate at DEBUG level.

    This is the primary diagnostic tool for ``unable to get local
    issuer certificate`` errors — it shows exactly which CAs the TLS
    layer will trust during the handshake.
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
    if not os.path.isfile(bundle_path):
        logger.debug("CA bundle file not found: %s", bundle_path)
        return
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(bundle_path)
        _log_trusted_ca_certs(ctx)
    except (ssl.SSLError, OSError) as exc:
        logger.debug("Could not parse CA bundle '%s': %s", bundle_path, exc)


# Deferred call — helpers above must be defined before this executes.
if CA_BUNDLE_PATH and CLUSTERS:
    _log_ca_bundle_contents(CA_BUNDLE_PATH)


def _get_ssl_socket():
    """Return the underlying SSL socket for the current request.

    Checks Gunicorn's ``gunicorn.socket`` environ key first, then
    falls back to the Werkzeug dev server's ``werkzeug.request``
    handler connection.

    Returns the socket object or ``None``.
    """
    sock = request.environ.get("gunicorn.socket")
    if sock is not None and hasattr(sock, "getpeercert"):
        return sock
    handler = request.environ.get("werkzeug.request")
    if handler is not None:
        conn = getattr(handler, "connection", None)
        if conn is not None and hasattr(conn, "getpeercert"):
            return conn
    return None


def _get_peer_certificate() -> dict | None:
    """Extract the parsed peer (client) certificate.

    Returns the certificate dictionary from
    :meth:`ssl.SSLSocket.getpeercert`, or ``None`` if no
    verified certificate is available.
    """
    sock = _get_ssl_socket()
    if sock is not None:
        cert = sock.getpeercert()
        if cert:
            return cert
    return None


def _get_cert_subjects(cert: dict) -> set[str]:
    """Extract CN and SAN values from a parsed peer certificate.

    Collects:
        - Common Name (CN) from the ``subject`` field.
        - DNS names and IP addresses from ``subjectAltName``.

    All values are lower-cased for case-insensitive comparison.

    Args:
        cert: Certificate dictionary as returned by
              :meth:`ssl.SSLSocket.getpeercert`.

    Returns:
        A set of lower-cased subject identifiers found in the
        certificate.
    """
    subjects: set[str] = set()

    # Extract CN from subject RDN sequence.
    for rdn in cert.get("subject", ()):
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                subjects.add(attr_value.lower())

    # Extract DNS names and IP addresses from SAN.
    for san_type, san_value in cert.get("subjectAltName", ()):
        if san_type in ("DNS", "IP Address"):
            subjects.add(san_value.lower())

    return subjects


# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB


@app.after_request
def _set_security_headers(response):
    """Add defense-in-depth security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers.pop("Server", None)
    return response


@app.before_request
def _enforce_cluster_access():
    """Enforce per-cluster IP and certificate subject access rules.

    When clusters are defined in the configuration file, every request
    to the ``/curri`` endpoint must match **at least one** cluster.
    Matching means satisfying **all** of the cluster's active rules:

        1. The client IP must be within one of the cluster's
           ``allowed_ips`` networks.  An empty list denies all IPs.
        2. If the cluster has certificate infrastructure configured
           (``allowed_subjects`` or ``ca_file``), the client
           certificate must contain at least one CN or SAN in the
           cluster's ``allowed_subjects``.  An empty set denies all
           subjects.

    When a cluster defines neither ``allowed_subjects`` nor
    ``ca_file``, the certificate subject check is skipped entirely,
    allowing IP-only access control (typical for insecure mode).

    Every active rule uses **deny-by-default** semantics: configuring
    a rule but leaving it empty blocks all traffic for that criterion.

    The ``/health`` endpoint is restricted to localhost (``127.0.0.1``
    and ``::1``) so that only the Docker health check and local probes
    can reach it. This allows mTLS (``CERT_REQUIRED``) to remain
    strict for all external connections.

    When no clusters are configured, access is unrestricted (but the
    service refuses to start without clusters unless insecure mode
    is enabled).

    Returns ``403 Forbidden`` if the request does not match any cluster.
    """
    # Always restrict /health to localhost, regardless of cluster config.
    if request.path == "/health":
        if request.remote_addr in ("127.0.0.1", "::1"):
            return None
        logger.warning(
            "Denied /health request from non-local IP %s",
            request.remote_addr,
        )
        return Response("Forbidden\n", status=403, mimetype="text/plain")

    if not CLUSTERS:
        return None

    # --- Parse client IP ---
    client_ip_str = request.remote_addr
    try:
        client_ip = ipaddress.ip_address(client_ip_str)
    except ValueError:
        logger.warning(
            "Could not parse client IP '%s' — denying request",
            client_ip_str,
        )
        return Response("Forbidden\n", status=403, mimetype="text/plain")

    # --- Obtain client certificate for subject validation ---
    # With deny-by-default semantics, subject checks always run, so
    # we always need the client certificate when clusters are defined.
    cert = _get_peer_certificate()
    if cert:
        _log_cert_details(cert, "Client")
    else:
        logger.debug(
            "No client certificate available for request from %s",
            client_ip_str,
        )
    cert_subjects: set[str] | None = (
        _get_cert_subjects(cert) if cert else None
    )

    # --- Check each cluster until one matches ---
    # Every active rule uses deny-by-default: an empty
    # allowed_networks list matches no IPs, and an empty
    # allowed_subjects set matches no subjects. A cluster must
    # explicitly list what it permits.
    #
    # In insecure mode only, when a cluster has no certificate
    # infrastructure (no allowed_subjects AND no ca_file), the
    # subject check is skipped for IP-only access control. In
    # secure mode the startup check ensures every cluster has cert
    # infrastructure, so this branch is never reached.
    for cluster in CLUSTERS:
        # 1. IP check (empty list → deny all)
        if not any(client_ip in net for net in cluster.allowed_networks):
            logger.debug(
                "Cluster '%s': IP %s not in allowed_ips",
                cluster.name,
                client_ip_str,
            )
            continue

        # 2. Certificate subject check.
        #    Skipped only in insecure mode when the cluster has no
        #    cert infrastructure (no allowed_subjects and no ca_file).
        _has_cert_rules = bool(cluster.allowed_subjects) or bool(cluster.ca_file)
        if _has_cert_rules or not INSECURE_MODE:
            if cert_subjects is None:
                logger.debug(
                    "Cluster '%s': client certificate is not accessible",
                    cluster.name,
                )
                continue
            if not (cert_subjects & cluster.allowed_subjects):
                logger.debug(
                    "Cluster '%s': cert subjects %s do not match "
                    "allowed_subjects %s",
                    cluster.name,
                    sorted(cert_subjects),
                    sorted(cluster.allowed_subjects),
                )
                continue

        # Note: CA chain validation is handled by the TLS layer
        # (Gunicorn with CERT_REQUIRED). If the client cert does not
        # chain to a trusted root in the CA bundle, the TLS handshake
        # fails before the request reaches the application.

        # All defined rules passed — request is authorized.
        logger.debug(
            "Request from %s authorized via cluster '%s'",
            client_ip_str,
            cluster.name,
        )
        return None

    # --- No cluster matched — deny ---
    logger.warning(
        "Denied request from %s to %s — no matching cluster "
        "(checked %d cluster(s))",
        client_ip_str,
        request.path,
        len(CLUSTERS),
    )
    return Response("Forbidden\n", status=403, mimetype="text/plain")


# In-memory phone directory loaded from CSV at startup.
# exact_directory: keys are normalized phone numbers (digits only), values are display names.
# prefix_trie: a trie of normalized prefix patterns for longest-prefix matching.
exact_directory: dict[str, str] = {}
prefix_trie: "PrefixTrie | None" = None


# ===========================================================================
# Prefix Trie for Efficient Longest-Prefix Matching
# ===========================================================================

class PrefixTrie:
    """A trie (prefix tree) for efficient longest-prefix phone number matching.

    Each node in the trie represents a single digit. Nodes that correspond
    to the end of a registered prefix store a display name. Lookup walks
    the trie character-by-character and remembers the last (i.e. longest)
    prefix that had a name, giving O(m) performance where *m* is the length
    of the phone number being looked up.
    """

    __slots__ = ("_root", "_size")

    def __init__(self) -> None:
        # Each node is a dict: digit -> child-node-dict.
        # A special key None stores the display name at that prefix.
        self._root: dict = {}
        self._size: int = 0

    def insert(self, prefix: str, display_name: str) -> None:
        """Insert a prefix -> display_name mapping into the trie."""
        node = self._root
        for ch in prefix:
            node = node.setdefault(ch, {})
        node[None] = display_name
        self._size += 1

    def longest_prefix_match(self, number: str) -> str | None:
        """Return the display name for the longest prefix matching *number*.

        Walks the trie digit-by-digit and tracks the most recent node that
        stores a display name. Returns ``None`` if no prefix matches.
        """
        node = self._root
        result: str | None = None
        for ch in number:
            child = node.get(ch)
            if child is None:
                break
            node = child
            name = node.get(None)
            if name is not None:
                result = name
        return result

    def __len__(self) -> int:
        return self._size


# ===========================================================================
# CSV Directory Loader
# ===========================================================================

def load_phone_directory(
    csv_path: str,
) -> tuple[dict[str, str], PrefixTrie]:
    """Load a phone number -> display name mapping from a CSV file.

    The CSV file must have a header row with at least two columns:
        - ``phone_number``  : The phone number (e.g. "+12125551212")
        - ``display_name``  : The name to display (e.g. "John Doe")

    An optional third column controls the matching behavior:
        - ``match_type``    : ``exact`` (default) or ``prefix``

    When ``match_type`` is ``exact`` (or the column is absent), the
    incoming calling number must match the normalized phone number
    exactly. When ``match_type`` is ``prefix``, the phone number is
    treated as a digit prefix — any incoming number that *starts with*
    those digits will match. Exact matches are always evaluated before
    prefix matches, and the *longest* matching prefix wins.

    Phone numbers are normalized by stripping whitespace, dashes,
    parentheses, and dots while preserving a leading ``+`` for E.164
    compatibility, so that lookup matching is resilient to formatting
    differences between the CSV and UCM's calling party numbers.

    Important:
        Phone numbers in the CSV should include the country code if UCM
        sends numbers in E.164 format (e.g. "12125551212" rather than
        "2125551212") to ensure correct matching.

    Args:
        csv_path: Filesystem path to the CSV file.

    Returns:
        A tuple of ``(exact_directory, prefix_trie)`` where
        *exact_directory* is a dict mapping normalized phone numbers to
        display names and *prefix_trie* is a :class:`PrefixTrie` for
        longest-prefix lookups.

    Raises:
        FileNotFoundError: If the CSV file does not exist.
        SystemExit: If the CSV file is malformed or missing required columns.
    """
    directory: dict[str, str] = {}
    trie = PrefixTrie()
    logger.info("Loading phone directory from: %s", csv_path)

    if not os.path.isfile(csv_path):
        logger.error("Phone directory CSV file not found: %s", csv_path)
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    valid_match_types = {"exact", "prefix"}

    try:
        with open(csv_path, mode="r", encoding="utf-8-sig") as csvfile:
            reader = csv.DictReader(csvfile)

            # --- Validate header columns ---
            if reader.fieldnames is None:
                logger.error("CSV file is empty or has no header row: %s", csv_path)
                sys.exit(1)

            required_columns = {"phone_number", "display_name"}
            actual_columns = {name.strip().lower() for name in reader.fieldnames}
            if not required_columns.issubset(actual_columns):
                missing = required_columns - actual_columns
                logger.error(
                    "CSV file is missing required columns: %s. Found columns: %s",
                    missing,
                    reader.fieldnames,
                )
                sys.exit(1)

            has_match_type_column = "match_type" in actual_columns

            # --- Load rows into the directory ---
            exact_count = 0
            prefix_count = 0
            for row in reader:
                # Normalize column names so minor header formatting is tolerated.
                normalized_row = {
                    k.strip().lower(): v.strip() for k, v in row.items()
                }
                phone = normalize_phone_number(
                    normalized_row.get("phone_number", "")
                )
                name = normalized_row.get("display_name", "")
                match_type = (
                    normalized_row.get("match_type", "exact").lower()
                    if has_match_type_column
                    else "exact"
                )

                if not phone or not name:
                    logger.warning(
                        "Skipping invalid CSV row (empty phone or name): %s",
                        {k: _obfuscate_pii(v) for k, v in row.items()}
                        if OBFUSCATE_PII else row,
                    )
                    continue

                if match_type not in valid_match_types:
                    logger.warning(
                        "Skipping CSV row with invalid match_type '%s' "
                        "(expected 'exact' or 'prefix'): %s",
                        match_type,
                        {k: _obfuscate_pii(v) for k, v in row.items()}
                        if OBFUSCATE_PII else row,
                    )
                    continue

                if match_type == "prefix":
                    trie.insert(phone, name)
                    prefix_count += 1
                else:
                    directory[phone] = name
                    exact_count += 1

        logger.info(
            "Phone directory loaded successfully from %s: "
            "%d exact entries, %d prefix entries",
            csv_path,
            exact_count,
            prefix_count,
        )

    except csv.Error as e:
        logger.error("Error reading CSV file %s: %s", csv_path, e)
        sys.exit(1)

    return directory, trie


def normalize_phone_number(phone: str) -> str:
    """Normalize a phone number for consistent matching.

    Strips whitespace and removes common formatting characters:
    ``-``, ``(``, ``)``, ``.``, and spaces. A leading ``+`` is
    preserved because it is a valid component of E.164 numbers.

    Examples::

        "+1 (212) 555-1212"  ->  "+12125551212"
        "12125551212"        ->  "12125551212"
        "+12125551212"       ->  "+12125551212"

    Args:
        phone: The raw phone number string.

    Returns:
        A normalized string containing only digits and an optional
        leading ``+``.
    """
    for ch in ("-", "(", ")", ".", " "):
        phone = phone.replace(ch, "")
    return phone.strip()


# ===========================================================================
# XACML Request Parser
# ===========================================================================

def parse_xacml_request(xml_data: bytes) -> dict[str, str]:
    """Parse a CURRI XACML request from UCM and extract call attributes.

    UCM sends an XACML 2.0 XML POST whose ``<Subject>`` element contains
    Cisco-specific ``<Attribute>`` elements describing the call:

        - ``urn:Cisco:uc:1.0:callingnumber``   – calling party number
        - ``urn:Cisco:uc:1.0:callednumber``     – called party number
        - ``urn:Cisco:uc:1.0:transformedcgpn``  – transformed calling number
        - ``urn:Cisco:uc:1.0:transformedcdpn``  – transformed called number

    Uses ``defusedxml`` for safe XML parsing to prevent XXE attacks.

    Args:
        xml_data: Raw XML bytes from the HTTP POST body.

    Returns:
        A dictionary whose keys are CURRI AttributeId URNs and whose
        values are the corresponding ``<AttributeValue>`` text.
        Returns an empty dict if parsing fails.
    """
    attributes: dict[str, str] = {}

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        logger.error("Failed to parse XACML request XML: %s", e)
        return attributes

    # Cisco UC attribute IDs we care about.
    target_attributes = {
        CURRI_ATTR_CALLING_NUMBER,
        CURRI_ATTR_CALLED_NUMBER,
        CURRI_ATTR_TRANSFORMED_CGPN,
        CURRI_ATTR_TRANSFORMED_CDPN,
    }

    # Iterate over every <Attribute> element in the document regardless
    # of its parent (Subject, Resource, Action, Environment).
    for attr_elem in root.iter(f"{{{XACML_NS}}}Attribute"):
        attr_id = attr_elem.get("AttributeId", "")
        if attr_id in target_attributes:
            value_elem = attr_elem.find(f"{{{XACML_NS}}}AttributeValue")
            if value_elem is not None and value_elem.text:
                attributes[attr_id] = value_elem.text.strip()
                logger.debug(
                    "Parsed XACML attribute: %s = %s",
                    attr_id,
                    _obfuscate_pii(attributes[attr_id]),
                )

    return attributes


def get_calling_number(attributes: dict[str, str]) -> str | None:
    """Extract the calling party number from parsed XACML attributes.

    Tries the direct calling number first, then falls back to the
    transformed calling party global number (``transformedcgpn``).

    Args:
        attributes: Dictionary of parsed XACML attributes.

    Returns:
        The calling party number string, or ``None`` if not found.
    """
    calling_number = attributes.get(CURRI_ATTR_CALLING_NUMBER)
    if not calling_number:
        calling_number = attributes.get(CURRI_ATTR_TRANSFORMED_CGPN)
        if calling_number:
            logger.debug(
                "Using transformedcgpn as calling number: %s",
                _obfuscate_pii(calling_number),
            )
    return calling_number


# ===========================================================================
# XACML / CIXML Response Builder
# ===========================================================================

def build_continue_response(display_name: str | None = None) -> str:
    """Build a CURRI XACML response with a Permit / Continue directive.

    The response **always** permits the call to continue. If a
    ``display_name`` is provided, the embedded CIXML obligation includes
    a ``<modify>`` element that instructs UCM to update the calling party
    display name shown on the receiving phone.

    CIXML with name modification (conceptual, before entity-encoding)::

        <cixml ver="1.0">
          <continue>
            <modify callingname="John Doe"/>
          </continue>
        </cixml>

    CIXML without modification::

        <cixml ver="1.0">
          <continue></continue>
        </cixml>

    The CIXML payload is HTML-entity-encoded inside the XACML
    ``<AttributeValue>`` element, as required by the CURRI protocol.

    Args:
        display_name: The name to display for the calling party.
                      If ``None``, a simple continue (no modification)
                      is returned.

    Returns:
        The complete XACML XML response string.
    """
    if display_name:
        # Step 1 – Escape the display name for safe use inside an XML
        #          attribute value at the CIXML level. This prevents
        #          XML injection if the name contains special characters.
        safe_name = xml_escape(display_name, {'"': "&quot;", "'": "&apos;"})

        # Step 2 – Build the raw CIXML string.
        cixml_raw = (
            '<cixml ver="1.0">'
            "<continue>"
            f'<modify callingname="{safe_name}"/>'
            "</continue>"
            "</cixml>"
        )

        logger.info(
            "Building continue response with display name: %s",
            _obfuscate_pii(display_name),
        )
    else:
        cixml_raw = '<cixml ver="1.0"><continue></continue></cixml>'
        logger.info("Building simple continue response (no name match)")

    # Step 3 – Entity-encode the CIXML for embedding inside the XACML
    #          <AttributeValue> text content. UCM will decode these
    #          entities to recover the original CIXML XML and parse it.
    cixml_encoded = xml_escape(cixml_raw)

    # Step 4 – Assemble the complete XACML response envelope.
    xacml_response = (
        '<?xml encoding="UTF-8" version="1.0"?>'
        "<Response>"
        "<Result>"
        "<Decision>Permit</Decision>"
        "<Status></Status>"
        "<Obligations>"
        '<Obligation FulfillOn="Permit" '
        'ObligationId="urn:cisco:xacml:policy-attribute">'
        '<AttributeAssignment AttributeId="Policy:simplecontinue">'
        '<AttributeValue DataType='
        '"http://www.w3.org/2001/XMLSchema#string">'
        f"{cixml_encoded}"
        "</AttributeValue>"
        "</AttributeAssignment>"
        "</Obligation>"
        "</Obligations>"
        "</Result>"
        "</Response>"
    )

    return xacml_response


# ===========================================================================
# Phone Number Lookup
# ===========================================================================

def lookup_display_name(calling_number: str) -> str | None:
    """Look up a display name for a phone number in the in-memory directory.

    The number is normalized before lookup so that formatting differences
    between UCM and the CSV do not prevent a match.

    Lookup order:
        1. **Exact match** — O(1) dictionary lookup against numbers loaded
           with ``match_type=exact`` (or no ``match_type`` column).
        2. **Longest prefix match** — O(m) trie walk (where *m* is the
           digit length of the number) against numbers loaded with
           ``match_type=prefix``. The longest matching prefix wins.

    Args:
        calling_number: The raw calling party number from the CURRI request.

    Returns:
        The display name if found, or ``None`` if no match exists.
    """
    normalized = normalize_phone_number(calling_number)

    # --- 1. Try exact match first (O(1) dict lookup) ---
    display_name = exact_directory.get(normalized)
    if display_name:
        logger.info(
            "Exact match found: %s -> %s",
            _obfuscate_pii(calling_number),
            _obfuscate_pii(display_name),
        )
        return display_name

    # --- 2. Fall back to longest prefix match (O(m) trie lookup) ---
    if prefix_trie is not None:
        display_name = prefix_trie.longest_prefix_match(normalized)
        if display_name:
            logger.info(
                "Prefix match found: %s -> %s",
                _obfuscate_pii(calling_number),
                _obfuscate_pii(display_name),
            )
            return display_name

    logger.info(
        "No name match for number: %s (normalized: %s)",
        _obfuscate_pii(calling_number),
        _obfuscate_pii(normalized),
    )
    return None


# ===========================================================================
# Flask Routes
# ===========================================================================

@app.route("/curri", methods=["POST", "HEAD"])
def curri_endpoint():
    """CURRI API endpoint for UCM External Call Control (ECC) requests.

    Accepts XACML XML POST requests from Cisco UCM, extracts the calling
    party number, performs a phone directory lookup, and returns an XACML
    response with a Permit / Continue decision.

    Behavior:
        - Name found   : responds with Continue + modify callingname.
        - Name not found: responds with a simple Continue (no modification).
        - Calls are **NEVER** rejected regardless of the lookup result.

    UCM Configuration:
        Create an External Call Control Profile in UCM pointing to this
        endpoint::

            http(s)://<server>:<port>/curri

    Returns:
        A ``Flask.Response`` with the XACML XML body and Content-Type
        ``text/xml; charset="utf-8"``.
    """
    logger.debug("Received CURRI request from %s", request.remote_addr)

    # --- Respond to HEAD keepalive probes from UCM ---
    if request.method == "HEAD":
        return Response(status=200, content_type='text/xml; charset="utf-8"')

    # --- Validate Content-Type (defense-in-depth) ---
    content_type = request.content_type or ""
    if content_type and not (
        "text/xml" in content_type or "application/xml" in content_type
    ):
        logger.warning(
            "Unexpected Content-Type '%s' from %s — expected text/xml",
            content_type,
            request.remote_addr,
        )

    # --- Read the raw XML body from UCM ---
    xml_data = request.data
    if not xml_data:
        logger.warning(
            "Received empty request body from %s", request.remote_addr
        )
        # Return a continue response even on empty input – never reject.
        return Response(
            build_continue_response(),
            status=200,
            content_type='text/xml; charset="utf-8"',
        )

    if OBFUSCATE_PII:
        logger.debug(
            "Raw XACML request body suppressed (obfuscate_pii is enabled)"
        )
    else:
        logger.debug(
            "Raw XACML request body:\n%s",
            xml_data.decode("utf-8", errors="replace"),
        )

    # --- Parse the XACML request to extract call attributes ---
    attributes = parse_xacml_request(xml_data)

    # --- Extract the calling party number ---
    calling_number = get_calling_number(attributes)
    called_number = attributes.get(CURRI_ATTR_CALLED_NUMBER, "unknown")

    if calling_number:
        logger.info(
            "Processing lookup: calling=%s, called=%s",
            _obfuscate_pii(calling_number),
            _obfuscate_pii(called_number),
        )
        # Look up the display name for the calling number.
        display_name = lookup_display_name(calling_number)
    else:
        logger.warning("No calling number found in XACML request")
        display_name = None

    # --- Build and return the XACML response (always Permit + Continue) ---
    response_xml = build_continue_response(display_name)

    if OBFUSCATE_PII:
        logger.debug(
            "XACML response body suppressed (obfuscate_pii is enabled)"
        )
    else:
        logger.debug("XACML response:\n%s", response_xml)

    return Response(
        response_xml,
        status=200,
        content_type='text/xml; charset="utf-8"',
    )


@app.route("/health", methods=["GET"])
def health_check():
    """Simple health-check endpoint.

    Returns the service status and the number of entries currently loaded
    in the phone directory. Useful for monitoring and load-balancer
    health probes.

    Returns:
        A JSON response with ``status`` and ``directory_entries`` fields.
    """
    return {
        "status": "healthy",
        "exact_entries": len(exact_directory),
        "prefix_entries": len(prefix_trie) if prefix_trie else 0,
    }


# ===========================================================================
# Application Startup
# ===========================================================================

def initialize_app():
    """Load the phone directory into memory.

    Called once at import time so that every Gunicorn worker (or the
    development server) has the directory available for lookups before
    serving its first request.
    """
    global exact_directory, prefix_trie
    try:
        exact_directory, prefix_trie = load_phone_directory(CSV_FILE_PATH)
    except FileNotFoundError:
        logger.error(
            "Cannot start without a phone directory. "
            "Please create '%s' or set the CSV_FILE_PATH environment variable.",
            CSV_FILE_PATH,
        )
        sys.exit(1)


# Load the phone directory when the module is first imported.
# This ensures Gunicorn workers each have the directory in memory.
initialize_app()


if __name__ == "__main__":
    # -----------------------------------------------------------------------
    # Flask development server – use Gunicorn for production deployments.
    # -----------------------------------------------------------------------
    logger.info("Starting UCM Name Lookup CURRI server (development mode)")
    logger.info("CURRI endpoint: POST /curri")
    logger.info("Health check:   GET  /health")

    # Configure TLS if certificate and key files are provided.
    ssl_context = None
    _tls_configured = (
        TLS_CERT_FILE
        and TLS_KEY_FILE
        and os.path.isfile(TLS_CERT_FILE)
        and os.path.isfile(TLS_KEY_FILE)
    )

    if _tls_configured:
        # Build an SSLContext so we can optionally enable mTLS.
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
        logger.info(
            "TLS enabled with cert=%s key=%s", TLS_CERT_FILE, TLS_KEY_FILE
        )

        # --- Mutual TLS (mTLS) ---
        # Load CA certificates from all clusters that define a
        # ca_file. Each call to load_verify_locations() adds to
        # the trust store, so clients from any configured cluster
        # will be accepted at the TLS layer. Application-level
        # cluster matching (IP + subject) provides further filtering.
        ca_loaded = False
        seen_ca_files: set[str] = set()
        for cluster in CLUSTERS:
            if cluster.ca_file:
                if cluster.ca_file in seen_ca_files:
                    continue
                seen_ca_files.add(cluster.ca_file)
                if os.path.isfile(cluster.ca_file):
                    ssl_context.load_verify_locations(cluster.ca_file)
                    ca_loaded = True
                    logger.info(
                        "Loaded CA for cluster '%s': %s",
                        cluster.name,
                        cluster.ca_file,
                    )
                else:
                    logger.error(
                        "CA file not found for cluster '%s': %s",
                        cluster.name,
                        cluster.ca_file,
                    )
                    sys.exit(1)

        if ca_loaded:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            logger.info(
                "Mutual TLS enabled — client certificates are "
                "required for all connections"
            )
            _log_trusted_ca_certs(ssl_context)
        else:
            logger.info(
                "Mutual TLS is not configured (no cluster defines "
                "ca_file). Client certificates will not be verified."
            )
    elif TLS_CERT_FILE and TLS_KEY_FILE:
        # Cert/key paths are configured but files are missing.
        logger.error(
            "TLS certificate or key file not found: cert=%s, key=%s",
            TLS_CERT_FILE,
            TLS_KEY_FILE,
        )
        sys.exit(1)
    else:
        # --- Secure by default: require insecure_mode to run without TLS ---
        if not INSECURE_MODE:
            logger.error(
                "TLS is not configured and insecure_mode is not enabled. "
                "The service requires TLS certificates to start. Either:\n"
                "  1. Configure tls_cert_file and tls_key_file in %s\n"
                "     (see: ./setup_certs.sh --hostname <your-host>)\n"
                "  2. Set 'insecure_mode: true' in %s to allow plaintext "
                "HTTP (development/testing only)",
                CONFIG_FILE,
                CONFIG_FILE,
            )
            sys.exit(1)

        # Insecure mode explicitly enabled — warn loudly.
        logger.warning(_INSECURE_BANNER)
        logger.warning(_INSECURE_HOURLY_MSG)
        _start_insecure_mode_warning()

    logger.info("Listening on %s:%d", FLASK_HOST, FLASK_PORT)

    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        ssl_context=ssl_context,
        debug=False,
    )
