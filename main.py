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

Environment Variables:
    CSV_FILE_PATH   - Path to the phone directory CSV file
                      (default: phone_directory.csv)
    FLASK_HOST      - Host to bind to in dev mode (default: 0.0.0.0)
    FLASK_PORT      - Port to bind to in dev mode (default: 5000)
    TLS_CERT_FILE   - Path to TLS certificate file (optional, dev HTTPS)
    TLS_KEY_FILE    - Path to TLS private key file (optional, dev HTTPS)
    LOG_LEVEL       - Logging level: DEBUG, INFO, WARNING, ERROR
                      (default: INFO)
"""

import csv
import logging
import os
import sys
from xml.sax.saxutils import escape as xml_escape

from defusedxml import ElementTree as ET
from flask import Flask, Response, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Path to the CSV file containing phone number -> display name mappings.
CSV_FILE_PATH = os.environ.get("CSV_FILE_PATH", "phone_directory.csv")

# Flask development server bind address and port.
FLASK_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.environ.get("FLASK_PORT", "5000"))

# Optional TLS certificate and key for HTTPS in development mode.
# For production, configure TLS through Gunicorn's --certfile / --keyfile.
TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE")

# Logging verbosity level.
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

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

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ucm_name_lookup")

# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------

app = Flask(__name__)

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

    Each node in the trie represents a single digit.  Nodes that correspond
    to the end of a registered prefix store a display name.  Lookup walks
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
        stores a display name.  Returns ``None`` if no prefix matches.
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
    exactly.  When ``match_type`` is ``prefix``, the phone number is
    treated as a digit prefix — any incoming number that *starts with*
    those digits will match.  Exact matches are always evaluated before
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
                        "Skipping invalid CSV row (empty phone or name): %s", row
                    )
                    continue

                if match_type not in valid_match_types:
                    logger.warning(
                        "Skipping CSV row with invalid match_type '%s' "
                        "(expected 'exact' or 'prefix'): %s",
                        match_type,
                        row,
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
    ``-``, ``(``, ``)``, ``.``, and spaces.  A leading ``+`` is
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
                    attributes[attr_id],
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
                "Using transformedcgpn as calling number: %s", calling_number
            )
    return calling_number


# ===========================================================================
# XACML / CIXML Response Builder
# ===========================================================================

def build_continue_response(display_name: str | None = None) -> str:
    """Build a CURRI XACML response with a Permit / Continue directive.

    The response **always** permits the call to continue.  If a
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
        #          attribute value at the CIXML level.  This prevents
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
            "Building continue response with display name: %s", display_name
        )
    else:
        cixml_raw = '<cixml ver="1.0"><continue></continue></cixml>'
        logger.info("Building simple continue response (no name match)")

    # Step 3 – Entity-encode the CIXML for embedding inside the XACML
    #          <AttributeValue> text content.  UCM will decode these
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
           ``match_type=prefix``.  The longest matching prefix wins.

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
            "Exact match found: %s -> %s", calling_number, display_name
        )
        return display_name

    # --- 2. Fall back to longest prefix match (O(m) trie lookup) ---
    if prefix_trie is not None:
        display_name = prefix_trie.longest_prefix_match(normalized)
        if display_name:
            logger.info(
                "Prefix match found: %s -> %s", calling_number, display_name
            )
            return display_name

    logger.info(
        "No name match for number: %s (normalized: %s)",
        calling_number,
        normalized,
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
            calling_number,
            called_number,
        )
        # Look up the display name for the calling number.
        display_name = lookup_display_name(calling_number)
    else:
        logger.warning("No calling number found in XACML request")
        display_name = None

    # --- Build and return the XACML response (always Permit + Continue) ---
    response_xml = build_continue_response(display_name)

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
    in the phone directory.  Useful for monitoring and load-balancer
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
            "Cannot start without a phone directory.  "
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
    logger.info("Listening on %s:%d", FLASK_HOST, FLASK_PORT)
    logger.info("CURRI endpoint: POST /curri")
    logger.info("Health check:   GET  /health")

    # Configure TLS if certificate and key files are provided.
    ssl_context = None
    if TLS_CERT_FILE and TLS_KEY_FILE:
        if os.path.isfile(TLS_CERT_FILE) and os.path.isfile(TLS_KEY_FILE):
            ssl_context = (TLS_CERT_FILE, TLS_KEY_FILE)
            logger.info(
                "TLS enabled with cert=%s key=%s", TLS_CERT_FILE, TLS_KEY_FILE
            )
        else:
            logger.error(
                "TLS certificate or key file not found: cert=%s, key=%s",
                TLS_CERT_FILE,
                TLS_KEY_FILE,
            )
            sys.exit(1)
    else:
        logger.warning(
            "TLS is not configured – running in plaintext HTTP mode.  "
            "Set TLS_CERT_FILE and TLS_KEY_FILE for HTTPS, or use "
            "Gunicorn's --certfile / --keyfile options in production."
        )

    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        ssl_context=ssl_context,
        debug=False,
    )
