#!/usr/bin/env bash
# ===========================================================================
# setup_certs.sh — Certificate helper for UCM Name Lookup Service
# ===========================================================================
# Generates TLS server certificates for the application. Two modes:
#
#   selfsigned   Generate a self-signed certificate that can be uploaded
#                directly to UCM's CallManager-trust store.
#
#   csr          Generate a Certificate Signing Request (CSR) for your
#                organization's CA to sign. Once signed, place the
#                certificate at <out-dir>/server.crt.
#
# Both modes produce a private key at <out-dir>/server.key. The hostname
# is embedded as the Subject CN and as a Subject Alternative Name (SAN).
#
# Dependencies:
#   - openssl (OpenSSL CLI) — must be installed and available in PATH.
#     macOS: included by default (LibreSSL) or install via `brew install openssl`
#     Linux: `apt install openssl` / `yum install openssl`
#
# Usage:
#   ./setup_certs.sh --hostname <fqdn_or_ip> [options]
#
# Examples:
#   ./setup_certs.sh --hostname curri.example.com
#   ./setup_certs.sh --hostname curri.example.com --mode csr
#   ./setup_certs.sh --hostname 10.1.1.50 --key-type rsa --days 730
# ===========================================================================
set -euo pipefail

# ---- Defaults ----
MODE="selfsigned"
OUT_DIR="certs"
DAYS=365
KEY_TYPE="ecdsa"
HOSTNAME=""

# ---- Color helpers (disabled when not a terminal) ----
if [[ -t 1 ]]; then
    BOLD='\033[1m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    RESET='\033[0m'
else
    BOLD='' GREEN='' YELLOW='' CYAN='' RESET=''
fi

# ---- Usage ----
usage() {
    cat <<EOF
Usage: $0 --hostname <fqdn_or_ip> [options]

Generate TLS certificates for the UCM Name Lookup Service.

Required:
  --hostname <value>        FQDN or IP address for the certificate CN and SAN

Options:
  --mode <selfsigned|csr>   Certificate mode (default: selfsigned)
  --out-dir <dir>           Output directory (default: certs)
  --days <n>                Validity period in days, selfsigned only (default: 365)
  --key-type <ecdsa|rsa>    Key algorithm: ecdsa (P-256) or rsa (4096-bit)
                            (default: ecdsa)
  -h, --help                Show this help

Modes:
  selfsigned   Generates a self-signed certificate. Upload it directly to
               UCM's CallManager-trust certificate store.

  csr          Generates a Certificate Signing Request. Submit it to your
               CA for signing, then save the signed certificate as
               <out-dir>/server.crt.
EOF
    exit "${1:-0}"
}

# ---- Parse arguments ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostname)   HOSTNAME="$2";  shift 2 ;;
        --mode)       MODE="$2";      shift 2 ;;
        --out-dir)    OUT_DIR="$2";   shift 2 ;;
        --days)       DAYS="$2";      shift 2 ;;
        --key-type)   KEY_TYPE="$2";  shift 2 ;;
        -h|--help)    usage 0 ;;
        *)            echo "Error: unknown option: $1" >&2; usage 1 ;;
    esac
done

# ---- Validate ----
if [[ -z "$HOSTNAME" ]]; then
    echo "Error: --hostname is required." >&2
    echo "" >&2
    usage 1
fi

if [[ "$MODE" != "selfsigned" && "$MODE" != "csr" ]]; then
    echo "Error: --mode must be 'selfsigned' or 'csr'." >&2
    exit 1
fi

if [[ "$KEY_TYPE" != "ecdsa" && "$KEY_TYPE" != "rsa" ]]; then
    echo "Error: --key-type must be 'ecdsa' or 'rsa'." >&2
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    echo "Error: openssl is required but not found in PATH." >&2
    exit 1
fi

# ---- File paths ----
KEY_FILE="$OUT_DIR/server.key"
CSR_FILE="$OUT_DIR/server.csr"
CRT_FILE="$OUT_DIR/server.crt"

# ---- Guard against overwriting existing keys ----
if [[ -f "$KEY_FILE" ]]; then
    echo -e "${YELLOW}Warning:${RESET} $KEY_FILE already exists."
    read -rp "Overwrite? (y/N) " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# ---- Create output directory ----
mkdir -p "$OUT_DIR"

# ---- Determine SAN type (IP address vs DNS name) ----
if [[ "$HOSTNAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN_ENTRY="IP:$HOSTNAME"
else
    SAN_ENTRY="DNS:$HOSTNAME"
fi

# ---- Build temporary OpenSSL config ----
OPENSSL_CONF=$(mktemp)
trap 'rm -f "$OPENSSL_CONF"' EXIT

cat > "$OPENSSL_CONF" <<CONF
[req]
default_md         = sha256
prompt             = no
distinguished_name = dn
req_extensions     = v3_req

[dn]
CN = $HOSTNAME

[v3_req]
subjectAltName     = $SAN_ENTRY
keyUsage           = critical, digitalSignature, keyEncipherment
extendedKeyUsage   = serverAuth

[v3_self]
subjectAltName     = $SAN_ENTRY
keyUsage           = critical, digitalSignature, keyEncipherment
extendedKeyUsage   = serverAuth
basicConstraints   = critical, CA:FALSE
CONF

# ---- Generate private key ----
echo -e "${BOLD}Generating $KEY_TYPE private key...${RESET}"
if [[ "$KEY_TYPE" == "ecdsa" ]]; then
    openssl ecparam -genkey -name prime256v1 -noout -out "$KEY_FILE" 2>/dev/null
else
    openssl genrsa -out "$KEY_FILE" 4096 2>/dev/null
fi
chmod 600 "$KEY_FILE"
echo -e "  ${GREEN}✓${RESET} $KEY_FILE"

# ===========================================================================
# Mode: CSR
# ===========================================================================
if [[ "$MODE" == "csr" ]]; then
    echo -e "${BOLD}Generating Certificate Signing Request...${RESET}"
    openssl req -new \
        -key "$KEY_FILE" \
        -out "$CSR_FILE" \
        -config "$OPENSSL_CONF" 2>/dev/null
    echo -e "  ${GREEN}✓${RESET} $CSR_FILE"

    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD} CSR Generated Successfully${RESET}"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""
    echo "Files created:"
    echo "  Private key : $KEY_FILE  (keep this secret!)"
    echo "  CSR         : $CSR_FILE"
    echo ""
    echo -e "${BOLD}CSR contents (submit this to your CA):${RESET}"
    echo ""
    cat "$CSR_FILE"
    echo ""
    echo -e "${CYAN}--- Next Steps ---${RESET}"
    echo ""
    echo "  1. Submit the CSR above to your Certificate Authority for signing."
    echo ""
    echo "  2. When you receive the signed certificate, save it as:"
    echo -e "     ${BOLD}$CRT_FILE${RESET}"
    echo ""
    echo "  3. Export UCM's CA certificate from each cluster:"
    echo "     Cisco Unified OS Administration > Security >"
    echo "     Certificate Management > Find > download 'CallManager.pem'"
    echo "     Save it to: $OUT_DIR/<cluster-name>-CallManager.pem"
    echo ""
    echo "  4. Upload this service's signed certificate ($CRT_FILE) to UCM:"
    echo "     Cisco Unified OS Administration > Security >"
    echo "     Certificate Management > Upload Certificate"
    echo "     Certificate Purpose: CallManager-trust"
    echo "     Repeat for every UCM node in the cluster."
    echo ""
    echo "  5. Configure config.yaml with your cluster settings."
    echo "     See the 'mTLS Setup Guide' section in README.md."
    echo ""
    echo "  6. Restart the Cisco CallManager service on each UCM node"
    echo "     for certificate changes to take effect."
    echo ""
    echo -e "  ${CYAN}Docker note:${RESET} The container runs as uid 1000. Ensure the"
    echo "  cert files are readable by that user on the deployment server:"
    echo "    sudo chown 1000:1000 $KEY_FILE $CRT_FILE"
    echo ""

# ===========================================================================
# Mode: Self-signed
# ===========================================================================
else
    echo -e "${BOLD}Generating self-signed certificate (valid for $DAYS days)...${RESET}"
    openssl req -new -x509 \
        -key "$KEY_FILE" \
        -out "$CRT_FILE" \
        -days "$DAYS" \
        -config "$OPENSSL_CONF" \
        -extensions v3_self 2>/dev/null
    echo -e "  ${GREEN}✓${RESET} $CRT_FILE"

    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD} Self-Signed Certificate Generated Successfully${RESET}"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""
    echo "Files created:"
    echo "  Private key  : $KEY_FILE  (keep this secret!)"
    echo "  Certificate  : $CRT_FILE"
    echo ""
    echo "Certificate details:"
    openssl x509 -noout -subject -dates -ext subjectAltName \
        -in "$CRT_FILE" 2>/dev/null | sed 's/^/  /'
    echo ""
    echo -e "${CYAN}--- Next Steps ---${RESET}"
    echo ""
    echo "  1. Upload the certificate to UCM:"
    echo "     Cisco Unified OS Administration > Security >"
    echo "     Certificate Management > Upload Certificate"
    echo "     Certificate Purpose: CallManager-trust"
    echo -e "     File: ${BOLD}$CRT_FILE${RESET}"
    echo "     Repeat for every UCM node in the cluster."
    echo ""
    echo "  2. Export UCM's CA certificate from each cluster:"
    echo "     Cisco Unified OS Administration > Security >"
    echo "     Certificate Management > Find > download 'CallManager.pem'"
    echo "     Save it to: $OUT_DIR/<cluster-name>-CallManager.pem"
    echo ""
    echo "  3. Configure config.yaml with your cluster settings."
    echo "     See the 'mTLS Setup Guide' section in README.md."
    echo ""
    echo "  4. Restart the Cisco CallManager service on each UCM node"
    echo "     for certificate changes to take effect."
    echo ""
    echo -e "  ${CYAN}Docker note:${RESET} The container runs as uid 1000. Ensure the"
    echo "  cert files are readable by that user on the deployment server:"
    echo "    sudo chown 1000:1000 $KEY_FILE $CRT_FILE"
    echo ""
fi
