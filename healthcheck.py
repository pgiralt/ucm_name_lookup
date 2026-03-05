"""Docker HEALTHCHECK script — probes the /health endpoint.

Auto-detects whether the server is running HTTPS or HTTP by checking
for the presence of TLS certificate files, then hits the appropriate URL.
"""

import os
import ssl
import sys
import urllib.request

import yaml

config_path = os.environ.get("CONFIG_FILE", "config.yaml")
config = {}
if os.path.isfile(config_path):
    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

cert = config.get("tls_cert_file", "certs/server.crt")
key = config.get("tls_key_file", "certs/server.key")

if os.path.isfile(cert) and os.path.isfile(key):
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
