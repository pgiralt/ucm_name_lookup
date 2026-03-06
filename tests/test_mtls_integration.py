"""End-to-end mTLS integration tests.

Spins up the Flask dev server with real TLS certificates on an ephemeral
port and makes HTTPS requests with client certificates to verify the
full mTLS flow, including chain validation and subject matching.
"""

import ipaddress
import ssl
import threading
import time
from unittest.mock import patch

import pytest
import urllib.request

import main
from tests.cert_helpers import (
    generate_ca,
    generate_leaf,
    write_pem_cert,
    write_pem_key,
)


def _find_free_port() -> int:
    """Find an available TCP port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_flask_tls(
    app,
    ssl_context: ssl.SSLContext,
    host: str,
    port: int,
) -> threading.Thread:
    """Start the Flask app in a background thread with the given SSLContext."""
    t = threading.Thread(
        target=app.run,
        kwargs={
            "host": host,
            "port": port,
            "ssl_context": ssl_context,
            "debug": False,
            "use_reloader": False,
        },
        daemon=True,
    )
    t.start()
    # Give the server time to bind
    time.sleep(0.5)
    return t


@pytest.fixture()
def mtls_server(tmp_path):
    """Start a Flask dev server with mTLS using ephemeral test certs.

    Yields a dict with connection info and cert paths.
    """
    # Generate CA
    ca_cert, ca_key = generate_ca(cn="Test mTLS CA")
    ca_path = write_pem_cert(ca_cert, tmp_path / "ca.pem")

    # Generate server cert
    server_cert, server_key = generate_leaf(
        ca_cert, ca_key, cn="localhost",
        san_dns=["localhost"], san_ips=["127.0.0.1"],
    )
    server_cert_path = write_pem_cert(server_cert, tmp_path / "server.pem")
    server_key_path = write_pem_key(server_key, tmp_path / "server-key.pem")

    # Generate client cert (trusted by same CA)
    client_cert, client_key = generate_leaf(
        ca_cert, ca_key, cn="cucm.example.com",
        san_dns=["cucm.example.com"],
    )
    client_cert_path = write_pem_cert(client_cert, tmp_path / "client.pem")
    client_key_path = write_pem_key(client_key, tmp_path / "client-key.pem")

    # Generate client cert signed by a different (untrusted) CA
    rogue_ca_cert, rogue_ca_key = generate_ca(cn="Rogue CA")
    rogue_cert, rogue_key = generate_leaf(
        rogue_ca_cert, rogue_ca_key, cn="rogue.example.com",
    )
    rogue_cert_path = write_pem_cert(rogue_cert, tmp_path / "rogue.pem")
    rogue_key_path = write_pem_key(rogue_key, tmp_path / "rogue-key.pem")

    # Build server SSLContext with mTLS
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server_ctx.load_cert_chain(server_cert_path, server_key_path)
    server_ctx.load_verify_locations(ca_path)
    server_ctx.verify_mode = ssl.CERT_REQUIRED

    # Configure clusters so the app enforces subject matching
    cluster = main.ClusterConfig(
        name="test-mtls",
        allowed_networks=[ipaddress.ip_network("127.0.0.1/32")],
        allowed_subjects={"cucm.example.com"},
        ca_file=ca_path,
    )
    original_clusters = main.CLUSTERS
    main.CLUSTERS = [cluster]
    main.app.config["TESTING"] = True

    port = _find_free_port()
    _start_flask_tls(main.app, server_ctx, "127.0.0.1", port)

    yield {
        "port": port,
        "ca_path": ca_path,
        "client_cert_path": client_cert_path,
        "client_key_path": client_key_path,
        "rogue_cert_path": rogue_cert_path,
        "rogue_key_path": rogue_key_path,
    }

    main.CLUSTERS = original_clusters


def _make_client_ctx(
    ca_path: str,
    client_cert_path: str | None = None,
    client_key_path: str | None = None,
) -> ssl.SSLContext:
    """Build a client SSLContext that trusts the test CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_path)
    if client_cert_path and client_key_path:
        ctx.load_cert_chain(client_cert_path, client_key_path)
    return ctx


class TestMtlsHandshake:
    def test_valid_client_cert_accepted(self, mtls_server):
        """A client cert signed by the trusted CA with matching subject
        should complete the handshake and get a 200."""
        ctx = _make_client_ctx(
            mtls_server["ca_path"],
            mtls_server["client_cert_path"],
            mtls_server["client_key_path"],
        )
        url = f"https://localhost:{mtls_server['port']}/health"
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, context=ctx)
        assert resp.status == 200

    def test_no_client_cert_rejected(self, mtls_server):
        """Without a client cert, mTLS handshake should fail."""
        ctx = _make_client_ctx(mtls_server["ca_path"])
        url = f"https://localhost:{mtls_server['port']}/health"
        req = urllib.request.Request(url)
        with pytest.raises((ssl.SSLError, urllib.error.URLError)):
            urllib.request.urlopen(req, context=ctx)

    def test_untrusted_client_cert_rejected(self, mtls_server):
        """A client cert signed by an untrusted CA should be rejected
        at the TLS layer."""
        ctx = _make_client_ctx(
            mtls_server["ca_path"],
            mtls_server["rogue_cert_path"],
            mtls_server["rogue_key_path"],
        )
        url = f"https://localhost:{mtls_server['port']}/health"
        req = urllib.request.Request(url)
        with pytest.raises((ssl.SSLError, urllib.error.URLError)):
            urllib.request.urlopen(req, context=ctx)

    def test_curri_post_with_valid_cert(self, mtls_server):
        """A full CURRI POST through mTLS should return 200 with Permit.

        Werkzeug's dev server does not expose the client certificate
        through the WSGI environ the way Gunicorn does, so we mock
        _get_peer_certificate to simulate what Gunicorn provides after
        a successful TLS handshake. The TLS-layer tests above already
        prove that cert chain validation works."""
        mock_cert = {
            "subject": ((("commonName", "cucm.example.com"),),),
            "subjectAltName": (("DNS", "cucm.example.com"),),
        }
        ctx = _make_client_ctx(
            mtls_server["ca_path"],
            mtls_server["client_cert_path"],
            mtls_server["client_key_path"],
        )
        url = f"https://localhost:{mtls_server['port']}/curri"
        xml_body = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<Request xmlns="urn:oasis:names:tc:xacml:2.0:context:schema:os">'
            b"<Subject>"
            b'<Attribute AttributeId="urn:Cisco:uc:1.0:callingnumber">'
            b"<AttributeValue>+12125551001</AttributeValue>"
            b"</Attribute>"
            b"</Subject>"
            b"</Request>"
        )
        req = urllib.request.Request(
            url, data=xml_body,
            headers={"Content-Type": "text/xml"},
            method="POST",
        )
        with patch.object(main, "_get_peer_certificate", return_value=mock_cert):
            resp = urllib.request.urlopen(req, context=ctx)
        assert resp.status == 200
        body = resp.read()
        assert b"<Decision>Permit</Decision>" in body
        assert b"Alice Johnson" in body

    def test_head_keepalive_with_valid_cert(self, mtls_server):
        """HEAD /curri keepalive should work through mTLS.

        See test_curri_post_with_valid_cert for why mock is needed."""
        mock_cert = {
            "subject": ((("commonName", "cucm.example.com"),),),
            "subjectAltName": (("DNS", "cucm.example.com"),),
        }
        ctx = _make_client_ctx(
            mtls_server["ca_path"],
            mtls_server["client_cert_path"],
            mtls_server["client_key_path"],
        )
        url = f"https://localhost:{mtls_server['port']}/curri"
        req = urllib.request.Request(url, method="HEAD")
        with patch.object(main, "_get_peer_certificate", return_value=mock_cert):
            resp = urllib.request.urlopen(req, context=ctx)
        assert resp.status == 200
