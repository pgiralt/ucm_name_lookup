"""Tests for certificate subject extraction, formatting, and logging helpers."""

import logging

import main
from tests.cert_helpers import generate_ca, generate_leaf


# ===========================================================================
# _get_cert_subjects
# ===========================================================================

class TestGetCertSubjects:
    def test_extracts_cn(self):
        cert_dict = {
            "subject": ((("commonName", "cucm.example.com"),),),
            "subjectAltName": (),
        }
        subjects = main._get_cert_subjects(cert_dict)
        assert "cucm.example.com" in subjects

    def test_extracts_dns_san(self):
        cert_dict = {
            "subject": ((("commonName", "cn-value"),),),
            "subjectAltName": (("DNS", "san.example.com"),),
        }
        subjects = main._get_cert_subjects(cert_dict)
        assert "san.example.com" in subjects
        assert "cn-value" in subjects

    def test_extracts_ip_san(self):
        cert_dict = {
            "subject": ((("commonName", "server"),),),
            "subjectAltName": (("IP Address", "10.0.0.1"),),
        }
        subjects = main._get_cert_subjects(cert_dict)
        assert "10.0.0.1" in subjects

    def test_lowercases_all_values(self):
        cert_dict = {
            "subject": ((("commonName", "CUCM.Example.COM"),),),
            "subjectAltName": (("DNS", "SAN.Example.COM"),),
        }
        subjects = main._get_cert_subjects(cert_dict)
        assert "cucm.example.com" in subjects
        assert "san.example.com" in subjects

    def test_empty_cert_returns_empty_set(self):
        cert_dict = {"subject": (), "subjectAltName": ()}
        subjects = main._get_cert_subjects(cert_dict)
        assert subjects == set()

    def test_multiple_rdns(self):
        cert_dict = {
            "subject": (
                (("organizationName", "Acme Corp"),),
                (("commonName", "server.acme.com"),),
            ),
            "subjectAltName": (),
        }
        subjects = main._get_cert_subjects(cert_dict)
        assert "server.acme.com" in subjects
        assert "acme corp" not in subjects  # only CN is extracted

    def test_multiple_sans(self):
        cert_dict = {
            "subject": ((("commonName", "primary"),),),
            "subjectAltName": (
                ("DNS", "alt1.example.com"),
                ("DNS", "alt2.example.com"),
                ("IP Address", "192.168.1.1"),
            ),
        }
        subjects = main._get_cert_subjects(cert_dict)
        assert subjects == {"primary", "alt1.example.com", "alt2.example.com", "192.168.1.1"}

    def test_ignores_non_dns_non_ip_san_types(self):
        cert_dict = {
            "subject": ((("commonName", "host"),),),
            "subjectAltName": (
                ("email", "admin@example.com"),
                ("URI", "https://example.com"),
                ("DNS", "valid.example.com"),
            ),
        }
        subjects = main._get_cert_subjects(cert_dict)
        assert "valid.example.com" in subjects
        assert "admin@example.com" not in subjects


# ===========================================================================
# _format_cert_name
# ===========================================================================

class TestFormatCertName:
    def test_formats_simple_subject(self):
        name_tuple = ((("commonName", "server"),),)
        result = main._format_cert_name(name_tuple)
        assert "commonName=server" in result

    def test_formats_multiple_rdns(self):
        name_tuple = (
            (("commonName", "server"),),
            (("organizationName", "Acme"),),
        )
        result = main._format_cert_name(name_tuple)
        assert "commonName=server" in result
        assert "organizationName=Acme" in result

    def test_empty_tuple_returns_empty_marker(self):
        assert main._format_cert_name(()) == "<empty>"

    def test_none_returns_empty_marker(self):
        assert main._format_cert_name(None) == "<empty>"


# ===========================================================================
# _log_cert_details
# ===========================================================================

class TestLogCertDetails:
    def test_logs_cert_fields_at_debug(self, caplog):
        cert_dict = {
            "subject": ((("commonName", "test-server"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "serialNumber": "ABCD1234",
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Dec 31 23:59:59 2025 GMT",
            "subjectAltName": (("DNS", "test-server.local"),),
        }
        with caplog.at_level(logging.DEBUG, logger="ucm_name_lookup"):
            main._log_cert_details(cert_dict, "Test")
        assert "test-server" in caplog.text
        assert "Test CA" in caplog.text
        assert "ABCD1234" in caplog.text
        assert "test-server.local" in caplog.text

    def test_no_output_above_debug(self, caplog):
        cert_dict = {
            "subject": ((("commonName", "test"),),),
            "issuer": ((("commonName", "CA"),),),
        }
        with caplog.at_level(logging.INFO, logger="ucm_name_lookup"):
            main._log_cert_details(cert_dict, "Test")
        assert "test" not in caplog.text


# ===========================================================================
# _log_trusted_ca_certs
# ===========================================================================

class TestLogTrustedCaCerts:
    def test_logs_ca_certs_from_context(self, tmp_path, caplog):
        import ssl
        ca_cert, _ = generate_ca(cn="Trusted Test CA")
        from tests.cert_helpers import write_pem_cert
        ca_path = write_pem_cert(ca_cert, tmp_path / "ca.pem")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(ca_path)

        with caplog.at_level(logging.DEBUG, logger="ucm_name_lookup"):
            main._log_trusted_ca_certs(ctx)
        assert "Trusted Test CA" in caplog.text

    def test_logs_empty_trust_store(self, caplog):
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Don't load any CA certs — trust store is empty
        with caplog.at_level(logging.DEBUG, logger="ucm_name_lookup"):
            main._log_trusted_ca_certs(ctx)
        assert "empty" in caplog.text.lower()
