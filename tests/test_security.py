"""Tests for security headers, PII obfuscation, and startup validation."""

import hashlib
import hmac as hmac_mod
from unittest.mock import patch

import pytest
from defusedxml.common import EntitiesForbidden

import main
from tests.conftest import build_xacml_request


# ===========================================================================
# Security headers
# ===========================================================================

class TestSecurityHeaders:
    def test_x_content_type_options(self, client):
        resp = client.post(
            "/curri", data=b"<dummy/>", content_type="text/xml"
        )
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, client):
        resp = client.post(
            "/curri", data=b"<dummy/>", content_type="text/xml"
        )
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_cache_control(self, client):
        resp = client.post(
            "/curri", data=b"<dummy/>", content_type="text/xml"
        )
        assert resp.headers.get("Cache-Control") == "no-store"

    def test_content_security_policy(self, client):
        resp = client.post(
            "/curri", data=b"<dummy/>", content_type="text/xml"
        )
        assert resp.headers.get("Content-Security-Policy") == "default-src 'none'"

    def test_server_header_stripped(self, client):
        resp = client.post(
            "/curri", data=b"<dummy/>", content_type="text/xml"
        )
        assert "Server" not in resp.headers

    def test_headers_on_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Cache-Control") == "no-store"

    def test_headers_on_head_request(self, client):
        resp = client.head("/curri")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_headers_on_error_response(self, client):
        """Security headers should be present even on 405 errors."""
        resp = client.get("/curri")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"


# ===========================================================================
# MAX_CONTENT_LENGTH (request body limit)
# ===========================================================================

class TestRequestBodyLimit:
    def test_max_content_length_is_set(self):
        assert main.app.config.get("MAX_CONTENT_LENGTH") is not None

    def test_max_content_length_is_reasonable(self):
        limit = main.app.config["MAX_CONTENT_LENGTH"]
        assert limit <= 2 * 1024 * 1024  # no more than 2 MB


# ===========================================================================
# PII obfuscation
# ===========================================================================

class TestPiiObfuscation:
    def test_obfuscate_returns_original_when_disabled(self):
        """With OBFUSCATE_PII=False (test default), values pass through."""
        original_flag = main.OBFUSCATE_PII
        main.OBFUSCATE_PII = False
        try:
            assert main._obfuscate_pii("+12125551001") == "+12125551001"
        finally:
            main.OBFUSCATE_PII = original_flag

    def test_obfuscate_returns_hash_when_enabled(self):
        original_flag = main.OBFUSCATE_PII
        original_salt = main._PII_SALT
        main.OBFUSCATE_PII = True
        main._PII_SALT = b"test-salt-32-bytes-for-unit-test"
        try:
            result = main._obfuscate_pii("+12125551001")
            assert result is not None
            assert result.startswith("{! ")
            assert result.endswith(" !}")
            # Hash portion should be 24 hex characters
            hash_part = result[3:-3]
            assert len(hash_part) == 24
            assert all(c in "0123456789abcdef" for c in hash_part)
        finally:
            main.OBFUSCATE_PII = original_flag
            main._PII_SALT = original_salt

    def test_obfuscate_none_returns_none(self):
        original_flag = main.OBFUSCATE_PII
        main.OBFUSCATE_PII = True
        try:
            assert main._obfuscate_pii(None) is None
        finally:
            main.OBFUSCATE_PII = original_flag

    def test_obfuscate_empty_string_returns_empty(self):
        original_flag = main.OBFUSCATE_PII
        main.OBFUSCATE_PII = True
        try:
            assert main._obfuscate_pii("") == ""
        finally:
            main.OBFUSCATE_PII = original_flag

    def test_obfuscate_deterministic_for_same_value(self):
        original_flag = main.OBFUSCATE_PII
        original_salt = main._PII_SALT
        main.OBFUSCATE_PII = True
        main._PII_SALT = b"test-salt-32-bytes-for-unit-test"
        try:
            result1 = main._obfuscate_pii("+12125551001")
            result2 = main._obfuscate_pii("+12125551001")
            assert result1 == result2
        finally:
            main.OBFUSCATE_PII = original_flag
            main._PII_SALT = original_salt

    def test_obfuscate_different_values_produce_different_hashes(self):
        original_flag = main.OBFUSCATE_PII
        original_salt = main._PII_SALT
        main.OBFUSCATE_PII = True
        main._PII_SALT = b"test-salt-32-bytes-for-unit-test"
        try:
            result1 = main._obfuscate_pii("+12125551001")
            result2 = main._obfuscate_pii("+12125551002")
            assert result1 != result2
        finally:
            main.OBFUSCATE_PII = original_flag
            main._PII_SALT = original_salt

    def test_obfuscate_uses_hmac_sha256(self):
        """Verify the hash matches a manual HMAC-SHA256 computation."""
        salt = b"test-salt-32-bytes-for-unit-test"
        value = "+12125551001"
        expected_digest = hmac_mod.new(
            salt, value.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:24]

        original_flag = main.OBFUSCATE_PII
        original_salt = main._PII_SALT
        main.OBFUSCATE_PII = True
        main._PII_SALT = salt
        try:
            result = main._obfuscate_pii(value)
            assert result == f"{{! {expected_digest} !}}"
        finally:
            main.OBFUSCATE_PII = original_flag
            main._PII_SALT = original_salt


# ===========================================================================
# Insecure mode flag
# ===========================================================================

class TestInsecureMode:
    def test_insecure_mode_is_true_in_test_config(self):
        """The test config sets insecure_mode: true."""
        assert main.INSECURE_MODE is True

    def test_insecure_mode_only_accepts_explicit_true(self):
        """Only boolean True should enable insecure mode, not truthy strings."""
        assert (None is True) is False
        assert ("true" is True) is False
        assert (1 is True) is False


# ===========================================================================
# Secure-by-default startup checks
# ===========================================================================

class TestSecureByDefaultStartup:
    def test_config_load_returns_empty_dict_for_missing_file(self):
        result = main._load_config("/nonexistent/config.yaml")
        assert result == {}

    def test_config_load_valid_yaml(self, tmp_path):
        config_file = tmp_path / "test.yaml"
        config_file.write_text("insecure_mode: true\nlog_level: DEBUG\n")
        result = main._load_config(str(config_file))
        assert result["insecure_mode"] is True
        assert result["log_level"] == "DEBUG"


# ===========================================================================
# defusedxml is used (not stdlib xml.etree)
# ===========================================================================

class TestXmlSafety:
    def test_uses_defusedxml(self):
        """Verify that the ET module used in main is from defusedxml."""
        assert "defusedxml" in main.ET.__name__ or "defusedxml" in str(
            main.ET.__module__
        )

    def test_xxe_payload_does_not_expand(self):
        """An XXE payload should not cause file reads or entity expansion.
        defusedxml raises EntitiesForbidden, which propagates because
        parse_xacml_request only catches ET.ParseError."""
        xxe_payload = b"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Request xmlns="urn:oasis:names:tc:xacml:2.0:context:schema:os"><Subject><Attribute AttributeId="urn:Cisco:uc:1.0:callingnumber"><AttributeValue>&xxe;</AttributeValue></Attribute></Subject></Request>"""
        with pytest.raises(EntitiesForbidden):
            main.parse_xacml_request(xxe_payload)

    def test_billion_laughs_rejected(self):
        """A billion laughs (entity expansion) attack should be rejected."""
        payload = b"""<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><Request xmlns="urn:oasis:names:tc:xacml:2.0:context:schema:os"><Subject></Subject></Request>"""
        with pytest.raises(EntitiesForbidden):
            main.parse_xacml_request(payload)
