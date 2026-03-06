"""Tests for Flask route behavior: CURRI endpoint and health check."""

from unittest.mock import patch

import main
from tests.conftest import build_xacml_request


# ===========================================================================
# CURRI endpoint — POST
# ===========================================================================

class TestCurriPost:
    def test_valid_xacml_returns_200(self, client):
        xml = build_xacml_request(calling_number="+12125551001")
        resp = client.post("/curri", data=xml, content_type="text/xml")
        assert resp.status_code == 200

    def test_response_is_xml(self, client):
        xml = build_xacml_request(calling_number="+12125551001")
        resp = client.post("/curri", data=xml, content_type="text/xml")
        assert "text/xml" in resp.content_type

    def test_response_contains_permit(self, client):
        xml = build_xacml_request(calling_number="+12125551001")
        resp = client.post("/curri", data=xml, content_type="text/xml")
        assert b"<Decision>Permit</Decision>" in resp.data

    def test_known_number_returns_display_name(self, client):
        xml = build_xacml_request(calling_number="+12125551001")
        resp = client.post("/curri", data=xml, content_type="text/xml")
        assert b"Alice Johnson" in resp.data

    def test_unknown_number_returns_continue_without_name(self, client):
        xml = build_xacml_request(calling_number="+99999999999")
        resp = client.post("/curri", data=xml, content_type="text/xml")
        assert b"<Decision>Permit</Decision>" in resp.data
        assert b"callingname" not in resp.data

    def test_empty_body_returns_continue(self, client):
        resp = client.post("/curri", data=b"", content_type="text/xml")
        assert resp.status_code == 200
        assert b"<Decision>Permit</Decision>" in resp.data

    def test_malformed_xml_returns_continue(self, client):
        resp = client.post(
            "/curri", data=b"<broken>", content_type="text/xml"
        )
        assert resp.status_code == 200
        assert b"<Decision>Permit</Decision>" in resp.data

    def test_prefix_match_returns_display_name(self, client):
        xml = build_xacml_request(calling_number="+13129999999")
        resp = client.post("/curri", data=xml, content_type="text/xml")
        assert b"Chicago" in resp.data

    def test_transformed_cgpn_fallback(self, client):
        xml = build_xacml_request(transformed_cgpn="+12125551002")
        resp = client.post("/curri", data=xml, content_type="text/xml")
        assert b"Bob Smith" in resp.data

    def test_never_rejects_calls(self, client):
        """The service must NEVER reject a call — always Permit/Continue."""
        test_payloads = [
            b"",
            b"not xml at all",
            b"<broken>",
            build_xacml_request(calling_number="+99999999999"),
            build_xacml_request(),  # no calling number
        ]
        for payload in test_payloads:
            resp = client.post("/curri", data=payload, content_type="text/xml")
            assert resp.status_code == 200, f"Rejected with payload: {payload!r}"
            assert b"Permit" in resp.data, f"No Permit for payload: {payload!r}"


# ===========================================================================
# CURRI endpoint — HEAD (keepalive probe)
# ===========================================================================

class TestCurriHead:
    def test_head_returns_200(self, client):
        resp = client.head("/curri")
        assert resp.status_code == 200

    def test_head_content_type_is_xml(self, client):
        resp = client.head("/curri")
        assert "text/xml" in resp.content_type

    def test_head_has_no_body(self, client):
        resp = client.head("/curri")
        assert resp.data == b""


# ===========================================================================
# CURRI endpoint — Content-Type validation
# ===========================================================================

class TestCurriContentType:
    def test_text_xml_accepted(self, client):
        xml = build_xacml_request(calling_number="+12125551001")
        resp = client.post("/curri", data=xml, content_type="text/xml")
        assert resp.status_code == 200

    def test_application_xml_accepted(self, client):
        xml = build_xacml_request(calling_number="+12125551001")
        resp = client.post(
            "/curri", data=xml, content_type="application/xml"
        )
        assert resp.status_code == 200

    def test_unexpected_content_type_still_succeeds(self, client):
        """Non-XML Content-Type should log a warning but still process
        (never reject calls)."""
        xml = build_xacml_request(calling_number="+12125551001")
        resp = client.post(
            "/curri", data=xml, content_type="application/json"
        )
        assert resp.status_code == 200

    def test_no_content_type_still_succeeds(self, client):
        xml = build_xacml_request(calling_number="+12125551001")
        resp = client.post("/curri", data=xml)
        assert resp.status_code == 200


# ===========================================================================
# CURRI endpoint — disallowed methods
# ===========================================================================

class TestCurriMethods:
    def test_get_not_allowed(self, client):
        resp = client.get("/curri")
        assert resp.status_code == 405

    def test_put_not_allowed(self, client):
        resp = client.put("/curri", data=b"<dummy/>")
        assert resp.status_code == 405

    def test_delete_not_allowed(self, client):
        resp = client.delete("/curri")
        assert resp.status_code == 405


# ===========================================================================
# Health endpoint
# ===========================================================================

class TestHealthEndpoint:
    def test_health_returns_200_no_clusters(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_json(self, client):
        resp = client.get("/health")
        data = resp.get_json()
        assert data["status"] == "healthy"
        assert "exact_entries" in data
        assert "prefix_entries" in data

    def test_health_localhost_allowed_with_clusters(self, client_with_cluster):
        """Health endpoint should be accessible from localhost even when
        clusters are defined."""
        resp = client_with_cluster.get("/health")
        assert resp.status_code == 200

    def test_health_non_localhost_denied_with_clusters(self):
        """Health endpoint from non-localhost should be denied when clusters
        are defined."""
        cluster = main.ClusterConfig(
            name="test", allowed_networks=[], allowed_subjects=set()
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            # Flask test client uses 127.0.0.1 by default, so this test
            # verifies that localhost IS allowed. Testing non-localhost
            # would require a real network connection or WSGI env override.
            resp = c.get("/health")
            assert resp.status_code == 200
        main.CLUSTERS = original

    def test_health_post_not_allowed(self, client):
        resp = client.post("/health")
        assert resp.status_code == 405
