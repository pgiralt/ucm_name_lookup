"""Tests for XACML request parsing and response building."""

import main
from tests.conftest import build_xacml_request


# ===========================================================================
# parse_xacml_request
# ===========================================================================

class TestParseXacmlRequest:
    def test_parses_calling_number(self):
        xml = build_xacml_request(calling_number="+12125551001")
        attrs = main.parse_xacml_request(xml)
        assert attrs[main.CURRI_ATTR_CALLING_NUMBER] == "+12125551001"

    def test_parses_called_number(self):
        xml = build_xacml_request(
            calling_number="+12125551001", called_number="+13125559999"
        )
        attrs = main.parse_xacml_request(xml)
        assert attrs[main.CURRI_ATTR_CALLED_NUMBER] == "+13125559999"

    def test_parses_transformed_cgpn(self):
        xml = build_xacml_request(transformed_cgpn="+12125551002")
        attrs = main.parse_xacml_request(xml)
        assert attrs[main.CURRI_ATTR_TRANSFORMED_CGPN] == "+12125551002"

    def test_empty_body_returns_empty_dict(self):
        attrs = main.parse_xacml_request(b"")
        assert attrs == {}

    def test_malformed_xml_returns_empty_dict(self):
        attrs = main.parse_xacml_request(b"<not>valid xml")
        assert attrs == {}

    def test_missing_attributes_returns_empty(self):
        xml = b"""<?xml version="1.0"?>
        <Request xmlns="urn:oasis:names:tc:xacml:2.0:context:schema:os">
          <Subject></Subject>
        </Request>"""
        attrs = main.parse_xacml_request(xml)
        assert attrs == {}

    def test_whitespace_stripped_from_values(self):
        xml = build_xacml_request(calling_number="  +12125551001  ")
        attrs = main.parse_xacml_request(xml)
        assert attrs[main.CURRI_ATTR_CALLING_NUMBER] == "+12125551001"


# ===========================================================================
# get_calling_number
# ===========================================================================

class TestGetCallingNumber:
    def test_prefers_direct_calling_number(self):
        attrs = {
            main.CURRI_ATTR_CALLING_NUMBER: "+12125551001",
            main.CURRI_ATTR_TRANSFORMED_CGPN: "+12125551002",
        }
        assert main.get_calling_number(attrs) == "+12125551001"

    def test_falls_back_to_transformed_cgpn(self):
        attrs = {main.CURRI_ATTR_TRANSFORMED_CGPN: "+12125551002"}
        assert main.get_calling_number(attrs) == "+12125551002"

    def test_returns_none_when_empty(self):
        assert main.get_calling_number({}) is None


# ===========================================================================
# build_continue_response
# ===========================================================================

class TestBuildContinueResponse:
    def test_simple_continue_no_name(self):
        response = main.build_continue_response()
        assert "<Decision>Permit</Decision>" in response
        assert "continue" in response
        assert "modify" not in response

    def test_continue_with_display_name(self):
        response = main.build_continue_response("Alice Johnson")
        assert "<Decision>Permit</Decision>" in response
        assert "Alice Johnson" in response
        assert "callingname" in response

    def test_xml_special_chars_escaped(self):
        response = main.build_continue_response('O\'Brien & "Friends" <3')
        assert "<Decision>Permit</Decision>" in response
        assert "&amp;" in response
        assert "&lt;" in response

    def test_always_returns_permit(self):
        for name in [None, "", "Test Name"]:
            response = main.build_continue_response(name)
            assert "<Decision>Permit</Decision>" in response

    def test_response_is_valid_xml_envelope(self):
        response = main.build_continue_response("Test")
        assert response.startswith("<?xml")
        assert "<Response>" in response
        assert "</Response>" in response
