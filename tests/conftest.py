"""Shared fixtures for the UCM Name Lookup test suite.

The CONFIG_FILE environment variable is set before main.py is imported
so the module-level initialization loads the test config and CSV rather
than production data.
"""

import ipaddress
import os

# Point at test config BEFORE any import of main.
os.environ["CONFIG_FILE"] = os.path.join(
    os.path.dirname(__file__), "fixtures", "test_config.yaml"
)

import pytest

import main


# ---------------------------------------------------------------------------
# XACML request templates
# ---------------------------------------------------------------------------

XACML_NS = "urn:oasis:names:tc:xacml:2.0:context:schema:os"


def build_xacml_request(
    calling_number: str | None = None,
    called_number: str | None = None,
    transformed_cgpn: str | None = None,
) -> bytes:
    """Build a minimal XACML request body for testing."""
    attrs = ""
    if calling_number is not None:
        attrs += (
            '<Attribute AttributeId="urn:Cisco:uc:1.0:callingnumber">'
            f"<AttributeValue>{calling_number}</AttributeValue>"
            "</Attribute>"
        )
    if called_number is not None:
        attrs += (
            '<Attribute AttributeId="urn:Cisco:uc:1.0:callednumber">'
            f"<AttributeValue>{called_number}</AttributeValue>"
            "</Attribute>"
        )
    if transformed_cgpn is not None:
        attrs += (
            '<Attribute AttributeId="urn:Cisco:uc:1.0:transformedcgpn">'
            f"<AttributeValue>{transformed_cgpn}</AttributeValue>"
            "</Attribute>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Request xmlns="{XACML_NS}">'
        f"<Subject>{attrs}</Subject>"
        "</Request>"
    )
    return xml.encode("utf-8")


# ---------------------------------------------------------------------------
# Flask test client (no clusters — unrestricted access)
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    """Flask test client with no cluster restrictions."""
    original_clusters = main.CLUSTERS
    main.CLUSTERS = []
    main.app.config["TESTING"] = True
    with main.app.test_client() as c:
        yield c
    main.CLUSTERS = original_clusters


# ---------------------------------------------------------------------------
# Cluster fixtures
# ---------------------------------------------------------------------------

def _make_cluster(
    name: str = "test-cluster",
    ips: list[str] | None = None,
    subjects: set[str] | None = None,
    ca_file: str | None = None,
) -> main.ClusterConfig:
    """Helper to build a ClusterConfig for tests."""
    networks = []
    if ips:
        for ip in ips:
            networks.append(ipaddress.ip_network(ip, strict=False))
    return main.ClusterConfig(
        name=name,
        allowed_networks=networks,
        allowed_subjects=subjects if subjects is not None else set(),
        ca_file=ca_file,
    )


@pytest.fixture()
def client_with_cluster():
    """Flask test client with a single cluster that allows 127.0.0.1 and
    any certificate subject."""
    cluster = _make_cluster(
        ips=["127.0.0.1/32"],
        subjects={"localhost"},
    )
    original_clusters = main.CLUSTERS
    main.CLUSTERS = [cluster]
    main.app.config["TESTING"] = True
    with main.app.test_client() as c:
        yield c
    main.CLUSTERS = original_clusters


@pytest.fixture()
def client_with_restrictive_cluster():
    """Flask test client with a cluster that denies the test client IP."""
    cluster = _make_cluster(
        ips=["10.99.99.0/24"],
        subjects={"cucm.example.com"},
    )
    original_clusters = main.CLUSTERS
    main.CLUSTERS = [cluster]
    main.app.config["TESTING"] = True
    with main.app.test_client() as c:
        yield c
    main.CLUSTERS = original_clusters


@pytest.fixture()
def client_with_empty_cluster():
    """Flask test client with a cluster that has no IPs or subjects
    (deny-by-default — should reject everything)."""
    cluster = _make_cluster(name="empty-cluster")
    original_clusters = main.CLUSTERS
    main.CLUSTERS = [cluster]
    main.app.config["TESTING"] = True
    with main.app.test_client() as c:
        yield c
    main.CLUSTERS = original_clusters
