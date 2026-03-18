"""Tests for cluster-based access control enforcement.

Validates deny-by-default semantics: empty allowed_networks denies all
IPs, empty allowed_subjects denies all certificate subjects when cert
infrastructure is configured. Clusters with no cert infrastructure
(no allowed_subjects and no ca_file) use IP-only access control.
"""

from unittest.mock import patch

import main
from tests.conftest import _make_cluster


# ===========================================================================
# Deny-by-default: empty cluster rules
# ===========================================================================

class TestDenyByDefault:
    def test_empty_allowed_networks_denies_all(self, client_with_empty_cluster):
        """A cluster with no allowed_ips should deny every IP."""
        resp = client_with_empty_cluster.post(
            "/curri", data=b"<dummy/>", content_type="text/xml"
        )
        assert resp.status_code == 403

    def test_empty_allowed_subjects_with_ca_file_denies_all(self):
        """A cluster with IPs and ca_file but empty subjects should deny
        (cert infrastructure is present, so subject check runs)."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects=set(),  # empty — deny all
            ca_file="/dummy/ca.pem",  # cert infrastructure present
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            assert resp.status_code == 403
        main.CLUSTERS = original

    def test_both_empty_denies(self):
        """A cluster with both rules empty should deny everything."""
        cluster = _make_cluster(ips=[], subjects=set())
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            assert resp.status_code == 403
        main.CLUSTERS = original


# ===========================================================================
# IP-based access control
# ===========================================================================

class TestIPAccess:
    def test_ip_only_cluster_allows_matching_ip(self):
        """A cluster with only allowed_ips (no cert infrastructure) should
        allow requests from matching IPs — subject check is skipped."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects=set(),  # no cert infrastructure
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            assert resp.status_code == 200
        main.CLUSTERS = original

    def test_ip_match_with_ca_file_still_requires_subjects(self):
        """When cert infrastructure is present (ca_file), matching IP
        alone is not enough — subject check runs and denies."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects=set(),  # empty subjects → deny all
            ca_file="/dummy/ca.pem",  # cert infrastructure present
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            assert resp.status_code == 403
        main.CLUSTERS = original

    def test_ip_only_cluster_allows_head_keepalive(self):
        """HEAD /curri (UCM keepalive probe) should be allowed by an
        IP-only cluster — this is the exact scenario that was failing."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects=set(),
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.head("/curri")
            assert resp.status_code == 200
        main.CLUSTERS = original

    def test_ip_only_cluster_denies_wrong_ip(self):
        """An IP-only cluster should still deny IPs not in allowed_ips."""
        cluster = _make_cluster(
            ips=["10.99.99.0/24"],
            subjects=set(),
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            assert resp.status_code == 403
        main.CLUSTERS = original

    def test_non_matching_ip_denied(self, client_with_restrictive_cluster):
        """Request from 127.0.0.1 should be denied by a cluster that only
        allows 10.99.99.0/24."""
        resp = client_with_restrictive_cluster.post(
            "/curri", data=b"<dummy/>", content_type="text/xml"
        )
        assert resp.status_code == 403

    def test_cidr_range_matching(self):
        """An IP within a CIDR range should pass the IP check (IP-only
        cluster with no cert infrastructure)."""
        cluster = _make_cluster(
            ips=["127.0.0.0/8"],
            subjects=set(),
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            assert resp.status_code == 200
        main.CLUSTERS = original


# ===========================================================================
# Certificate subject access control
# ===========================================================================

class TestSubjectAccess:
    def test_allowed_subjects_without_ca_file_still_enforces(self):
        """A cluster with allowed_subjects but no ca_file should still
        run the subject check (cert infrastructure is present via
        subjects alone)."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects={"cucm.example.com"},  # cert infra present
            # no ca_file
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            # No cert available → subject check fails → denied
            with patch.object(main, "_get_peer_certificate", return_value=None):
                resp = c.post(
                    "/curri", data=b"<dummy/>", content_type="text/xml"
                )
                assert resp.status_code == 403
        main.CLUSTERS = original

    def test_matching_subject_and_ip_allows(self):
        """When both IP and subject match, request should be allowed."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects={"localhost"},
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        # Mock _get_peer_certificate to return a cert with CN=localhost
        mock_cert = {
            "subject": ((("commonName", "localhost"),),),
            "subjectAltName": (),
        }
        with main.app.test_client() as c:
            with patch.object(main, "_get_peer_certificate", return_value=mock_cert):
                resp = c.post(
                    "/curri", data=b"<dummy/>", content_type="text/xml"
                )
                assert resp.status_code == 200
        main.CLUSTERS = original

    def test_mismatched_subject_denied(self):
        """When IP matches but subject does not, request is denied."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects={"cucm.example.com"},
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        mock_cert = {
            "subject": ((("commonName", "wrong-host.example.com"),),),
            "subjectAltName": (),
        }
        with main.app.test_client() as c:
            with patch.object(main, "_get_peer_certificate", return_value=mock_cert):
                resp = c.post(
                    "/curri", data=b"<dummy/>", content_type="text/xml"
                )
                assert resp.status_code == 403
        main.CLUSTERS = original

    def test_no_cert_available_denied(self):
        """When no client certificate is available, subject check fails."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects={"localhost"},
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            with patch.object(main, "_get_peer_certificate", return_value=None):
                resp = c.post(
                    "/curri", data=b"<dummy/>", content_type="text/xml"
                )
                assert resp.status_code == 403
        main.CLUSTERS = original

    def test_san_matching(self):
        """SAN entries should also be checked for subject matching."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects={"cucm.example.com"},
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        mock_cert = {
            "subject": ((("commonName", "other-cn"),),),
            "subjectAltName": (("DNS", "cucm.example.com"),),
        }
        with main.app.test_client() as c:
            with patch.object(main, "_get_peer_certificate", return_value=mock_cert):
                resp = c.post(
                    "/curri", data=b"<dummy/>", content_type="text/xml"
                )
                assert resp.status_code == 200
        main.CLUSTERS = original


# ===========================================================================
# Multi-cluster matching (at least one must match)
# ===========================================================================

class TestMultiCluster:
    def test_second_cluster_matches(self):
        """If the first cluster doesn't match but the second does, allow."""
        cluster1 = _make_cluster(
            name="wrong-cluster",
            ips=["10.0.0.0/8"],
            subjects={"other.example.com"},
        )
        cluster2 = _make_cluster(
            name="right-cluster",
            ips=["127.0.0.1/32"],
            subjects={"localhost"},
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster1, cluster2]
        main.app.config["TESTING"] = True
        mock_cert = {
            "subject": ((("commonName", "localhost"),),),
            "subjectAltName": (),
        }
        with main.app.test_client() as c:
            with patch.object(main, "_get_peer_certificate", return_value=mock_cert):
                resp = c.post(
                    "/curri", data=b"<dummy/>", content_type="text/xml"
                )
                assert resp.status_code == 200
        main.CLUSTERS = original

    def test_no_cluster_matches_denied(self):
        """When no cluster matches, request is denied."""
        cluster1 = _make_cluster(
            name="cluster-a", ips=["10.0.0.0/8"], subjects={"a.example.com"}
        )
        cluster2 = _make_cluster(
            name="cluster-b", ips=["172.16.0.0/12"], subjects={"b.example.com"}
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster1, cluster2]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            assert resp.status_code == 403
        main.CLUSTERS = original


# ===========================================================================
# Mixed cluster types (IP-only + cert infrastructure)
# ===========================================================================

class TestMixedClusterTypes:
    def test_ip_only_cluster_matches_when_cert_cluster_does_not(self):
        """In insecure mode, when one cluster requires certs and another
        is IP-only, the IP-only cluster should authorize matching IPs."""
        cert_cluster = _make_cluster(
            name="secure-cluster",
            ips=["127.0.0.1/32"],
            subjects={"cucm.example.com"},
            ca_file="/dummy/ca.pem",
        )
        ip_only_cluster = _make_cluster(
            name="insecure-cluster",
            ips=["127.0.0.1/32"],
            subjects=set(),
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cert_cluster, ip_only_cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            # No cert → cert_cluster fails subject check, but
            # ip_only_cluster skips it (insecure mode) → authorized
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            assert resp.status_code == 200
        main.CLUSTERS = original

    def test_cert_cluster_matches_with_valid_cert(self):
        """When a cert cluster and IP-only cluster both match IPs,
        the cert cluster should authorize when the cert matches."""
        cert_cluster = _make_cluster(
            name="secure-cluster",
            ips=["127.0.0.1/32"],
            subjects={"cucm.example.com"},
        )
        ip_only_cluster = _make_cluster(
            name="insecure-cluster",
            ips=["10.0.0.0/8"],  # does NOT match 127.0.0.1
            subjects=set(),
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cert_cluster, ip_only_cluster]
        main.app.config["TESTING"] = True
        mock_cert = {
            "subject": ((("commonName", "cucm.example.com"),),),
            "subjectAltName": (),
        }
        with main.app.test_client() as c:
            with patch.object(main, "_get_peer_certificate", return_value=mock_cert):
                resp = c.post(
                    "/curri", data=b"<dummy/>", content_type="text/xml"
                )
                assert resp.status_code == 200
        main.CLUSTERS = original


# ===========================================================================
# Secure mode: IP-only clusters must be denied
# ===========================================================================

class TestSecureModeEnforcement:
    """In secure mode (INSECURE_MODE=False), the subject check is never
    skipped.  IP-only clusters without cert infrastructure should deny
    all requests because the empty allowed_subjects matches nothing."""

    def test_ip_only_cluster_denied_in_secure_mode(self):
        """An IP-only cluster with matching IP should still deny when
        INSECURE_MODE is False — subject check is always enforced."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects=set(),
        )
        original_clusters = main.CLUSTERS
        original_mode = main.INSECURE_MODE
        main.CLUSTERS = [cluster]
        main.INSECURE_MODE = False
        main.app.config["TESTING"] = True
        try:
            with main.app.test_client() as c:
                resp = c.post(
                    "/curri", data=b"<dummy/>", content_type="text/xml"
                )
                assert resp.status_code == 403
        finally:
            main.CLUSTERS = original_clusters
            main.INSECURE_MODE = original_mode

    def test_ip_only_cluster_head_denied_in_secure_mode(self):
        """HEAD keepalive from an IP-only cluster should also be denied
        in secure mode."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects=set(),
        )
        original_clusters = main.CLUSTERS
        original_mode = main.INSECURE_MODE
        main.CLUSTERS = [cluster]
        main.INSECURE_MODE = False
        main.app.config["TESTING"] = True
        try:
            with main.app.test_client() as c:
                resp = c.head("/curri")
                assert resp.status_code == 403
        finally:
            main.CLUSTERS = original_clusters
            main.INSECURE_MODE = original_mode

    def test_cert_cluster_still_works_in_secure_mode(self):
        """A cluster with cert infrastructure should still authorize
        when both IP and subject match in secure mode."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects={"cucm.example.com"},
        )
        mock_cert = {
            "subject": ((("commonName", "cucm.example.com"),),),
            "subjectAltName": (),
        }
        original_clusters = main.CLUSTERS
        original_mode = main.INSECURE_MODE
        main.CLUSTERS = [cluster]
        main.INSECURE_MODE = False
        main.app.config["TESTING"] = True
        try:
            with main.app.test_client() as c:
                with patch.object(
                    main, "_get_peer_certificate", return_value=mock_cert
                ):
                    resp = c.post(
                        "/curri",
                        data=b"<dummy/>",
                        content_type="text/xml",
                    )
                    assert resp.status_code == 200
        finally:
            main.CLUSTERS = original_clusters
            main.INSECURE_MODE = original_mode


# ===========================================================================
# No clusters defined (insecure mode fallback)
# ===========================================================================

class TestNoClusters:
    def test_no_clusters_allows_all(self, client):
        """When no clusters are defined, access is unrestricted."""
        resp = client.post("/curri", data=b"<dummy/>", content_type="text/xml")
        assert resp.status_code == 200
