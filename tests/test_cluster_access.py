"""Tests for cluster-based access control enforcement.

Validates deny-by-default semantics: empty allowed_networks denies all
IPs, empty allowed_subjects denies all certificate subjects.
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

    def test_empty_allowed_subjects_denies_all(self):
        """A cluster with IPs but empty subjects should deny (no cert can
        match an empty subject set)."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects=set(),  # empty — deny all
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
    def test_matching_ip_passes_ip_check(self):
        """Request from 127.0.0.1 should pass a cluster allowing 127.0.0.1,
        but will still be denied if subjects don't match."""
        cluster = _make_cluster(
            ips=["127.0.0.1/32"],
            subjects=set(),  # empty subjects → deny
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            # IP matches, but subjects are empty → denied
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
        """An IP within a CIDR range should pass the IP check."""
        cluster = _make_cluster(
            ips=["127.0.0.0/8"],
            subjects=set(),
        )
        original = main.CLUSTERS
        main.CLUSTERS = [cluster]
        main.app.config["TESTING"] = True
        with main.app.test_client() as c:
            resp = c.post("/curri", data=b"<dummy/>", content_type="text/xml")
            # IP passes (127.0.0.1 in 127.0.0.0/8), subjects empty → 403
            assert resp.status_code == 403
        main.CLUSTERS = original


# ===========================================================================
# Certificate subject access control
# ===========================================================================

class TestSubjectAccess:
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
# No clusters defined (insecure mode fallback)
# ===========================================================================

class TestNoClusters:
    def test_no_clusters_allows_all(self, client):
        """When no clusters are defined, access is unrestricted."""
        resp = client.post("/curri", data=b"<dummy/>", content_type="text/xml")
        assert resp.status_code == 200
