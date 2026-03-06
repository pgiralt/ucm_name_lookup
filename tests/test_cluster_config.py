"""Tests for cluster configuration parsing with real CA files."""

import pytest

import main
from tests.cert_helpers import generate_ca, generate_leaf, write_pem_cert


# ===========================================================================
# _parse_network_list
# ===========================================================================

class TestParseNetworkList:
    def test_valid_ipv4_cidr(self):
        result = main._parse_network_list(["10.0.0.0/8"], "test")
        assert len(result) == 1
        assert str(result[0]) == "10.0.0.0/8"

    def test_valid_single_ip(self):
        result = main._parse_network_list(["192.168.1.1"], "test")
        assert len(result) == 1

    def test_valid_ipv6(self):
        result = main._parse_network_list(["::1/128"], "test")
        assert len(result) == 1

    def test_invalid_entry_skipped(self):
        result = main._parse_network_list(
            ["10.0.0.0/8", "not-an-ip", "172.16.0.0/12"], "test"
        )
        assert len(result) == 2

    def test_empty_entries_skipped(self):
        result = main._parse_network_list(["", "  ", "10.0.0.0/8"], "test")
        assert len(result) == 1

    def test_empty_list(self):
        result = main._parse_network_list([], "test")
        assert result == []

    def test_non_strict_host_bits(self):
        result = main._parse_network_list(["10.0.0.1/8"], "test")
        assert len(result) == 1
        assert str(result[0]) == "10.0.0.0/8"


# ===========================================================================
# _parse_subject_list
# ===========================================================================

class TestParseSubjectList:
    def test_basic_subjects(self):
        result = main._parse_subject_list(["cucm.example.com", "server.local"])
        assert result == {"cucm.example.com", "server.local"}

    def test_lowercases_values(self):
        result = main._parse_subject_list(["CUCM.Example.COM"])
        assert "cucm.example.com" in result

    def test_strips_whitespace(self):
        result = main._parse_subject_list(["  host.example.com  "])
        assert "host.example.com" in result

    def test_empty_entries_skipped(self):
        result = main._parse_subject_list(["host", "", "  "])
        assert result == {"host"}

    def test_empty_list(self):
        result = main._parse_subject_list([])
        assert result == set()


# ===========================================================================
# _parse_clusters
# ===========================================================================

class TestParseClusters:
    def test_empty_dict_returns_empty(self):
        assert main._parse_clusters({}) == []

    def test_none_returns_empty(self):
        assert main._parse_clusters(None) == []

    def test_non_dict_exits(self):
        with pytest.raises(SystemExit):
            main._parse_clusters("not a dict")

    def test_cluster_value_not_dict_exits(self):
        with pytest.raises(SystemExit):
            main._parse_clusters({"bad-cluster": "not a dict"})

    def test_basic_cluster_without_ca(self):
        raw = {
            "test-cluster": {
                "allowed_ips": ["10.0.0.0/8"],
                "allowed_subjects": ["cucm.example.com"],
            }
        }
        clusters = main._parse_clusters(raw)
        assert len(clusters) == 1
        assert clusters[0].name == "test-cluster"
        assert len(clusters[0].allowed_networks) == 1
        assert "cucm.example.com" in clusters[0].allowed_subjects
        assert clusters[0].ca_file is None

    def test_cluster_with_valid_ca_file(self, tmp_path):
        ca_cert, _ = generate_ca(cn="Test Cluster CA")
        ca_path = write_pem_cert(ca_cert, tmp_path / "ca.pem")
        raw = {
            "secure-cluster": {
                "allowed_ips": ["10.0.0.0/8"],
                "allowed_subjects": ["cucm.example.com"],
                "ca_file": ca_path,
            }
        }
        clusters = main._parse_clusters(raw)
        assert len(clusters) == 1
        assert clusters[0].ca_file == ca_path

    def test_cluster_with_missing_ca_file_exits(self):
        raw = {
            "bad-ca": {
                "allowed_ips": ["10.0.0.0/8"],
                "ca_file": "/nonexistent/ca.pem",
            }
        }
        with pytest.raises(SystemExit):
            main._parse_clusters(raw)

    def test_cluster_with_leaf_cert_ca_exits(self, tmp_path):
        """Using a leaf certificate as ca_file should exit."""
        ca_cert, ca_key = generate_ca()
        leaf_cert, _ = generate_leaf(ca_cert, ca_key, cn="leaf.example.com")
        leaf_path = write_pem_cert(leaf_cert, tmp_path / "leaf.pem")
        raw = {
            "leaf-ca": {
                "allowed_ips": ["10.0.0.0/8"],
                "ca_file": leaf_path,
            }
        }
        with pytest.raises(SystemExit):
            main._parse_clusters(raw)

    def test_multiple_clusters(self, tmp_path):
        ca1_cert, _ = generate_ca(cn="CA One")
        ca2_cert, _ = generate_ca(cn="CA Two")
        ca1_path = write_pem_cert(ca1_cert, tmp_path / "ca1.pem")
        ca2_path = write_pem_cert(ca2_cert, tmp_path / "ca2.pem")
        raw = {
            "cluster-a": {
                "allowed_ips": ["10.0.0.0/8"],
                "allowed_subjects": ["cucm-a.example.com"],
                "ca_file": ca1_path,
            },
            "cluster-b": {
                "allowed_ips": ["172.16.0.0/12"],
                "allowed_subjects": ["cucm-b.example.com"],
                "ca_file": ca2_path,
            },
        }
        clusters = main._parse_clusters(raw)
        assert len(clusters) == 2
        names = {c.name for c in clusters}
        assert names == {"cluster-a", "cluster-b"}

    def test_cluster_defaults_empty_when_omitted(self):
        raw = {"minimal": {}}
        clusters = main._parse_clusters(raw)
        assert len(clusters) == 1
        assert clusters[0].allowed_networks == []
        assert clusters[0].allowed_subjects == set()
        assert clusters[0].ca_file is None
