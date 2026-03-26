"""Tests for CA certificate validation, leaf rejection, and CA bundle generation."""

import os
from unittest.mock import patch

import pytest

import main
from tests.cert_helpers import (
    generate_ca,
    generate_leaf,
    write_pem_cert,
    write_pem_bundle,
    write_pem_key,
)


# ===========================================================================
# _validate_ca_cert
# ===========================================================================

class TestValidateCaCert:
    def test_valid_ca_cert_returns_true(self, tmp_path):
        ca_cert, _ca_key = generate_ca(cn="Test Root CA")
        ca_path = write_pem_cert(ca_cert, tmp_path / "ca.pem")
        assert main._validate_ca_cert(ca_path, "test-cluster") is True

    def test_leaf_cert_exits(self, tmp_path):
        """A leaf certificate should cause sys.exit(1)."""
        ca_cert, ca_key = generate_ca()
        leaf_cert, _leaf_key = generate_leaf(ca_cert, ca_key, cn="leaf.example.com")
        leaf_path = write_pem_cert(leaf_cert, tmp_path / "leaf.pem")
        with pytest.raises(SystemExit) as exc_info:
            main._validate_ca_cert(leaf_path, "test-cluster")
        assert exc_info.value.code == 1

    def test_nonexistent_file_returns_false(self):
        result = main._validate_ca_cert("/nonexistent/ca.pem", "test-cluster")
        assert result is False

    def test_empty_file_returns_false(self, tmp_path):
        empty_path = tmp_path / "empty.pem"
        empty_path.write_text("")
        result = main._validate_ca_cert(str(empty_path), "test-cluster")
        assert result is False

    def test_garbage_file_returns_false(self, tmp_path):
        garbage_path = tmp_path / "garbage.pem"
        garbage_path.write_text("not a certificate")
        result = main._validate_ca_cert(str(garbage_path), "test-cluster")
        assert result is False


# ===========================================================================
# _generate_ca_bundle
# ===========================================================================

class TestGenerateCaBundle:
    def test_generates_bundle_from_clusters(self, tmp_path):
        ca1_cert, _ = generate_ca(cn="CA One")
        ca2_cert, _ = generate_ca(cn="CA Two")
        ca1_path = write_pem_cert(ca1_cert, tmp_path / "ca1.pem")
        ca2_path = write_pem_cert(ca2_cert, tmp_path / "ca2.pem")

        clusters = [
            main.ClusterConfig(
                name="cluster1", ca_file=ca1_path,
                allowed_networks=[], allowed_subjects=set(),
            ),
            main.ClusterConfig(
                name="cluster2", ca_file=ca2_path,
                allowed_networks=[], allowed_subjects=set(),
            ),
        ]
        bundle_path = str(tmp_path / "bundle.pem")
        main._generate_ca_bundle(clusters, bundle_path)

        assert os.path.isfile(bundle_path)
        content = open(bundle_path).read()
        assert content.count("BEGIN CERTIFICATE") == 2

    def test_deduplicates_ca_files(self, tmp_path):
        ca_cert, _ = generate_ca(cn="Shared CA")
        ca_path = write_pem_cert(ca_cert, tmp_path / "shared_ca.pem")

        clusters = [
            main.ClusterConfig(
                name="cluster1", ca_file=ca_path,
                allowed_networks=[], allowed_subjects=set(),
            ),
            main.ClusterConfig(
                name="cluster2", ca_file=ca_path,
                allowed_networks=[], allowed_subjects=set(),
            ),
        ]
        bundle_path = str(tmp_path / "bundle.pem")
        main._generate_ca_bundle(clusters, bundle_path)

        content = open(bundle_path).read()
        assert content.count("BEGIN CERTIFICATE") == 1

    def test_skips_when_no_ca_files(self, tmp_path):
        clusters = [
            main.ClusterConfig(
                name="no-ca", ca_file=None,
                allowed_networks=[], allowed_subjects=set(),
            ),
        ]
        bundle_path = str(tmp_path / "bundle.pem")
        main._generate_ca_bundle(clusters, bundle_path)
        assert not os.path.isfile(bundle_path)

    def test_empty_cluster_list(self, tmp_path):
        bundle_path = str(tmp_path / "bundle.pem")
        main._generate_ca_bundle([], bundle_path)
        assert not os.path.isfile(bundle_path)

    def test_handles_unwritable_path_insecure_mode(self, tmp_path):
        """Non-writable path in insecure mode should log warning, not crash."""
        ca_cert, _ = generate_ca()
        ca_path = write_pem_cert(ca_cert, tmp_path / "ca.pem")
        clusters = [
            main.ClusterConfig(
                name="test", ca_file=ca_path,
                allowed_networks=[], allowed_subjects=set(),
            ),
        ]
        with patch.object(main, "INSECURE_MODE", True):
            main._generate_ca_bundle(clusters, "/nonexistent/dir/bundle.pem")
            # Should not raise — just logs a warning

    def test_unwritable_path_exits_in_secure_mode(self, tmp_path):
        """Non-writable path in secure mode should sys.exit(1)."""
        ca_cert, _ = generate_ca()
        ca_path = write_pem_cert(ca_cert, tmp_path / "ca.pem")
        clusters = [
            main.ClusterConfig(
                name="test", ca_file=ca_path,
                allowed_networks=[], allowed_subjects=set(),
            ),
        ]
        with patch.object(main, "INSECURE_MODE", False):
            with pytest.raises(SystemExit) as exc_info:
                main._generate_ca_bundle(
                    clusters, "/nonexistent/dir/bundle.pem"
                )
            assert exc_info.value.code == 1


# ===========================================================================
# _log_ca_bundle_contents
# ===========================================================================

class TestLogCaBundleContents:
    def test_logs_bundle_contents(self, tmp_path, caplog):
        """Should parse and log CA bundle at DEBUG level."""
        ca_cert, _ = generate_ca(cn="Logged CA")
        bundle_path = write_pem_cert(ca_cert, tmp_path / "bundle.pem")

        import logging
        with caplog.at_level(logging.DEBUG, logger="ucm_name_lookup"):
            main._log_ca_bundle_contents(bundle_path)
        assert "Logged CA" in caplog.text

    def test_handles_missing_bundle(self, caplog):
        import logging
        with caplog.at_level(logging.DEBUG, logger="ucm_name_lookup"):
            main._log_ca_bundle_contents("/nonexistent/bundle.pem")
        assert "not found" in caplog.text

    def test_handles_invalid_bundle(self, tmp_path, caplog):
        import logging
        bad_path = tmp_path / "bad.pem"
        bad_path.write_text("not a cert")
        with caplog.at_level(logging.DEBUG, logger="ucm_name_lookup"):
            main._log_ca_bundle_contents(str(bad_path))
