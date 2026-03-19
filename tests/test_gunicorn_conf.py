"""Tests for gunicorn.conf.py post_fork TLS handshake failure logging.

Validates that the ``post_fork`` hook in ``gunicorn.conf.py`` correctly:

1. Layer 1: Monkey-patches ``gunicorn.sock.ssl_wrap_socket`` to log TLS
   handshake failures at WARNING level via ``server.log``.
2. Layer 2: Wraps the gthread worker's ``enqueue_req`` to prevent
   event-loop crashes when handshake errors raise.
3. Layer 3: Wraps ``TConn.init`` to install a ``_TlsLoggingParser`` proxy
   around the HTTP parser, catching lazy-handshake TLS errors that
   ``handle()`` would otherwise swallow at DEBUG level.
4. Produces visible WARNING output when a real Gunicorn process encounters
   a TLS handshake failure from a client that rejects the server certificate.
"""

import errno
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

from tests.cert_helpers import (
    generate_ca,
    generate_leaf,
    write_pem_cert,
    write_pem_key,
)

# Path to the real gunicorn.conf.py at the project root.
_CONF_PY = pathlib.Path(__file__).resolve().parent.parent / "gunicorn.conf.py"


# ===========================================================================
# Helpers
# ===========================================================================

def _load_gunicorn_conf(tmp_path):
    """Load ``gunicorn.conf.py`` via ``exec()`` the way Gunicorn does.

    Creates ephemeral TLS certs and a minimal ``config.yaml`` so the TLS
    auto-detection block executes and ``post_fork`` is defined.  Returns
    the module namespace object.
    """
    ca_cert, ca_key = generate_ca(cn="GConf Test CA")
    srv_cert, srv_key = generate_leaf(
        ca_cert, ca_key, cn="localhost",
        san_dns=["localhost"], san_ips=["127.0.0.1"],
    )
    write_pem_cert(srv_cert, tmp_path / "srv.pem")
    write_pem_key(srv_key, tmp_path / "srv-key.pem")

    config_yaml = tmp_path / "config.yaml"
    config_yaml.write_text(
        f"tls_cert_file: {tmp_path / 'srv.pem'}\n"
        f"tls_key_file: {tmp_path / 'srv-key.pem'}\n"
        "clusters:\n"
        "  test:\n"
        "    allowed_ips:\n"
        "      - 127.0.0.1/32\n"
    )

    saved = os.environ.get("CONFIG_FILE")
    os.environ["CONFIG_FILE"] = str(config_yaml)
    try:
        mod = types.ModuleType("gunicorn_conf_test")
        mod.__file__ = str(_CONF_PY)
        code = _CONF_PY.read_text()
        exec(compile(code, str(_CONF_PY), "exec"), mod.__dict__)
    finally:
        if saved is None:
            os.environ.pop("CONFIG_FILE", None)
        else:
            os.environ["CONFIG_FILE"] = saved

    return mod


def _find_free_port():
    """Bind to port 0 and return the OS-assigned ephemeral port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ===========================================================================
# Unit tests — load real gunicorn.conf.py, call post_fork with mocks
# ===========================================================================

class TestPostForkHook:
    """Load the real ``gunicorn.conf.py``, extract ``post_fork``, and verify
    it patches ``gunicorn.sock.ssl_wrap_socket`` and wraps ``enqueue_req``
    correctly using mock server / worker objects."""

    @pytest.fixture
    def conf(self, tmp_path):
        """Load gunicorn.conf.py with TLS enabled."""
        return _load_gunicorn_conf(tmp_path)

    @pytest.fixture(autouse=True)
    def _restore_patched_objects(self):
        """Save and restore objects patched by ``post_fork`` so that
        changes do not leak between tests."""
        import gunicorn.sock as gsock
        orig_ssl_wrap = gsock.ssl_wrap_socket

        try:
            import gunicorn.workers.gthread as gthread
            orig_tconn_init = gthread.TConn.init
        except ImportError:
            gthread = None
            orig_tconn_init = None

        yield

        gsock.ssl_wrap_socket = orig_ssl_wrap
        if gthread is not None and orig_tconn_init is not None:
            gthread.TConn.init = orig_tconn_init

    # --- Config-level assertions ---

    def test_post_fork_is_defined(self, conf):
        """``post_fork`` should be a callable when TLS is enabled."""
        assert hasattr(conf, "post_fork")
        assert callable(conf.post_fork)

    def test_do_handshake_on_connect_enabled(self, conf):
        """``do_handshake_on_connect`` should be ``True``."""
        assert conf.do_handshake_on_connect is True

    def test_ssl_context_enforces_tls12(self, conf):
        """``ssl_context`` hook should set minimum TLS version to 1.2."""
        mock_ctx = MagicMock()
        factory = MagicMock(return_value=mock_ctx)
        result = conf.ssl_context(MagicMock(), factory)
        assert result is mock_ctx
        assert mock_ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    # --- ssl_wrap_socket patching ---

    def test_patches_ssl_wrap_socket(self, conf):
        """``post_fork`` should replace ``gunicorn.sock.ssl_wrap_socket``."""
        import gunicorn.sock as gsock
        original = gsock.ssl_wrap_socket

        conf.post_fork(MagicMock(), MagicMock())
        assert gsock.ssl_wrap_socket is not original

    def test_patched_logs_ssl_error(self, conf):
        """Patched ``ssl_wrap_socket`` should log ``ssl.SSLError`` at
        WARNING via ``server.log``."""
        import gunicorn.sock as gsock

        # Replace with a mock that raises — post_fork captures this as
        # _orig_ssl_wrap in its closure.
        gsock.ssl_wrap_socket = MagicMock(
            side_effect=ssl.SSLError(1, "[SSL] certificate verify failed")
        )

        server = MagicMock()
        conf.post_fork(server, MagicMock())

        mock_sock = MagicMock()
        mock_sock.getpeername.return_value = ("10.0.0.1", 12345)

        with pytest.raises(ssl.SSLError):
            gsock.ssl_wrap_socket(mock_sock, MagicMock())

        assert server.log.warning.called
        fmt_string = server.log.warning.call_args[0][0]
        peer_arg = server.log.warning.call_args[0][1]
        assert "TLS handshake failed" in fmt_string
        assert peer_arg == "10.0.0.1:12345"

    def test_patched_logs_os_error_with_client_disconnect_hint(self, conf):
        """Patched ``ssl_wrap_socket`` should log ``OSError`` at WARNING
        with a hint that the client may have rejected the server cert."""
        import gunicorn.sock as gsock

        gsock.ssl_wrap_socket = MagicMock(
            side_effect=ConnectionResetError("Connection reset by peer")
        )

        server = MagicMock()
        conf.post_fork(server, MagicMock())

        mock_sock = MagicMock()
        mock_sock.getpeername.return_value = ("10.0.0.2", 54321)

        with pytest.raises(ConnectionResetError):
            gsock.ssl_wrap_socket(mock_sock, MagicMock())

        assert server.log.warning.called
        fmt_string = server.log.warning.call_args[0][0]
        assert "TLS handshake failed" in fmt_string
        assert "client disconnected" in fmt_string

    def test_patched_logs_unknown_peer_on_getpeername_failure(self, conf):
        """If ``getpeername()`` fails, the log should show ``<unknown>``."""
        import gunicorn.sock as gsock

        gsock.ssl_wrap_socket = MagicMock(
            side_effect=ssl.SSLError(1, "handshake failure")
        )

        server = MagicMock()
        conf.post_fork(server, MagicMock())

        mock_sock = MagicMock()
        mock_sock.getpeername.side_effect = OSError("not connected")

        with pytest.raises(ssl.SSLError):
            gsock.ssl_wrap_socket(mock_sock, MagicMock())

        peer_arg = server.log.warning.call_args[0][1]
        assert peer_arg == "<unknown>"

    def test_patched_reraises_original_exception(self, conf):
        """The wrapper should re-raise the original exception after logging."""
        import gunicorn.sock as gsock

        original_exc = ssl.SSLError(1, "specific error")
        gsock.ssl_wrap_socket = MagicMock(side_effect=original_exc)

        conf.post_fork(MagicMock(), MagicMock())

        with pytest.raises(ssl.SSLError) as exc_info:
            gsock.ssl_wrap_socket(MagicMock(), MagicMock())
        assert exc_info.value is original_exc

    # --- enqueue_req wrapping ---

    def test_wraps_enqueue_req(self, conf):
        """``post_fork`` should replace ``worker.enqueue_req``."""
        worker = MagicMock()
        original = worker.enqueue_req
        conf.post_fork(MagicMock(), worker)
        assert worker.enqueue_req is not original

    def test_enqueue_req_catches_ssl_error(self, conf):
        """Wrapped ``enqueue_req`` should swallow ``ssl.SSLError``, close
        the connection, and decrement ``nr_conns``."""
        worker = MagicMock()
        worker.nr_conns = 5
        worker.enqueue_req = MagicMock(
            side_effect=ssl.SSLError(1, "handshake failure")
        )

        conf.post_fork(MagicMock(), worker)

        mock_conn = MagicMock()
        worker.enqueue_req(mock_conn)  # must not raise
        assert worker.nr_conns == 4
        mock_conn.close.assert_called_once()

    def test_enqueue_req_catches_os_error(self, conf):
        """Wrapped ``enqueue_req`` should swallow ``OSError``."""
        worker = MagicMock()
        worker.nr_conns = 3
        worker.enqueue_req = MagicMock(
            side_effect=ConnectionResetError("reset")
        )

        conf.post_fork(MagicMock(), worker)

        mock_conn = MagicMock()
        worker.enqueue_req(mock_conn)
        assert worker.nr_conns == 2
        mock_conn.close.assert_called_once()

    def test_enqueue_req_tolerates_close_failure(self, conf):
        """If ``conn.close()`` raises, ``nr_conns`` should still be
        decremented and the worker should not crash."""
        worker = MagicMock()
        worker.nr_conns = 2
        worker.enqueue_req = MagicMock(
            side_effect=ssl.SSLError(1, "handshake failure")
        )

        conf.post_fork(MagicMock(), worker)

        mock_conn = MagicMock()
        mock_conn.close.side_effect = OSError("close failed")
        worker.enqueue_req(mock_conn)  # must not raise
        assert worker.nr_conns == 1

    # --- Confirmation log ---

    def test_info_message_logged(self, conf):
        """``post_fork`` should log the confirmation message with
        do_handshake_on_connect and parser_wrapper status."""
        server = MagicMock()
        worker = MagicMock()
        worker.cfg.do_handshake_on_connect = True
        conf.post_fork(server, worker)
        fmt = server.log.info.call_args[0][0]
        assert "TLS handshake failure logging enabled" in fmt
        assert "do_handshake_on_connect" in fmt
        assert "parser_wrapper" in fmt

    # --- Non-gthread workers ---

    def test_skips_enqueue_req_for_non_gthread(self, conf):
        """Workers without ``enqueue_req`` should still get
        ``ssl_wrap_socket`` patched without crashing."""
        import gunicorn.sock as gsock
        original = gsock.ssl_wrap_socket

        server = MagicMock()
        worker = MagicMock(spec=[])  # no attributes → no enqueue_req

        conf.post_fork(server, worker)
        assert gsock.ssl_wrap_socket is not original

    # --- Layer 3: TConn.init parser wrapper ---

    def test_patches_tconn_init(self, conf):
        """``post_fork`` should replace ``TConn.init`` at the class level."""
        import gunicorn.workers.gthread as gthread
        original = gthread.TConn.init

        conf.post_fork(MagicMock(), MagicMock())
        assert gthread.TConn.init is not original

    def test_parser_wrapper_logs_ssl_error(self, conf):
        """Verify that TConn.init wraps the parser and that the wrapper
        logs ssl.SSLError (non-EOF) at WARNING."""
        import gunicorn.workers.gthread as gthread

        server = MagicMock()
        worker = MagicMock()
        worker.cfg.do_handshake_on_connect = True

        # Set TConn.init to no-op so post_fork captures it as _orig.
        # This lets us control what self.parser is when the wrapper runs.
        gthread.TConn.init = lambda self: None
        conf.post_fork(server, worker)

        class StubConn:
            pass

        stub = StubConn()
        stub.cfg = MagicMock(is_ssl=True)
        stub.client = ("10.0.0.5", 9999)
        stub.parser = MagicMock()
        stub.parser.__next__ = MagicMock(
            side_effect=ssl.SSLError(ssl.SSL_ERROR_SSL, "cert verify failed")
        )

        # Call the patched init (no-op original + wrapper logic)
        gthread.TConn.init(stub)

        # Parser should now be wrapped
        assert type(stub.parser).__name__ == "_TlsLoggingParser"

        # Iterating should log WARNING and re-raise
        server.log.reset_mock()
        with pytest.raises(ssl.SSLError):
            next(stub.parser)

        assert server.log.warning.called
        fmt = server.log.warning.call_args[0][0]
        assert "TLS error" in fmt
        peer = server.log.warning.call_args[0][1]
        assert peer == "10.0.0.5:9999"

    def test_parser_wrapper_skips_ssl_eof(self, conf):
        """SSL_ERROR_EOF should NOT be logged at WARNING (it is a normal
        clean close handled by handle() at DEBUG)."""
        import gunicorn.workers.gthread as gthread

        server = MagicMock()
        worker = MagicMock()
        worker.cfg.do_handshake_on_connect = True

        # Set TConn.init to no-op so post_fork captures that
        gthread.TConn.init = lambda self: None
        conf.post_fork(server, worker)

        class StubConn:
            pass

        stub = StubConn()
        stub.cfg = MagicMock(is_ssl=True)
        stub.client = ("10.0.0.5", 9999)
        stub.parser = MagicMock()
        stub.parser.__next__ = MagicMock(
            side_effect=ssl.SSLError(ssl.SSL_ERROR_EOF, "EOF occurred")
        )

        gthread.TConn.init(stub)

        server.log.reset_mock()
        with pytest.raises(ssl.SSLError):
            next(stub.parser)

        server.log.warning.assert_not_called()

    def test_parser_wrapper_logs_connection_reset(self, conf):
        """ECONNRESET from the parser should be logged at WARNING."""
        import gunicorn.workers.gthread as gthread

        server = MagicMock()
        worker = MagicMock()
        worker.cfg.do_handshake_on_connect = True

        gthread.TConn.init = lambda self: None
        conf.post_fork(server, worker)

        class StubConn:
            pass

        stub = StubConn()
        stub.cfg = MagicMock(is_ssl=True)
        stub.client = ("10.0.0.7", 5555)
        reset_err = OSError(errno.ECONNRESET, "Connection reset by peer")
        stub.parser = MagicMock()
        stub.parser.__next__ = MagicMock(side_effect=reset_err)

        gthread.TConn.init(stub)

        server.log.reset_mock()
        with pytest.raises(OSError):
            next(stub.parser)

        assert server.log.warning.called
        fmt = server.log.warning.call_args[0][0]
        assert "disconnected during TLS" in fmt

    def test_parser_wrapper_skips_non_ssl(self, conf):
        """When ``cfg.is_ssl`` is False, the parser should NOT be wrapped."""
        import gunicorn.workers.gthread as gthread

        server = MagicMock()
        worker = MagicMock()
        worker.cfg.do_handshake_on_connect = True

        gthread.TConn.init = lambda self: None
        conf.post_fork(server, worker)

        class StubConn:
            pass

        stub = StubConn()
        stub.cfg = MagicMock(is_ssl=False)
        stub.client = ("10.0.0.8", 1234)
        original_parser = MagicMock()
        stub.parser = original_parser

        gthread.TConn.init(stub)

        assert stub.parser is original_parser

    def test_diagnostic_debug_log_in_ssl_wrap_socket(self, conf):
        """The patched ssl_wrap_socket should emit a DEBUG log on every
        call showing the do_handshake_on_connect value."""
        import gunicorn.sock as gsock

        # Replace with a mock that succeeds
        gsock.ssl_wrap_socket = MagicMock(return_value=MagicMock())

        server = MagicMock()
        conf.post_fork(server, MagicMock())

        mock_conf = MagicMock()
        mock_conf.do_handshake_on_connect = True
        gsock.ssl_wrap_socket(MagicMock(), mock_conf)

        assert server.log.debug.called
        fmt = server.log.debug.call_args[0][0]
        assert "ssl_wrap_socket called" in fmt


# ===========================================================================
# Subprocess integration test — real Gunicorn process with TLS
# ===========================================================================

class TestGunicornSubprocessTls:
    """Start a real Gunicorn process with TLS, trigger a handshake failure,
    and verify that the WARNING appears in the log output.

    These tests start a subprocess and are inherently slower than unit
    tests. They prove the entire chain works end-to-end: config loading →
    post_fork → ssl_wrap_socket patch → handshake error → WARNING log.
    """

    def test_post_fork_fires_on_startup(self, tmp_path):
        """Gunicorn should log 'TLS handshake failure logging enabled'
        at worker startup when TLS is configured."""
        cert_path, key_path, _, stderr = self._run_gunicorn_with_bad_client(
            tmp_path, trigger_handshake=False,
        )
        assert "TLS handshake failure logging enabled" in stderr, (
            f"post_fork confirmation not found in stderr:\n{stderr}"
        )
        assert "do_handshake_on_connect" in stderr, (
            f"Expected do_handshake_on_connect diagnostic in stderr:\n{stderr}"
        )

    def test_handshake_failure_produces_warning(self, tmp_path):
        """When a client rejects the server certificate, Gunicorn should
        log a TLS failure at WARNING level (verified by the ``[WARNING]``
        tag appearing on the same line as the TLS error message)."""
        _, _, _, stderr = self._run_gunicorn_with_bad_client(
            tmp_path, trigger_handshake=True,
        )
        assert "TLS handshake failure logging enabled" in stderr, (
            f"post_fork hook did not fire. stderr:\n{stderr}"
        )
        # Verify the actual [WARNING] log level tag appears on the same
        # line as the TLS failure message. Layer 1 produces
        # "TLS handshake failed" and Layer 3 produces "TLS error from"
        # or "disconnected during TLS".
        tls_patterns = (
            "TLS handshake failed",
            "TLS error from",
            "disconnected during TLS",
        )
        warning_lines = [
            line for line in stderr.splitlines()
            if "[WARNING]" in line
            and any(pat in line for pat in tls_patterns)
        ]
        assert warning_lines, (
            f"Expected a [WARNING] line containing a TLS failure message "
            f"in Gunicorn stderr:\n{stderr}"
        )

    # --- Helper ---

    def _run_gunicorn_with_bad_client(self, tmp_path, trigger_handshake):
        """Start Gunicorn with TLS and optionally trigger a handshake
        failure. Returns (cert_path, key_path, port, full_stderr)."""
        # --- Generate two separate CAs so the client rejects the server ---
        srv_ca_cert, srv_ca_key = generate_ca(cn="Subprocess Server CA")
        cli_ca_cert, cli_ca_key = generate_ca(cn="Subprocess Untrusted CA")

        srv_cert, srv_key = generate_leaf(
            srv_ca_cert, srv_ca_key, cn="localhost",
            san_dns=["localhost"], san_ips=["127.0.0.1"],
        )
        cert_path = write_pem_cert(srv_cert, tmp_path / "srv.pem")
        key_path = write_pem_key(srv_key, tmp_path / "srv-key.pem")
        cli_ca_path = write_pem_cert(cli_ca_cert, tmp_path / "cli-ca.pem")

        # Minimal phone directory so main.py doesn't warn about missing file
        csv_file = tmp_path / "directory.csv"
        csv_file.write_text("phone_number,display_name\n")

        port = _find_free_port()

        config = tmp_path / "config.yaml"
        config.write_text(
            f"tls_cert_file: {cert_path}\n"
            f"tls_key_file: {key_path}\n"
            f"phone_directory_file: {csv_file}\n"
            "clusters:\n"
            "  test:\n"
            "    allowed_ips:\n"
            "      - 127.0.0.1/32\n"
            "    allowed_subjects:\n"
            "      - localhost\n"
        )

        env = os.environ.copy()
        env["CONFIG_FILE"] = str(config)

        stderr_lines: list[str] = []
        ready_event = threading.Event()

        proc = subprocess.Popen(
            [
                sys.executable, "-m", "gunicorn",
                "main:app",
                "-c", str(_CONF_PY),
                "--bind", f"127.0.0.1:{port}",
                "--workers", "1",
                "--threads", "1",
                "--timeout", "10",
            ],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=env,
            text=True,
            cwd=str(_CONF_PY.parent),
        )

        def _read_stderr():
            for line in proc.stderr:
                stderr_lines.append(line)
                if "Listening at" in line:
                    ready_event.set()

        reader = threading.Thread(target=_read_stderr, daemon=True)
        reader.start()

        try:
            assert ready_event.wait(timeout=15), (
                f"Gunicorn did not start within 15s. "
                f"stderr so far:\n{''.join(stderr_lines)}"
            )

            if trigger_handshake:
                # Client trusts the wrong CA → rejects server cert
                client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_ctx.load_verify_locations(cli_ca_path)
                try:
                    sock = socket.create_connection(
                        ("127.0.0.1", port), timeout=5,
                    )
                    client_ctx.wrap_socket(sock, server_hostname="localhost")
                except (ssl.SSLError, ConnectionResetError,
                        BrokenPipeError, OSError):
                    pass

                # Give the worker time to process and log
                time.sleep(2)

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            reader.join(timeout=3)

        return cert_path, key_path, port, "".join(stderr_lines)
