"""
Unit tests for scoped HTTP header auditing and TLS inspection.
"""

from unittest.mock import MagicMock, patch

from app.services.http_checks import HttpSecurityChecker
from app.services.tls_checks import TlsChecker


class TestHttpAndTlsChecks:
    @patch("requests.Session.get")
    def test_http_security_headers_evaluation(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Content-Type": "text/html",
            "Server": "nginx/1.22.1",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        }
        mock_resp.raw.read.return_value = b"<html>Test</html>"
        mock_get.return_value = mock_resp

        checker = HttpSecurityChecker(timeout_seconds=1.0)
        res = checker.evaluate_target("127.0.0.1", 80, is_https=False)

        assert res.tested is True
        assert res.status_code == 200
        assert res.server_header == "nginx/1.22.1"

        # Check that X-Frame-Options is recorded as present
        x_frame = next(h for h in res.headers_analyzed if h.header_name == "X-Frame-Options")
        assert x_frame.present is True

        # Check that CSP is recorded as missing
        csp = next(h for h in res.headers_analyzed if h.header_name == "Content-Security-Policy")
        assert csp.present is False

    @patch("socket.socket")
    @patch("ssl.SSLContext.wrap_socket")
    def test_tls_weak_protocol_detection(self, mock_wrap, mock_sock_cls):
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.version.return_value = "TLSv1"  # Deprecated
        mock_ssl_sock.cipher.return_value = ("ECDHE-RSA-AES128-SHA", "TLSv1.0", 128)
        mock_ssl_sock.getpeercert.return_value = b""
        mock_wrap.return_value = mock_ssl_sock

        checker = TlsChecker(timeout_seconds=1.0)
        res = checker.inspect_tls("127.0.0.1", 443)

        assert res.connected is True
        assert res.protocol_version == "TLSv1"
        assert res.is_weak_protocol is True
