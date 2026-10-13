"""
Unit tests for SocketScanner fallback functionality and cancellation.
"""

from unittest.mock import MagicMock, patch

from app.services.socket_scanner import SocketScanner


class TestSocketScanner:
    @patch("socket.socket")
    def test_open_port_detection(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        # connect succeeds without exception
        mock_sock.connect.return_value = None
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"

        scanner = SocketScanner(per_port_timeout=0.1, rate_limit_delay=0.0)
        res = scanner.check_port("127.0.0.1", 22)

        assert res.state == "open"
        assert res.port == 22
        assert res.reason == "syn-ack"
        assert res.banner == "SSH-2.0-OpenSSH_8.9"

    @patch("socket.socket")
    def test_closed_port_detection(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")

        scanner = SocketScanner(per_port_timeout=0.1, rate_limit_delay=0.0)
        res = scanner.check_port("127.0.0.1", 80)

        assert res.state == "closed"
        assert res.reason == "conn-refused"

    @patch("socket.socket")
    def test_filtered_port_timeout(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = TimeoutError("Timed out")

        scanner = SocketScanner(per_port_timeout=0.1, rate_limit_delay=0.0)
        res = scanner.check_port("127.0.0.1", 443)

        assert res.state == "filtered"
        assert res.reason == "no-response"

    def test_cancellation_callback(self):
        scanner = SocketScanner(per_port_timeout=0.01, rate_limit_delay=0.0)
        ports = [21, 22, 23, 25, 80, 443]

        called_count = 0

        def cancel_check():
            nonlocal called_count
            called_count += 1
            return called_count > 2  # Cancel after 2 ports

        with patch.object(scanner, "check_port") as mock_check:
            mock_check.return_value = MagicMock(port=22, state="closed", reason="test")
            results = scanner.scan_ports("127.0.0.1", ports, cancellation_check=cancel_check)

        # Should have stopped early
        assert len(results) < len(ports)
