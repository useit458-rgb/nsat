"""
Module 1 Fallback: Socket-based TCP Port Scanner.
Pure-Python fallback when Nmap is unavailable.
Performs bounded TCP connect checks with cancellation callbacks and rate limiting.
"""

from __future__ import annotations

import logging
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SocketPortResult:
    port: int
    protocol: str
    state: str  # open, closed, filtered
    reason: str
    banner: str | None = None
    response_time_ms: float = 0.0


class SocketScanner:
    """Bounded, safe pure-Python socket scanner with cancellation support."""

    def __init__(self, per_port_timeout: float = 0.8, rate_limit_delay: float = 0.02):
        self.per_port_timeout = per_port_timeout
        self.rate_limit_delay = rate_limit_delay

    def scan_ports(
        self,
        target_ip: str,
        ports: list[int],
        cancellation_check: Callable[[], bool] | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[SocketPortResult]:
        """
        Scan a list of TCP ports sequentially with safety bounds and rate limiting.
        """
        results: list[SocketPortResult] = []
        total = len(ports)

        for idx, port in enumerate(ports, start=1):
            if cancellation_check and cancellation_check():
                logger.info("Socket scan cancelled by user during port %d scan.", port)
                break

            result = self.check_port(target_ip, port)
            results.append(result)

            if progress_callback and idx % 5 == 0:
                progress_callback(idx, total)

            if self.rate_limit_delay > 0:
                time.sleep(self.rate_limit_delay)

        return results

    def check_port(self, target_ip: str, port: int) -> SocketPortResult:
        """
        Test a single TCP port using standard socket connect.
        Determines open, closed (ConnectionRefusedError), or filtered (timeout).
        """
        start = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.per_port_timeout)

        try:
            sock.connect((target_ip, port))
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            banner = self._grab_banner(sock, port)
            sock.close()
            return SocketPortResult(
                port=port,
                protocol="tcp",
                state="open",
                reason="syn-ack",
                banner=banner,
                response_time_ms=elapsed_ms,
            )
        except ConnectionRefusedError:
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            sock.close()
            return SocketPortResult(
                port=port,
                protocol="tcp",
                state="closed",
                reason="conn-refused",
                response_time_ms=elapsed_ms,
            )
        except TimeoutError:
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            sock.close()
            return SocketPortResult(
                port=port,
                protocol="tcp",
                state="filtered",
                reason="no-response",
                response_time_ms=elapsed_ms,
            )
        except OSError as e:
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            sock.close()
            return SocketPortResult(
                port=port,
                protocol="tcp",
                state="closed",
                reason=f"os-error: {e}",
                response_time_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            sock.close()
            return SocketPortResult(
                port=port,
                protocol="tcp",
                state="untested",
                reason=f"error: {e}",
                response_time_ms=elapsed_ms,
            )

    def _grab_banner(self, sock: socket.socket, port: int) -> str | None:
        """
        Attempt a conservative, safe banner grab on an already-connected socket.
        Does not send intrusive exploit payloads.
        """
        try:
            sock.settimeout(0.5)
            # For HTTP ports, send a minimal HEAD request
            if port in (80, 8080, 8000, 8888, 3000, 5000):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")

            data = sock.recv(512)
            if data:
                text = data.decode("utf-8", errors="replace").strip()
                # Return the first readable line
                return text.split("\r\n")[0][:150]
        except Exception:
            pass
        return None
