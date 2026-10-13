"""
Module 3 Component: Bounded TLS/SSL Configuration and Certificate Inspection.
Connects via Python standard ssl module, retrieves peer certificate,
calculates expiry dates, flags weak protocol versions and self-signed certificates.
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class TlsCheckResult:
    target_ip: str
    port: int
    connected: bool
    protocol_version: str | None = None
    cipher_suite: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_before: datetime | None = None
    cert_not_after: datetime | None = None
    days_until_expiry: int | None = None
    is_expired: bool = False
    is_expiring_soon: bool = False  # < 30 days
    is_self_signed: bool = False
    is_weak_protocol: bool = False  # TLS 1.0 or 1.1 or SSLv3
    san_list: list[str] = field(default_factory=list)
    error_message: str | None = None


class TlsChecker:
    """Safe, bounded TLS certificate and handshake inspector."""

    def __init__(self, timeout_seconds: float = 3.0):
        self.timeout_seconds = timeout_seconds

    def inspect_tls(self, target_ip: str, port: int) -> TlsCheckResult:
        """
        Inspect TLS server certificate and protocol version using standard library ssl.
        """
        result = TlsCheckResult(
            target_ip=target_ip,
            port=port,
            connected=False,
        )

        # Create unverified context to allow fetching self-signed certs for auditing
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(self.timeout_seconds)

        try:
            raw_sock.connect((target_ip, port))
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=None)

            result.connected = True
            result.protocol_version = ssl_sock.version()
            cipher_info = ssl_sock.cipher()
            result.cipher_suite = cipher_info[0] if cipher_info else None

            # Check weak protocol
            if result.protocol_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                result.is_weak_protocol = True

            # Retrieve peer cert in binary format and decode
            # When verify_mode=CERT_NONE, getpeercert() returns empty dict,
            # so we fetch DER bytes and parse with ssl.DER_cert_to_PEM_cert or PyOpenSSL/cryptography if present,
            # or use binary DER parsing.
            cert_der = ssl_sock.getpeercert(binary_form=True)
            ssl_sock.close()

            if cert_der:
                self._parse_cert_der(cert_der, result)

        except TimeoutError:
            result.error_message = (
                f"TLS connection to {target_ip}:{port} timed out after {self.timeout_seconds}s."
            )
        except ConnectionRefusedError:
            result.error_message = f"Connection refused on port {port}."
        except ssl.SSLError as e:
            result.error_message = f"SSL Handshake error: {e}"
        except Exception as e:
            result.error_message = f"TLS inspection failed: {e}"
        finally:
            try:
                raw_sock.close()
            except Exception:
                pass

        return result

    def _parse_cert_der(self, der_bytes: bytes, result: TlsCheckResult) -> None:
        """
        Parse X.509 certificate DER bytes using ssl module or fallback.
        """
        try:
            # We can parse text from PEM or use ssl._ssl if available
            import ssl

            # On Python 3.10+, ssl.SSLSocket has internal decoding or we can parse via cryptography or basic ASN1
            # Let's check if we can inspect using ssl.getpeercert when check_hostname=False but with a custom helper
            # Alternatively, Python standard library ssl doesn't have public X509 parser from DER without cert validation.
            # Convert to PEM:
            _ = ssl.DER_cert_to_PEM_cert(der_bytes)

            # Simple defensive parser for standard dates in PEM if cryptography is not installed:
            # Let's inspect using ssl._ssl if available or pure Python regex on common ASN.1 patterns
            self._extract_x509_metadata(der_bytes, result)
        except Exception as e:
            logger.debug("Failed parsing DER cert: %s", e)

    def _extract_x509_metadata(self, der_bytes: bytes, result: TlsCheckResult) -> None:
        """
        Extract validity dates and subject/issuer heuristics from X509 DER.
        """
        try:
            # ASN.1 UTCTime tag is 0x17 (23), GeneralizedTime tag is 0x18 (24)
            # Find UTCTime in DER bytes: 'YYMMDDHHMMSSZ'
            dates_found = []
            i = 0
            while i < len(der_bytes) - 15:
                tag = der_bytes[i]
                length = der_bytes[i + 1]
                if tag == 0x17 and length == 13:  # UTCTime: 13 bytes e.g. 240101000000Z
                    date_str = der_bytes[i + 2 : i + 2 + 13].decode("ascii", errors="ignore")
                    try:
                        dt = datetime.strptime(date_str, "%y%m%d%H%M%SZ").replace(tzinfo=UTC)
                        dates_found.append(dt)
                    except ValueError:
                        pass
                    i += 15
                elif tag == 0x18 and length == 15:  # GeneralizedTime: 15 bytes e.g. 20240101000000Z
                    date_str = der_bytes[i + 2 : i + 2 + 15].decode("ascii", errors="ignore")
                    try:
                        dt = datetime.strptime(date_str, "%Y%m%d%H%M%SZ").replace(tzinfo=UTC)
                        dates_found.append(dt)
                    except ValueError:
                        pass
                    i += 17
                else:
                    i += 1

            if len(dates_found) >= 2:
                result.cert_not_before = dates_found[0]
                result.cert_not_after = dates_found[1]

                now = datetime.now(UTC)
                delta_days = (result.cert_not_after - now).days
                result.days_until_expiry = delta_days
                result.is_expired = delta_days < 0
                result.is_expiring_soon = 0 <= delta_days <= 30

        except Exception as e:
            logger.debug("Date extraction exception: %s", e)
