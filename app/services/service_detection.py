"""
Module 2: Service Detection and Identification.
Analyzes open ports, infers or parses confirmed service identities, products, and versions,
and provides contextual security implications and administrative recommendations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Standard well-known port mapping for defensive baseline inference
KNOWN_PORT_SERVICES: dict[int, tuple[str, str, str]] = {
    21: (
        "ftp",
        "File Transfer Protocol (FTP)",
        "Plaintext credentials and file data transfer. Ensure anonymous access is disabled and TLS (FTPS) is enforced.",
    ),
    22: (
        "ssh",
        "Secure Shell (SSH)",
        "Encrypted remote administration. Ensure root login is disabled and key-based authentication is enforced.",
    ),
    23: (
        "telnet",
        "Telnet Remote Protocol",
        "Unencrypted legacy remote access. Highly vulnerable to eavesdropping and credential theft; should be replaced with SSH.",
    ),
    25: (
        "smtp",
        "Simple Mail Transfer Protocol (SMTP)",
        "Mail transmission. Check for open relay configuration and enforce STARTTLS encryption.",
    ),
    53: (
        "dns",
        "Domain Name System (DNS)",
        "Name resolution service. Verify DNS recursion restrictions and zone transfer controls.",
    ),
    80: (
        "http",
        "Hypertext Transfer Protocol (HTTP)",
        "Cleartext web traffic. Ensure redirection to HTTPS and apply modern HTTP security headers.",
    ),
    110: (
        "pop3",
        "Post Office Protocol (POP3)",
        "Cleartext email retrieval. Migrate to POP3S (port 995) or IMAP over TLS.",
    ),
    135: (
        "msrpc",
        "Microsoft RPC Endpoint Mapper",
        "Windows internal RPC. Should never be exposed to untrusted networks or outside management subnets.",
    ),
    139: (
        "netbios-ssn",
        "NetBIOS Session Service",
        "Legacy SMB/NetBIOS file sharing. Restrict to authorized internal subnets only.",
    ),
    143: (
        "imap",
        "Internet Message Access Protocol (IMAP)",
        "Email retrieval. Migrate to IMAPS (port 993) to protect credentials.",
    ),
    389: (
        "ldap",
        "Lightweight Directory Access Protocol (LDAP)",
        "Directory queries. Enforce LDAPS (port 636) or StartTLS to protect authentication tokens.",
    ),
    443: (
        "https",
        "HTTP over TLS/SSL (HTTPS)",
        "Encrypted web service. Verify TLS protocol versions, cipher suites, and certificate validity.",
    ),
    445: (
        "microsoft-ds",
        "Microsoft Directory Services / SMB",
        "File and print sharing. Restrict to internal trusted subnets to mitigate lateral movement.",
    ),
    1433: (
        "ms-sql-s",
        "Microsoft SQL Server",
        "Relational database server. Verify network firewalling and strong database authentication.",
    ),
    1521: (
        "oracle",
        "Oracle Database TNS Listener",
        "Database management interface. Ensure restricted IP access and patched listener.",
    ),
    3306: (
        "mysql",
        "MySQL Database",
        "Database server. Verify bind address (prefer 127.0.0.1) and disable remote root login.",
    ),
    3389: (
        "ms-wbt-server",
        "Remote Desktop Protocol (RDP)",
        "Windows GUI remote management. Restrict via VPN/NLA, enforce MFA and brute-force protection.",
    ),
    5432: (
        "postgresql",
        "PostgreSQL Database",
        "Relational database server. Ensure pg_hba.conf restricts host access and enforces SSL.",
    ),
    5900: (
        "vnc",
        "Virtual Network Computing (VNC)",
        "Remote desktop sharing. Often lacks modern encryption; enforce VPN and strong passwords.",
    ),
    6379: (
        "redis",
        "Redis Key-Value Store",
        "In-memory database. Historically unauthenticated by default; ensure protected-mode and strong AUTH.",
    ),
    8080: (
        "http-proxy",
        "HTTP Alternate / Proxy",
        "Web proxy or alternate web server. Verify authentication and header configuration.",
    ),
    8443: (
        "https-alt",
        "HTTPS Alternate",
        "Encrypted alternate web server. Verify TLS configuration and certificates.",
    ),
    9200: (
        "elasticsearch",
        "Elasticsearch REST API",
        "Search engine interface. Verify authentication, TLS, and access restrictions.",
    ),
    27017: (
        "mongodb",
        "MongoDB Database",
        "NoSQL document database. Ensure auth is enabled and external bindings are restricted.",
    ),
}


@dataclass
class ServiceDetail:
    port: int
    service_name: str
    product: str | None
    version: str | None
    extrainfo: str | None
    confidence: str  # high, medium, low
    method: str  # nmap-banner, nmap-probe, socket-banner, port-inference
    implications: str
    recommendation: str


class ServiceDetector:
    """Consolidates service detection observations and produces actionable context."""

    @staticmethod
    def enrich_observation(
        port: int,
        raw_service: str | None = None,
        product: str | None = None,
        version: str | None = None,
        extrainfo: str | None = None,
        banner: str | None = None,
        method: str = "port-inference",
    ) -> ServiceDetail:
        """
        Enrich an observed open port with service name, version details,
        confidence scoring, security implications, and recommendations.
        """
        known_service, display_name, baseline_advice = KNOWN_PORT_SERVICES.get(
            port,
            (
                raw_service or "unknown",
                f"TCP Service on port {port}",
                "Review service necessity and restrict access to authorized users.",
            ),
        )

        service_name = raw_service or known_service

        # Banner heuristic if product/version not yet set
        if banner and not product:
            banner_lower = banner.lower()
            if "apache" in banner_lower:
                product = "Apache HTTP Server"
            elif "nginx" in banner_lower:
                product = "nginx"
            elif "openssh" in banner_lower:
                product = "OpenSSH"
            elif "microsoft" in banner_lower or "iis" in banner_lower:
                product = "Microsoft IIS"

        # Determine confidence
        if product or version:
            confidence = "high"
        elif banner or (method in ("nmap-probe", "nmap")) or raw_service:
            confidence = "medium"
        else:
            confidence = "low"

        # Tailor implications & recommendations
        implications, recommendation = ServiceDetector._get_context(
            service_name, port, baseline_advice
        )

        return ServiceDetail(
            port=port,
            service_name=service_name,
            product=product,
            version=version,
            extrainfo=extrainfo,
            confidence=confidence,
            method=method,
            implications=implications,
            recommendation=recommendation,
        )

    @staticmethod
    def _get_context(service_name: str, port: int, default_advice: str) -> tuple[str, str]:
        s = service_name.lower()
        if "telnet" in s or port == 23:
            return (
                "Telnet transmits authentication and session data unencrypted over the wire.",
                "Disable Telnet immediately and migrate all administrative access to SSH.",
            )
        if "ftp" in s or port == 21:
            return (
                "Standard FTP transmits credentials and data in cleartext.",
                "Enforce FTPS or SFTP, disable anonymous access, and restrict firewall access.",
            )
        if "ssh" in s or port == 22:
            return (
                "SSH provides encrypted remote terminal management. Vulnerable if weak passwords or outdated versions are used.",
                "Enforce public-key authentication, disable password authentication, and disable root login.",
            )
        if "http" in s and "https" not in s and port in (80, 8080):
            return (
                "Cleartext HTTP exposes session tokens and user data to interception on local network segments.",
                "Implement HTTPS with TLS 1.2/1.3, configure automatic HTTP-to-HTTPS redirect, and enable HSTS.",
            )
        if "https" in s or port in (443, 8443):
            return (
                "HTTPS encrypts web traffic. Weak ciphers or expired certificates can compromise confidentiality.",
                "Inspect certificate expiration and ensure modern cipher suites and TLS 1.3/1.2 are configured.",
            )
        if "rdp" in s or "ms-wbt" in s or port == 3389:
            return (
                "RDP exposes GUI access. Internet-facing or broad network exposure attracts automated brute-force attacks.",
                "Require VPN or SSH tunneling to reach RDP, enable Network Level Authentication (NLA), and enforce MFA.",
            )
        if "redis" in s or port == 6379:
            return (
                "Redis instances without authentication permit unauthorized arbitrary memory read/write.",
                "Bind Redis strictly to 127.0.0.1, enable strong requirepass authentication, and isolate network access.",
            )
        if "mysql" in s or port == 3306 or "postgres" in s or port == 5432:
            return (
                "Database listening on network socket. Direct database exposure increases risk of unauthorized access or data exfiltration.",
                "Bind database to localhost (127.0.0.1) if only accessed locally, or place behind a firewall with TLS enforced.",
            )
        if "smb" in s or port in (139, 445):
            return (
                "SMB file sharing protocol. Broad access risks credential relay and lateral movement.",
                "Block SMB at perimeter and subnet boundaries, disable SMBv1, and require SMB signing.",
            )
        return (f"Service '{service_name}' listening on TCP port {port}.", default_advice)
