"""
Module 3: Security Risk Assessment and Findings Engine.
Translates verified network observations, service detections, HTTP headers,
TLS certificates, and Lynis audits into prioritized, actionable findings.
Applies a documented, deterministic scoring model.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.models.port_result import PortResult
from app.models.service_observation import ServiceObservation
from app.services.http_checks import HttpCheckResult
from app.services.lynis_service import LynisAuditResult
from app.services.tls_checks import TlsCheckResult

logger = logging.getLogger(__name__)


@dataclass
class RuleFinding:
    finding_key: str  # Unique stable identifier for deduplication
    title: str
    severity: str  # Critical, High, Medium, Low, Informational
    confidence: str  # High, Medium, Low
    category: str
    asset_ip: str
    port: int | None
    description: str
    evidence: str
    reasoning: str
    remediation: str
    references: list[str] = field(default_factory=list)


class RiskEngine:
    """
    Deterministic rules engine.
    Separates severity (potential impact) from confidence (certainty of evidence).
    Never invents CVEs or claims confirmed exploits.
    """

    SEVERITY_WEIGHTS = {
        "Critical": 25.0,
        "High": 15.0,
        "Medium": 7.0,
        "Low": 2.5,
        "Informational": 0.5,
    }

    CONFIDENCE_MULTIPLIERS = {
        "High": 1.0,
        "Medium": 0.8,
        "Low": 0.5,
    }

    def evaluate(
        self,
        target_ip: str,
        port_results: list[PortResult],
        service_obs: list[ServiceObservation],
        http_results: list[HttpCheckResult] | None = None,
        tls_results: list[TlsCheckResult] | None = None,
        lynis_result: LynisAuditResult | None = None,
    ) -> tuple[list[RuleFinding], float]:
        """
        Evaluate all gathered evidence against defensive security rules.
        Returns deduplicated list of findings and overall composite risk score (0-100).
        """
        findings_map: dict[str, RuleFinding] = {}

        # 1. Evaluate Port & Service Exposures
        self._evaluate_network_services(target_ip, port_results, service_obs, findings_map)

        # 2. Evaluate HTTP Security Headers
        if http_results:
            self._evaluate_http_headers(target_ip, http_results, findings_map)

        # 3. Evaluate TLS Configurations
        if tls_results:
            self._evaluate_tls(target_ip, tls_results, findings_map)

        # 4. Evaluate Lynis Local Audit
        if lynis_result and lynis_result.is_executed:
            self._evaluate_lynis(target_ip, lynis_result, findings_map)

        findings = list(findings_map.values())

        # Sort findings by severity (Critical -> Informational), then by port
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.port or 0))

        # Calculate composite deterministic risk score (capped at 100)
        risk_score = self._calculate_risk_score(findings)

        return findings, risk_score

    def _evaluate_network_services(
        self,
        target_ip: str,
        port_results: list[PortResult],
        service_obs: list[ServiceObservation],
        findings_map: dict[str, RuleFinding],
    ) -> None:
        open_ports = [p for p in port_results if p.state == "open"]
        services_by_port = {s.port_number: s for s in service_obs}

        for p in open_ports:
            port = p.port_number
            svc = services_by_port.get(port)
            svc_name = (svc.service_name if svc else p.service_name or "").lower()
            product = svc.product if svc else None
            version = svc.version if svc else None
            conf = svc.confidence if svc else "Medium"
            conf_cap = conf.capitalize()

            # Rule: Telnet (Cleartext terminal administration)
            if port == 23 or "telnet" in svc_name:
                key = f"EXP-TELNET-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title="Exposed Insecure Telnet Service",
                    severity="High",
                    confidence="High" if (svc and svc.product) else conf_cap,
                    category="Cleartext Protocol",
                    asset_ip=target_ip,
                    port=port,
                    description=f"TCP port {port} is open and running Telnet. Telnet transmits authentication credentials and commands in unencrypted plaintext.",
                    evidence=f"TCP Port {port} responded open. Service identification: '{svc_name}' (Product: {product or 'Generic'}).",
                    reasoning="Unencrypted transport enables eavesdropping and credential interception by any observer on the local network path.",
                    remediation="Disable the Telnet daemon immediately and replace it with OpenSSH using SSHv2 and key-based authentication.",
                    references=[
                        "https://datatracker.ietf.org/doc/html/rfc854",
                        "https://csrc.nist.gov/publications/detail/sp/800-123/final",
                    ],
                )

            # Rule: FTP (Cleartext file transfer)
            elif port == 21 or "ftp" in svc_name:
                key = f"EXP-FTP-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title="Exposed Plaintext FTP Service",
                    severity="Medium",
                    confidence=conf_cap,
                    category="Cleartext Protocol",
                    asset_ip=target_ip,
                    port=port,
                    description=f"TCP port {port} is exposing File Transfer Protocol (FTP). Standard FTP sends credentials in cleartext.",
                    evidence=f"Port {port} open. Service identified as {svc_name} {product or ''} {version or ''}.",
                    reasoning="Credentials transmitted via basic FTP can be captured through network sniffing on shared segments.",
                    remediation="Migrate to SFTP (over SSH) or FTPS with explicit TLS. Verify that anonymous FTP access is strictly disabled.",
                    references=["https://datatracker.ietf.org/doc/html/rfc2228"],
                )

            # Rule: SMB Exposure
            elif port in (139, 445) or "smb" in svc_name or "microsoft-ds" in svc_name:
                key = f"EXP-SMB-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title="Exposed Server Message Block (SMB) Service",
                    severity="High",
                    confidence=conf_cap,
                    category="Network Exposure",
                    asset_ip=target_ip,
                    port=port,
                    description=f"TCP port {port} is hosting SMB file sharing. Unrestricted SMB exposure creates significant lateral movement risks.",
                    evidence=f"Port {port} reported open with service '{svc_name}'.",
                    reasoning="Exposed SMB services are frequent targets for credential relay, enumeration, and wormable exploits.",
                    remediation="Restrict access to port 445/139 using firewall rules. Disable legacy SMBv1 and enforce SMB packet signing.",
                    references=[
                        "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security"
                    ],
                )

            # Rule: RDP Exposure
            elif port == 3389 or "rdp" in svc_name or "ms-wbt" in svc_name:
                key = f"EXP-RDP-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title="Exposed Remote Desktop Protocol (RDP)",
                    severity="High",
                    confidence=conf_cap,
                    category="Network Exposure",
                    asset_ip=target_ip,
                    port=port,
                    description=f"TCP port {port} exposes Windows Remote Desktop. RDP access should not be reachable without network isolation.",
                    evidence=f"Port {port} open with service '{svc_name}'.",
                    reasoning="Exposed RDP instances attract persistent brute-force attacks and automated scanning.",
                    remediation="Place RDP behind a VPN gateway or Remote Desktop Gateway. Enforce Network Level Authentication (NLA) and MFA.",
                    references=["https://csrc.nist.gov/publications/detail/sp/800-46/rev-2/final"],
                )

            # Rule: VNC Exposure
            elif port == 5900 or "vnc" in svc_name:
                key = f"EXP-VNC-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title="Exposed Virtual Network Computing (VNC)",
                    severity="High",
                    confidence=conf_cap,
                    category="Network Exposure",
                    asset_ip=target_ip,
                    port=port,
                    description=f"TCP port {port} is hosting VNC remote desktop sharing. VNC authentication passwords are often limited or poorly protected.",
                    evidence=f"Port {port} open with VNC signature.",
                    reasoning="Standard VNC lacks modern session encryption and is susceptible to brute-force attacks and session snooping.",
                    remediation="Tunnel VNC connections through SSH or a VPN. Do not expose port 5900 directly.",
                    references=[
                        "https://www.cisa.gov/news-events/alerts/2006/05/23/vnc-vulnerabilities"
                    ],
                )

            # Rule: Redis In-Memory Database
            elif port == 6379 or "redis" in svc_name:
                key = f"EXP-REDIS-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title="Exposed Redis In-Memory Datastore",
                    severity="High",
                    confidence=conf_cap,
                    category="Database Exposure",
                    asset_ip=target_ip,
                    port=port,
                    description=f"TCP port {port} is exposing Redis. Default Redis configurations frequently lack authentication and transport encryption.",
                    evidence=f"Port {port} open with service '{svc_name}'.",
                    reasoning="Unauthenticated Redis exposure allows unauthorized actors to read, flush, or write arbitrary key-value data.",
                    remediation="Bind Redis to 127.0.0.1, enable 'protected-mode yes', and configure a strong password in 'requirepass'.",
                    references=["https://redis.io/docs/management/security/"],
                )

            # Rule: Relational Databases (MySQL, PostgreSQL, MSSQL, MongoDB)
            elif port in (1433, 3306, 5432, 27017) or any(
                db in svc_name for db in ("mysql", "postgres", "ms-sql", "mongodb")
            ):
                key = f"EXP-DB-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title=f"Directly Accessible Database Port ({port})",
                    severity="Medium",
                    confidence=conf_cap,
                    category="Database Exposure",
                    asset_ip=target_ip,
                    port=port,
                    description=f"Database port {port} is open and reachable over the network socket.",
                    evidence=f"Port {port} open. Service '{svc_name}' detected.",
                    reasoning="Database ports should not be exposed across general network interfaces; applications should connect via localhost or isolated subnets.",
                    remediation="Bind the database listener to 127.0.0.1 or an isolated private management subnet. Enforce TLS and authentication.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"
                    ],
                )

            # Rule: Plaintext HTTP
            elif port in (80, 8080) and "https" not in svc_name:
                key = f"EXP-HTTP-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title=f"Unencrypted HTTP Service on Port {port}",
                    severity="Low",
                    confidence="High",
                    category="Cleartext Protocol",
                    asset_ip=target_ip,
                    port=port,
                    description=f"TCP port {port} is serving cleartext HTTP traffic.",
                    evidence=f"Port {port} open with HTTP service.",
                    reasoning="Web sessions transmitted over plain HTTP do not protect cookie values, passwords, or data from local eavesdroppers.",
                    remediation="Configure TLS/HTTPS and automatically redirect all HTTP requests to HTTPS.",
                    references=["https://letsencrypt.org/docs/https-adoption/"],
                )

            # Rule: Baseline SSH exposure
            elif port == 22 or "ssh" in svc_name:
                key = f"INFO-SSH-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title=f"SSH Remote Administration Service Detected ({port})",
                    severity="Informational",
                    confidence=conf_cap,
                    category="Network Exposure",
                    asset_ip=target_ip,
                    port=port,
                    description=f"SSH daemon detected on port {port}. SSH provides secure encrypted remote access when properly configured.",
                    evidence=f"Port {port} open. Identified as {svc_name} {product or ''} {version or ''}.",
                    reasoning="Normal administrative access point. Does not imply vulnerability unless weak credentials or outdated versions are present.",
                    remediation="Audit sshd_config: disable PermitRootLogin and PasswordAuthentication, and enforce Fail2ban/rate-limiting.",
                    references=["https://www.ssh.com/academy/ssh/sshd_config"],
                )

            # General open port notice
            else:
                key = f"INFO-PORT-{port}"
                if key not in findings_map:
                    findings_map[key] = RuleFinding(
                        finding_key=key,
                        title=f"Exposed TCP Port {port} ({svc_name or 'Unidentified'})",
                        severity="Informational",
                        confidence="Medium",
                        category="Network Exposure",
                        asset_ip=target_ip,
                        port=port,
                        description=f"TCP port {port} was confirmed open during assessment.",
                        evidence=f"Port {port} responded open (reason: {p.reason}).",
                        reasoning="Services listening on exposed sockets expand the attack surface of the host.",
                        remediation="Verify whether this service is business-critical. If unnecessary, stop the daemon and close the firewall port.",
                        references=[],
                    )

    def _evaluate_http_headers(
        self,
        target_ip: str,
        http_results: list[HttpCheckResult],
        findings_map: dict[str, RuleFinding],
    ) -> None:
        for res in http_results:
            if not res.tested or res.status_code is None:
                continue

            port = res.port
            # Evaluate missing security headers
            for hdr in res.headers_analyzed:
                if not hdr.present:
                    key = f"HTTP-MISSING-{hdr.header_name.upper()}-{port}"
                    findings_map[key] = RuleFinding(
                        finding_key=key,
                        title=f"Missing HTTP Header: {hdr.header_name} (Port {port})",
                        severity=hdr.severity,
                        confidence="High",
                        category="HTTP Security",
                        asset_ip=target_ip,
                        port=port,
                        description=f"The web service on port {port} did not return the standard defensive header '{hdr.header_name}'.",
                        evidence=f"HTTP GET {res.target_url} returned status {res.status_code}. Header '{hdr.header_name}' was absent from response headers.",
                        reasoning=f"Absence of {hdr.header_name}: {hdr.description}",
                        remediation=f"Configure the web server or reverse proxy to include header: '{hdr.header_name}: {hdr.recommended_value}'.",
                        references=["https://owasp.org/www-project-secure-headers/"],
                    )

            # Check server banner information leakage
            if res.server_header:
                key = f"HTTP-SERVER-LEAK-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title=f"Server Banner Information Disclosure (Port {port})",
                    severity="Low",
                    confidence="High",
                    category="Information Disclosure",
                    asset_ip=target_ip,
                    port=port,
                    description=f"Web server revealed internal software banner: '{res.server_header}'.",
                    evidence=f"Response header: Server: {res.server_header}",
                    reasoning="Detailed version banners assist reconnaissance by revealing specific software stacks and patch levels.",
                    remediation="Configure web server to suppress or tokenize the Server header (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                    ],
                )

    def _evaluate_tls(
        self,
        target_ip: str,
        tls_results: list[TlsCheckResult],
        findings_map: dict[str, RuleFinding],
    ) -> None:
        for res in tls_results:
            if not res.connected:
                continue
            port = res.port

            if res.is_expired:
                key = f"TLS-EXPIRED-CERT-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title=f"Expired TLS Certificate (Port {port})",
                    severity="High",
                    confidence="High",
                    category="TLS/SSL",
                    asset_ip=target_ip,
                    port=port,
                    description=f"The TLS certificate presented on port {port} expired on {res.cert_not_after}.",
                    evidence=f"Certificate notAfter date: {res.cert_not_after} (Expired by {abs(res.days_until_expiry or 0)} days).",
                    reasoning="Expired certificates cause browser trust rejections, break automated clients, and increase risk of MITM acceptance.",
                    remediation="Renew and deploy an active, valid TLS certificate immediately.",
                    references=["https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"],
                )
            elif res.is_expiring_soon:
                key = f"TLS-EXPIRING-SOON-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title=f"TLS Certificate Expiring Soon (Port {port})",
                    severity="Medium",
                    confidence="High",
                    category="TLS/SSL",
                    asset_ip=target_ip,
                    port=port,
                    description=f"The TLS certificate on port {port} will expire in {res.days_until_expiry} days.",
                    evidence=f"Certificate notAfter date: {res.cert_not_after}.",
                    reasoning="Imminent expiration requires renewal action to prevent service outage.",
                    remediation="Schedule automated certificate renewal before expiration occurs.",
                    references=[],
                )

            if res.is_weak_protocol:
                key = f"TLS-WEAK-PROTOCOL-{port}"
                findings_map[key] = RuleFinding(
                    finding_key=key,
                    title=f"Deprecated TLS Protocol ({res.protocol_version}) on Port {port}",
                    severity="High",
                    confidence="High",
                    category="TLS/SSL",
                    asset_ip=target_ip,
                    port=port,
                    description=f"Server negotiated deprecated protocol {res.protocol_version}.",
                    evidence=f"Handshake protocol: {res.protocol_version}.",
                    reasoning="Legacy protocols (SSLv3, TLS 1.0, TLS 1.1) suffer from known cryptographic weaknesses.",
                    remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 on the server. Enforce TLS 1.2 and TLS 1.3 only.",
                    references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                )

    def _evaluate_lynis(
        self,
        target_ip: str,
        lynis_result: LynisAuditResult,
        findings_map: dict[str, RuleFinding],
    ) -> None:
        # Convert Lynis warnings into High/Medium findings
        for warn in lynis_result.warnings:
            key = f"LYNIS-WARN-{warn.test_id}"
            findings_map[key] = RuleFinding(
                finding_key=key,
                title=f"System Audit Warning: {warn.description} [{warn.test_id}]",
                severity="Medium",
                confidence="High",
                category="System Audit",
                asset_ip=target_ip,
                port=None,
                description=f"Lynis host audit flagged warning during test {warn.test_id}.",
                evidence=f"Lynis check [{warn.test_id}]: {warn.description}",
                reasoning="System configuration deviates from recommended Linux hardening baselines.",
                remediation=warn.solution
                or "Inspect Lynis documentation for test ID to apply recommended configuration hardening.",
                references=[f"https://cisofy.com/lynis/controls/{warn.test_id}/"],
            )

        # Convert Lynis suggestions into Low/Informational findings (limit to top 10 to prevent report bloat)
        for idx, sug in enumerate(lynis_result.suggestions[:10]):
            key = f"LYNIS-SUG-{sug.test_id}"
            findings_map[key] = RuleFinding(
                finding_key=key,
                title=f"System Hardening Suggestion: {sug.description} [{sug.test_id}]",
                severity="Low",
                confidence="High",
                category="System Audit",
                asset_ip=target_ip,
                port=None,
                description=f"Lynis suggestion for system hardening: {sug.description}",
                evidence=f"Lynis recommendation [{sug.test_id}].",
                reasoning="Adopting defensive hardening measures reduces potential attack surface on the host.",
                remediation=sug.solution
                or "Implement hardening suggestion as appropriate for system workload.",
                references=[f"https://cisofy.com/lynis/controls/{sug.test_id}/"],
            )

    def _calculate_risk_score(self, findings: list[RuleFinding]) -> float:
        """
        Calculate a normalized composite risk score (0.0 to 100.0).
        Score incorporates severity weights and evidence confidence.
        """
        if not findings:
            return 0.0

        raw_score = 0.0
        for f in findings:
            weight = self.SEVERITY_WEIGHTS.get(f.severity, 1.0)
            mult = self.CONFIDENCE_MULTIPLIERS.get(f.confidence, 0.8)
            raw_score += weight * mult

        # Non-linear asymptotic curve to cap at 100
        # 100 * (1 - e^(-raw / 50))
        import math

        normalized = 100.0 * (1.0 - math.exp(-raw_score / 60.0))
        return round(min(normalized, 100.0), 1)
