"""
Module 1 & 2: Nmap Port Scanning and Service Detection Integration.
Executes Nmap safely using subprocess argument arrays, captures XML output,
and parses port states and service banners defensively.
"""

from __future__ import annotations

import logging
import shutil
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field

from app.utils.subprocess_runner import run_command_safely

logger = logging.getLogger(__name__)


@dataclass
class ParsedPort:
    port: int
    protocol: str
    state: str  # open, closed, filtered, untested
    reason: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    confidence: str = "medium"  # high, medium, low
    method: str = "nmap"


@dataclass
class NmapScanResult:
    target_ip: str
    is_host_up: bool
    ports: list[ParsedPort] = field(default_factory=list)
    raw_xml: str = ""
    duration_seconds: float = 0.0
    error_message: str | None = None
    command_executed: list[str] = field(default_factory=list)
    tool_status: str = "success"  # success, failure, timed_out, missing


class NmapService:
    """Service wrapper for executing bounded Nmap scans and parsing structured XML."""

    def __init__(self, nmap_path: str = "nmap"):
        self.nmap_path = nmap_path

    def is_available(self) -> bool:
        """Check if Nmap binary is executable on the host system."""
        return shutil.which(self.nmap_path) is not None

    def get_version(self) -> str | None:
        """Retrieve installed Nmap version string safely."""
        if not self.is_available():
            return None
        res = run_command_safely([self.nmap_path, "--version"], timeout_seconds=5.0)
        if res.is_success and res.stdout:
            first_line = res.stdout.strip().split("\n")[0]
            return first_line
        return None

    def scan_ports(
        self,
        target_ip: str,
        ports: list[int],
        timeout_seconds: int = 60,
        enable_service_detection: bool = True,
        cancellation_check: Callable[[], bool] | None = None,
    ) -> NmapScanResult:
        """
        Execute a bounded TCP connect scan against target_ip for specified ports.
        Uses machine-readable XML output (-oX -).
        """
        if not self.is_available():
            return NmapScanResult(
                target_ip=target_ip,
                is_host_up=False,
                error_message="Nmap binary not found on system PATH.",
                tool_status="missing",
            )

        if not ports:
            return NmapScanResult(
                target_ip=target_ip,
                is_host_up=False,
                error_message="No ports provided for scanning.",
                tool_status="failure",
            )

        port_arg = ",".join(str(p) for p in ports)

        # Build argument list strictly without shell interpolation
        # -sT: unprivileged TCP connect scan (safer, does not require root)
        # -Pn: Treat host as online (prevents ICMP drop misclassification in firewalled LANs)
        # -oX -: Output XML to stdout
        # --host-timeout: bounded execution
        cmd = [
            self.nmap_path,
            "-sT",
            "-Pn",
            "-p",
            port_arg,
            "-oX",
            "-",
            "--host-timeout",
            f"{timeout_seconds}s",
            "--max-retries",
            "1",
        ]

        if enable_service_detection:
            # -sV --version-light (intensity 2): bounded probe intensity for safety
            cmd.extend(["-sV", "--version-light"])

        cmd.append(target_ip)

        if cancellation_check and cancellation_check():
            return NmapScanResult(
                target_ip=target_ip,
                is_host_up=False,
                error_message="Assessment cancelled prior to scan execution.",
                tool_status="failure",
                command_executed=cmd,
            )

        cmd_res = run_command_safely(cmd, timeout_seconds=float(timeout_seconds + 5))

        if cmd_res.timed_out:
            return NmapScanResult(
                target_ip=target_ip,
                is_host_up=False,
                error_message=f"Nmap scan timed out after {timeout_seconds} seconds.",
                duration_seconds=cmd_res.duration_seconds,
                command_executed=cmd,
                tool_status="timed_out",
            )

        if cmd_res.exit_code != 0 and not cmd_res.stdout:
            err = (
                cmd_res.stderr.strip() or cmd_res.error_message or f"Exit code {cmd_res.exit_code}"
            )
            return NmapScanResult(
                target_ip=target_ip,
                is_host_up=False,
                error_message=f"Nmap execution error: {err}",
                duration_seconds=cmd_res.duration_seconds,
                command_executed=cmd,
                tool_status="failure",
            )

        # Parse XML output defensively
        parsed = self.parse_nmap_xml(cmd_res.stdout, target_ip, ports)
        parsed.duration_seconds = cmd_res.duration_seconds
        parsed.command_executed = cmd
        parsed.raw_xml = cmd_res.stdout[:50000]  # Store preview safely
        return parsed

    @staticmethod
    def parse_nmap_xml(
        xml_content: str, target_ip: str, requested_ports: list[int]
    ) -> NmapScanResult:
        """
        Defensively parse Nmap XML output.
        Handles missing elements, unusual port states, and service attributes.
        """
        if not xml_content or not xml_content.strip():
            return NmapScanResult(
                target_ip=target_ip,
                is_host_up=False,
                error_message="Nmap returned empty XML output.",
                tool_status="failure",
            )

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            logger.warning("Failed to parse Nmap XML: %s", e)
            return NmapScanResult(
                target_ip=target_ip,
                is_host_up=False,
                error_message=f"Malformed Nmap XML output: {e}",
                tool_status="failure",
            )

        host_elem = root.find("host")
        if host_elem is None:
            # Host was not found in XML or target was unreachable
            return NmapScanResult(
                target_ip=target_ip,
                is_host_up=False,
                error_message="Host was not reported in Nmap XML output (host may be down or unreachable).",
                tool_status="success",
            )

        # Check host status
        status_elem = host_elem.find("status")
        is_up = status_elem is not None and status_elem.get("state") == "up"

        observed_ports: list[ParsedPort] = []
        ports_elem = host_elem.find("ports")

        if ports_elem is not None:
            for port_tag in ports_elem.findall("port"):
                try:
                    port_id = int(port_tag.get("portid", 0))
                except ValueError:
                    continue
                protocol = port_tag.get("protocol", "tcp")

                state_tag = port_tag.find("state")
                state = state_tag.get("state", "unknown") if state_tag is not None else "unknown"
                reason = state_tag.get("reason", "unknown") if state_tag is not None else "unknown"

                service_tag = port_tag.find("service")
                service_name = service_tag.get("name") if service_tag is not None else None
                product = service_tag.get("product") if service_tag is not None else None
                version = service_tag.get("version") if service_tag is not None else None
                extrainfo = service_tag.get("extrainfo") if service_tag is not None else None

                # Confidence determination
                conf_str = service_tag.get("conf") if service_tag is not None else None
                confidence = "medium"
                if conf_str:
                    try:
                        conf_val = int(conf_str)
                        if conf_val >= 8:
                            confidence = "high"
                        elif conf_val >= 5:
                            confidence = "medium"
                        else:
                            confidence = "low"
                    except ValueError:
                        pass
                elif product or version:
                    confidence = "high"
                elif service_name:
                    confidence = "medium"
                else:
                    confidence = "low"

                observed_ports.append(
                    ParsedPort(
                        port=port_id,
                        protocol=protocol,
                        state=state,
                        reason=reason,
                        service_name=service_name,
                        product=product,
                        version=version,
                        extrainfo=extrainfo,
                        confidence=confidence,
                        method="nmap",
                    )
                )

        return NmapScanResult(
            target_ip=target_ip,
            is_host_up=is_up,
            ports=observed_ports,
            tool_status="success",
        )
