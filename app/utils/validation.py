"""
Strict input validation utilities for IP addresses, ports, and assessment parameters.
Enforces defensive scope restrictions (private and loopback targets only).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


class ValidationError(ValueError):
    """Raised when user input violates validation or security rules."""


# Well-known port presets for quick selection
PORT_PRESETS = {
    "top20": [
        20,
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        1723,
        3306,
        3389,
        8080,
    ],
    "top100": [
        7,
        9,
        13,
        21,
        22,
        23,
        25,
        26,
        37,
        53,
        79,
        80,
        81,
        88,
        106,
        110,
        111,
        113,
        119,
        135,
        139,
        143,
        144,
        179,
        199,
        389,
        427,
        443,
        444,
        445,
        465,
        513,
        514,
        515,
        543,
        548,
        554,
        587,
        631,
        646,
        873,
        990,
        993,
        995,
        1025,
        1026,
        1027,
        1028,
        1029,
        1110,
        1433,
        1720,
        1723,
        1755,
        1900,
        2000,
        2001,
        2049,
        2121,
        2717,
        3000,
        3128,
        3306,
        3389,
        3986,
        4899,
        5000,
        5009,
        5051,
        5060,
        5101,
        5190,
        5357,
        5432,
        5631,
        5666,
        5800,
        5900,
        6000,
        6001,
        6646,
        7070,
        8000,
        8008,
        8080,
        8081,
        8443,
        8888,
        9000,
        9090,
        9100,
        9999,
        10000,
        32768,
        49152,
    ],
    "web": [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000],
    "database": [1433, 1521, 3306, 5432, 6379, 9042, 27017, 27018],
    "management": [22, 23, 3389, 5900, 5985, 5986],
}


def validate_target_ip(
    ip_str: str, allow_public: bool = False
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """
    Validate that an input string is a valid, single IP address.
    Strictly forbids domain names/hostnames, CIDR ranges, and (by default) public addresses.

    Returns the parsed ipaddress object.
    Raises ValidationError on violation.
    """
    if not ip_str or not isinstance(ip_str, str):
        raise ValidationError("Target IP address is required.")

    cleaned = ip_str.strip()

    # Reject hostnames or FQDNs immediately
    if re.search(r"[a-zA-Z]", cleaned) and ":" not in cleaned:  # IPv6 contains hex letters
        raise ValidationError(
            "Target must be a raw IP address, not a hostname or domain name. "
            "DNS hostname resolution is intentionally disabled for safety."
        )

    if "/" in cleaned:
        raise ValidationError(
            "Subnet CIDR notation is not permitted. Only single IP targets are allowed."
        )

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address format: {e}") from e

    # Scope validation: Loopback is always safe
    if ip_obj.is_loopback:
        return ip_obj

    # Multicast, reserved, unspecified
    if ip_obj.is_multicast:
        raise ValidationError("Multicast IP addresses cannot be assessed.")
    if ip_obj.is_unspecified:
        raise ValidationError("Unspecified address (0.0.0.0) cannot be assessed.")
    if ip_obj.is_reserved:
        raise ValidationError("Reserved IP addresses cannot be assessed.")

    # Private scope validation
    if not ip_obj.is_private and not allow_public:
        raise ValidationError(
            f"Address '{cleaned}' is a public IP address. "
            "NSAT safety controls strictly restrict initial assessments to private "
            "(RFC 1918) or loopback addresses (127.0.0.1, ::1) to prevent unauthorized network scanning."
        )

    return ip_obj


def parse_and_validate_ports(port_spec: str, max_ports: int = 1000) -> list[int]:
    """
    Parse a port specification string into a sorted, unique list of integer ports.
    Supports:
      - Named presets (e.g. 'top20', 'top100', 'web', 'database', 'management')
      - Comma-separated lists (e.g. '22, 80, 443')
      - Hyphenated ranges (e.g. '80-85')
      - Mixed formats (e.g. '22, 80-85, 443')

    Enforces valid port boundaries (1-65535) and maximum port count limit.
    """
    if not port_spec or not isinstance(port_spec, str):
        raise ValidationError("Port specification is required.")

    cleaned = port_spec.strip().lower()

    # Check preset
    if cleaned in PORT_PRESETS:
        ports = sorted(set(PORT_PRESETS[cleaned]))
        return ports

    ports_set: set[int] = set()
    tokens = [t.strip() for t in cleaned.split(",") if t.strip()]

    if not tokens:
        raise ValidationError("No valid ports specified.")

    for token in tokens:
        # Check if token is a range (e.g. '80-85')
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                raise ValidationError(f"Invalid port range specification: '{token}'")
            try:
                start = int(parts[0].strip())
                end = int(parts[1].strip())
            except ValueError:
                raise ValidationError(f"Port range values must be integers: '{token}'")

            if start > end:
                raise ValidationError(
                    f"Range start ({start}) cannot be greater than range end ({end})."
                )
            if start < 1 or end > 65535:
                raise ValidationError(
                    f"Ports must be within the 1-65535 range. Received: '{token}'"
                )

            # Prevent excessive single-range expansion
            if (end - start + 1) > max_ports:
                raise ValidationError(
                    f"Port range '{token}' encompasses {end - start + 1} ports, which exceeds the maximum limit of {max_ports} ports."
                )

            ports_set.update(range(start, end + 1))
        else:
            try:
                port_num = int(token)
            except ValueError:
                raise ValidationError(
                    f"Invalid port value: '{token}'. Must be an integer or preset name."
                )

            if port_num < 1 or port_num > 65535:
                raise ValidationError(f"Port {port_num} is outside the valid TCP range (1-65535).")

            ports_set.add(port_num)

        if len(ports_set) > max_ports:
            raise ValidationError(
                f"Total number of requested ports exceeds safety limit of {max_ports} ports."
            )

    if not ports_set:
        raise ValidationError("Port list cannot be empty.")

    return sorted(ports_set)


def validate_timeout(timeout_val: Any, min_val: int = 5, max_val: int = 300) -> int:
    """Validate scan timeout bounds in seconds."""
    try:
        val = int(timeout_val)
    except (TypeError, ValueError):
        raise ValidationError(
            f"Timeout must be an integer between {min_val} and {max_val} seconds."
        )

    if val < min_val or val > max_val:
        raise ValidationError(
            f"Timeout ({val}s) is out of allowed bounds ({min_val}s - {max_val}s)."
        )

    return val


def validate_selected_modules(modules_list: list[str]) -> list[str]:
    """Validate that requested assessment modules are recognized."""
    allowed = {
        "port_scan",
        "service_detection",
        "risk_assessment",
        "http_tls_checks",
        "lynis_audit",
    }
    if not modules_list:
        return ["port_scan", "service_detection", "risk_assessment"]

    for m in modules_list:
        if m not in allowed:
            raise ValidationError(f"Unknown assessment module '{m}'. Allowed: {sorted(allowed)}")

    return modules_list
