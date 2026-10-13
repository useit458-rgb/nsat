"""
Module 3 Component: Bounded HTTP Security Header Assessment.
Performs scoped, unredirected HTTP requests against identified HTTP/HTTPS ports
to inspect standard defensive response headers and information disclosure tokens.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import requests

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "description": "Enforces secure (HTTPS) connections and prevents SSL-stripping attacks.",
        "recommended": "max-age=31536000; includeSubDomains",
        "severity": "Medium",
    },
    {
        "name": "Content-Security-Policy",
        "key": "content-security-policy",
        "description": "Restricts resource loading (scripts, styles, images) to prevent Cross-Site Scripting (XSS) and data injection.",
        "recommended": "default-src 'self'",
        "severity": "Medium",
    },
    {
        "name": "X-Frame-Options",
        "key": "x-frame-options",
        "description": "Protects against Clickjacking by specifying whether the browser may render the page in a <frame> or <iframe>.",
        "recommended": "DENY or SAMEORIGIN",
        "severity": "Low",
    },
    {
        "name": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "description": "Prevents MIME-type sniffing, forcing the browser to adhere to the declared Content-Type header.",
        "recommended": "nosniff",
        "severity": "Low",
    },
    {
        "name": "Referrer-Policy",
        "key": "referrer-policy",
        "description": "Controls how much referrer information is sent along with outbound requests.",
        "recommended": "strict-origin-when-cross-origin or no-referrer",
        "severity": "Low",
    },
    {
        "name": "Permissions-Policy",
        "key": "permissions-policy",
        "description": "Restricts browser feature access (e.g. geolocation, microphone, camera) in web contexts.",
        "recommended": "camera=(), microphone=(), geolocation=()",
        "severity": "Informational",
    },
]


@dataclass
class HttpHeaderResult:
    header_name: str
    present: bool
    value: str | None
    recommended_value: str
    description: str
    severity: str


@dataclass
class HttpCheckResult:
    target_url: str
    port: int
    is_https: bool
    status_code: int | None
    headers_analyzed: list[HttpHeaderResult] = field(default_factory=list)
    server_header: str | None = None
    powered_by_header: str | None = None
    error_message: str | None = None
    tested: bool = True


class HttpSecurityChecker:
    """Bounded, safe HTTP security header evaluator."""

    def __init__(self, timeout_seconds: float = 3.0, max_bytes: int = 16384):
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def evaluate_target(self, target_ip: str, port: int, is_https: bool = False) -> HttpCheckResult:
        """
        Send a single bounded HTTP GET request with redirection disabled
        to prevent moving outside the declared target scope.
        """
        protocol = "https" if is_https else "http"
        # Wrap IPv6 addresses in brackets for URL formatting
        host_str = f"[{target_ip}]" if ":" in target_ip else target_ip
        url = f"{protocol}://{host_str}:{port}/"

        result = HttpCheckResult(
            target_url=url,
            port=port,
            is_https=is_https,
            status_code=None,
        )

        try:
            # allow_redirects=False ensures we do NOT follow redirects out of scope
            session = requests.Session()
            session.trust_env = False  # Avoid proxy issues for localhost testing

            resp = session.get(
                url,
                timeout=self.timeout_seconds,
                allow_redirects=False,
                verify=False,  # For private/self-signed cert testing, inspect headers regardless
                headers={"User-Agent": "NSAT-Security-Audit/1.0", "Accept": "*/*"},
                stream=True,
            )

            # Read bounded chunk only
            _ = resp.raw.read(self.max_bytes)
            result.status_code = resp.status_code

            # Normalize response headers to lowercase
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check server banner leakage
            result.server_header = resp_headers.get("server")
            result.powered_by_header = resp_headers.get("x-powered-by")

            # Evaluate standard security headers
            for defn in SECURITY_HEADERS:
                val = resp_headers.get(defn["key"])
                # For HSTS, only applicable if HTTPS
                if defn["key"] == "strict-transport-security" and not is_https:
                    continue

                result.headers_analyzed.append(
                    HttpHeaderResult(
                        header_name=defn["name"],
                        present=(val is not None),
                        value=val,
                        recommended_value=defn["recommended"],
                        description=defn["description"],
                        severity=defn["severity"],
                    )
                )

        except requests.exceptions.SSLError as e:
            result.error_message = f"SSL/TLS handshake failed during HTTP check: {e}"
            result.tested = True
        except requests.exceptions.Timeout:
            result.error_message = f"HTTP connection timed out after {self.timeout_seconds}s."
            result.tested = True
        except requests.exceptions.ConnectionError:
            result.error_message = "Connection refused or target not listening on HTTP."
            result.tested = False
        except Exception as e:
            result.error_message = f"HTTP check error: {e}"
            result.tested = False

        return result
