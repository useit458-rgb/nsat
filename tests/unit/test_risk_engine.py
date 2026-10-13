"""
Unit tests for deterministic risk scoring and rules engine.
"""

from datetime import UTC, datetime, timedelta

from app.models.port_result import PortResult
from app.models.service_observation import ServiceObservation
from app.services.http_checks import HttpCheckResult, HttpHeaderResult
from app.services.lynis_service import LynisAuditResult, LynisFinding
from app.services.risk_engine import RiskEngine
from app.services.tls_checks import TlsCheckResult


class TestRiskEngine:
    def test_telnet_exposure_rule(self):
        engine = RiskEngine()
        port_results = [PortResult(port_number=23, protocol="tcp", state="open", reason="syn-ack")]
        service_obs = [ServiceObservation(port_number=23, service_name="telnet", confidence="high")]

        findings, score = engine.evaluate("127.0.0.1", port_results, service_obs)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "High"
        assert f.category == "Cleartext Protocol"
        assert "Telnet" in f.title
        assert score > 0.0

    def test_redis_exposure_rule(self):
        engine = RiskEngine()
        port_results = [
            PortResult(port_number=6379, protocol="tcp", state="open", reason="syn-ack")
        ]
        service_obs = [
            ServiceObservation(port_number=6379, service_name="redis", confidence="high")
        ]

        findings, score = engine.evaluate("127.0.0.1", port_results, service_obs)
        assert any("Redis" in f.title for f in findings)
        assert any(f.severity == "High" for f in findings)

    def test_http_headers_evaluation(self):
        engine = RiskEngine()
        port_results = [PortResult(port_number=80, protocol="tcp", state="open", reason="syn-ack")]
        service_obs = [ServiceObservation(port_number=80, service_name="http", confidence="high")]

        http_res = [
            HttpCheckResult(
                target_url="http://127.0.0.1:80/",
                port=80,
                is_https=False,
                status_code=200,
                headers_analyzed=[
                    HttpHeaderResult(
                        header_name="Content-Security-Policy",
                        present=False,
                        value=None,
                        recommended_value="default-src 'self'",
                        description="CSP Prevents XSS",
                        severity="Medium",
                    )
                ],
                server_header="Apache/2.4.56",
            )
        ]

        findings, score = engine.evaluate(
            "127.0.0.1", port_results, service_obs, http_results=http_res
        )
        assert any("Content-Security-Policy" in f.title for f in findings)
        assert any("Server Banner" in f.title for f in findings)

    def test_tls_expired_cert_rule(self):
        engine = RiskEngine()
        port_results = [PortResult(port_number=443, protocol="tcp", state="open", reason="syn-ack")]
        service_obs = [ServiceObservation(port_number=443, service_name="https", confidence="high")]

        tls_res = [
            TlsCheckResult(
                target_ip="127.0.0.1",
                port=443,
                connected=True,
                is_expired=True,
                days_until_expiry=-10,
                cert_not_after=datetime.now(UTC) - timedelta(days=10),
            )
        ]

        findings, score = engine.evaluate(
            "127.0.0.1", port_results, service_obs, tls_results=tls_res
        )
        assert any("Expired TLS Certificate" in f.title for f in findings)
        assert any(f.severity == "High" for f in findings)

    def test_lynis_findings_import(self):
        engine = RiskEngine()
        lynis_res = LynisAuditResult(
            is_executed=True,
            status="completed",
            warnings=[
                LynisFinding(
                    test_id="AUTH-9262",
                    kind="WARNING",
                    description="Password hashing rounds insufficient",
                )
            ],
            suggestions=[
                LynisFinding(
                    test_id="FILE-7524",
                    kind="SUGGESTION",
                    description="Set permissions on /etc/crontab",
                )
            ],
        )

        findings, score = engine.evaluate("127.0.0.1", [], [], lynis_result=lynis_res)
        assert any("AUTH-9262" in f.title for f in findings)
        assert any("FILE-7524" in f.title for f in findings)

    def test_deterministic_scoring_bounds(self):
        engine = RiskEngine()
        # Test with empty findings
        findings, score = engine.evaluate("127.0.0.1", [], [])
        assert score == 0.0

        # Score must always be between 0.0 and 100.0
        assert 0.0 <= score <= 100.0
