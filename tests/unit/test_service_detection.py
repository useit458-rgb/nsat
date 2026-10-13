"""
Unit tests for service detection enrichment and security implications.
"""

from app.services.service_detection import ServiceDetector


class TestServiceDetector:
    def test_enrich_telnet_implications(self):
        detail = ServiceDetector.enrich_observation(port=23, raw_service="telnet")
        assert detail.service_name == "telnet"
        assert (
            "unencrypted" in detail.implications.lower()
            or "cleartext" in detail.implications.lower()
        )
        assert "ssh" in detail.recommendation.lower()

    def test_enrich_ssh_with_banner(self):
        detail = ServiceDetector.enrich_observation(
            port=22, banner="SSH-2.0-OpenSSH_9.0", method="socket-banner"
        )
        assert detail.service_name == "ssh"
        assert detail.product == "OpenSSH"
        assert detail.confidence == "high"

    def test_enrich_redis_database(self):
        detail = ServiceDetector.enrich_observation(port=6379, raw_service="redis")
        assert detail.service_name == "redis"
        assert (
            "authentication" in detail.implications.lower()
            or "memory" in detail.implications.lower()
        )
        assert (
            "requirepass" in detail.recommendation.lower()
            or "127.0.0.1" in detail.recommendation.lower()
        )

    def test_unknown_port_enrichment(self):
        detail = ServiceDetector.enrich_observation(port=45678, raw_service=None)
        assert detail.service_name == "unknown"
        assert detail.confidence == "low"
        assert "45678" in detail.implications
