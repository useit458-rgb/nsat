"""
Unit tests for strict input validation rules.
Verifies defensive private/loopback scope enforcement, port parsing, and timeout bounds.
"""

import pytest

from app.utils.validation import (
    ValidationError,
    parse_and_validate_ports,
    validate_selected_modules,
    validate_target_ip,
    validate_timeout,
)


class TestTargetIpValidation:
    """Tests for defensive IP target validation."""

    def test_valid_loopback_ipv4(self):
        ip = validate_target_ip("127.0.0.1")
        assert str(ip) == "127.0.0.1"
        assert ip.is_loopback

    def test_valid_loopback_ipv6(self):
        ip = validate_target_ip("::1")
        assert str(ip) == "::1"
        assert ip.is_loopback

    def test_valid_private_lan_addresses(self):
        for addr in ["10.0.0.1", "172.16.5.20", "192.168.1.1", "192.168.100.254"]:
            ip = validate_target_ip(addr)
            assert str(ip) == addr
            assert ip.is_private

    def test_reject_public_ips_by_default(self):
        public_ips = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "142.250.190.46"]
        for addr in public_ips:
            with pytest.raises(ValidationError) as exc:
                validate_target_ip(addr, allow_public=False)
            assert "public IP address" in str(exc.value)

    def test_allow_public_ips_when_configured(self):
        ip = validate_target_ip("8.8.8.8", allow_public=True)
        assert str(ip) == "8.8.8.8"

    def test_reject_domain_names_and_hostnames(self):
        hostnames = ["example.com", "google.com", "localhost", "my-router.local", "scanme.nmap.org"]
        for h in hostnames:
            with pytest.raises(ValidationError) as exc:
                validate_target_ip(h)
            assert "DNS hostname resolution is intentionally disabled" in str(exc.value)

    def test_reject_cidr_subnets(self):
        with pytest.raises(ValidationError) as exc:
            validate_target_ip("192.168.1.0/24")
        assert "Subnet CIDR notation is not permitted" in str(exc.value)

    def test_reject_multicast_and_unspecified(self):
        with pytest.raises(ValidationError) as exc:
            validate_target_ip("224.0.0.1")
        assert "Multicast" in str(exc.value)

        with pytest.raises(ValidationError) as exc:
            validate_target_ip("0.0.0.0")
        assert "Unspecified" in str(exc.value)

    def test_reject_malformed_ips(self):
        for bad in ["999.999.999.999", "abc.def", "", None]:
            with pytest.raises(ValidationError):
                validate_target_ip(bad)


class TestPortValidation:
    """Tests for TCP port parsing, presets, and safety ceilings."""

    def test_parse_presets(self):
        top20 = parse_and_validate_ports("top20")
        assert 22 in top20
        assert 80 in top20
        assert 443 in top20
        assert len(top20) == 20

        web = parse_and_validate_ports("web")
        assert 80 in web
        assert 443 in web
        assert 8080 in web

    def test_parse_comma_separated(self):
        ports = parse_and_validate_ports("22, 80, 443, 8080")
        assert ports == [22, 80, 443, 8080]

    def test_parse_range(self):
        ports = parse_and_validate_ports("80-85")
        assert ports == [80, 81, 82, 83, 84, 85]

    def test_parse_mixed(self):
        ports = parse_and_validate_ports("22, 80-82, 443")
        assert ports == [22, 80, 81, 82, 443]

    def test_deduplication_and_sorting(self):
        ports = parse_and_validate_ports("443, 22, 80, 22, 443")
        assert ports == [22, 80, 443]

    def test_reject_out_of_bounds_ports(self):
        with pytest.raises(ValidationError):
            parse_and_validate_ports("0")
        with pytest.raises(ValidationError):
            parse_and_validate_ports("65536")
        with pytest.raises(ValidationError):
            parse_and_validate_ports("-5")
        with pytest.raises(ValidationError):
            parse_and_validate_ports("invalid_port")

    def test_reject_inverted_range(self):
        with pytest.raises(ValidationError) as exc:
            parse_and_validate_ports("100-80")
        assert "Range start (100) cannot be greater than range end (80)" in str(exc.value)

    def test_reject_excessive_port_count(self):
        with pytest.raises(ValidationError) as exc:
            parse_and_validate_ports("1-2000", max_ports=1000)
        assert "exceeds the maximum limit" in str(exc.value)


class TestTimeoutAndModuleValidation:
    """Tests for timeout numbers and module flags."""

    def test_valid_timeout(self):
        assert validate_timeout(60, min_val=5, max_val=300) == 60
        assert validate_timeout("120", min_val=5, max_val=300) == 120

    def test_out_of_bounds_timeout(self):
        with pytest.raises(ValidationError):
            validate_timeout(2, min_val=5, max_val=300)
        with pytest.raises(ValidationError):
            validate_timeout(400, min_val=5, max_val=300)
        with pytest.raises(ValidationError):
            validate_timeout("abc")

    def test_valid_modules(self):
        mods = validate_selected_modules(["port_scan", "service_detection", "risk_assessment"])
        assert len(mods) == 3

    def test_unknown_module_rejected(self):
        with pytest.raises(ValidationError) as exc:
            validate_selected_modules(["port_scan", "malicious_exploit_module"])
        assert "Unknown assessment module" in str(exc.value)
