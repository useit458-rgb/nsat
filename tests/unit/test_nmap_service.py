"""
Unit tests for Nmap XML parsing and service integration.
"""

from app.services.nmap_service import NmapService

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -p 22,80,443 -oX - 127.0.0.1" start="1700000000">
<host starttime="1700000001" endtime="1700000005">
<status state="up" reason="localhost-response"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="9.2p1 Debian 2+deb12u2" conf="10"/>
  </port>
  <port protocol="tcp" portid="80">
    <state state="closed" reason="conn-refused"/>
  </port>
  <port protocol="tcp" portid="443">
    <state state="filtered" reason="no-response"/>
    <service name="https" conf="3"/>
  </port>
</ports>
</host>
</nmaprun>
"""

MALFORMED_XML = "<nmaprun><host><unclosed_tag>"


class TestNmapService:
    def test_parse_valid_nmap_xml(self):
        res = NmapService.parse_nmap_xml(SAMPLE_NMAP_XML, "127.0.0.1", [22, 80, 443])
        assert res.is_host_up is True
        assert len(res.ports) == 3

        # Port 22 open
        p22 = next(p for p in res.ports if p.port == 22)
        assert p22.state == "open"
        assert p22.service_name == "ssh"
        assert p22.product == "OpenSSH"
        assert p22.version == "9.2p1 Debian 2+deb12u2"
        assert p22.confidence == "high"

        # Port 80 closed
        p80 = next(p for p in res.ports if p.port == 80)
        assert p80.state == "closed"
        assert p80.reason == "conn-refused"

        # Port 443 filtered
        p443 = next(p for p in res.ports if p.port == 443)
        assert p443.state == "filtered"
        assert p443.service_name == "https"
        assert p443.confidence == "low"

    def test_parse_malformed_xml(self):
        res = NmapService.parse_nmap_xml(MALFORMED_XML, "127.0.0.1", [80])
        assert res.is_host_up is False
        assert res.tool_status == "failure"
        assert "Malformed Nmap XML" in res.error_message

    def test_parse_empty_xml(self):
        res = NmapService.parse_nmap_xml("", "127.0.0.1", [80])
        assert res.is_host_up is False
        assert "empty XML" in res.error_message

    def test_missing_host_xml(self):
        no_host_xml = '<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>'
        res = NmapService.parse_nmap_xml(no_host_xml, "127.0.0.1", [80])
        assert res.is_host_up is False
        assert "Host was not reported" in res.error_message

    def test_missing_binary_behavior(self):
        svc = NmapService(nmap_path="nonexistent_nmap_binary_xyz_123")
        assert svc.is_available() is False
        res = svc.scan_ports("127.0.0.1", [80])
        assert res.tool_status == "missing"
        assert "not found" in res.error_message
