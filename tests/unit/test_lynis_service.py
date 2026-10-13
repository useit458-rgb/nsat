"""
Unit tests for Lynis local Linux audit service and output parsing.
"""

from unittest.mock import patch

from app.services.lynis_service import LynisService

SAMPLE_LYNIS_STDOUT = """
[+] Security Scan Details
    Hardening index : 68
    Tests performed : 240

[+] Warnings
    ------------------------------------
    ! Found a warning: password hashing rounds [AUTH-9262]
    ! Found another warning: core dumps enabled [KRNL-5820]

[+] Suggestions
    ------------------------------------
    * Install package auditd for system auditing [ACCT-9622] | Solution: apt-get install auditd
    * Configure minimum password age in login.defs [AUTH-9286]
"""


class TestLynisService:
    def test_parse_lynis_stdout(self):
        res = LynisService.parse_lynis_output(SAMPLE_LYNIS_STDOUT)
        assert res.hardening_index == 68
        assert len(res.warnings) == 2
        assert res.warnings[0].test_id == "AUTH-9262"
        assert res.warnings[1].test_id == "KRNL-5820"

        assert len(res.suggestions) == 2
        assert res.suggestions[0].test_id == "ACCT-9622"
        assert res.suggestions[0].solution == "apt-get install auditd"

    def test_non_linux_platform_skips_audit(self):
        svc = LynisService()
        with patch.object(svc, "is_linux", return_value=False):
            res = svc.audit_system()
            assert res.is_executed is False
            assert res.status == "skipped_non_linux"
            assert "Linux systems only" in res.error_message

    def test_missing_lynis_binary_skips_audit(self):
        svc = LynisService(lynis_path="nonexistent_lynis_binary_123")
        with (
            patch.object(svc, "is_linux", return_value=True),
            patch.object(svc, "is_installed", return_value=False),
        ):
            res = svc.audit_system()
            assert res.is_executed is False
            assert res.status == "skipped_missing_binary"
            assert "not found on PATH" in res.error_message
