"""
Module 3 Component: Local Linux System Auditing via Lynis.
Performs scoped local host security auditing on Linux systems.
Defensively checks platform compatibility, binary availability, and parses
warnings and suggestions from standard Lynis execution output.
"""

from __future__ import annotations

import logging
import platform
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from app.utils.subprocess_runner import run_command_safely

logger = logging.getLogger(__name__)


@dataclass
class LynisFinding:
    test_id: str
    kind: str  # WARNING, SUGGESTION
    description: str
    solution: str | None = None


@dataclass
class LynisAuditResult:
    is_executed: bool
    status: str  # completed, skipped_non_linux, skipped_missing_binary, timed_out, error
    hardening_index: int | None = None
    warnings: list[LynisFinding] = field(default_factory=list)
    suggestions: list[LynisFinding] = field(default_factory=list)
    raw_log_preview: str = ""
    duration_seconds: float = 0.0
    error_message: str | None = None
    explanation: str = ""


class LynisService:
    """Service wrapper for executing and parsing local Lynis security audits."""

    def __init__(self, lynis_path: str = "lynis"):
        self.lynis_path = lynis_path

    def is_linux(self) -> bool:
        """Verify operating system is Linux."""
        return platform.system().lower() == "linux"

    def is_installed(self) -> bool:
        """Check if Lynis binary exists on system PATH."""
        return shutil.which(self.lynis_path) is not None

    def audit_system(self, timeout_seconds: int = 180) -> LynisAuditResult:
        """
        Execute local Lynis security audit with defensive checks.
        Lynis only audits the LOCAL host system and requires Linux.
        """
        if not self.is_linux():
            msg = (
                f"Local system auditing via Lynis is supported on Linux systems only. "
                f"Current host platform is '{platform.system()}'. Check skipped."
            )
            return LynisAuditResult(
                is_executed=False,
                status="skipped_non_linux",
                error_message=msg,
                explanation=msg,
            )

        if not self.is_installed():
            msg = (
                f"Lynis binary ('{self.lynis_path}') was not found on PATH. "
                "To enable local system audits on Debian/Ubuntu/Kali, install it via: sudo apt-get install lynis"
            )
            return LynisAuditResult(
                is_executed=False,
                status="skipped_missing_binary",
                error_message=msg,
                explanation=msg,
            )

        # Build bounded safe command
        # --quick: skips interactive prompts
        # --no-colors: clean stdout parsing
        # --quiet: minimal output
        cmd = [self.lynis_path, "audit", "system", "--quick", "--no-colors"]

        logger.info("Starting local Lynis audit (timeout=%ds)...", timeout_seconds)
        cmd_res = run_command_safely(cmd, timeout_seconds=float(timeout_seconds))

        if cmd_res.timed_out:
            return LynisAuditResult(
                is_executed=False,
                status="timed_out",
                duration_seconds=cmd_res.duration_seconds,
                error_message=f"Lynis audit exceeded timeout of {timeout_seconds} seconds.",
                explanation="Local audit took longer than maximum configured timeout limit.",
            )

        if cmd_res.exit_code not in (0, 1):  # Lynis returns 1 if warnings were detected
            err_msg = (
                cmd_res.stderr
                or cmd_res.error_message
                or f"Process exited with code {cmd_res.exit_code}"
            )
            return LynisAuditResult(
                is_executed=False,
                status="error",
                duration_seconds=cmd_res.duration_seconds,
                error_message=f"Lynis execution failed: {err_msg}",
                raw_log_preview=cmd_res.stdout[:5000],
                explanation="Lynis encountered an execution failure (e.g., insufficient permissions or broken configuration).",
            )

        # Parse Lynis output from stdout and report file if present
        parsed = self.parse_lynis_output(cmd_res.stdout)
        parsed.is_executed = True
        parsed.status = "completed"
        parsed.duration_seconds = cmd_res.duration_seconds
        parsed.raw_log_preview = cmd_res.stdout[:25000]
        parsed.explanation = f"Audit completed with {len(parsed.warnings)} warnings and {len(parsed.suggestions)} suggestions."
        return parsed

    @staticmethod
    def parse_lynis_output(stdout_text: str) -> LynisAuditResult:
        """
        Defensively parse warnings, suggestions, and hardening index from Lynis terminal output.
        """
        result = LynisAuditResult(is_executed=True, status="completed")

        if not stdout_text:
            return result

        # Hardening index regex e.g. "Hardening index : 64"
        hi_match = re.search(r"Hardening\s+index\s*:\s*(\d+)", stdout_text, re.IGNORECASE)
        if hi_match:
            try:
                result.hardening_index = int(hi_match.group(1))
            except ValueError:
                pass

        lines = stdout_text.splitlines()
        current_section = None

        for line in lines:
            line_str = line.strip()

            # Identify section transitions
            if "Warnings" in line_str and ("---" in line_str or "=" in line_str):
                current_section = "warnings"
                continue
            elif "Suggestions" in line_str and ("---" in line_str or "=" in line_str):
                current_section = "suggestions"
                continue

            # Warning item e.g. "! Found some warning [TEST-1234]"
            if "! " in line_str or current_section == "warnings":
                m = re.search(r"!*\s*(.+?)\s*\[([A-Z0-9_\-]+)\]", line_str)
                if m:
                    result.warnings.append(
                        LynisFinding(
                            test_id=m.group(2),
                            kind="WARNING",
                            description=m.group(1).strip(),
                        )
                    )

            # Suggestion item e.g. "* Set password hashing algorithm [AUTH-9262] | Solution: text"
            if "* " in line_str or current_section == "suggestions":
                m = re.search(
                    r"\*\s*(.+?)\s*\[([A-Z0-9_\-]+)\](?:\s*\|\s*Solution:\s*(.+))?",
                    line_str,
                    re.IGNORECASE,
                )
                if m:
                    desc = m.group(1).strip()
                    test_id = m.group(2)
                    solution = m.group(3).strip() if m.group(3) else None

                    result.suggestions.append(
                        LynisFinding(
                            test_id=test_id,
                            kind="SUGGESTION",
                            description=desc,
                            solution=solution,
                        )
                    )

        # Check for /var/log/lynis-report.dat if available
        dat_path = Path("/var/log/lynis-report.dat")
        if dat_path.is_file():
            try:
                content = dat_path.read_text(encoding="utf-8", errors="replace")
                hi_dat = re.search(r"^hardening_index=(\d+)", content, re.MULTILINE)
                if hi_dat and result.hardening_index is None:
                    result.hardening_index = int(hi_dat.group(1))
            except Exception:
                pass

        return result
