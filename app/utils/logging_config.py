"""
Logging configuration for NSAT.
Sets up structured, security-aware logging for development and production.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path


class SecurityFilter(logging.Filter):
    """Filters or redacts potentially sensitive data from application logs."""

    SENSITIVE_PATTERNS = [
        re.compile(r"(password|secret|key|token|auth)\s*[:=]\s*([^\s,]+)", re.IGNORECASE),
        re.compile(r"(bearer\s+)([a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern in self.SENSITIVE_PATTERNS:
                msg = pattern.sub(r"\1: [REDACTED]", msg)
            record.msg = msg
        return True


def setup_logging(log_level: int = logging.INFO, log_dir: Path | None = None) -> None:
    """Configure root logger with console and file handlers."""
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Avoid duplicate handlers on re-init
    if not root_logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.addFilter(SecurityFilter())
        root_logger.addHandler(console_handler)

        if log_dir is not None:
            log_dir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_dir / "nsat.log", encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.addFilter(SecurityFilter())
            root_logger.addHandler(file_handler)
