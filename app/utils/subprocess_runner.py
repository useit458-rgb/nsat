"""
Safe subprocess execution runner.
Enforces argument array execution (never shell=True), explicit timeouts,
error wrapping, and structured execution logs.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Encapsulates the outcome of an external command execution."""

    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error_message: str | None = None

    @property
    def is_success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and self.error_message is None


def run_command_safely(
    args: Sequence[str],
    timeout_seconds: float = 60.0,
    check_binary_exists: bool = True,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """
    Execute an external command safely without shell interpolation.

    Args:
        args: Sequence of command and its arguments. args[0] is the executable.
        timeout_seconds: Maximum wall-clock runtime in seconds.
        check_binary_exists: If True, verifies that args[0] is available on PATH.
        env: Optional environment dictionary override.

    Returns:
        CommandResult with captured outputs, timing, and error details.
    """
    if not args:
        return CommandResult(
            command=[],
            exit_code=-1,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            error_message="Empty command argument list provided.",
        )

    binary = args[0]
    cmd_list = list(args)

    # Check if executable exists
    if check_binary_exists and not os.path.isabs(binary):
        resolved = shutil.which(binary)
        if not resolved:
            return CommandResult(
                command=cmd_list,
                exit_code=127,
                stdout="",
                stderr="",
                duration_seconds=0.0,
                error_message=f"Executable '{binary}' not found on system PATH.",
            )

    start_time = time.monotonic()

    try:
        logger.debug(
            "Executing safe command: %s (timeout=%ss)", " ".join(cmd_list), timeout_seconds
        )

        # Merge safe minimal env if not explicitly provided
        exec_env = os.environ.copy() if env is None else env

        # Run process safely WITHOUT shell=True
        process = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            env=exec_env,
            errors="replace",  # Avoid UnicodeDecodeError on unexpected binary output
        )

        duration = time.monotonic() - start_time

        return CommandResult(
            command=cmd_list,
            exit_code=process.returncode,
            stdout=process.stdout or "",
            stderr=process.stderr or "",
            duration_seconds=round(duration, 3),
            timed_out=False,
        )

    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start_time
        logger.warning("Command '%s' timed out after %s seconds.", cmd_list[0], timeout_seconds)
        return CommandResult(
            command=cmd_list,
            exit_code=-1,
            stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
            stderr=exc.stderr or "" if isinstance(exc.stderr, str) else "",
            duration_seconds=round(duration, 3),
            timed_out=True,
            error_message=f"Execution exceeded timeout limit of {timeout_seconds} seconds.",
        )

    except PermissionError as exc:
        duration = time.monotonic() - start_time
        logger.error("Permission denied when trying to execute %s: %s", cmd_list[0], exc)
        return CommandResult(
            command=cmd_list,
            exit_code=126,
            stdout="",
            stderr=str(exc),
            duration_seconds=round(duration, 3),
            error_message=f"Permission denied: {exc}",
        )

    except Exception as exc:  # Catch all OS errors defensively
        duration = time.monotonic() - start_time
        logger.exception("Unexpected failure executing command: %s", cmd_list[0])
        return CommandResult(
            command=cmd_list,
            exit_code=-1,
            stdout="",
            stderr=str(exc),
            duration_seconds=round(duration, 3),
            error_message=f"Subprocess execution error: {exc}",
        )
