"""
Tool execution database model.
Logs external subprocess or module executions, durations, and results.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db


class ToolExecution(db.Model):
    __tablename__ = "tool_executions"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_name = db.Column(
        db.String(50), nullable=False
    )  # nmap, socket_scanner, lynis, http_checks, tls_checks
    command_line = db.Column(db.Text, nullable=False)
    exit_code = db.Column(db.Integer, nullable=False)
    duration_seconds = db.Column(db.Float, default=0.0, nullable=False)
    stdout_preview = db.Column(db.Text, nullable=True)
    stderr_preview = db.Column(db.Text, nullable=True)
    status = db.Column(
        db.String(20), default="success", nullable=False
    )  # success, failure, timed_out, skipped
    executed_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)

    assessment = db.relationship("Assessment", back_populates="tool_executions")

    def __repr__(self) -> str:
        return f"<ToolExecution {self.tool_name} (code={self.exit_code})>"
