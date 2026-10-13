"""
Port scan result database model.
Records individual port scan observations from Nmap or socket checks.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db


class PortResult(db.Model):
    __tablename__ = "port_results"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port_number = db.Column(db.Integer, nullable=False, index=True)
    protocol = db.Column(db.String(10), default="tcp", nullable=False)
    state = db.Column(db.String(20), nullable=False)  # open, closed, filtered, untested
    reason = db.Column(db.String(100), nullable=True)  # syn-ack, conn-refused, timeout
    service_name = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)

    assessment = db.relationship("Assessment", back_populates="port_results")

    def __repr__(self) -> str:
        return f"<PortResult {self.protocol}/{self.port_number} {self.state}>"
