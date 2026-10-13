"""
Service observation database model.
Records identified services, banner info, product, and version confidence.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db


class ServiceObservation(db.Model):
    __tablename__ = "service_observations"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port_number = db.Column(db.Integer, nullable=False)
    service_name = db.Column(db.String(100), nullable=False)
    product = db.Column(db.String(150), nullable=True)
    version = db.Column(db.String(100), nullable=True)
    extrainfo = db.Column(db.String(255), nullable=True)
    confidence = db.Column(
        db.String(20), default="medium", nullable=False
    )  # high, medium, low, unknown
    method = db.Column(
        db.String(50), default="nmap-version", nullable=False
    )  # nmap-version, socket-banner, http-head
    raw_output = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)

    assessment = db.relationship("Assessment", back_populates="service_observations")

    def __repr__(self) -> str:
        prod = f" {self.product} {self.version}" if self.product else ""
        return f"<ServiceObservation {self.port_number}: {self.service_name}{prod}>"
