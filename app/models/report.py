"""
Report artifact database model.
Tracks generated assessment reports (HTML, JSON, PDF).
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db


class ReportArtifact(db.Model):
    __tablename__ = "report_artifacts"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    format = db.Column(db.String(10), nullable=False)  # html, json, pdf
    file_path = db.Column(db.String(500), nullable=False)
    file_size_bytes = db.Column(db.Integer, default=0, nullable=False)
    status = db.Column(db.String(20), default="generated", nullable=False)  # generated, failed
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)

    assessment = db.relationship("Assessment", back_populates="reports")

    def __repr__(self) -> str:
        return f"<ReportArtifact {self.format.upper()} for Assessment #{self.assessment_id}>"
