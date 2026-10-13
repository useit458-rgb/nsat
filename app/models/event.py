"""
Assessment event database model.
Maintains an audit trail of execution events, milestones, and errors.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from app.extensions import db


class AssessmentEvent(db.Model):
    __tablename__ = "assessment_events"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type = db.Column(
        db.String(50), nullable=False
    )  # info, warning, error, milestone, tool_run
    message = db.Column(db.String(500), nullable=False)
    details_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)

    assessment = db.relationship("Assessment", back_populates="events")

    @property
    def details(self) -> dict:
        if not self.details_json:
            return {}
        try:
            return json.loads(self.details_json)
        except Exception:
            return {"raw": self.details_json}

    def __repr__(self) -> str:
        return f"<AssessmentEvent [{self.event_type}] {self.message}>"
