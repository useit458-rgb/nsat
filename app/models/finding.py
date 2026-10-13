"""
Security finding database model.
Prioritized assessment findings with severity, confidence, reasoning, and remediation.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from app.extensions import db


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_key = db.Column(db.String(100), nullable=False, index=True)  # Stable rule identifier
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(
        db.String(20), nullable=False, index=True
    )  # Critical, High, Medium, Low, Informational
    confidence = db.Column(db.String(20), nullable=False)  # High, Medium, Low
    category = db.Column(
        db.String(100), nullable=False
    )  # Network Exposure, Cleartext Protocol, HTTP, TLS, System Audit
    asset_ip = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, nullable=True)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text, nullable=False)
    reasoning = db.Column(db.Text, nullable=False)
    remediation = db.Column(db.Text, nullable=False)
    references_json = db.Column(db.Text, default="[]", nullable=False)
    status = db.Column(
        db.String(50), default="Active", nullable=False
    )  # Active, Resolved, Suppressed
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)

    assessment = db.relationship("Assessment", back_populates="findings")

    @property
    def references(self) -> list[str]:
        try:
            return json.loads(self.references_json or "[]")
        except Exception:
            return []

    @references.setter
    def references(self, val: list[str]) -> None:
        self.references_json = json.dumps(val or [])

    @property
    def severity_rank(self) -> int:
        ranks = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
        return ranks.get(self.severity, 0)

    def __repr__(self) -> str:
        return f"<Finding [{self.severity}] {self.title}>"
