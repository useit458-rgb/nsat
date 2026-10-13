"""
Assessment database model.
Central orchestrator entity storing scan scope, runtime, state, and relationships.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from app.extensions import db


class Assessment(db.Model):
    __tablename__ = "assessments"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True
    )
    title = db.Column(db.String(200), nullable=False)
    target_ip = db.Column(db.String(45), nullable=False, index=True)
    ports_spec = db.Column(db.String(500), nullable=False)  # Raw user-requested port string
    modules_json = db.Column(
        db.Text, default='["port_scan", "service_detection", "risk_assessment"]', nullable=False
    )
    timeout_seconds = db.Column(db.Integer, default=60, nullable=False)

    # Lifecycle Status: QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    status = db.Column(db.String(20), default="QUEUED", nullable=False, index=True)
    cancellation_requested = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)

    error_message = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Float, default=0.0, nullable=False)

    # Relationships
    asset_id = db.Column(
        db.Integer, db.ForeignKey("target_assets.id", ondelete="SET NULL"), nullable=True
    )
    asset = db.relationship("TargetAsset", back_populates="assessments")

    port_results = db.relationship(
        "PortResult", back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )
    service_observations = db.relationship(
        "ServiceObservation",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    findings = db.relationship(
        "Finding", back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )
    events = db.relationship(
        "AssessmentEvent",
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="AssessmentEvent.created_at.asc()",
        lazy="selectin",
    )
    reports = db.relationship(
        "ReportArtifact", back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )
    tool_executions = db.relationship(
        "ToolExecution", back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def modules(self) -> list[str]:
        try:
            return json.loads(self.modules_json or "[]")
        except Exception:
            return []

    @modules.setter
    def modules(self, val: list[str]) -> None:
        self.modules_json = json.dumps(val or [])

    @property
    def duration_seconds(self) -> float | None:
        if self.start_time and self.end_time:
            st = self.start_time.replace(tzinfo=None) if self.start_time.tzinfo else self.start_time
            et = self.end_time.replace(tzinfo=None) if self.end_time.tzinfo else self.end_time
            return round((et - st).total_seconds(), 2)
        elif self.start_time:
            st = self.start_time.replace(tzinfo=None) if self.start_time.tzinfo else self.start_time
            now = datetime.now(UTC).replace(tzinfo=None)
            return round((now - st).total_seconds(), 2)
        return None

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    @property
    def open_ports_count(self) -> int:
        return sum(1 for p in self.port_results if p.state == "open")

    def __repr__(self) -> str:
        return f"<Assessment #{self.id} {self.target_ip} [{self.status}]>"
