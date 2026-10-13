"""
Target asset database model.
Tracks discovered or assessed hosts, avoiding duplication.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db


class TargetAsset(db.Model):
    __tablename__ = "target_assets"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(255), nullable=True)
    asset_type = db.Column(
        db.String(50), default="host", nullable=False
    )  # host, loopback, private_lan
    is_private = db.Column(db.Boolean, default=True, nullable=False)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)

    assessments = db.relationship(
        "Assessment", back_populates="asset", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<TargetAsset {self.ip_address}>"
