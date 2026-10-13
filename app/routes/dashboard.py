"""
Dashboard routes: Overview metrics, severity charts, and recent activity.
"""

from __future__ import annotations

import platform
import shutil

from flask import Blueprint, current_app, render_template

from app.models.assessment import Assessment
from app.models.asset import TargetAsset
from app.models.finding import Finding

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """Main overview dashboard with defensive metrics, charts, and activity summary."""
    total_assessments = Assessment.query.count()
    completed_assessments = Assessment.query.filter_by(status="COMPLETED").count()
    active_assessments = Assessment.query.filter(
        Assessment.status.in_(["QUEUED", "RUNNING"])
    ).count()
    total_assets = TargetAsset.query.count()

    # Recent assessments
    recent_assessments = Assessment.query.order_by(Assessment.created_at.desc()).limit(8).all()

    # Overall findings breakdown by severity
    findings = Finding.query.all()
    severity_counts = {
        "Critical": sum(1 for f in findings if f.severity == "Critical"),
        "High": sum(1 for f in findings if f.severity == "High"),
        "Medium": sum(1 for f in findings if f.severity == "Medium"),
        "Low": sum(1 for f in findings if f.severity == "Low"),
        "Informational": sum(1 for f in findings if f.severity == "Informational"),
    }
    total_findings = len(findings)

    # Tool status check
    nmap_path = current_app.config.get("NMAP_PATH", "nmap")
    lynis_path = current_app.config.get("LYNIS_PATH", "lynis")
    tools_status = {
        "nmap": bool(shutil.which(nmap_path)),
        "lynis": bool(shutil.which(lynis_path)) and (platform.system().lower() == "linux"),
        "platform": platform.system(),
        "python_version": platform.python_version(),
    }

    # Data for Chart.js
    chart_data = {
        "labels": ["Critical", "High", "Medium", "Low", "Informational"],
        "counts": [
            severity_counts["Critical"],
            severity_counts["High"],
            severity_counts["Medium"],
            severity_counts["Low"],
            severity_counts["Informational"],
        ],
        "recent_labels": [a.title[:18] for a in reversed(recent_assessments[:6])],
        "recent_scores": [a.risk_score for a in reversed(recent_assessments[:6])],
    }

    return render_template(
        "dashboard/overview.html",
        total_assessments=total_assessments,
        completed_assessments=completed_assessments,
        active_assessments=active_assessments,
        total_assets=total_assets,
        total_findings=total_findings,
        severity_counts=severity_counts,
        recent_assessments=recent_assessments,
        tools_status=tools_status,
        chart_data=chart_data,
    )
