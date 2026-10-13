"""
Findings routes: Prioritized findings browser and detail inspections.
"""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.extensions import db
from app.models.finding import Finding

findings_bp = Blueprint("findings", __name__, url_prefix="/findings")


@findings_bp.route("/")
def list_findings():
    """Browse all security findings across assessments with filtering."""
    severity_filter = request.args.get("severity", "").strip()
    category_filter = request.args.get("category", "").strip()
    search_query = request.args.get("q", "").strip()

    query = Finding.query
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if category_filter:
        query = query.filter_by(category=category_filter)
    if search_query:
        query = query.filter(
            (Finding.title.ilike(f"%{search_query}%"))
            | (Finding.description.ilike(f"%{search_query}%"))
            | (Finding.asset_ip.ilike(f"%{search_query}%"))
        )

    findings = query.order_by(Finding.created_at.desc()).all()

    # Get distinct categories for filter dropdown
    categories = [r[0] for r in db.session.query(Finding.category).distinct().all() if r[0]]

    return render_template(
        "findings/list.html",
        findings=findings,
        severity_filter=severity_filter,
        category_filter=category_filter,
        search_query=search_query,
        categories=categories,
    )


@findings_bp.route("/<int:finding_id>")
def finding_detail(finding_id: int):
    """Detailed view of an individual security finding."""
    finding = db.session.get(Finding, finding_id)
    if not finding:
        flash(f"Finding #{finding_id} not found.", "warning")
        return redirect(url_for("findings.list_findings"))

    return render_template("findings/detail.html", finding=finding)
