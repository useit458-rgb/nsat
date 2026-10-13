"""
Report generation and download routes.
Supports HTML, JSON, and PDF report creation and secure file delivery.
"""

from __future__ import annotations

import logging
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    send_file,
    url_for,
)

from app.extensions import db
from app.models.assessment import Assessment
from app.models.report import ReportArtifact
from app.services.report_service import ReportService

logger = logging.getLogger(__name__)
reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
def list_reports():
    """List all generated report artifacts."""
    artifacts = ReportArtifact.query.order_by(ReportArtifact.created_at.desc()).all()
    return render_template("reports/list.html", artifacts=artifacts)


@reports_bp.route("/generate/<int:assessment_id>/<string:fmt>", methods=["POST"])
def generate_report(assessment_id: int, fmt: str):
    """Generate an assessment report in HTML, JSON, or PDF format."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        flash(f"Assessment #{assessment_id} not found.", "warning")
        return redirect(url_for("reports.list_reports"))

    fmt = fmt.lower()
    if fmt not in ("html", "json", "pdf"):
        flash("Invalid report format requested. Choose HTML, JSON, or PDF.", "danger")
        return redirect(url_for("assessments.assessment_detail", assessment_id=assessment_id))

    output_dir = Path(current_app.config["REPORT_OUTPUT_DIR"])
    report_svc = ReportService(output_dir=output_dir)

    try:
        if fmt == "html":
            file_path = report_svc.generate_html_report(assessment)
        elif fmt == "json":
            file_path = report_svc.generate_json_report(assessment)
        elif fmt == "pdf":
            file_path = report_svc.generate_pdf_report(assessment)

        file_size = file_path.stat().st_size

        artifact = ReportArtifact(
            assessment_id=assessment.id,
            format=fmt,
            file_path=str(file_path),
            file_size_bytes=file_size,
            status="generated",
        )
        db.session.add(artifact)
        db.session.commit()

        flash(f"{fmt.upper()} report generated successfully ({file_size} bytes).", "success")
    except Exception as e:
        logger.exception(
            "Failed generating %s report for assessment #%d: %s", fmt, assessment_id, e
        )
        artifact = ReportArtifact(
            assessment_id=assessment.id,
            format=fmt,
            file_path="",
            file_size_bytes=0,
            status="failed",
            error_message=str(e),
        )
        db.session.add(artifact)
        db.session.commit()
        flash(f"Failed to generate {fmt.upper()} report: {e}", "danger")

    return redirect(url_for("assessments.assessment_detail", assessment_id=assessment_id))


@reports_bp.route("/download/<int:report_id>")
def download_report(report_id: int):
    """Safely deliver a generated report file to the user."""
    artifact = db.session.get(ReportArtifact, report_id)
    if not artifact or artifact.status != "generated":
        flash("Report file not found or generation failed.", "warning")
        return redirect(url_for("reports.list_reports"))

    target_path = Path(artifact.file_path).resolve()
    base_report_dir = Path(current_app.config["REPORT_OUTPUT_DIR"]).resolve()

    # Prevent path traversal attacks
    if not str(target_path).startswith(str(base_report_dir)):
        logger.error("Path traversal attempt detected on report download: %s", artifact.file_path)
        abort(403)

    if not target_path.is_file():
        flash("Report file no longer exists on disk.", "warning")
        return redirect(url_for("reports.list_reports"))

    mimetypes = {
        "html": "text/html",
        "json": "application/json",
        "pdf": "application/pdf",
    }
    mimetype = mimetypes.get(artifact.format, "application/octet-stream")

    return send_file(
        target_path,
        mimetype=mimetype,
        as_attachment=True,
        download_name=target_path.name,
    )
