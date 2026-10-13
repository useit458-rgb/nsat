"""
Assessment routes: Wizard, execution management, live details, and comparisons.
"""

from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from app.extensions import db
from app.models.assessment import Assessment
from app.services.assessment_service import AssessmentService
from app.utils.validation import (
    PORT_PRESETS,
    ValidationError,
    parse_and_validate_ports,
    validate_selected_modules,
    validate_target_ip,
    validate_timeout,
)

assessments_bp = Blueprint("assessments", __name__, url_prefix="/assessments")


@assessments_bp.route("/")
def list_assessments():
    """List assessments with target filtering and status indicators."""
    search_query = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()

    query = Assessment.query
    if search_query:
        query = query.filter(
            (Assessment.target_ip.ilike(f"%{search_query}%"))
            | (Assessment.title.ilike(f"%{search_query}%"))
        )
    if status_filter:
        query = query.filter_by(status=status_filter)

    assessments = query.order_by(Assessment.created_at.desc()).all()

    return render_template(
        "assessments/list.html",
        assessments=assessments,
        search_query=search_query,
        status_filter=status_filter,
    )


@assessments_bp.route("/new", methods=["GET", "POST"])
def new_assessment():
    """New assessment creation wizard with strict defensive validation."""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        target_ip_raw = request.form.get("target_ip", "").strip()
        ports_raw = request.form.get("ports", "").strip()
        selected_preset = request.form.get("port_preset", "").strip()
        timeout_raw = request.form.get("timeout", "60").strip()
        authorized = request.form.get("authorized") == "yes"
        modules_list = request.form.getlist("modules")

        # 1. Authorization Confirmation
        if not authorized:
            flash(
                "You must explicitly verify that you own this network target or possess authorized written permission.",
                "danger",
            )
            return render_template(
                "assessments/new.html", form_data=request.form, presets=PORT_PRESETS
            )

        # 2. Strict Input Validation
        try:
            # IP validation (Loopback or Private only by default)
            allow_public = current_app.config.get("ALLOW_PUBLIC_TARGETS", False)
            ip_obj = validate_target_ip(target_ip_raw, allow_public=allow_public)
            target_ip = str(ip_obj)

            # Title fallback
            if not title:
                title = f"Security Assessment - {target_ip}"

            # Ports resolution
            ports_to_validate = ports_raw
            if selected_preset and selected_preset in PORT_PRESETS:
                ports_to_validate = selected_preset
            elif not ports_to_validate:
                ports_to_validate = "top20"

            max_ports = current_app.config.get("MAX_PORTS_PER_SCAN", 1000)
            valid_ports = parse_and_validate_ports(ports_to_validate, max_ports=max_ports)

            # Timeout validation
            min_t = current_app.config.get("MIN_SCAN_TIMEOUT", 5)
            max_t = current_app.config.get("MAX_SCAN_TIMEOUT", 300)
            timeout = validate_timeout(timeout_raw, min_val=min_t, max_val=max_t)

            # Modules validation
            modules = validate_selected_modules(modules_list)

        except ValidationError as e:
            flash(str(e), "danger")
            return render_template(
                "assessments/new.html", form_data=request.form, presets=PORT_PRESETS
            )

        # 3. Create Assessment Record
        assessment = Assessment(
            title=title,
            target_ip=target_ip,
            ports_spec=",".join(str(p) for p in valid_ports[:50])
            + (f" (+{len(valid_ports) - 50} more)" if len(valid_ports) > 50 else ""),
            timeout_seconds=timeout,
            status="QUEUED",
        )
        assessment.modules = modules
        db.session.add(assessment)
        db.session.commit()

        # 4. Launch Asynchronous Worker
        launched = AssessmentService.start_assessment_async(
            current_app._get_current_object(), assessment.id
        )
        if not launched:
            flash("Assessment created and queued. Background runner will begin shortly.", "info")
        else:
            flash(f"Assessment #{assessment.id} launched successfully.", "success")

        return redirect(url_for("assessments.assessment_detail", assessment_id=assessment.id))

    return render_template("assessments/new.html", form_data={}, presets=PORT_PRESETS)


@assessments_bp.route("/<int:assessment_id>")
def assessment_detail(assessment_id: int):
    """Assessment details page with real-time results and tabbed navigation."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        flash(f"Assessment #{assessment_id} not found.", "warning")
        return redirect(url_for("assessments.list_assessments"))

    return render_template("assessments/detail.html", assessment=assessment)


@assessments_bp.route("/<int:assessment_id>/status")
def assessment_status(assessment_id: int):
    """JSON API endpoint for real-time dashboard progress polling."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({"error": "Assessment not found"}), 404

    return jsonify(
        {
            "id": assessment.id,
            "status": assessment.status,
            "risk_score": assessment.risk_score,
            "duration_seconds": assessment.duration_seconds,
            "open_ports_count": assessment.open_ports_count,
            "total_ports_count": len(assessment.port_results),
            "findings_count": len(assessment.findings),
            "events_count": len(assessment.events),
            "error_message": assessment.error_message,
        }
    )


@assessments_bp.route("/<int:assessment_id>/cancel", methods=["POST"])
def cancel_assessment(assessment_id: int):
    """Gracefully cancel an active assessment."""
    success = AssessmentService.request_cancellation(assessment_id)
    if success:
        flash(f"Cancellation requested for Assessment #{assessment_id}.", "info")
    else:
        flash(f"Assessment #{assessment_id} cannot be cancelled or is already finished.", "warning")
    return redirect(url_for("assessments.assessment_detail", assessment_id=assessment_id))


@assessments_bp.route("/<int:assessment_id>/delete", methods=["POST"])
def delete_assessment(assessment_id: int):
    """Delete an assessment record and remove its generated report files from disk."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        flash(f"Assessment #{assessment_id} not found.", "warning")
        return redirect(url_for("assessments.list_assessments"))

    # If running, cancel worker first
    if assessment.status in ("QUEUED", "RUNNING"):
        AssessmentService.request_cancellation(assessment_id)

    # Delete any associated report files from disk safely
    for rep in assessment.reports:
        if rep.file_path:
            try:
                p = Path(rep.file_path)
                if p.is_file():
                    p.unlink()
            except Exception:
                pass

    target_ip = assessment.target_ip
    db.session.delete(assessment)
    db.session.commit()

    flash(f"Assessment #{assessment_id} ({target_ip}) was permanently deleted.", "success")

    next_url = request.form.get("next") or request.referrer
    if next_url and ("assessments" in next_url or "/" in next_url):
        if f"/assessments/{assessment_id}" not in next_url:
            return redirect(next_url)
    return redirect(url_for("assessments.list_assessments"))


@assessments_bp.route("/compare")
def compare_assessments():
    """Compare two assessments side-by-side to highlight newly opened ports or findings."""
    id_a = request.args.get("a", type=int)
    id_b = request.args.get("b", type=int)

    all_assessments = Assessment.query.order_by(Assessment.created_at.desc()).all()
    assessment_a = db.session.get(Assessment, id_a) if id_a else None
    assessment_b = db.session.get(Assessment, id_b) if id_b else None

    diff_data = None
    if assessment_a and assessment_b:
        ports_a = {p.port_number: p for p in assessment_a.port_results if p.state == "open"}
        ports_b = {p.port_number: p for p in assessment_b.port_results if p.state == "open"}

        common_ports = sorted(set(ports_a.keys()) & set(ports_b.keys()))
        new_in_b = sorted(set(ports_b.keys()) - set(ports_a.keys()))
        closed_in_b = sorted(set(ports_a.keys()) - set(ports_b.keys()))

        findings_a_keys = {f.finding_key for f in assessment_a.findings}
        findings_b_keys = {f.finding_key for f in assessment_b.findings}

        new_findings = [f for f in assessment_b.findings if f.finding_key not in findings_a_keys]
        resolved_findings = [
            f for f in assessment_a.findings if f.finding_key not in findings_b_keys
        ]

        diff_data = {
            "common_ports": common_ports,
            "new_in_b": new_in_b,
            "closed_in_b": closed_in_b,
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
        }

    return render_template(
        "assessments/compare.html",
        all_assessments=all_assessments,
        assessment_a=assessment_a,
        assessment_b=assessment_b,
        diff_data=diff_data,
    )
