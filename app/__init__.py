"""
Network Security Assessment Toolkit (NSAT) Application Factory.
Initializes configuration, extensions, routes, and custom template filters.
"""

from __future__ import annotations

import os

from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFError

from app.config import config_by_name
from app.extensions import csrf, db
from app.utils.logging_config import setup_logging


def create_app(config_name: str | None = None) -> Flask:
    """Application factory for NSAT."""
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "default")

    config_class = config_by_name.get(config_name, config_by_name["default"])

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    # Initialize Logging
    setup_logging(log_dir=app.config.get("INSTANCE_DIR"))

    # Initialize Extensions
    db.init_app(app)
    csrf.init_app(app)

    # Register Blueprints
    from app.routes.assessments import assessments_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.findings import findings_bp
    from app.routes.reports import reports_bp
    from app.routes.settings import settings_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(assessments_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)

    @app.route("/health")
    def top_level_health():
        return {"status": "healthy", "service": "NSAT"}, 200

    # Register Custom Jinja2 Template Filters
    _register_template_filters(app)

    # Register Error Handlers & Security Headers
    _register_error_handlers(app)
    _register_security_headers(app)

    # Ensure Database Tables Exist
    with app.app_context():
        import app.models as _models  # noqa: F401
        db.create_all()

    return app


def _register_template_filters(app: Flask) -> None:
    """Register custom formatting filters for Jinja2 templates."""

    @app.template_filter("format_dt")
    def format_dt(dt, fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
        if not dt:
            return "N/A"
        try:
            return dt.strftime(fmt)
        except Exception:
            return str(dt)

    @app.template_filter("severity_badge")
    def severity_badge(severity: str) -> str:
        mapping = {
            "Critical": "bg-danger text-white",
            "High": "bg-warning text-dark",
            "Medium": "bg-primary text-white",
            "Low": "bg-info text-dark",
            "Informational": "bg-secondary text-white",
        }
        return mapping.get(severity, "bg-secondary text-white")

    @app.template_filter("status_badge")
    def status_badge(status: str) -> str:
        mapping = {
            "COMPLETED": "bg-success text-white",
            "RUNNING": "bg-primary text-white",
            "QUEUED": "bg-warning text-dark",
            "FAILED": "bg-danger text-white",
            "CANCELLED": "bg-secondary text-white",
        }
        return mapping.get(status, "bg-secondary text-white")

    @app.template_filter("round_num")
    def round_num(val, decimals: int = 1) -> str:
        try:
            return str(round(float(val), decimals))
        except (ValueError, TypeError):
            return "0.0"


def _register_error_handlers(app: Flask) -> None:
    """Register HTTP and security error pages."""

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        return render_template("errors/csrf_error.html", reason=error.description), 400


def _register_security_headers(app: Flask) -> None:
    """Register HTTP security headers and host-validation protocols."""

    @app.before_request
    def validate_host_header():
        """Prevent HTTP Host Header injection and DNS rebinding attacks."""
        if app.config.get("TESTING"):
            return None
        host = request.host
        allowed = app.config.get("ALLOWED_HOSTS")
        if allowed:
            if "*" in allowed:
                return None
            raw_host = host.split(":")[0]
            if host in allowed or raw_host in allowed:
                return None
            # Check wildcard domains like *.railway.app
            for domain in allowed:
                if domain.startswith("*.") and (raw_host.endswith(domain[1:]) or raw_host == domain[2:]):
                    return None
            return render_template("errors/403.html"), 403
        return None

    @app.after_request
    def apply_security_headers(response):
        """Inject defense-in-depth HTTP security headers into every response."""
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        return response
