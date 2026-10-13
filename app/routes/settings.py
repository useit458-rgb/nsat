"""
Settings and system health routes.
Diagnostics for external tools (Nmap, Lynis), database connectivity, and configuration bounds.
"""

from __future__ import annotations

import os
import platform
import sys

from flask import Blueprint, current_app, jsonify, render_template

from app.extensions import db
from app.services.lynis_service import LynisService
from app.services.nmap_service import NmapService

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/")
def view_settings():
    """System health and diagnostic settings panel."""
    nmap_svc = NmapService(nmap_path=current_app.config.get("NMAP_PATH", "nmap"))
    lynis_svc = LynisService(lynis_path=current_app.config.get("LYNIS_PATH", "lynis"))

    # Check database connectivity
    db_connected = False
    try:
        db.session.execute(db.text("SELECT 1"))
        db_connected = True
    except Exception:
        db_connected = False

    # Get DB file size if SQLite
    db_uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")
    db_size_bytes = 0
    if "sqlite:///" in db_uri:
        db_file = db_uri.replace("sqlite:///", "")
        if os.path.isfile(db_file):
            db_size_bytes = os.path.getsize(db_file)

    diagnostics = {
        "app_name": current_app.config.get("APP_NAME", "NSAT"),
        "app_version": current_app.config.get("APP_VERSION", "1.0.0"),
        "python_version": sys.version.split()[0],
        "os_platform": platform.platform(),
        "is_linux": platform.system().lower() == "linux",
        "nmap_path": current_app.config.get("NMAP_PATH", "nmap"),
        "nmap_available": nmap_svc.is_available(),
        "nmap_version": nmap_svc.get_version()
        if nmap_svc.is_available()
        else "Not installed (socket fallback active)",
        "lynis_path": current_app.config.get("LYNIS_PATH", "lynis"),
        "lynis_available": lynis_svc.is_installed() and lynis_svc.is_linux(),
        "lynis_status": "Installed & Ready"
        if (lynis_svc.is_installed() and lynis_svc.is_linux())
        else ("Linux only" if not lynis_svc.is_linux() else "Not installed"),
        "db_connected": db_connected,
        "db_uri": db_uri,
        "db_size_kb": round(db_size_bytes / 1024, 2),
        "max_ports_per_scan": current_app.config.get("MAX_PORTS_PER_SCAN", 1000),
        "default_timeout": current_app.config.get("DEFAULT_SCAN_TIMEOUT", 60),
        "max_timeout": current_app.config.get("MAX_SCAN_TIMEOUT", 300),
        "allow_public": current_app.config.get("ALLOW_PUBLIC_TARGETS", False),
        "report_output_dir": str(current_app.config.get("REPORT_OUTPUT_DIR", "")),
    }

    return render_template("settings/settings.html", diagnostics=diagnostics)


@settings_bp.route("/health")
def health_check():
    """System health check endpoint for monitoring."""
    nmap_svc = NmapService(nmap_path=current_app.config.get("NMAP_PATH", "nmap"))
    lynis_svc = LynisService(lynis_path=current_app.config.get("LYNIS_PATH", "lynis"))

    db_ok = True
    try:
        db.session.execute(db.text("SELECT 1"))
    except Exception:
        db_ok = False

    return jsonify(
        {
            "status": "healthy" if db_ok else "unhealthy",
            "app_version": current_app.config.get("APP_VERSION", "1.0.0"),
            "database_connected": db_ok,
            "nmap_available": nmap_svc.is_available(),
            "lynis_available": lynis_svc.is_installed() and lynis_svc.is_linux(),
            "operating_system": platform.system(),
        }
    )
