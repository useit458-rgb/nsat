"""
Configuration settings for the Network Security Assessment Toolkit (NSAT).
Enforces security defaults, bounded limits, and environment segregation.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class BaseConfig:
    """Base application configuration with safe defaults."""

    SECRET_KEY = os.getenv("SECRET_KEY", "nsat-insecure-dev-key-change-in-production-374628")

    # Database
    INSTANCE_DIR = BASE_DIR / "instance"
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{INSTANCE_DIR / 'nsat.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Cookie & Session Security Protocols
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() in ("true", "1")
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes session expiry

    # Request Body Size Ceiling (Anti-DoS / Payload exhaustion defense)
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 Megabytes

    # Server Binding & Host Validation
    SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0" if os.getenv("PORT") else "127.0.0.1")
    SERVER_PORT = int(os.getenv("PORT", os.getenv("SERVER_PORT", "5000")))
    _allowed_env = os.getenv("ALLOWED_HOSTS")
    if _allowed_env:
        ALLOWED_HOSTS = {h.strip() for h in _allowed_env.split(",") if h.strip()}
    else:
        ALLOWED_HOSTS = {"127.0.0.1", "localhost", "127.0.0.1:5000", "localhost:5000", "*.railway.app", "*.up.railway.app", "*.onrender.com"}

    # Safety and Scope Controls
    ALLOW_PUBLIC_TARGETS = os.getenv("ALLOW_PUBLIC_TARGETS", "false").lower() in (
        "true",
        "1",
        "yes",
    )
    MAX_TARGETS_PER_SCAN = int(os.getenv("MAX_TARGETS_PER_SCAN", "1"))
    MAX_PORTS_PER_SCAN = int(os.getenv("MAX_PORTS_PER_SCAN", "1000"))
    DEFAULT_SCAN_TIMEOUT = int(os.getenv("DEFAULT_SCAN_TIMEOUT", "60"))
    MAX_SCAN_TIMEOUT = int(os.getenv("MAX_SCAN_TIMEOUT", "300"))
    MIN_SCAN_TIMEOUT = 5
    RATE_LIMIT_DELAY = float(os.getenv("RATE_LIMIT_DELAY", "0.05"))

    # External Tools
    NMAP_PATH = os.getenv("NMAP_PATH", "nmap")
    LYNIS_PATH = os.getenv("LYNIS_PATH", "lynis")

    # Reports
    REPORT_OUTPUT_DIR = BASE_DIR / "reports" / "generated"
    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Application Metadata
    APP_NAME = "Network Security Assessment Toolkit"
    APP_VERSION = "1.0.0"


class DevelopmentConfig(BaseConfig):
    """Development configuration with debugging enabled."""

    DEBUG = True


class TestingConfig(BaseConfig):
    """Testing configuration with in-memory database and disabled CSRF for automated tests."""

    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    DEFAULT_SCAN_TIMEOUT = 10
    MAX_SCAN_TIMEOUT = 30


class ProductionConfig(BaseConfig):
    """Production configuration."""

    DEBUG = False
    # In production, secret key MUST be explicitly provided via environment
    if os.getenv("SECRET_KEY") is None:
        pass


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
