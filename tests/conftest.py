"""
Pytest fixtures for NSAT test suite.
"""

import pytest

from app import create_app, db
from app.models.assessment import Assessment


@pytest.fixture
def app():
    """Create testing application instance with in-memory database."""
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client for HTTP requests."""
    return app.test_client()


@pytest.fixture
def sample_assessment(app):
    """Provide a persisted sample assessment for route tests."""
    with app.app_context():
        assessment = Assessment(
            title="Loopback Baseline Test",
            target_ip="127.0.0.1",
            ports_spec="22,80,443",
            timeout_seconds=30,
            status="COMPLETED",
            risk_score=15.0,
        )
        assessment.modules = ["port_scan", "service_detection", "risk_assessment"]
        db.session.add(assessment)
        db.session.commit()
        # Refresh to load within session
        db.session.refresh(assessment)
        return assessment
