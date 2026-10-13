"""
Integration tests for assessment execution workflow and database persistence.
"""

from unittest.mock import patch

from app.extensions import db
from app.models.assessment import Assessment
from app.models.asset import TargetAsset
from app.models.event import AssessmentEvent
from app.services.assessment_service import AssessmentService
from app.services.socket_scanner import SocketPortResult


class TestAssessmentWorkflow:
    @patch("app.services.socket_scanner.SocketScanner.scan_ports")
    def test_complete_assessment_pipeline(self, mock_scan, app):
        with app.app_context():
            # Mock socket scan results
            mock_scan.return_value = [
                SocketPortResult(
                    port=22, protocol="tcp", state="open", reason="syn-ack", banner="SSH-2.0-Test"
                ),
                SocketPortResult(port=80, protocol="tcp", state="closed", reason="conn-refused"),
            ]

            assessment = Assessment(
                title="Integration Pipeline Test",
                target_ip="127.0.0.1",
                ports_spec="22,80",
                timeout_seconds=30,
                status="QUEUED",
            )
            assessment.modules = ["port_scan", "service_detection", "risk_assessment"]
            db.session.add(assessment)
            db.session.commit()

            # Execute pipeline
            AssessmentService._execute_assessment(app, assessment)

            # Refresh from DB
            db.session.refresh(assessment)

            assert assessment.status == "COMPLETED"
            assert assessment.start_time is not None
            assert assessment.end_time is not None
            assert assessment.duration_seconds is not None
            assert len(assessment.port_results) == 2

            # Check that TargetAsset was created or linked
            asset = TargetAsset.query.filter_by(ip_address="127.0.0.1").first()
            assert asset is not None
            assert assessment.asset_id == asset.id

            # Check audit events recorded
            events = AssessmentEvent.query.filter_by(assessment_id=assessment.id).all()
            assert len(events) >= 3

    def test_cancellation_during_execution(self, app):
        with app.app_context():
            assessment = Assessment(
                title="Cancellation Test",
                target_ip="127.0.0.1",
                ports_spec="22,80,443",
                timeout_seconds=30,
                status="QUEUED",
                cancellation_requested=True,
            )
            db.session.add(assessment)
            db.session.commit()

            AssessmentService._execute_assessment(app, assessment)

            db.session.refresh(assessment)
            assert assessment.status == "CANCELLED"
