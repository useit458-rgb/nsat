"""
Integration tests for Flask web routes and UI endpoints.
"""

from unittest.mock import patch


class TestWebRoutes:
    def test_dashboard_overview(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Security Overview Dashboard" in resp.data

    def test_assessment_list_route(self, client):
        resp = client.get("/assessments/")
        assert resp.status_code == 200
        assert b"Assessment History" in resp.data

    def test_new_assessment_wizard_get(self, client):
        resp = client.get("/assessments/new")
        assert resp.status_code == 200
        assert b"Launch Security Assessment" in resp.data

    @patch(
        "app.services.assessment_service.AssessmentService.start_assessment_async",
        return_value=True,
    )
    def test_new_assessment_wizard_post_success(self, mock_async, client):
        data = {
            "title": "Local Host Test",
            "target_ip": "127.0.0.1",
            "port_preset": "top20",
            "timeout": "20",
            "authorized": "yes",
            "modules": ["port_scan", "service_detection", "risk_assessment"],
        }
        resp = client.post("/assessments/new", data=data, follow_redirects=False)
        assert resp.status_code == 302
        assert "/assessments/" in resp.headers["Location"]

    def test_new_assessment_rejects_unauthorized(self, client):
        data = {
            "title": "Unauthorized Test",
            "target_ip": "127.0.0.1",
            "port_preset": "top20",
            "timeout": "60",
            # authorized omitted
        }
        resp = client.post("/assessments/new", data=data)
        assert resp.status_code == 200
        assert b"explicitly verify that you own this network target" in resp.data

    def test_new_assessment_rejects_public_ip(self, client):
        data = {
            "title": "Public Target Test",
            "target_ip": "8.8.8.8",
            "port_preset": "top20",
            "timeout": "60",
            "authorized": "yes",
        }
        resp = client.post("/assessments/new", data=data)
        assert resp.status_code == 200
        assert b"public IP address" in resp.data

    def test_assessment_detail_route(self, client, sample_assessment):
        resp = client.get(f"/assessments/{sample_assessment.id}")
        assert resp.status_code == 200
        assert sample_assessment.target_ip.encode() in resp.data

    def test_assessment_status_api(self, client, sample_assessment):
        resp = client.get(f"/assessments/{sample_assessment.id}/status")
        assert resp.status_code == 200
        json_data = resp.get_json()
        assert json_data["id"] == sample_assessment.id
        assert json_data["status"] == "COMPLETED"

    def test_assessment_compare_route(self, client):
        resp = client.get("/assessments/compare")
        assert resp.status_code == 200
        assert b"Compare Security Assessments" in resp.data

    def test_findings_list_route(self, client):
        resp = client.get("/findings/")
        assert resp.status_code == 200
        assert b"Security Findings Directory" in resp.data

    def test_reports_list_route(self, client):
        resp = client.get("/reports/")
        assert resp.status_code == 200
        assert b"Generated Assessment Reports" in resp.data

    def test_settings_and_health_routes(self, client):
        resp = client.get("/settings/")
        assert resp.status_code == 200
        assert (
            b"System Health &amp; Environment Settings" in resp.data
            or b"System Health & Environment Settings" in resp.data
        )

        health_resp = client.get("/settings/health")
        assert health_resp.status_code == 200
        assert health_resp.get_json()["status"] == "healthy"

    def test_delete_assessment_route(self, client, sample_assessment):
        resp = client.post(f"/assessments/{sample_assessment.id}/delete", follow_redirects=True)
        assert resp.status_code == 200
        assert b"permanently deleted" in resp.data

    def test_404_error_page(self, client):
        resp = client.get("/nonexistent-endpoint-xyz-987")
        assert resp.status_code == 404
        assert b"404" in resp.data
