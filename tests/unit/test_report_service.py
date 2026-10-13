"""
Unit tests for ReportService: HTML, JSON, and PDF generation.
"""

import json

from app.services.report_service import ReportService


class TestReportService:
    def test_generate_html_report(self, app, sample_assessment, tmp_path):
        with app.app_context():
            svc = ReportService(output_dir=tmp_path)
            html_path = svc.generate_html_report(sample_assessment)

            assert html_path.is_file()
            content = html_path.read_text(encoding="utf-8")
            assert sample_assessment.target_ip in content
            assert sample_assessment.title in content
            assert "Network Security Assessment Report" in content

    def test_generate_json_report(self, app, sample_assessment, tmp_path):
        with app.app_context():
            svc = ReportService(output_dir=tmp_path)
            json_path = svc.generate_json_report(sample_assessment)

            assert json_path.is_file()
            data = json.loads(json_path.read_text(encoding="utf-8"))

            assert "report_metadata" in data
            assert data["scope_and_target"]["target_ip"] == "127.0.0.1"
            assert "findings" in data
            assert "summary" in data

    def test_generate_pdf_report(self, app, sample_assessment, tmp_path):
        with app.app_context():
            svc = ReportService(output_dir=tmp_path)
            pdf_path = svc.generate_pdf_report(sample_assessment)

            assert pdf_path.is_file()
            assert pdf_path.stat().st_size > 500  # Valid PDF size
            # Check standard PDF file header
            with open(pdf_path, "rb") as f:
                header = f.read(5)
                assert header.startswith(b"%PDF")
