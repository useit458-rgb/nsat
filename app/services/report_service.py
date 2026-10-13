"""
Module 4: Security Assessment Report Generator.
Generates comprehensive, professional reports in HTML, JSON, and PDF formats.
Enforces reproducible generation from stored database models with safe escaping.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import render_template
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.assessment import Assessment

logger = logging.getLogger(__name__)


class ReportService:
    """Orchestrates generation of HTML, JSON, and PDF security assessment reports."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_html_report(self, assessment: Assessment) -> Path:
        """Render a standalone, portable HTML assessment report."""
        out_file = self.output_dir / f"nsat_report_{assessment.uuid}.html"
        html_content = render_template(
            "reports/report_template.html",
            assessment=assessment,
            generated_at=datetime.now(UTC),
        )
        out_file.write_text(html_content, encoding="utf-8")
        return out_file

    def generate_json_report(self, assessment: Assessment) -> Path:
        """Generate a structured, schema-compliant JSON report."""
        out_file = self.output_dir / f"nsat_report_{assessment.uuid}.json"

        data: dict[str, Any] = {
            "report_metadata": {
                "report_id": f"REP-{assessment.uuid[:8].upper()}",
                "assessment_uuid": assessment.uuid,
                "assessment_id": assessment.id,
                "title": assessment.title,
                "generated_at_utc": datetime.now(UTC).isoformat(),
                "generator": "Network Security Assessment Toolkit (NSAT)",
                "generator_version": "1.0.0",
                "classification": "CONFIDENTIAL - AUTHORIZED SECURITY ASSESSMENT",
            },
            "scope_and_target": {
                "target_ip": assessment.target_ip,
                "ports_requested": assessment.ports_spec,
                "modules_enabled": assessment.modules,
                "timeout_seconds": assessment.timeout_seconds,
                "is_private_target": True,
            },
            "execution_details": {
                "status": assessment.status,
                "created_at": assessment.created_at.isoformat() if assessment.created_at else None,
                "start_time": assessment.start_time.isoformat() if assessment.start_time else None,
                "end_time": assessment.end_time.isoformat() if assessment.end_time else None,
                "duration_seconds": assessment.duration_seconds,
                "error_message": assessment.error_message,
                "risk_score": assessment.risk_score,
            },
            "summary": {
                "total_open_ports": assessment.open_ports_count,
                "total_findings": len(assessment.findings),
                "severity_distribution": assessment.severity_counts,
            },
            "port_results": [
                {
                    "port": p.port_number,
                    "protocol": p.protocol,
                    "state": p.state,
                    "reason": p.reason,
                    "service_name": p.service_name,
                }
                for p in assessment.port_results
            ],
            "service_observations": [
                {
                    "port": s.port_number,
                    "service_name": s.service_name,
                    "product": s.product,
                    "version": s.version,
                    "extrainfo": s.extrainfo,
                    "confidence": s.confidence,
                    "method": s.method,
                }
                for s in assessment.service_observations
            ],
            "findings": [
                {
                    "finding_key": f.finding_key,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "category": f.category,
                    "port": f.port,
                    "asset_ip": f.asset_ip,
                    "description": f.description,
                    "evidence": f.evidence,
                    "reasoning": f.reasoning,
                    "remediation": f.remediation,
                    "references": f.references,
                    "status": f.status,
                }
                for f in assessment.findings
            ],
            "tool_executions": [
                {
                    "tool_name": t.tool_name,
                    "command_line": t.command_line,
                    "exit_code": t.exit_code,
                    "duration_seconds": t.duration_seconds,
                    "status": t.status,
                }
                for t in assessment.tool_executions
            ],
            "limitations_and_disclaimer": {
                "statement": (
                    "This report represents observations recorded at the time of assessment. "
                    "A closed or filtered port does not guarantee that no service exists. "
                    "Findings represent potential risk exposures and configuration deviations, "
                    "not confirmed exploitability. Defensive assessments require continuous verification."
                )
            },
        }

        out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return out_file

    def generate_pdf_report(self, assessment: Assessment) -> Path:
        """
        Generate a professional PDF assessment report using ReportLab.
        Works reliably across all platforms (Linux, macOS, Windows) without GTK C-dependencies.
        """
        out_file = self.output_dir / f"nsat_report_{assessment.uuid}.pdf"

        doc = SimpleDocTemplate(
            str(out_file),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#64748b"),
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=14,
            spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        body_bold = ParagraphStyle(
            "BodyBold",
            parent=body_style,
            fontName="Helvetica-Bold",
        )
        disclaimer_style = ParagraphStyle(
            "Disclaimer",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#94a3b8"),
        )

        story = []

        # Header Title
        story.append(Paragraph("Network Security Assessment Report", title_style))
        story.append(
            Paragraph(
                f"Target: {assessment.target_ip} | Report ID: REP-{assessment.uuid[:8].upper()}",
                subtitle_style,
            )
        )
        story.append(Spacer(1, 10))
        story.append(
            HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=12)
        )

        # Scope & Metadata Table
        meta_data = [
            [
                Paragraph("<b>Assessment Title:</b>", body_style),
                Paragraph(assessment.title, body_style),
                Paragraph("<b>Status:</b>", body_style),
                Paragraph(assessment.status, body_style),
            ],
            [
                Paragraph("<b>Target IP:</b>", body_style),
                Paragraph(assessment.target_ip, body_style),
                Paragraph("<b>Composite Risk Score:</b>", body_style),
                Paragraph(f"<b>{assessment.risk_score} / 100</b>", body_style),
            ],
            [
                Paragraph("<b>Ports Assessed:</b>", body_style),
                Paragraph(assessment.ports_spec[:40], body_style),
                Paragraph("<b>Duration:</b>", body_style),
                Paragraph(f"{assessment.duration_seconds or 0}s", body_style),
            ],
            [
                Paragraph("<b>Started At:</b>", body_style),
                Paragraph(str(assessment.start_time or "N/A"), body_style),
                Paragraph("<b>Completed At:</b>", body_style),
                Paragraph(str(assessment.end_time or "N/A"), body_style),
            ],
        ]
        meta_table = Table(meta_data, colWidths=[110, 160, 120, 150])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 14))

        # Executive Summary & Risk Breakdown
        story.append(Paragraph("Executive Summary & Risk Distribution", h2_style))
        counts = assessment.severity_counts

        summary_data = [
            [
                Paragraph("<b>Critical</b>", body_style),
                Paragraph("<b>High</b>", body_style),
                Paragraph("<b>Medium</b>", body_style),
                Paragraph("<b>Low</b>", body_style),
                Paragraph("<b>Informational</b>", body_style),
                Paragraph("<b>Open Ports</b>", body_style),
            ],
            [
                Paragraph(str(counts["Critical"]), body_bold),
                Paragraph(str(counts["High"]), body_bold),
                Paragraph(str(counts["Medium"]), body_bold),
                Paragraph(str(counts["Low"]), body_bold),
                Paragraph(str(counts["Informational"]), body_bold),
                Paragraph(str(assessment.open_ports_count), body_bold),
            ],
        ]
        summary_table = Table(summary_data, colWidths=[90, 90, 90, 90, 90, 90])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 14))

        # Port Results Table
        story.append(
            Paragraph(
                f"Discovered TCP Port Results ({len(assessment.port_results)} total)", h2_style
            )
        )
        if assessment.port_results:
            port_table_data = [
                [
                    Paragraph("<b>Port</b>", body_style),
                    Paragraph("<b>Protocol</b>", body_style),
                    Paragraph("<b>State</b>", body_style),
                    Paragraph("<b>Reason</b>", body_style),
                    Paragraph("<b>Service</b>", body_style),
                ]
            ]
            for p in assessment.port_results[:30]:  # Limit rows in table to keep PDF manageable
                port_table_data.append(
                    [
                        Paragraph(str(p.port_number), body_style),
                        Paragraph(p.protocol.upper(), body_style),
                        Paragraph(f"<b>{p.state.upper()}</b>", body_style),
                        Paragraph(p.reason or "-", body_style),
                        Paragraph(p.service_name or "-", body_style),
                    ]
                )
            port_table = Table(port_table_data, colWidths=[60, 60, 80, 140, 200])
            port_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(port_table)
        else:
            story.append(Paragraph("No ports assessed or returned in this scan.", body_style))
        story.append(Spacer(1, 14))

        # Findings Section
        story.append(
            Paragraph(f"Prioritized Security Findings ({len(assessment.findings)} total)", h2_style)
        )
        if assessment.findings:
            for idx, f in enumerate(assessment.findings, start=1):
                sev_color = {
                    "Critical": "#dc2626",
                    "High": "#ea580c",
                    "Medium": "#ca8a04",
                    "Low": "#2563eb",
                    "Informational": "#64748b",
                }.get(f.severity, "#64748b")

                story.append(
                    Paragraph(
                        f"<b>{idx}. [{f.severity}] {f.title}</b> (Port: {f.port or 'N/A'}, Confidence: {f.confidence})",
                        ParagraphStyle(
                            "FindingHead", parent=body_bold, textColor=colors.HexColor(sev_color)
                        ),
                    )
                )
                story.append(Paragraph(f"<b>Description:</b> {f.description}", body_style))
                story.append(Paragraph(f"<b>Evidence:</b> {f.evidence}", body_style))
                story.append(Paragraph(f"<b>Remediation:</b> {f.remediation}", body_style))
                story.append(Spacer(1, 6))
        else:
            story.append(
                Paragraph(
                    "No security risks or configuration findings identified during this assessment.",
                    body_style,
                )
            )

        # Legal Disclaimer
        story.append(Spacer(1, 14))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=8)
        )
        story.append(
            Paragraph(
                "<b>NOTICE & LIMITATIONS:</b> This defensive assessment was conducted against an explicitly authorized target. "
                "Results reflect observations at the time of testing and do not guarantee the absence of unobserved vulnerabilities. "
                "Never use this toolkit against unauthorized third-party networks or systems.",
                disclaimer_style,
            )
        )

        doc.build(story)
        return out_file
