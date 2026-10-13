"""
Assessment Orchestration Service and Background Execution Queue.
Coordinates Module 1 (Port Scanning), Module 2 (Service Detection),
Module 3 (Risk Assessment & Auditing), and saves structured findings into SQLAlchemy.
Thread-safe execution with concurrency locks and cancellation support.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime

from app.extensions import db
from app.models.assessment import Assessment
from app.models.asset import TargetAsset
from app.models.event import AssessmentEvent
from app.models.finding import Finding
from app.models.port_result import PortResult
from app.models.service_observation import ServiceObservation
from app.models.tool_execution import ToolExecution
from app.services.http_checks import HttpSecurityChecker
from app.services.lynis_service import LynisService
from app.services.nmap_service import NmapService
from app.services.risk_engine import RiskEngine
from app.services.service_detection import ServiceDetector
from app.services.socket_scanner import SocketScanner
from app.utils.validation import parse_and_validate_ports

logger = logging.getLogger(__name__)


class AssessmentService:
    """Thread-safe orchestrator for executing background security assessments."""

    _lock = threading.Lock()
    _active_threads: dict[int, threading.Thread] = {}

    @classmethod
    def get_active_count(cls) -> int:
        with cls._lock:
            # Clean up dead threads
            dead = [aid for aid, t in cls._active_threads.items() if not t.is_alive()]
            for aid in dead:
                del cls._active_threads[aid]
            return len(cls._active_threads)

    @classmethod
    def start_assessment_async(cls, app, assessment_id: int) -> bool:
        """Enqueue and launch assessment in a background worker thread."""
        with cls._lock:
            if (
                assessment_id in cls._active_threads
                and cls._active_threads[assessment_id].is_alive()
            ):
                logger.warning("Assessment %d is already running.", assessment_id)
                return False

            worker = threading.Thread(
                target=cls._run_worker,
                args=(app, assessment_id),
                name=f"NSAT-Worker-{assessment_id}",
                daemon=True,
            )
            cls._active_threads[assessment_id] = worker
            worker.start()
            return True

    @classmethod
    def request_cancellation(cls, assessment_id: int) -> bool:
        """Signal an active assessment to cancel gracefully."""
        assessment = db.session.get(Assessment, assessment_id)
        if not assessment:
            return False
        if assessment.status in ("COMPLETED", "FAILED", "CANCELLED"):
            return False

        assessment.cancellation_requested = True
        db.session.commit()
        logger.info("Cancellation requested for assessment #%d.", assessment_id)
        return True

    @classmethod
    def _run_worker(cls, app, assessment_id: int) -> None:
        """Worker thread entrypoint within Flask application context."""
        with app.app_context():
            assessment = db.session.get(Assessment, assessment_id)
            if not assessment:
                logger.error("Assessment #%d not found in database.", assessment_id)
                return

            try:
                cls._execute_assessment(app, assessment)
            except Exception as e:
                logger.exception(
                    "Fatal unhandled error during assessment #%d execution: %s", assessment_id, e
                )
                assessment.status = "FAILED"
                assessment.error_message = f"Execution error: {e}"
                assessment.end_time = datetime.now(UTC)
                cls._log_event(assessment, "error", f"Assessment failed: {e}")
                db.session.commit()
            finally:
                with cls._lock:
                    if assessment_id in cls._active_threads:
                        del cls._active_threads[assessment_id]

    @classmethod
    def _execute_assessment(cls, app, assessment: Assessment) -> None:
        """Step-by-step orchestrator pipeline."""
        if assessment.cancellation_requested:
            assessment.status = "CANCELLED"
            db.session.commit()
            return

        assessment.status = "RUNNING"
        assessment.start_time = datetime.now(UTC)
        db.session.commit()

        cls._log_event(
            assessment, "milestone", f"Assessment started against target {assessment.target_ip}."
        )

        # Track or create TargetAsset
        asset = TargetAsset.query.filter_by(ip_address=assessment.target_ip).first()
        if not asset:
            asset = TargetAsset(
                ip_address=assessment.target_ip,
                asset_type="loopback"
                if assessment.target_ip in ("127.0.0.1", "::1")
                else "private_host",
                is_private=True,
            )
            db.session.add(asset)
            db.session.flush()
        else:
            asset.last_seen = datetime.now(UTC)
        assessment.asset_id = asset.id
        db.session.commit()

        # Parse requested ports
        ports = parse_and_validate_ports(
            assessment.ports_spec, max_ports=app.config.get("MAX_PORTS_PER_SCAN", 1000)
        )
        enabled_modules = set(assessment.modules)
        timeout_sec = assessment.timeout_seconds

        def is_cancelled() -> bool:
            # Query fresh state from db
            refreshed = db.session.get(Assessment, assessment.id)
            return bool(refreshed and refreshed.cancellation_requested)

        nmap_svc = NmapService(nmap_path=app.config.get("NMAP_PATH", "nmap"))
        socket_scanner = SocketScanner(rate_limit_delay=app.config.get("RATE_LIMIT_DELAY", 0.02))

        # --- STEP 1: PORT SCANNING ---
        cls._log_event(assessment, "tool_run", f"Starting port scan on {len(ports)} ports...")
        open_ports: list[int] = []

        if is_cancelled():
            cls._cancel(assessment)
            return

        if nmap_svc.is_available():
            # Module 1 with Nmap
            scan_res = nmap_svc.scan_ports(
                target_ip=assessment.target_ip,
                ports=ports,
                timeout_seconds=timeout_sec,
                enable_service_detection=("service_detection" in enabled_modules),
                cancellation_check=is_cancelled,
            )

            # Record tool execution
            cls._record_tool_run(
                assessment,
                tool_name="nmap",
                cmd=scan_res.command_executed,
                exit_code=0 if scan_res.tool_status == "success" else 1,
                duration=scan_res.duration_seconds,
                status=scan_res.tool_status,
                stdout_preview=scan_res.raw_xml[:5000],
                stderr_preview=scan_res.error_message,
            )

            if scan_res.tool_status == "timed_out":
                cls._log_event(assessment, "warning", f"Nmap timed out after {timeout_sec}s.")
            elif scan_res.tool_status == "failure":
                cls._log_event(
                    assessment,
                    "warning",
                    f"Nmap execution issue: {scan_res.error_message}. Falling back to socket scanner.",
                )

            if scan_res.ports:
                for p in scan_res.ports:
                    pr = PortResult(
                        assessment_id=assessment.id,
                        port_number=p.port,
                        protocol=p.protocol,
                        state=p.state,
                        reason=p.reason,
                        service_name=p.service_name,
                    )
                    db.session.add(pr)
                    if p.state == "open":
                        open_ports.append(p.port)
                        # Save service observation if available
                        if "service_detection" in enabled_modules:
                            detail = ServiceDetector.enrich_observation(
                                port=p.port,
                                raw_service=p.service_name,
                                product=p.product,
                                version=p.version,
                                extrainfo=p.extrainfo,
                                method="nmap-version" if p.product else "nmap-probe",
                            )
                            so = ServiceObservation(
                                assessment_id=assessment.id,
                                port_number=p.port,
                                service_name=detail.service_name,
                                product=detail.product,
                                version=detail.version,
                                extrainfo=detail.extrainfo,
                                confidence=detail.confidence,
                                method=detail.method,
                            )
                            db.session.add(so)
                db.session.commit()
            else:
                # No ports from Nmap, fallback to socket scanner
                open_ports = cls._run_socket_scan_step(
                    assessment, socket_scanner, ports, is_cancelled, enabled_modules
                )
        else:
            # Nmap not installed -> Socket Scanner Fallback
            cls._log_event(
                assessment,
                "info",
                "Nmap is not installed on this system. Operating in Python socket fallback mode.",
            )
            open_ports = cls._run_socket_scan_step(
                assessment, socket_scanner, ports, is_cancelled, enabled_modules
            )

        cls._log_event(
            assessment,
            "milestone",
            f"Port scan completed. Discovered {len(open_ports)} open TCP ports.",
        )

        if is_cancelled():
            cls._cancel(assessment)
            return

        # --- STEP 2: HTTP & TLS CHECKS (if enabled) ---
        http_results = []
        tls_results = []
        if "http_tls_checks" in enabled_modules and open_ports:
            cls._log_event(
                assessment,
                "tool_run",
                "Evaluating HTTP security headers and TLS certificates on relevant open ports...",
            )
            http_checker = HttpSecurityChecker(timeout_seconds=3.0)
            from app.services.tls_checks import TlsChecker

            tls_checker = TlsChecker(timeout_seconds=3.0)

            # Check web ports
            web_ports = [
                p for p in open_ports if p in (80, 443, 8000, 8080, 8443, 3000, 5000, 8888, 9000)
            ]
            for wp in web_ports:
                if is_cancelled():
                    cls._cancel(assessment)
                    return
                is_https = wp in (443, 8443)
                # HTTP Header check
                h_res = http_checker.evaluate_target(assessment.target_ip, wp, is_https=is_https)
                if h_res.tested:
                    http_results.append(h_res)

                # TLS Certificate check if HTTPS or port 443/8443
                if is_https:
                    t_res = tls_checker.inspect_tls(assessment.target_ip, wp)
                    tls_results.append(t_res)

        # --- STEP 3: LYNIS LOCAL AUDIT (if enabled and applicable) ---
        lynis_result = None
        if "lynis_audit" in enabled_modules:
            # Lynis can only audit local machine (127.0.0.1 or ::1)
            if assessment.target_ip in ("127.0.0.1", "::1", "localhost"):
                cls._log_event(
                    assessment, "tool_run", "Executing local Linux Lynis system audit..."
                )
                lynis_svc = LynisService(lynis_path=app.config.get("LYNIS_PATH", "lynis"))
                lynis_result = lynis_svc.audit_system(timeout_seconds=min(timeout_sec, 120))
                cls._log_event(
                    assessment,
                    "info",
                    f"Lynis Audit Status: {lynis_result.status}. {lynis_result.explanation}",
                )
            else:
                cls._log_event(
                    assessment,
                    "info",
                    f"Lynis audit skipped: Lynis audits the local operating system only and cannot perform remote host scans against {assessment.target_ip}.",
                )

        if is_cancelled():
            cls._cancel(assessment)
            return

        # --- STEP 4: RISK ASSESSMENT ENGINE ---
        if "risk_assessment" in enabled_modules:
            cls._log_event(
                assessment,
                "tool_run",
                "Running risk rules engine and prioritizing security findings...",
            )
            risk_engine = RiskEngine()

            # Fetch persisted port results & service observations
            p_results = PortResult.query.filter_by(assessment_id=assessment.id).all()
            s_obs = ServiceObservation.query.filter_by(assessment_id=assessment.id).all()

            findings_list, composite_score = risk_engine.evaluate(
                target_ip=assessment.target_ip,
                port_results=p_results,
                service_obs=s_obs,
                http_results=http_results,
                tls_results=tls_results,
                lynis_result=lynis_result,
            )

            # Persist findings
            for rf in findings_list:
                f = Finding(
                    assessment_id=assessment.id,
                    finding_key=rf.finding_key,
                    title=rf.title,
                    severity=rf.severity,
                    confidence=rf.confidence,
                    category=rf.category,
                    asset_ip=rf.asset_ip,
                    port=rf.port,
                    description=rf.description,
                    evidence=rf.evidence,
                    reasoning=rf.reasoning,
                    remediation=rf.remediation,
                    references_json="[]",
                    status="Active",
                )
                f.references = rf.references
                db.session.add(f)

            assessment.risk_score = composite_score
            db.session.commit()
            cls._log_event(
                assessment,
                "milestone",
                f"Risk engine completed. Generated {len(findings_list)} prioritized findings. Composite Risk Score: {composite_score}/100.",
            )

        # --- FINALIZE ASSESSMENT ---
        assessment.status = "COMPLETED"
        assessment.end_time = datetime.now(UTC)
        cls._log_event(
            assessment,
            "milestone",
            f"Assessment successfully completed in {assessment.duration_seconds}s.",
        )
        db.session.commit()

    @classmethod
    def _run_socket_scan_step(
        cls,
        assessment: Assessment,
        socket_scanner: SocketScanner,
        ports: list[int],
        is_cancelled: Callable[[], bool],
        enabled_modules: set[str],
    ) -> list[int]:
        open_ports: list[int] = []
        sock_results = socket_scanner.scan_ports(
            target_ip=assessment.target_ip,
            ports=ports,
            cancellation_check=is_cancelled,
        )

        for sr in sock_results:
            pr = PortResult(
                assessment_id=assessment.id,
                port_number=sr.port,
                protocol=sr.protocol,
                state=sr.state,
                reason=sr.reason,
            )
            db.session.add(pr)
            if sr.state == "open":
                open_ports.append(sr.port)
                if "service_detection" in enabled_modules:
                    detail = ServiceDetector.enrich_observation(
                        port=sr.port,
                        banner=sr.banner,
                        method="socket-banner" if sr.banner else "port-inference",
                    )
                    so = ServiceObservation(
                        assessment_id=assessment.id,
                        port_number=sr.port,
                        service_name=detail.service_name,
                        product=detail.product,
                        version=detail.version,
                        confidence=detail.confidence,
                        method=detail.method,
                        raw_output=sr.banner,
                    )
                    db.session.add(so)
        db.session.commit()
        return open_ports

    @classmethod
    def _cancel(cls, assessment: Assessment) -> None:
        assessment.status = "CANCELLED"
        assessment.end_time = datetime.now(UTC)
        cls._log_event(assessment, "warning", "Assessment execution was cancelled by user.")
        db.session.commit()

    @classmethod
    def _log_event(cls, assessment: Assessment, event_type: str, message: str) -> None:
        ev = AssessmentEvent(
            assessment_id=assessment.id,
            event_type=event_type,
            message=message,
        )
        db.session.add(ev)
        db.session.commit()

    @classmethod
    def _record_tool_run(
        cls,
        assessment: Assessment,
        tool_name: str,
        cmd: list[str],
        exit_code: int,
        duration: float,
        status: str,
        stdout_preview: str | None = None,
        stderr_preview: str | None = None,
    ) -> None:
        te = ToolExecution(
            assessment_id=assessment.id,
            tool_name=tool_name,
            command_line=" ".join(cmd),
            exit_code=exit_code,
            duration_seconds=duration,
            status=status,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
        )
        db.session.add(te)
        db.session.commit()
