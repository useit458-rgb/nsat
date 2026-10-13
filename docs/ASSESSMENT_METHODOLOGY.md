# NSAT Assessment Methodology & Risk Classification

## 1. Defensive Security Philosophy

A core requirement of ethical defensive security engineering is **transparency and truth in reporting**:

> **Never describe an unverified exposure as a confirmed vulnerability.**

In NSAT, findings represent **observed potential risks and configuration deviations**, not confirmed software exploits.

### Distinct Assessment Concepts:

1. **Port Exposure:** An open TCP port indicates that an operating system socket accepted a TCP handshake (`SYN-ACK`). It does **not** indicate whether the underlying software contains exploitable bugs.
2. **Service Identification:** The process of inspecting banner strings or protocol responses to identify software products (e.g., OpenSSH 9.2). Identification can carry different confidence levels depending on whether direct banner text was extracted or standard port defaults were inferred.
3. **Configuration Weakness:** An observed setting that deviates from established security baselines (e.g., running unencrypted Telnet on port 23, exposing an unauthenticated Redis instance, or missing HTTP `Content-Security-Policy` headers).
4. **Confirmed Vulnerability:** A proven, validated flaw that permits unauthorized execution, bypass, or denial of service. **NSAT intentionally does not execute intrusive exploit payloads.**

---

## 2. Risk Scoring & Severity Model

NSAT implements a documented, deterministic scoring algorithm:

$$\text{Raw Risk} = \sum_{f \in \text{Findings}} \left( \text{Weight}(\text{Severity}_f) \times \text{Multiplier}(\text{Confidence}_f) \right)$$

$$\text{Composite Risk Score} = 100 \times \left(1 - e^{-\frac{\text{Raw Risk}}{60}}\right)$$

### Severity Criteria

- **Critical (Weight: 25.0):** Immediate, high-impact exposure that compromises host boundaries (e.g., unauthenticated databases on exposed segments).
- **High (Weight: 15.0):** Insecure cleartext administrative protocol (Telnet), exposed Windows SMB (Port 445), exposed Remote Desktop without network isolation (Port 3389), or expired TLS certificate.
- **Medium (Weight: 7.0):** Exposed relational database port (MySQL, Postgres), deprecated TLS protocol version (TLS 1.0, SSLv3), or missing critical HTTP security headers (`Strict-Transport-Security`, `Content-Security-Policy`).
- **Low (Weight: 2.5):** Missing defensive HTTP headers (`X-Frame-Options`, `X-Content-Type-Options`) or server banner information disclosure.
- **Informational (Weight: 0.5):** Discovered baseline service operating within standard parameters (e.g., OpenSSH detected on port 22).

### Evidence Confidence Multipliers

- **High (1.0x):** Directly observed and confirmed via protocol banner or TLS handshake (e.g., HTTP response headers, SSL certificate fields, Nmap service banner).
- **Medium (0.8x):** Supported by active TCP probe response or reliable service signature.
- **Low (0.5x):** Inferred solely from well-known port mapping without confirmed banner reply.

---

## 3. Local Linux Host Auditing (Lynis)

Lynis is a specialized security auditing tool designed specifically for local Unix/Linux systems.

**Key Distinctions:**
- **Local Host Only:** Lynis inspects local system files, kernel configuration parameters, systemd services, user authentication accounts, and installed packages on `/`. It cannot perform remote network scans against external IP addresses.
- **Non-Linux Platform Isolation:** When running on Windows or macOS development environments, NSAT detects the operating system and cleanly marks the Lynis audit as `skipped_non_linux` rather than failing or fabricating results.
- **Permission Awareness:** Lynis runs in unprivileged user mode or normal audit mode. Skipped tests or checks requiring root privileges are recorded transparently in the assessment audit trail.
