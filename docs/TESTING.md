# NSAT Automated Testing Specification

## 1. Test Architecture & Methodology

NSAT includes a 63-test automated test suite covering:
- **Unit Tests:** Input validation, Nmap XML parsing, socket scanning, risk engine rules, HTTP headers, TLS inspection, Lynis parsing, and report generation.
- **Integration Tests:** End-to-end background execution pipelines, state transitions, database persistence, and Flask web routes.

External binaries and network interfaces are mocked using `unittest.mock` to ensure fast, deterministic, non-destructive test execution without touching public networks.

---

## 2. Running Automated Tests

Run the full test suite with verbose output:

```bash
pytest -v
```

Generate test coverage analysis:

```bash
pytest --cov=app --cov-report=term-missing
```

Run code style and linting verification with Ruff:

```bash
ruff check app tests
```

---

## 3. Test Coverage Summary

Key test cases verified across the suite:
- [x] Valid private and loopback IPv4 and IPv6 addresses.
- [x] Rejection of public IPs in initial restricted scope.
- [x] Rejection of hostnames, domain names, CIDR blocks, and malformed strings.
- [x] Port presets (`top20`, `top100`, `web`, `database`), ranges, and comma-separated lists.
- [x] Rejection of out-of-bounds ports, inverted ranges, and excessive port counts.
- [x] Parsing of machine-readable Nmap XML with open, closed, and filtered states.
- [x] Handling of missing Nmap executable with automatic fallback to socket scanning.
- [x] Process execution timeouts and user cancellation callbacks.
- [x] Non-Linux platform detection for Lynis and parsing of Lynis suggestions/warnings.
- [x] Deterministic risk score calculation (bounded between 0.0 and 100.0).
- [x] HTML, JSON, and PDF report generation.
- [x] CSRF protection and HTTP error handling (404, 403, 500).
