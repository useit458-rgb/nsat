# NSAT Application Security Policy & Controls

## 1. Threat Modeling & Scope Safeguards

The toolkit enforces defense-in-depth safeguards across all layers of execution:

### Strict Target Scope Enforcement
- **Loopback & Private Subnets Only:** Target IP validation is implemented via Python's standard `ipaddress` module. By default, inputs are strictly checked:
  - Loopback (`127.0.0.1`, `::1`)
  - RFC 1918 Private IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- **Public IPs Rejected:** Arbitrary Internet scanning is forbidden in the default configuration to prevent abuse.
- **Hostname Resolution Disabled:** Domain names (e.g. `example.com`) are explicitly rejected to prevent unintended targets resulting from DNS rebinding, spoofing, or resolution changes.

---

## 2. Subprocess Security & Command Injection Mitigation

External tools (`nmap`, `lynis`) are invoked using `app/utils/subprocess_runner.py`:

- **No Shell Execution:** Subprocesses are **never** executed via `shell=True`. Arguments are passed as structured lists:
  ```python
  subprocess.run(cmd_list, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  ```
- **Explicit Timeouts:** Every subprocess execution carries an explicit timeout (e.g., 60 seconds). Hanging processes are terminated automatically.
- **Defensive Output Parsing:** Outputs are decoded with `errors="replace"` to protect against binary garble, terminal escape injections, or Unicode decode exceptions.

---

## 3. Web Application Security Controls

- **CSRF Protection:** All state-changing POST and DELETE requests require cryptographic CSRF tokens managed by `Flask-WTF` (`CSRFProtect`).
- **Context-Aware Escaping:** Templates use Jinja2 auto-escaping to mitigate Cross-Site Scripting (XSS).
- **Path Traversal Defense:** Report downloads verify that the resolved target path begins strictly within the configured `reports/generated/` directory before delivering files.
- **Localhost Binding:** Development and production WSGI bindings default to `127.0.0.1` to prevent unauthorized exposure over local area networks.
- **Credential Redaction in Logs:** `SecurityFilter` inspects log records and automatically redacts tokens, passwords, and sensitive keys.
