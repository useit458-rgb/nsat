# NSAT Installation & Deployment Guide

## 1. System Requirements

- **Python:** Version 3.11 or newer (Python 3.11, 3.12, 3.13, 3.14 supported).
- **Operating System:**
  - **Linux (Recommended):** Ubuntu 22.04+, Debian 12+, Kali Linux 2023+, or Linux Mint.
  - **Windows:** Windows 10/11 with PowerShell (Python socket scanning fallback active).
  - **macOS:** macOS 12+ (Socket scanner fallback active for Lynis).
- **External Tools (Optional but Recommended):**
  - `nmap` (Network port scanner)
  - `lynis` (Local Linux security auditor)

---

## 2. Linux Installation (Debian / Ubuntu / Kali)

### Automated Setup
```bash
git clone <repo-url> nsat
cd nsat
chmod +x scripts/setup_linux.sh
./scripts/setup_linux.sh
```

### Manual Step-by-Step Setup
1. **Install Linux System Packages:**
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-venv python3-pip nmap lynis
   ```

2. **Initialize Python Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Verify Tool Availability:**
   ```bash
   nmap --version
   lynis --version
   ```

5. **Run Test Suite:**
   ```bash
   pytest -v
   ```

6. **Start Application:**
   ```bash
   python wsgi.py
   ```
   Navigate to `http://127.0.0.1:5000` in your web browser.

---

## 3. Windows Installation

1. **Verify Python 3.11+:**
   ```powershell
   python --version
   ```

2. **Create and Activate Virtual Environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install Python Packages:**
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Run Pytest:**
   ```powershell
   pytest -v
   ```

5. **Start Web Dashboard:**
   ```powershell
   python wsgi.py
   ```

---

## 4. Docker Deployment

Build and run using Docker Compose:

```bash
docker compose up --build -d
```
Dashboard will be available at `http://127.0.0.1:5000`.
