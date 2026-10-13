#!/usr/bin/env bash
# ==============================================================================
# Network Security Assessment Toolkit (NSAT) - Automated Setup for Linux
# Supported OS: Debian, Ubuntu, Kali Linux, Linux Mint
# ==============================================================================

set -euo pipefail

echo "=================================================================="
echo "    NETWORK SECURITY ASSESSMENT TOOLKIT (NSAT) - SETUP"
echo "=================================================================="

# 1. Check Python Version
echo "[+] Step 1: Checking Python runtime..."
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is not installed."
    echo "    Install via: sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip"
    exit 1
fi

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "    Detected Python version: $PYTHON_VER"
PYTHON_MAJOR=$(echo "$PYTHON_VER" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VER" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]); then
    echo "[-] Error: NSAT requires Python 3.11 or newer. Detected: $PYTHON_VER"
    exit 1
fi

# 2. Check System Tools
echo "[+] Step 2: Checking external security tools (Nmap & Lynis)..."
if command -v nmap &> /dev/null; then
    echo "    [OK] Nmap is installed: $(nmap --version | head -n 1)"
else
    echo "    [!] Warning: Nmap is not installed. NSAT will use Python socket scanner fallback."
    echo "        To install Nmap: sudo apt-get install -y nmap"
fi

if command -v lynis &> /dev/null; then
    echo "    [OK] Lynis is installed: $(lynis --version | head -n 1)"
else
    echo "    [!] Warning: Lynis is not installed. Local system audits will be skipped."
    echo "        To install Lynis: sudo apt-get install -y lynis"
fi

# 3. Virtual Environment Setup
echo "[+] Step 3: Configuring Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "    Virtual environment created at ./venv"
else
    echo "    Existing virtual environment found at ./venv"
fi

# Activate virtual environment
# shellcheck disable=SC1091
source ./venv/bin/activate

# 4. Install Dependencies
echo "[+] Step 4: Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# 5. Initialize Database
echo "[+] Step 5: Initializing local SQLite database..."
python3 -c "from app import create_app, db; app = create_app(); print('[OK] Database schema verified.')"

# 6. Run Automated Test Suite
echo "[+] Step 6: Running automated validation tests..."
pytest -v

echo "=================================================================="
echo "    [SUCCESS] NSAT installation and test suite passed!"
echo "    To launch the web dashboard, run:"
echo "        source ./venv/bin/activate"
echo "        python wsgi.py"
echo "    Then open your browser to: http://127.0.0.1:5000"
echo "=================================================================="
