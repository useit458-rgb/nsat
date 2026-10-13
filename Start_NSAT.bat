@echo off
title Network Security Assessment Toolkit (NSAT)
echo ========================================================
echo  Starting Network Security Assessment Toolkit (NSAT)...
echo ========================================================
echo.

cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo [!] Virtual environment not found. Please ensure venv exists.
    pause
    exit /b 1
)

echo [*] Launching local secure web server...
start "" "http://127.0.0.1:5000"
venv\Scripts\python.exe wsgi.py

pause
