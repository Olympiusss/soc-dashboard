@echo off
title Sentrium Integrated SOC Dashboard
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║   Sentrium Integrated SOC Dashboard                 ║
echo  ║   Security Operations Center                        ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

:: Check if dependencies are installed
echo [1/2] Checking dependencies...
pip install -r requirements.txt --quiet --disable-pip-version-check 2>nul

echo [2/2] Starting dashboard server...
echo.
echo  ┌────────────────────────────────────────────┐
echo  │  Dashboard: http://localhost:8080           │
echo  │  Health:    http://localhost:8080/api/health │
echo  └────────────────────────────────────────────┘
echo.
echo  Press Ctrl+C to stop.
echo.

uvicorn app:app --host 0.0.0.0 --port 8080 --reload --log-level info
