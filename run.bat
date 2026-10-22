@echo off
chcp 65001 >nul
title ShieldCloud Security Platform
echo ===============================================================
echo   SHIELDCLOUD // CLOUD POSTURE ^& SECRET LEAKAGE PLATFORM
echo ===============================================================
echo.
echo [*] Starting backend server on port 8000...
echo [*] Open browser at: http://localhost:8000
echo [*] Press Ctrl+C to stop the server.
echo.

python backend\server.py
