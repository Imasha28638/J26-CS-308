@echo off
cd /d "%~dp0"
title TetraTrace - verify dashboard
if not exist ".venv312\Scripts\python.exe" (
  echo Run start.bat first.
  pause
  exit /b 1
)
set DASHBOARD_URL=http://localhost:8050
".venv312\Scripts\python.exe" verify.py
pause
