@echo off
setlocal
cd /d "%~dp0"
title TetraTrace - Member 4 dashboard

rem ---- 1. model file present? ----
if exist "m4_scanner_bundle.joblib" goto have_model
echo.
echo [!] The model file m4_scanner_bundle.joblib is missing.
echo     Download it from Google Drive, folder m4_terraform\models,
echo     and put it in this folder:
echo     %CD%
echo.
pause
exit /b 1
:have_model

rem ---- 2. Python 3.12 available? ----
py -3.12 -c "import sys" >nul 2>nul
if not errorlevel 1 goto have_py
echo.
echo [!] Python 3.12 was not found.
echo     Run python-3.12.0-amd64.exe from your Downloads folder,
echo     tick "Add python.exe to PATH", install, then double-click start.bat again.
echo.
pause
exit /b 1
:have_py

rem ---- 3. scikit-learn version (asked once, then remembered) ----
if exist "sklearn_version.txt" goto have_ver
echo.
echo Colab Cell 45 printed a line like:  Install on your laptop: scikit-learn == 1.6.1
set /p SKV=Type only the version number, for example 1.6.1, then press Enter:
>sklearn_version.txt echo %SKV%
:have_ver
set /p SKV=<sklearn_version.txt
echo Using scikit-learn %SKV%

rem ---- 4. create the environment on first run ----
if exist ".venv312\Scripts\python.exe" goto have_env
echo.
echo First run: creating a Python 3.12 environment and installing packages. This takes a few minutes...
py -3.12 -m venv .venv312
if errorlevel 1 goto fail
".venv312\Scripts\python.exe" -m pip install --upgrade pip
".venv312\Scripts\python.exe" -m pip install -r requirements.txt "scikit-learn==%SKV%"
if errorlevel 1 goto fail
:have_env

rem ---- 5. make sure the port is free ----
netstat -ano | findstr /R /C:":8050 .*LISTENING" >nul
if errorlevel 1 goto port_free
echo.
echo [!] Another dashboard server is already running on port 8050.
echo     Close every other black Command Prompt window, then double-click start.bat again.
echo     If you cannot find it, restart the computer.
pause
exit /b 1
:port_free

rem ---- 6. start the server and open the browser ----
echo.
echo Starting the dashboard at http://localhost:8050  (keep this window open; close it to stop)
start "" cmd /c "timeout /t 8 >nul & start http://localhost:8050"
".venv312\Scripts\python.exe" -m uvicorn server:app --port 8050
pause
exit /b 0

:fail
echo.
echo [!] Setup failed. Take a screenshot of this window and send it to Claude.
echo     To retry from scratch, delete the .venv312 folder and sklearn_version.txt.
pause
exit /b 1
