@echo off
REM ============================================================
REM  Domain Monitor - one-click launcher for Windows
REM  First run: creates a private venv and installs from GitHub.
REM  Next runs: just launches the app and opens the browser.
REM ============================================================
setlocal

set "APP_DIR=%LOCALAPPDATA%\DomainMonitor"
set "VENV_DIR=%APP_DIR%\.venv"
set "PY=%VENV_DIR%\Scripts\python.exe"
set "EXE=%VENV_DIR%\Scripts\domain-monitor.exe"
set "REPO=https://github.com/Cracka01/domain-monitor.git"

if not exist "%APP_DIR%" mkdir "%APP_DIR%"

REM --- Locate a system Python ---
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Install Python 3.10+ from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

REM --- Create venv on first run ---
if not exist "%PY%" (
    echo [setup] Creating private environment at "%VENV_DIR%" ...
    python -m venv "%VENV_DIR%"
    if errorlevel 1 goto :fail
    "%PY%" -m ensurepip --upgrade >nul
    "%PY%" -m pip install --upgrade pip --quiet
)

REM --- Install / update package ---
if not exist "%EXE%" (
    echo [setup] Installing Domain Monitor from GitHub ...
    "%PY%" -m pip install --quiet "git+%REPO%"
    if errorlevel 1 goto :fail
)

REM --- Launch ---
echo.
echo [run] Starting Domain Monitor ...
"%EXE%" %*
exit /b %errorlevel%

:fail
echo.
echo [ERROR] Setup failed. Check the messages above.
pause
exit /b 1
