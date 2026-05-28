# Build a standalone Windows executable for Domain Monitor
# Usage:  .\build_exe.ps1
#
# Output: dist\domain-monitor.exe (single file, no Python required on target machine)
#
# Requirements:
# - You ran this once from the project root inside a venv with the package installed.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    python -m venv .venv
    .\.venv\Scripts\python.exe -m ensurepip --upgrade
}

Write-Host "Installing project and PyInstaller..." -ForegroundColor Cyan
.\.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
.\.venv\Scripts\python.exe -m pip install -e . pyinstaller --quiet

Write-Host "Cleaning previous build artifacts..." -ForegroundColor Cyan
Remove-Item -Recurse -Force .\build, .\dist -ErrorAction SilentlyContinue

Write-Host "Building executable..." -ForegroundColor Cyan
.\.venv\Scripts\pyinstaller.exe domain-monitor.spec --clean --noconfirm

if (Test-Path .\dist\domain-monitor.exe) {
    $size = (Get-Item .\dist\domain-monitor.exe).Length / 1MB
    Write-Host ("`nSUCCESS: dist\domain-monitor.exe ({0:N1} MB)" -f $size) -ForegroundColor Green
    Write-Host "Double-click it to launch. The browser will open automatically." -ForegroundColor Green
} else {
    Write-Host "`nBuild failed: dist\domain-monitor.exe not produced." -ForegroundColor Red
    exit 1
}
