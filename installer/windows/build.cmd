@echo off
REM Tamandua EDR Agent MSI Builder
REM Simple batch wrapper for build.ps1

setlocal

REM Change to script directory
cd /d "%~dp0"

REM Check for PowerShell
where powershell >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: PowerShell is required but not found in PATH
    exit /b 1
)

REM Run PowerShell build script with all arguments
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*

exit /b %errorlevel%
