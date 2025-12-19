# Windows SIEM - Complete Launcher
# Handles admin elevation and keeps window open

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check if running as Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    # Not admin - restart elevated
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "  Administrator Privileges Required" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Requesting elevation..." -ForegroundColor Cyan
    Write-Host "Please click 'Yes' on the UAC prompt" -ForegroundColor Cyan
    Write-Host ""
    
    # Start new elevated process
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# Running as admin now
Clear-Host

# Set console to UTF-8 to support emojis
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Windows SIEM - Starting..." -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[OK] Running as Administrator" -ForegroundColor Green
Write-Host ""

# Change to script directory
Set-Location $ScriptDir

# Run main.py
Write-Host "Starting SIEM..." -ForegroundColor Yellow
Write-Host ""

# Run Python 3.12 explicitly for consistency
$python = "C:\Users\hmjad\AppData\Local\Microsoft\WindowsApps\python3.12.exe"
& $python "${ScriptDir}\main.py"

# If script exits, pause
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "SIEM stopped with error code: $LASTEXITCODE" -ForegroundColor Red
    Write-Host ""
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
