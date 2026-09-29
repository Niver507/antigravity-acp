<#
.SYNOPSIS
    Google Antigravity ACP Setup & Manager for Windows PowerShell
.DESCRIPTION
    Setup and management script for Google Antigravity ACP Server, OAuth authentication,
    transparent tool bridge (Read slice & Edit diff), and Paseo integration on Windows.
.EXAMPLE
    .\setup.ps1
    .\setup.ps1 paseo
    .\setup.ps1 status
    .\setup.ps1 auth
    .\setup.ps1 install
    .\setup.ps1 check-agy
#>

param(
    [Parameter(Position=0, ValueFromRemainingArguments=$true)]
    [string[]]$Arguments = @("setup")
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Locate Python 3.10+
$PythonCmd = $null
$CandidatePythons = @(
    "python",
    "py",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python310\python.exe"
)

foreach ($c in $CandidatePythons) {
    if (Get-Command $c -ErrorAction SilentlyContinue) {
        $PythonCmd = $c
        break
    }
    if (Test-Path $c) {
        $PythonCmd = $c
        break
    }
}

$env:PYTHONIOENCODING = "utf-8"
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
} catch {}

if (-not $PythonCmd) {
    Write-Error "Python 3 is required but not found. Please install Python 3.10+ from python.org or Microsoft Store."
    exit 1
}

$ScriptPath = Join-Path $ScriptDir "agy_acp.py"
& $PythonCmd $ScriptPath @Arguments
exit $LASTEXITCODE

