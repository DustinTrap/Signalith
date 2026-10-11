# Installs Signalith as a Windows service.
# Run in an elevated PowerShell from the folder that contains signalith.exe:
#   .\install.ps1 -OpenSearchUrl http://127.0.0.1:9200
param(
  [string]$OpenSearchUrl = "http://127.0.0.1:9200",
  [string]$Listen = "0.0.0.0:8080",
  [string]$InstallDir = "$env:ProgramFiles\Signalith",
  [string]$ConfigDir = "$env:ProgramData\Signalith"
)
$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir | Out-Null
Copy-Item -Force (Join-Path $PSScriptRoot "signalith.exe") $InstallDir
$exe = Join-Path $InstallDir "signalith.exe"
$config = Join-Path $ConfigDir "signalith.yaml"

if (-not (Test-Path $config)) {
  & $exe init -c $config -listen $Listen -opensearch $OpenSearchUrl
}
# Only Administrators and SYSTEM may read the config (it holds the ingest token).
icacls $ConfigDir /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null

& $exe validate -c $config
& $exe service install -c $config
& $exe service start
New-NetFirewallRule -DisplayName "Signalith" -Direction Inbound -Protocol TCP -LocalPort ($Listen.Split(":")[-1]) -Action Allow -ErrorAction SilentlyContinue | Out-Null
Write-Host "Signalith is running. Open http://localhost:$($Listen.Split(':')[-1])"
