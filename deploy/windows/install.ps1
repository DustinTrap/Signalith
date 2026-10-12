# Installs Signalith as a Windows service.
# Run in an elevated PowerShell from the folder that contains signalith.exe:
#   .\install.ps1 -OpenSearchUrl http://127.0.0.1:9200
# A new config receives syslog on UDP and TCP 514; pass -SyslogUdp "" and
# -SyslogTcp "" to leave it off, or other addresses such as 0.0.0.0:1514.
param(
  [string]$OpenSearchUrl = "http://127.0.0.1:9200",
  [string]$Listen = "0.0.0.0:8080",
  [string]$SyslogUdp = "0.0.0.0:514",
  [string]$SyslogTcp = "0.0.0.0:514",
  [string]$InstallDir = "$env:ProgramFiles\Signalith",
  [string]$ConfigDir = "$env:ProgramData\Signalith"
)
$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir | Out-Null
Copy-Item -Force (Join-Path $PSScriptRoot "signalith.exe") $InstallDir
$exe = Join-Path $InstallDir "signalith.exe"
$config = Join-Path $ConfigDir "signalith.yaml"

if (-not (Test-Path $config)) {
  # -flag=value keeps an empty value, which PowerShell would otherwise drop.
  & $exe init -c $config -listen $Listen -opensearch $OpenSearchUrl "-syslog-udp=$SyslogUdp" "-syslog-tcp=$SyslogTcp"
}
# Only Administrators and SYSTEM may read the config (it holds the ingest token).
icacls $ConfigDir /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null

& $exe validate -c $config
& $exe service install -c $config
& $exe service start
New-NetFirewallRule -DisplayName "Signalith" -Direction Inbound -Protocol TCP -LocalPort ($Listen.Split(":")[-1]) -Action Allow -ErrorAction SilentlyContinue | Out-Null

# Open the syslog ports the config turns on (syslog.udp, syslog.tcp, syslog.tls).
$syslog = @{}
$inSyslog = $false
foreach ($line in Get-Content $config) {
  if ($line -match '^\S') { $inSyslog = $line -match '^syslog:'; continue }
  if ($inSyslog -and $line -match '^\s+(udp|tcp|tls):\s*["'']?([^"''#\s]*)') { $syslog[$Matches[1]] = $Matches[2] }
}
foreach ($kind in "udp", "tcp", "tls") {
  $addr = $syslog[$kind]
  if (-not $addr) { continue }
  $port = $addr.Split(":")[-1]
  $protocol = if ($kind -eq "udp") { "UDP" } else { "TCP" }
  $name = "Signalith syslog $($kind.ToUpper()) $port"
  Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
  New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol $protocol -LocalPort $port -Action Allow -ErrorAction SilentlyContinue | Out-Null
  Write-Host "Syslog: receiving on $protocol port $port ($kind)."
}
Write-Host "Signalith is running. Open http://localhost:$($Listen.Split(':')[-1])"
