# Installs Signalith as a Windows service.
# Run in an elevated PowerShell from the folder that contains signalith.exe:
#   .\install.ps1 -OpenSearchUrl http://127.0.0.1:9200
# A new config receives syslog on UDP and TCP 514; pass -SyslogUdp "" and
# -SyslogTcp "" to leave it off, or other addresses such as 0.0.0.0:1514.
# The firewall rules for syslog admit only the syslog.allow senders when the
# config lists any.
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

# Open the syslog ports the config turns on (syslog.udp, syslog.tcp,
# syslog.tls), only to the senders in syslog.allow when it lists any.
# signalith reads the config itself, so every YAML style works.
$ports = @(& $exe validate -c $config -syslog-ports)
if ($LASTEXITCODE -ne 0) {
  Write-Warning "Could not read the syslog settings in $config, so no firewall rules for syslog were added. Fix the config, then run this script again."
} else {
  foreach ($line in $ports) {
    $kind, $port, $allow = $line -split ' '
    if (-not $port) { continue }
    $protocol = if ($kind -eq "udp") { "UDP" } else { "TCP" }
    $name = "Signalith syslog $($kind.ToUpper()) $port"
    $rule = @{ DisplayName = $name; Direction = "Inbound"; Protocol = $protocol; LocalPort = $port; Action = "Allow" }
    $from = "any sender"
    if ($allow -and $allow -ne "any") {
      $rule.RemoteAddress = $allow -split ','
      $from = $allow -replace ',', ', '
    }
    Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    New-NetFirewallRule @rule -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Syslog: receiving on $protocol port $port ($kind) from $from."
  }
}
Write-Host "Signalith is running. Open http://localhost:$($Listen.Split(':')[-1])"
# Retention settings saved in the web UI go to $ConfigDir\lookups, and days
# archived before deletion to $ConfigDir\archive (retention.archive_dir in
# signalith.yaml moves them). The lookups folder inherits the Administrators
# and SYSTEM only permissions above. The server gives the archive folder,
# wherever it is, its own access list: SYSTEM, Administrators and the service
# account only, not inherited from the drive.
