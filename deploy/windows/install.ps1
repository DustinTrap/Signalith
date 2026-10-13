# Installs or upgrades Signalith as a Windows service.
# Run in an elevated PowerShell from the folder that contains signalith.exe:
#   .\install.ps1 -OpenSearchUrl http://127.0.0.1:9200
# To upgrade, put the new signalith.exe next to this script and run it
# again: it stops the service, replaces the program, keeps the config and
# data, encrypts passwords and keys still stored as plain text, and starts
# the service again.
#
# The service runs as its own account, NT SERVICE\Signalith, which may
# change files only in the config folder (and in data folders set in
# signalith.yaml). Only SYSTEM, Administrators and that account can read
# the config folder, since it holds the master key, the encrypted
# passwords and keys, and the key of the HTTPS certificate. It is also the
# state folder, where the server keeps its identity among the servers that
# share one OpenSearch (node.id, and cluster\lock while it runs).
#
# A new config serves the web UI over HTTPS with a certificate Signalith
# makes for itself, and receives syslog on UDP and TCP 514 and over TLS on
# 6514; pass -SyslogUdp "", -SyslogTcp "" or -SyslogTls "" to leave one
# off, or other addresses such as 0.0.0.0:1514.
# The firewall rules for syslog admit only the syslog.allow senders when the
# config lists any.
param(
  [string]$OpenSearchUrl = "http://127.0.0.1:9200",
  [string]$Listen = "0.0.0.0:8080",
  [string]$SyslogUdp = "0.0.0.0:514",
  [string]$SyslogTcp = "0.0.0.0:514",
  [string]$SyslogTls = "0.0.0.0:6514",
  [string]$InstallDir = "$env:ProgramFiles\Signalith",
  [string]$ConfigDir = "$env:ProgramData\Signalith"
)
$ErrorActionPreference = "Stop"

$system = "S-1-5-18"
$admins = "S-1-5-32-544"
$users = "S-1-5-32-545"
# NT SERVICE\Signalith is S-1-5-80- and the SHA-1 of the upper-case service
# name in UTF-16, as Windows works it out, so it is known before the
# service exists and folders can be prepared for it first.
$hash = [Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::Unicode.GetBytes("SIGNALITH"))
$serviceSid = "S-1-5-80-" + ((0..4 | ForEach-Object { [BitConverter]::ToUInt32($hash, $_ * 4) }) -join "-")
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Invoke-Checked runs a program and stops the script if it fails.
function Invoke-Checked {
  param([string]$What, [scriptblock]$Command)
  & $Command
  if ($LASTEXITCODE -ne 0) { throw "$What failed (exit code $LASTEXITCODE). Nothing after it was done; fix the problem and run this script again." }
}

# A running service is stopped first, so its program can be replaced.
$existing = Get-Service -Name Signalith -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne "Stopped") {
  Write-Host "Stopping the Signalith service to upgrade it..."
  # A stop may take up to 90 seconds: the background jobs finish their
  # current step and are handed to another server first.
  Stop-Service -Name Signalith -Force
  $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(120))
}

New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir | Out-Null
$exe = Join-Path $InstallDir "signalith.exe"
$config = Join-Path $ConfigDir "signalith.yaml"

# Any user may create folders in ProgramData, so a config folder or file
# that someone else made first could hold settings of theirs. They are
# used only when SYSTEM, Administrators, you or the service own them.
foreach ($path in @($ConfigDir, $config)) {
  if (-not (Test-Path -LiteralPath $path)) { continue }
  $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value
  if (@($system, $admins, $me, $serviceSid) -notcontains $owner) {
    $name = $owner
    try { $name = ([Security.Principal.SecurityIdentifier]$owner).Translate([Security.Principal.NTAccount]).Value } catch { }
    throw "$path belongs to $name, not to an administrator, so it may not be what you expect. Check what is in it; if it is yours, make Administrators its owner (icacls `"$path`" /setowner *$admins /T) and run this script again."
  }
}

# Outside Program Files only administrators may change the program, since
# the service runs whatever signalith.exe is there.
if (-not $InstallDir.StartsWith($env:ProgramFiles, [StringComparison]::OrdinalIgnoreCase)) {
  Invoke-Checked "Protecting $InstallDir" { icacls $InstallDir /inheritance:r /grant:r "*${system}:(OI)(CI)F" "*${admins}:(OI)(CI)F" "*${users}:(OI)(CI)RX" "*${serviceSid}:(OI)(CI)RX" /Q }
}
Copy-Item -Force (Join-Path $PSScriptRoot "signalith.exe") $InstallDir

if (-not (Test-Path -LiteralPath $config)) {
  # -flag=value keeps an empty value, which PowerShell would otherwise drop.
  Invoke-Checked "signalith init" { & $exe init -c $config -listen $Listen -opensearch $OpenSearchUrl "-syslog-udp=$SyslogUdp" "-syslog-tcp=$SyslogTcp" "-syslog-tls=$SyslogTls" }
} else {
  # An upgrade: passwords and keys an older version kept as plain text are
  # encrypted, without changing anything else in the files.
  & $exe secrets encrypt -c $config
  if ($LASTEXITCODE -ne 0) { Write-Warning "Some passwords or keys could not be encrypted (see above). Check with: signalith secrets status" }
}

# The config folder is owned by Administrators, readable only by SYSTEM and
# Administrators (not inherited from ProgramData, where every user can
# read), and changeable by the service. Everything inside gets that list,
# the state folder's files too: the master key (keys), the HTTPS
# certificate (tls) and this server's identity (node.id, cluster\lock).
Invoke-Checked "Taking ownership of $ConfigDir" { icacls $ConfigDir /setowner "*$admins" /T /C /Q }
Invoke-Checked "Protecting $ConfigDir" { icacls $ConfigDir /inheritance:r /grant:r "*${system}:(OI)(CI)F" "*${admins}:(OI)(CI)F" /Q }
Invoke-Checked "Resetting the permissions inside $ConfigDir" { icacls "$ConfigDir\*" /reset /T /C /Q }
Invoke-Checked "Giving NT SERVICE\Signalith access to $ConfigDir" { icacls $ConfigDir /grant "*${serviceSid}:(OI)(CI)M" /Q }

Invoke-Checked "signalith validate" { & $exe validate -c $config }
# Creates the service, or updates one installed before (older versions ran
# as LocalSystem), to run as NT SERVICE\Signalith and restart after a
# failure. It also gives that account the data folders signalith.yaml
# names outside this folder, such as an archive on another disk, and the
# folder of the Settings page's file, and read access to the certificate
# and key files that signalith.yaml or the Settings page names.
Invoke-Checked "signalith service install" { & $exe service install -c $config }
# Waits until the service runs, and stops here, naming the log, if it
# stops again instead.
Invoke-Checked "signalith service start" { & $exe service start -c $config }
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
Write-Host "Signalith is running. Open https://localhost:$($Listen.Split(':')[-1])"
Write-Host "Your browser warns about the certificate until you trust Signalith's own CA ($ConfigDir\tls\ca.pem); docs\https.md says how."
Write-Host "The master key for the passwords and keys Signalith stores is in $ConfigDir\keys, protected for this computer only."
Write-Host "This server's identity, shown on the Servers page, is in $ConfigDir\node.id; never copy it to another server."
Write-Host "Keep a copy of those passwords and keys, or a key you can move, as docs\encryption.md explains."
# The HTTPS certificate and its CA go to $ConfigDir\tls. Retention settings
# saved in the web UI go to $ConfigDir\lookups, and days archived before
# deletion to $ConfigDir\archive (retention.archive_dir in signalith.yaml
# moves them). Those folders get the permissions above. An archive folder
# elsewhere gets its own access list from the server (SYSTEM,
# Administrators and NT SERVICE\Signalith only).
