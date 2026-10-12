# Sets up Signalith after the installer copies its files: downloads and
# configures OpenSearch, writes the Signalith config, and installs both as
# Windows services. The installer runs it elevated; it can also be run by
# hand from an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File setup.ps1 -InstallDir "C:\Program Files\Signalith"
#
# The admin password comes from $env:SIGNALITH_ADMIN_PASSWORD so it never
# appears on a command line. Run again to repair; existing settings and data
# are kept. -Uninstall removes the services and keeps the data.
param(
  [Parameter(Mandatory = $true)][string]$InstallDir,
  [string]$OpenSearchUrl = "",   # use an existing OpenSearch instead of installing one
  [string]$OpenSearchZip = "",   # install OpenSearch from this zip instead of downloading it
  [string]$OpenSearchVersion = "2.17.1",
  [int]$Port = 8080,
  [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # Invoke-WebRequest is much faster without the progress bar

$DataDir = Join-Path $env:ProgramData "Signalith"
$Config = Join-Path $DataDir "signalith.yaml"
$Exe = Join-Path $InstallDir "signalith.exe"
$OsHome = Join-Path $InstallDir "opensearch"
$OsService = "signalith-opensearch"
$FirewallRule = "Signalith"

function Step($msg) { Write-Host "==> $msg" }

function Wait-Http($url, $what, $seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 5 | Out-Null
      return
    } catch {
      # 401 means Signalith is up and asking for a sign-in.
      if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { return }
    }
    Start-Sleep -Seconds 3
  }
  throw "$what did not start within $seconds seconds. Check the logs in $DataDir."
}

function Remove-ServiceIfPresent($name) {
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if (-not $svc) { return }
  if ($svc.Status -ne "Stopped") { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue }
  sc.exe delete $name | Out-Null
}

if ($Uninstall) {
  Step "Removing the Signalith and OpenSearch services"
  Remove-ServiceIfPresent "Signalith"
  Remove-ServiceIfPresent $OsService
  Remove-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
  Write-Host "Services removed. Your data and settings are kept in $DataDir; delete that folder to remove them."
  exit 0
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Start-Transcript -Path (Join-Path $DataDir "setup.log") -Append | Out-Null
trap { Write-Host "Setup failed: $_"; Stop-Transcript | Out-Null; exit 1 }

# ---- OpenSearch ----
if ($OpenSearchUrl -eq "") {
  $OpenSearchUrl = "http://127.0.0.1:9200"
  if (-not (Test-Path (Join-Path $OsHome "bin\opensearch.bat"))) {
    $zip = $OpenSearchZip
    if ($zip -eq "") {
      $zip = Join-Path $env:TEMP "opensearch-$OpenSearchVersion-windows-x64.zip"
      $url = "https://artifacts.opensearch.org/releases/bundle/opensearch/$OpenSearchVersion/opensearch-$OpenSearchVersion-windows-x64.zip"
      Step "Downloading OpenSearch $OpenSearchVersion (about 1 GB; this can take several minutes)"
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
    }
    Step "Unpacking OpenSearch"
    $tmp = Join-Path $env:TEMP ("signalith-os-" + [guid]::NewGuid())
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)
    $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
    if (Test-Path $OsHome) { Remove-Item -Recurse -Force $OsHome }
    Move-Item $inner.FullName $OsHome
    Remove-Item -Recurse -Force $tmp
    if ($OpenSearchZip -eq "") { Remove-Item -Force $zip -ErrorAction SilentlyContinue }
  }

  Step "Configuring OpenSearch"
  $osData = Join-Path $DataDir "opensearch\data"
  $osLogs = Join-Path $DataDir "opensearch\logs"
  New-Item -ItemType Directory -Force -Path $osData, $osLogs | Out-Null
  # Only Signalith talks to OpenSearch, so it listens on this machine only.
  @"
# Written by the Signalith installer; changes are replaced on repair.
cluster.name: signalith
node.name: signalith-1
path.data: $($osData -replace '\\', '/')
path.logs: $($osLogs -replace '\\', '/')
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
plugins.security.disabled: true
action.auto_create_index: true
"@ | Set-Content -Encoding ASCII (Join-Path $OsHome "config\opensearch.yml")
  New-Item -ItemType Directory -Force -Path (Join-Path $OsHome "config\jvm.options.d") | Out-Null
  "-Xms1g`r`n-Xmx1g" | Set-Content -Encoding ASCII (Join-Path $OsHome "config\jvm.options.d\signalith.options")

  if (-not (Get-Service -Name $OsService -ErrorAction SilentlyContinue)) {
    Step "Installing the OpenSearch service"
    $env:OPENSEARCH_START_TYPE = "auto"
    $env:SERVICE_DISPLAY_NAME = "Signalith OpenSearch"
    $env:SERVICE_DESCRIPTION = "Event storage for Signalith"
    & (Join-Path $OsHome "bin\opensearch-service.bat") install $OsService
    if ($LASTEXITCODE -ne 0) { throw "Installing the OpenSearch service failed." }
  }
  sc.exe config $OsService start= auto | Out-Null
  Step "Starting OpenSearch"
  Start-Service -Name $OsService
  Wait-Http $OpenSearchUrl "OpenSearch" 300
}

# ---- Signalith ----
if (-not (Test-Path $Config)) {
  Step "Writing $Config"
  $out = & $Exe init -c $Config -listen "0.0.0.0:$Port" -opensearch $OpenSearchUrl
  if ($LASTEXITCODE -ne 0) { throw "signalith init failed: $out" }
  $out | Write-Host
  if (-not $env:SIGNALITH_ADMIN_PASSWORD) {
    # No password was given (a silent install), so init generated one.
    $out | Set-Content -Encoding UTF8 (Join-Path $DataDir "first-login.txt")
  }
}
# Only Administrators and SYSTEM may read the config (it holds the ingest token).
icacls $DataDir /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null

& $Exe validate -c $Config
if ($LASTEXITCODE -ne 0) { throw "The configuration in $Config has errors." }

if (-not (Get-Service -Name "Signalith" -ErrorAction SilentlyContinue)) {
  Step "Installing the Signalith service"
  & $Exe service install -c $Config
  if ($LASTEXITCODE -ne 0) { throw "Installing the Signalith service failed." }
}
if (Get-Service -Name $OsService -ErrorAction SilentlyContinue) {
  sc.exe config Signalith depend= $OsService | Out-Null
}
Step "Starting Signalith"
$svc = Get-Service -Name "Signalith"
if ($svc.Status -eq "Running") { Restart-Service -Name "Signalith" -Force } else { Start-Service -Name "Signalith" }

New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue | Out-Null
Wait-Http "http://127.0.0.1:$Port/api/health" "Signalith" 120
Write-Host "Signalith is running at http://localhost:$Port"
Stop-Transcript | Out-Null
