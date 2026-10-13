# Checks deploy\windows\install.ps1 without installing anything: that it
# parses, and that New-PrivateFolder makes a folder owned by
# Administrators that only SYSTEM and Administrators may use, with no
# entries inherited from the folder above. Run it with both Windows
# PowerShell and PowerShell 7 (the folder is made a different way in each).
$ErrorActionPreference = "Stop"
$script = Join-Path $PSScriptRoot "..\..\deploy\windows\install.ps1"
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $script), [ref]$tokens, [ref]$errors)
if ($errors) { $errors | Format-List; exit 1 }

$fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq "New-PrivateFolder" }, $true)
if (-not $fn) { throw "install.ps1 has no New-PrivateFolder" }
$system = "S-1-5-18"
$admins = "S-1-5-32-544"
. ([scriptblock]::Create($fn.Extent.Text))

$dir = Join-Path ([IO.Path]::GetTempPath()) ("signalith-check-" + [guid]::NewGuid())
New-PrivateFolder (Join-Path $dir "ProgramData\Signalith")
$acl = Get-Acl -LiteralPath (Join-Path $dir "ProgramData\Signalith")
$owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if ($owner -ne $admins) { throw "owner is $owner, want Administrators" }
if (-not $acl.AreAccessRulesProtected) { throw "the folder inherits entries from the folder above" }
$sids = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
if (($sids -join ",") -ne "S-1-5-18,S-1-5-32-544") { throw "entries for $($sids -join ', '), want only SYSTEM and Administrators" }
Remove-Item -Recurse -Force $dir
Write-Host "install.ps1 parses, and New-PrivateFolder makes a private folder ($($PSVersionTable.PSEdition))."
