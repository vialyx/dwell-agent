param(
    [string]$ServiceName = "dwell-agent",
    [string]$DisplayName = "Dwell Agent",
    [Parameter(Mandatory = $true)]
    [string]$ExePath,
    [string]$StateDir = "C:\ProgramData\dwell-agent",
    [string]$ConfigPath,
    [string]$ProfileKey,
    [switch]$StartAfterInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run from an elevated PowerShell session (Run as Administrator)."
    }
}

Assert-Admin

$resolvedExePath = (Resolve-Path -Path $ExePath).Path
if (-not (Test-Path -Path $resolvedExePath -PathType Leaf)) {
    throw "Executable not found: $resolvedExePath"
}

if (-not $resolvedExePath.ToLowerInvariant().EndsWith(".exe")) {
    throw "ExePath must point to dwell-agent.exe"
}

New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $StateDir "webhook-spool") -Force | Out-Null

$stateConfigPath = Join-Path $StateDir "dwell-agent.toml"
if ($ConfigPath) {
    $resolvedConfigPath = (Resolve-Path -Path $ConfigPath).Path
    Copy-Item -Path $resolvedConfigPath -Destination $stateConfigPath -Force
}
elseif (-not (Test-Path -Path $stateConfigPath -PathType Leaf)) {
    throw "No config present at '$stateConfigPath'. Pass -ConfigPath or place dwell-agent.toml in StateDir."
}

if ($ProfileKey) {
    if ($ProfileKey.Length -ne 64) {
        throw "ProfileKey must be a 64-character hex string."
    }
    [Environment]::SetEnvironmentVariable("DWELL_PROFILE_KEY", $ProfileKey, "Machine")
    Write-Host "Set machine-level DWELL_PROFILE_KEY."
}

$runnerPath = Join-Path $StateDir "run-dwell-agent.ps1"
$runnerContent = @"
`$ErrorActionPreference = 'Stop'
Set-Location -Path '$StateDir'
& '$resolvedExePath'
"@
Set-Content -Path $runnerPath -Value $runnerContent -Encoding UTF8 -Force

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Service '$ServiceName' already exists. Recreating it..."
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

$binPath = "\"$($PSHOME)\powershell.exe\" -NoProfile -ExecutionPolicy Bypass -File \"$runnerPath\""
& sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= $DisplayName | Out-Null
& sc.exe description $ServiceName "Dwell Agent continuous authentication runtime" | Out-Null

Write-Host "Installed service '$ServiceName'."
Write-Host "State directory: $StateDir"
Write-Host "Runner script: $runnerPath"
Write-Host "Config file: $stateConfigPath"

if ($StartAfterInstall) {
    Start-Service -Name $ServiceName
    Write-Host "Started service '$ServiceName'."
}

Write-Host "Done."
