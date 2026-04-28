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

function Test-Hex64 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value -match '^[0-9a-fA-F]{64}$'
}

function Protect-PathAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        return
    }

    if ((Get-Item -Path $Path).PSIsContainer) {
        & icacls.exe $Path /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    }
    else {
        & icacls.exe $Path /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
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
Protect-PathAcl -Path $StateDir

$stateConfigPath = Join-Path $StateDir "dwell-agent.toml"
if ($ConfigPath) {
    $resolvedConfigPath = (Resolve-Path -Path $ConfigPath).Path
    Copy-Item -Path $resolvedConfigPath -Destination $stateConfigPath -Force
}
elseif (-not (Test-Path -Path $stateConfigPath -PathType Leaf)) {
    throw "No config present at '$stateConfigPath'. Pass -ConfigPath or place dwell-agent.toml in StateDir."
}
Protect-PathAcl -Path $stateConfigPath

if ($ProfileKey) {
    if (-not (Test-Hex64 -Value $ProfileKey)) {
        throw "ProfileKey must be a 64-character hex string ([0-9a-fA-F]{64})."
    }
}

$runnerPath = Join-Path $StateDir "run-dwell-agent.ps1"
$runnerContent = @"
`$ErrorActionPreference = 'Stop'
Set-Location -Path '$StateDir'
& '$resolvedExePath'
"@
Set-Content -Path $runnerPath -Value $runnerContent -Encoding UTF8 -Force
Protect-PathAcl -Path $runnerPath

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Service '$ServiceName' already exists. Recreating it..."
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

$binPath = "\"$($PSHOME)\powershell.exe\" -NoProfile -ExecutionPolicy RemoteSigned -File \"$runnerPath\""
& sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= $DisplayName | Out-Null
& sc.exe description $ServiceName "Dwell Agent continuous authentication runtime" | Out-Null

if ($ProfileKey) {
    $serviceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    New-ItemProperty -Path $serviceRegPath -Name "Environment" -PropertyType MultiString -Value @("DWELL_PROFILE_KEY=$ProfileKey") -Force | Out-Null
    Write-Host "Set service-scoped DWELL_PROFILE_KEY in service registry environment."
}

Write-Host "Installed service '$ServiceName'."
Write-Host "State directory: $StateDir"
Write-Host "Runner script: $runnerPath"
Write-Host "Config file: $stateConfigPath"

if ($StartAfterInstall) {
    Start-Service -Name $ServiceName
    Write-Host "Started service '$ServiceName'."
}

Write-Host "Done."
