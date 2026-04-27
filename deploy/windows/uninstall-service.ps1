param(
    [string]$ServiceName = "dwell-agent",
    [string]$StateDir = "C:\ProgramData\dwell-agent",
    [switch]$RemoveStateDir,
    [switch]$ClearProfileKey
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

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
    }
    & sc.exe delete $ServiceName | Out-Null
    Write-Host "Removed service '$ServiceName'."
}
else {
    Write-Host "Service '$ServiceName' does not exist."
}

if ($ClearProfileKey) {
    [Environment]::SetEnvironmentVariable("DWELL_PROFILE_KEY", $null, "Machine")
    Write-Host "Cleared machine-level DWELL_PROFILE_KEY."
}

if ($RemoveStateDir -and (Test-Path -Path $StateDir)) {
    Remove-Item -Path $StateDir -Recurse -Force
    Write-Host "Removed state directory '$StateDir'."
}

Write-Host "Done."
