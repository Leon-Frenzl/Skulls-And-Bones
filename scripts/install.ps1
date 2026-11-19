# Skulls & Bones — One-Command Windows Client Installer
# Usage (from GitHub Release):
#   irm https://raw.githubusercontent.com/Leon-Frenzl/Skulls-And-Bones/main/scripts/install.ps1 | iex
# Usage (from local build):
#   .\scripts\install.ps1 -LocalDir .\target\release
param(
    [string]$Version = "v0.2.3",
    [string]$Repo = "Leon-Frenzl/Skulls-And-Bones",
    [string]$InstallDir = "",
    [string]$LocalDir = "",
    [switch]$SystemWide
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$useSystemWide = $SystemWide -or $isAdmin

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if ($useSystemWide) {
        $InstallDir = Join-Path $env:ProgramFiles "SkullsAndBones\bin"
    } else {
        $InstallDir = Join-Path $env:LOCALAPPDATA "SkullsAndBones\bin"
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

if (-not [string]::IsNullOrWhiteSpace($LocalDir)) {
    Write-Host "==> Installiere lokale Binaries aus $LocalDir nach $InstallDir ..." -ForegroundColor Cyan
    Copy-Item -Path (Join-Path $LocalDir "sb.exe") -Destination (Join-Path $InstallDir "sb.exe") -Force
    $nodeSrc = Join-Path $LocalDir "sb-node.exe"
    if (Test-Path $nodeSrc) {
        try {
            Copy-Item -Path $nodeSrc -Destination (Join-Path $InstallDir "sb-node.exe") -Force
        } catch {
            Write-Warning "sb-node.exe wird gerade verwendet (z. B. vom Service); bitte bei Bedarf Dienst kurz stoppen."
        }
    }
    $dllSrc = Join-Path $LocalDir "sb_cred_provider.dll"
    if (Test-Path $dllSrc) {
        Copy-Item -Path $dllSrc -Destination (Join-Path $InstallDir "sb_cred_provider.dll") -Force -ErrorAction SilentlyContinue
    }
} else {
    $zipName = "sb-$Version-windows-x86_64.zip"
    $url = "https://github.com/$Repo/releases/download/$Version/$zipName"
    $tmpZip = Join-Path $env:TEMP $zipName
    Write-Host "==> Lade $url ..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $url -OutFile $tmpZip -UseBasicParsing
    Expand-Archive -Path $tmpZip -DestinationPath $InstallDir -Force
    Remove-Item -Force -ErrorAction SilentlyContinue $tmpZip
}

$scope = if ($useSystemWide) { "Machine" } else { "User" }
$currentPath = [Environment]::GetEnvironmentVariable("Path", $scope)
$entries = ($currentPath -split ";") | Where-Object { $_ -ne "" }
if ($entries -notcontains $InstallDir) {
    $newPath = ($entries + $InstallDir) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
    Write-Host "==> $InstallDir dauerhaft zu $scope-PATH hinzugefügt." -ForegroundColor Green
}

if (($env:Path -split ";") -notcontains $InstallDir) {
    $env:Path = "$InstallDir;$env:Path"
}

Write-Host ""
Write-Host "✓ Skulls & Bones CLI installiert: $InstallDir" -ForegroundColor Green
& (Join-Path $InstallDir "sb.exe") --version
Write-Host "  Beispiel: sb join corp.example.sb --dc https://console.example.org --username sb.admin" -ForegroundColor DarkGray
