#Requires -RunAsAdministrator
<#
.SYNOPSIS
  seclab installer for Windows 10 (2004+) / 11: WSL2 distro with Docker Engine + seclab engine + desktop app.

.DESCRIPTION
  The lab engine needs Linux Docker (>= 28), so it runs inside a dedicated WSL2 distro (default name "seclab").
  The Electron app runs on Windows and starts the engine through wsl.exe; WSL2 forwards 127.0.0.1 ports,
  so lab sites and SSH forwards are reachable from Windows as localhost:<port>.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install\install.ps1
  powershell -ExecutionPolicy Bypass -File .\install\install.ps1 -Distro Ubuntu-24.04 -SkipDesktop
#>
param(
    [string]$Distro = "seclab",
    [switch]$SkipDesktop
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

function Invoke-Wsl {
    param([Parameter(Mandatory)][string]$Command)
    & wsl.exe -d $Distro -u root -- bash -lc $Command
    if ($LASTEXITCODE -ne 0) { Fail "WSL command failed ($LASTEXITCODE): $Command" }
}

# wsl.exe writes UTF-16; normalise for parsing
function Get-WslText([string[]]$WslArgs) {
    $out = & wsl.exe @WslArgs 2>$null
    return (($out | Out-String) -replace "`0", "")
}

# ---- 1. WSL itself ---------------------------------------------------------------------------
$build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
if ($build -lt 19041) { Fail "Windows build $build is too old for WSL2 (need 19041+)" }

$status = Get-WslText @("--status")
if (-not $status -or $LASTEXITCODE -ne 0) {
    Say "installing WSL2 (a reboot is required afterwards)"
    & wsl.exe --install --no-distribution
    Write-Host "Reboot Windows, then run this installer again." -ForegroundColor Yellow
    exit 3010
}
& wsl.exe --update | Out-Null
& wsl.exe --set-default-version 2 | Out-Null

# ---- 2. dedicated distro -----------------------------------------------------------------------
$distros = (Get-WslText @("--list", "--quiet")) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if ($distros -notcontains $Distro) {
    Say "installing Ubuntu 24.04 as WSL distro '$Distro'"
    if ($Distro -eq "Ubuntu-24.04") {
        & wsl.exe --install -d Ubuntu-24.04 --no-launch
    } else {
        & wsl.exe --install Ubuntu-24.04 --name $Distro --no-launch
        if ($LASTEXITCODE -ne 0) {
            Fail "this WSL version cannot name distros. Update WSL ('wsl --update') or rerun with -Distro Ubuntu-24.04"
        }
    }
    if ($LASTEXITCODE -ne 0) { Fail "distro installation failed" }
}

# ---- 3. systemd (Docker service) --------------------------------------------------------------
Say "enabling systemd in '$Distro'"
Invoke-Wsl "printf '[boot]\nsystemd=true\n\n[user]\ndefault=root\n' > /etc/wsl.conf"
& wsl.exe --terminate $Distro | Out-Null
Start-Sleep -Seconds 3
Invoke-Wsl "for i in `$(seq 1 30); do [ `"`$(ps -p 1 -o comm=)`" = systemd ] && exit 0; sleep 1; done; exit 1"

# ---- 4. engine inside WSL -------------------------------------------------------------------
$wslRoot = (Get-WslText @("-d", $Distro, "-u", "root", "--", "wslpath", "-a", $Root.Replace('\', '/'))).Trim()
if (-not $wslRoot) { Fail "cannot map $Root into WSL" }
Say "installing Docker + seclab engine inside '$Distro' (downloads Docker and images once)"
Invoke-Wsl "rm -rf /opt/seclab-src && cp -r '$wslRoot' /opt/seclab-src && cd /opt/seclab-src && bash install/install.sh --wsl"

# ---- 5. desktop app ---------------------------------------------------------------------------
[Environment]::SetEnvironmentVariable("SECLAB_WSL_DISTRO", $Distro, "User")
if (-not $SkipDesktop) {
    $setup = Get-ChildItem -Path (Join-Path $Root "dist") -Filter "seclab-setup-*.exe" -ErrorAction SilentlyContinue |
             Sort-Object Name | Select-Object -Last 1
    if ($setup) {
        Say "installing desktop app $($setup.Name)"
        Start-Process -FilePath $setup.FullName -ArgumentList "/S" -Wait
    } else {
        Write-Host "warn: no dist\seclab-setup-*.exe found; build it with 'cd desktop; npm ci; npm run dist:win' or use a release archive." -ForegroundColor Yellow
        Write-Host "      Meanwhile: wsl -d $Distro -- seclab ui   (then open the printed URL)" -ForegroundColor Yellow
    }
}

Invoke-Wsl "seclab lab list"
Say "done. Start 'seclab' from the Start menu. Engine shell: wsl -d $Distro"
