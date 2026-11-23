# Builds Network Checkup for Windows on this PC.
# Needs: Visual Studio C++ build tools, Rust (rustup) and Node.js. No admin rights.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

foreach ($tool in 'cargo', 'npm') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool was not found. Install Rust from https://rustup.rs and Node.js from https://nodejs.org, then open a new PowerShell window."
    }
}

Write-Host 'Installing the Tauri command line tool (first run only)...'
npm ci --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }

Write-Host 'Running unit tests...'
cargo test -p netcheck
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }

Write-Host 'Building the app (the first build takes a few minutes)...'
npx tauri build --bundles nsis
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }

$exe = Join-Path $PSScriptRoot 'target\release\NetworkCheckup.exe'
$setup = Get-ChildItem (Join-Path $PSScriptRoot 'target\release\bundle\nsis') -Filter *.exe | Select-Object -First 1
Write-Host ''
Write-Host "Done. App:       $exe"
if ($setup) { Write-Host "     Installer: $($setup.FullName)" }
