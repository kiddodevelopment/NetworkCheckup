# Builds Network Checkup for Windows. Only Go is needed.
# Run from this folder in PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host 'Go is not installed. Install it from https://go.dev/dl/ (Windows .msi), then open a new PowerShell window.' -ForegroundColor Red
    exit 1
}

$arch = (go env GOHOSTARCH)
New-Item -ItemType Directory -Force -Path build\bin | Out-Null
$env:CGO_ENABLED = '0'

Write-Host "Building the desktop app ($arch)... the first build downloads libraries and can take a few minutes."
go build -tags 'desktop,production' -trimpath -ldflags '-w -s -H windowsgui' -o build\bin\NetworkCheckup.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host 'The desktop app build failed. Copy everything above this line and send it to Claude.' -ForegroundColor Red
    exit 1
}

Write-Host 'Building the command-line version...'
go build -trimpath -ldflags '-s -w' -o build\bin\netcheckup-cli.exe .\cmd\netcheckup-cli
if ($LASTEXITCODE -ne 0) {
    Write-Host 'The command-line build failed (the desktop app above is fine).' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Done. Your app is at:' -ForegroundColor Green
Write-Host ('  ' + (Resolve-Path build\bin\NetworkCheckup.exe))
