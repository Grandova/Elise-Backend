param (
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Elise Linux Multi-Arch Builder ===" -ForegroundColor Cyan

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if (Test-Path $cargoBin) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
}

Write-Host "Ensuring Rust MUSL targets are installed..." -ForegroundColor Yellow
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

$DistDir = Join-Path $PSScriptRoot "dist"
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
}

if (-not (Get-Command cargo-zigbuild -ErrorAction SilentlyContinue)) {
    Write-Host "cargo-zigbuild not found. Installing cargo-zigbuild..." -ForegroundColor Yellow
    cargo install cargo-zigbuild
}

if ($Target -eq "all" -or $Target -eq "amd64") {
    Write-Host "`n>>> Building Elise for Linux amd64 (x86_64-unknown-linux-musl)..." -ForegroundColor Green
    cargo zigbuild --target x86_64-unknown-linux-musl --release
    
    $SrcAmd64 = Join-Path $PSScriptRoot "target\x86_64-unknown-linux-musl\release\elise"
    if (-not (Test-Path $SrcAmd64)) {
        if ($env:CARGO_TARGET_DIR) {
            $SrcAmd64 = Join-Path $env:CARGO_TARGET_DIR "x86_64-unknown-linux-musl\release\elise"
        }
    }
    
    $DstAmd64 = Join-Path $DistDir "elise-linux-amd64"
    Copy-Item -Path $SrcAmd64 -Destination $DstAmd64 -Force
    Write-Host ">>> Built successfully: $DstAmd64" -ForegroundColor Green
}

if ($Target -eq "all" -or $Target -eq "arm64") {
    Write-Host "`n>>> Building Elise for Linux arm64 (aarch64-unknown-linux-musl)..." -ForegroundColor Green
    cargo zigbuild --target aarch64-unknown-linux-musl --release
    
    $SrcArm64 = Join-Path $PSScriptRoot "target\aarch64-unknown-linux-musl\release\elise"
    if (-not (Test-Path $SrcArm64)) {
        if ($env:CARGO_TARGET_DIR) {
            $SrcArm64 = Join-Path $env:CARGO_TARGET_DIR "aarch64-unknown-linux-musl\release\elise"
        }
    }
    
    $DstArm64 = Join-Path $DistDir "elise-linux-arm64"
    Copy-Item -Path $SrcArm64 -Destination $DstArm64 -Force
    Write-Host ">>> Built successfully: $DstArm64" -ForegroundColor Green
}

Write-Host "`n=== Build Completed Successfully! ===" -ForegroundColor Cyan
Get-ChildItem -Path $DistDir | Select-Object Name, Length, LastWriteTime
