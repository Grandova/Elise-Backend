# ==============================================================================
# Elise - Linux Multi-Architecture Build Script for Windows
# Targets: Linux amd64 (x86_64-unknown-linux-musl) and arm64 (aarch64-unknown-linux-musl)
# ==============================================================================

param (
    [string]$Target = "all" # "amd64", "arm64", or "all"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Elise Linux Multi-Arch Builder ===" -ForegroundColor Cyan

# 1. Check Cargo & Rustup
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $env:PATH = "C:\Users\Yoshino\.cargo\bin;$env:PATH"
}

# 2. Add required rust targets
Write-Host "Ensuring Rust MUSL targets are installed..." -ForegroundColor Yellow
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# 3. Create dist output directory
$DistDir = Join-Path $PSScriptRoot "dist"
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
}

# 4. Check for cargo-zigbuild
if (-not (Get-Command cargo-zigbuild -ErrorAction SilentlyContinue)) {
    Write-Host "cargo-zigbuild not found. Installing cargo-zigbuild..." -ForegroundColor Yellow
    cargo install cargo-zigbuild
}

# 5. Build for Linux amd64
if ($Target -eq "all" -or $Target -eq "amd64") {
    Write-Host "`n>>> Building Elise for Linux amd64 (x86_64-unknown-linux-musl)..." -ForegroundColor Green
    cargo zigbuild --target x86_64-unknown-linux-musl --release
    
    $SrcAmd64 = Join-Path $PSScriptRoot "target\x86_64-unknown-linux-musl\release\elise"
    if (-not (Test-Path $SrcAmd64)) {
        # Check target in alternate cargo target dir if set
        if ($env:CARGO_TARGET_DIR) {
            $SrcAmd64 = Join-Path $env:CARGO_TARGET_DIR "x86_64-unknown-linux-musl\release\elise"
        }
    }
    
    $DstAmd64 = Join-Path $DistDir "elise-linux-amd64"
    Copy-Item -Path $SrcAmd64 -Destination $DstAmd64 -Force
    Write-Host ">>> Built successfully: $DstAmd64" -ForegroundColor Green
}

# 6. Build for Linux arm64
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
