# install.ps1 - build entroc on Windows and copy it to a bin directory.
# Prefers gcc/clang (MinGW/LLVM); falls back to MSVC 'cl' if present.
# Usage:  powershell -ExecutionPolicy Bypass -File install.ps1 [-Dest <dir>]
param(
    [string]$Dest = "$env:LOCALAPPDATA\Programs\entroc"
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = Join-Path $here "entroc.c"
$out  = Join-Path $here "entroc.exe"

function Have($name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

if (Have gcc) {
    Write-Host "building with gcc ..."
    & gcc -O2 -std=c99 -Wall -Wextra -o $out $src -lm
} elseif (Have clang) {
    Write-Host "building with clang ..."
    & clang -O2 -std=c99 -Wall -Wextra -o $out $src -lm
} elseif (Have cl) {
    Write-Host "building with MSVC cl ..."
    # MSVC links the CRT math functions automatically; /O2 optimize.
    & cl /O2 /nologo /Fe:$out $src
} else {
    Write-Error "No C compiler found. Install one of: MinGW-w64 gcc, LLVM clang, or MSVC (Build Tools). Then re-run."
    exit 1
}

if (-not (Test-Path $Dest)) { New-Item -ItemType Directory -Force -Path $Dest | Out-Null }
Copy-Item $out (Join-Path $Dest "entroc.exe") -Force
Write-Host "installed entroc to $Dest"
Write-Host "Add it to PATH:  setx PATH `"$env:PATH;$Dest`""
& (Join-Path $Dest "entroc.exe") --version
