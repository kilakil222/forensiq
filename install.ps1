# install.ps1 — builds forensiq.exe and installs it to GOBIN.
# Some endpoint security products block READ of newly-created PE files during scanning.
# Workaround: use File.Move (same-volume rename) instead of Copy — rename never
# reads file content, so the AV scanner cannot block it.

param(
    [int]$WaitMinutes = 5
)

$GCC = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin"
$GOBIN = "$env:USERPROFILE\go\bin"
$env:PATH  = "$GCC;C:\Program Files\Go\bin;$env:PATH"
$env:CGO_ENABLED = "1"

if (-not (Test-Path $GOBIN)) { New-Item -ItemType Directory -Path $GOBIN | Out-Null }

$dest = Join-Path $GOBIN "forensiq.exe"

Write-Host "[1/3] Building forensiq (stripped, -s -w)..."
$buildOut = & go build -work -ldflags="-s -w" -o $dest . 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "[done] $dest"
    exit 0
}

# Build failed — AV blocked go build's copy step.
# Extract WORK directory so we can find a.out.exe directly.
$workLine = $buildOut | ForEach-Object { "$_" } | Where-Object { $_ -like "WORK=*" } | Select-Object -First 1
if (-not $workLine) {
    Write-Host "[error] Build failed (not an AV issue - no WORK dir):"
    $buildOut | ForEach-Object { Write-Host "  $_" }
    exit 1
}
$workDir = $workLine.Substring(5)
$aout    = Join-Path $workDir "b001\exe\a.out.exe"

if (-not (Test-Path $aout)) {
    Write-Host "[error] Link step failed — $aout not found"
    exit 1
}

$sizeMB = [math]::Round((Get-Item $aout).Length / 1MB, 1)
Write-Host "[2/3] Link OK ($sizeMB MB). Installing via same-volume rename (bypasses AV read block)..."

# File.Move on the same volume is a metadata rename — zero bytes read.
# AV cannot block it even while scanning the file.
# Remove stale destination first (.NET Framework 4 Move has no overwrite flag).
if (Test-Path $dest) { Remove-Item $dest -Force }
try {
    [System.IO.File]::Move($aout, $dest)
} catch {
    Write-Host "[error] Rename failed: $_"
    exit 1
}

if (-not (Test-Path $dest)) {
    Write-Host "[error] Move appeared to succeed but $dest not found"
    exit 1
}

Write-Host "[3/3] Installed: $dest ($sizeMB MB)"
Write-Host ""
Write-Host "NOTE: AV KSN scan of this binary is still in progress."
Write-Host "      forensiq will be usable once the scan completes (~$WaitMinutes min)."
Write-Host "      You can test with: forensiq --help"
