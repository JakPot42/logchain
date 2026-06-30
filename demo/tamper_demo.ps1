<#
.SYNOPSIS
    Full end-to-end demo of logchain tamper detection.

.DESCRIPTION
    Orchestrates the complete demo sequence:
      1. Generate a realistic sample log
      2. Ingest it into the Merkle journal
      3. Verify clean (all entries intact)
      4. Export a signed snapshot
      5. Surgically tamper with a historical journal entry
      6. Verify again - show that logchain catches the tampering

    Run from the repo root:
        .\demo\tamper_demo.ps1
#>

Set-StrictMode -Version Latest

# ── Paths ─────────────────────────────────────────────────────────────────────

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$Binary     = Join-Path $RepoRoot "target\release\logchain.exe"
$DataDir    = Join-Path $RepoRoot "demo\data"
$LogFile    = Join-Path $RepoRoot "demo\sample.log"
$SnapshotFile = Join-Path $RepoRoot "demo\snapshot.json"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Banner($text) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Step($n, $text) {
    Write-Host "[Step $n] $text" -ForegroundColor Yellow
}

function OK($text) {
    Write-Host "  OK  $text" -ForegroundColor Green
}

function ERR($text) {
    Write-Host "  !!  $text" -ForegroundColor Red
}

# ── Pre-flight ────────────────────────────────────────────────────────────────

Banner "logchain - Tamper-Evident Audit Trail Demo"

if (-not (Test-Path $Binary)) {
    ERR "Release binary not found at: $Binary"
    ERR "Run 'cargo build --release' first."
    exit 1
}

# Clean up any prior demo run.
if (Test-Path $DataDir)    { Remove-Item -Recurse -Force $DataDir }
if (Test-Path $LogFile)    { Remove-Item -Force $LogFile }
if (Test-Path $SnapshotFile) { Remove-Item -Force $SnapshotFile }

New-Item -ItemType Directory -Force $DataDir | Out-Null

# ── Step 1: Generate sample log ───────────────────────────────────────────────

Step 1 "Generating sample log file (20 entries)"
py "$PSScriptRoot\generate_log.py" $LogFile
if (-not (Test-Path $LogFile)) {
    ERR "Failed to generate log file."
    exit 1
}
OK "Log file: $LogFile"

Write-Host ""
Write-Host "  First 5 lines of sample.log:" -ForegroundColor DarkGray
Get-Content $LogFile | Select-Object -First 5 | ForEach-Object {
    Write-Host "    $_" -ForegroundColor DarkGray
}
Write-Host "    ..." -ForegroundColor DarkGray
Write-Host ""

# ── Step 2: Ingest into Merkle journal ────────────────────────────────────────

Step 2 "Ingesting log file into Merkle journal"
& $Binary --data-dir $DataDir tail $LogFile --once
if ($LASTEXITCODE -ne 0) { ERR "Ingestion failed."; exit 1 }

# ── Step 3: Show status ───────────────────────────────────────────────────────

Step 3 "Journal status after ingestion"
& $Binary --data-dir $DataDir status

# ── Step 4: Verify clean ──────────────────────────────────────────────────────

Step 4 "Verifying integrity (should be CLEAN)"
& $Binary --data-dir $DataDir verify
if ($LASTEXITCODE -ne 0) { ERR "Unexpected: verify failed on fresh journal."; exit 1 }
OK "Journal is clean - Merkle root matches all entries."

# ── Step 5: Export snapshot ───────────────────────────────────────────────────

Step 5 "Exporting signed Merkle snapshot for archival"
& $Binary --data-dir $DataDir export | Tee-Object -FilePath $SnapshotFile
OK "Snapshot written to: $SnapshotFile"
$Root = (Get-Content $SnapshotFile | ConvertFrom-Json).merkle_root
Write-Host ""
Write-Host "  Archived root: $Root" -ForegroundColor DarkGray

# ── Step 6: Tamper with the journal ──────────────────────────────────────────

Step 6 "Tampering with journal entry seq=7 (simulating a log falsification)"

$JournalFile = Join-Path $DataDir "logchain.journal"
$lines = Get-Content $JournalFile -Encoding utf8

$tampered = $lines | ForEach-Object -Begin { $i = 0 } -Process {
    if ($i -eq 7) {
        $entry = $_ | ConvertFrom-Json
        $entry.raw = "2026-06-30T08:24:59Z INFO  ** FALSIFIED: database timeout entry removed by attacker **"
        $entry | ConvertTo-Json -Compress
    } else {
        $_
    }
    $i++
}

[System.IO.File]::WriteAllLines($JournalFile, $tampered, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "  Original entry #7 (from export snapshot):" -ForegroundColor DarkGray
$snapshotData = Get-Content $SnapshotFile | ConvertFrom-Json
Write-Host "    hash: $($snapshotData.entry_hashes[7].hash)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Tampered raw text:" -ForegroundColor Red
Write-Host "    $($tampered[7] | ConvertFrom-Json | Select-Object -ExpandProperty raw)" -ForegroundColor Red
Write-Host ""

# ── Step 7: Verify again - catch the tampering ────────────────────────────────

Step 7 "Re-verifying integrity - logchain should catch the falsification"
& $Binary --data-dir $DataDir verify
$exitCode = $LASTEXITCODE

Write-Host ""
if ($exitCode -eq 2) {
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host "  DEMO COMPLETE: Tampering detected as expected." -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host ""
    Write-Host "  The SHA-256 of the tampered raw field no longer matches" -ForegroundColor DarkGray
    Write-Host "  the stored hash. Any modification (even a single character)" -ForegroundColor DarkGray
    Write-Host "  is cryptographically visible without comparing full log files." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  To confirm: compare the Merkle root in the archived snapshot" -ForegroundColor DarkGray
    Write-Host "  ($SnapshotFile)" -ForegroundColor DarkGray
    Write-Host "  against the recomputed root shown above - they differ." -ForegroundColor DarkGray
    Write-Host ""
} else {
    ERR "Demo failed: verify should have exited with code 2 (tamper detected)."
    exit 1
}
