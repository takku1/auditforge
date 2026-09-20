# Evaluation gate for session-updater.
# Primary metric: updater_success_all_sources (1.0 = every source OK; higher better).
# Runs the real updater (-SkipSync: pulls/clones only, no metadata regen).
$root = $PSScriptRoot
while ($root -and -not (Test-Path (Join-Path $root '.git'))) { $root = Split-Path $root -Parent }
& powershell -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $root 'scripts/update_sources.ps1') -SkipSync *> $null
$code = $LASTEXITCODE

@{ metric = 'updater_success_all_sources'; value = $(if ($code -eq 0) { 1.0 } else { 0.0 }); direction = 'higher'; target = 1.0 } |
    ConvertTo-Json -Compress | Write-Output
exit 0
