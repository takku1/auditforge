# Correctness backpressure for session-updater (offline checks).
# 1. updater script parses cleanly (no syntax errors)
# 2. origin registry covers every git clone actually present at workspace root
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
while ($root -and -not (Test-Path (Join-Path $root '.git'))) { $root = Split-Path $root -Parent }
$script = Join-Path $root 'scripts/update_sources.ps1'
$fail = 0

$errs = $null
[System.Management.Automation.PSParser]::Tokenize(
    (Get-Content $script -Raw), [ref]$errs) | Out-Null
if ($errs.Count -gt 0) { Write-Host "FAIL parse errors:"; $errs | ForEach-Object { Write-Host "  $($_.Message)" }; $fail++ }

$text = Get-Content $script -Raw
$registered = [regex]::Matches($text, "(?m)^\s+'([^']+)'\s+=") | ForEach-Object { $_.Groups[1].Value }
$actual = Get-ChildItem $root -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName '.git') } |
    Select-Object -ExpandProperty Name

foreach ($a in $actual) {
    if ($a -notin $registered) { Write-Host "MISS registry entry for clone: $a"; $fail++ }
}
if ($registered.Count -lt 14) { Write-Host "FAIL registry too small: $($registered.Count)"; $fail++ }

exit $(if ($fail -gt 0) { 1 } else { 0 })
