# Correctness backpressure for workspace-hygiene.
# 1. root repo exists and tracks only owned paths
# 2. .gitignore denies every clone dir + reports/ + caches + .env
# 3. every third-party import in scripts/*.py is declared in requirements.txt
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
while ($root -and -not (Test-Path (Join-Path $root '.git'))) { $root = Split-Path $root -Parent }
$fail = 0

if (-not (Test-Path (Join-Path $root '.git'))) { Write-Host 'MISS .git repo'; $fail++ }

$ignore = Get-Content (Join-Path $root '.gitignore') -Raw
$cloneDirs = @('asvs', 'attack-stix-data', 'comp-ai', 'compliance-as-code', 'comply',
    'gdpr-checklist', 'juice-shop', 'jupiterone-policies', 'nist-csf',
    'opengrc', 'oscal-content', 'owasp-top10', 'probo',
    'secure-controls-framework', 'security-templates',
    'fedramp-rules', 'mitre-saf-cis')
foreach ($d in $cloneDirs) {
    if ($ignore -notmatch [regex]::Escape("$d/")) { Write-Host "MISS .gitignore rule: $d/"; $fail++ }
}
foreach ($pat in @('reports/', '__pycache__/', '.env')) {
    if ($ignore -notmatch [regex]::Escape($pat)) { Write-Host "MISS .gitignore rule: $pat"; $fail++ }
}

$tracked = git -C $root ls-files
$leaks = $tracked | Where-Object { $_ -match "^($(($cloneDirs -join '|'))|reports|graphify-out)/" }
if ($leaks) { Write-Host "FAIL tracked clone/report paths:"; $leaks | ForEach-Object { Write-Host "  $_" }; $fail++ }

$reqs = Get-Content (Join-Path $root 'requirements.txt') | ForEach-Object {
    ($_ -split '[<>=~]')[0].Trim().ToLower() } | Where-Object { $_ }
# dist-name -> import-name aliases for packages whose module differs
$aliases = @{ 'pyyaml' = 'yaml'; 'python-dotenv' = 'dotenv' }
$provided = $reqs | ForEach-Object { @($_, $aliases[$_]) | Where-Object { $_ } }
$local = @(Get-ChildItem (Join-Path $root 'scripts') -Filter '*.py' |
        Select-Object -ExpandProperty BaseName) +
    @(Get-ChildItem (Join-Path $root 'scripts') -Directory |
        Select-Object -ExpandProperty Name)
$stdlib = @('os','json','re','sys','subprocess','argparse','pathlib','typing','unittest',
            'tempfile','shutil','datetime','urllib','contextlib','__future__','hashlib','sqlite3')
$imports = Get-ChildItem (Join-Path $root 'scripts') -Filter '*.py' |
    Get-Content | ForEach-Object {
        if ($_ -match '^\s*(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)') { $Matches[1].ToLower() }
    } | Sort-Object -Unique
foreach ($m in $imports) {
    if ($m -in $stdlib -or $m -in $local) { continue }
    if ($m -notin $provided) { Write-Host "MISS requirement: $m"; $fail++ }
}

exit $(if ($fail -gt 0) { 1 } else { 0 })
