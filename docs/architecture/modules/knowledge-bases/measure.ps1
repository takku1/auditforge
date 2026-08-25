# Primary metric: framework_catalogs_present (higher = better; target >= 12).
# Counts distinct framework families resolvable from local sources:
# families registered in metadata + control-key prefixes actually indexed.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
while ($root -and -not (Test-Path (Join-Path $root '.git'))) { $root = Split-Path $root -Parent }
$meta = Join-Path $root 'scripts/framework_metadata.json'

if (-not (Test-Path $meta)) {
    @{ metric = 'framework_catalogs_present'; value = 0; direction = 'higher'; target = 12 } |
        ConvertTo-Json -Compress | Write-Output
    exit 0
}

$data = Get-Content $meta -Raw | ConvertFrom-Json
$families = @()
if ($data.frameworks) { $families += ($data.frameworks.PSObject.Properties.Name) }
$prefixes = $data.controls.PSObject.Properties.Name |
    ForEach-Object { ($_ -split ':')[0] } | Sort-Object -Unique
$families += $prefixes
$value = ($families | Sort-Object -Unique).Count

@{ metric = 'framework_catalogs_present'; value = $value; direction = 'higher'; target = 12 } |
    ConvertTo-Json -Compress | Write-Output
