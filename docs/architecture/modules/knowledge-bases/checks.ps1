# Correctness backpressure for knowledge-bases module.
# Fails if any expected catalog artifact is missing locally.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
while ($root -and -not (Test-Path (Join-Path $root '.git'))) { $root = Split-Path $root -Parent }

$required = @(
    'oscal-content/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json',
    'oscal-content/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json',
    'oscal-content/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json',
    'compliance-as-code/controls/hipaa.yml',
    'compliance-as-code/controls/pcidss_4.yml',
    'owasp-top10/osib/export',
    'attack-stix-data/enterprise-attack'
)

$fail = 0
foreach ($rel in $required) {
    if (Test-Path (Join-Path $root $rel)) {
        Write-Host "ok   $rel"
    } else {
        Write-Host "MISS $rel"
        $fail++
    }
}

# ASVS: any non-flat, non-legacy english JSON
$asvs = Get-ChildItem (Join-Path $root 'asvs/5.0/docs_en') -Filter '*_en.json' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '\.(flat|legacy)' }
if ($asvs) { Write-Host "ok   asvs/5.0/docs_en/$($asvs[0].Name)" } else { Write-Host 'MISS asvs json'; $fail++ }

# SCF: any xlsx
$scf = Get-ChildItem (Join-Path $root 'secure-controls-framework') -Filter '*.xlsx' -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($scf) { Write-Host "ok   secure-controls-framework/$($scf.Name)" } else { Write-Host 'MISS scf xlsx'; $fail++ }

exit $(if ($fail -gt 0) { 1 } else { 0 })
