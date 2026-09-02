# AuditForge session updater.
# Pulls every knowledge base to latest (cloning any that are missing),
# regenerates framework metadata, and inventories audit tools.
#
# Usage:
#   pwsh scripts/update_sources.ps1            # full refresh
#   pwsh scripts/update_sources.ps1 -SkipSync  # pulls only
#
# Exit code 0 = every source OK; 1 = at least one source failed.

param(
    [switch]$SkipSync
)

$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent

# Origin registry: name -> git URL (shallow-cloned when missing).
# URLs mirror each clone's recorded `git remote get-url origin`.
$sources = [ordered]@{
    'comply'                    = 'https://github.com/strongdm/comply.git'
    'jupiterone-policies'       = 'https://github.com/JupiterOne/security-policy-templates.git'
    'nist-csf'                  = 'https://github.com/magoo/nist-csf-markdown.git'
    'gdpr-checklist'            = 'https://github.com/privacyradius/gdpr-checklist.git'
    'security-templates'        = 'https://github.com/davila7/claude-code-templates.git'
    'probo'                     = 'https://github.com/getprobo/probo.git'
    'comp-ai'                   = 'https://github.com/trycompai/comp.git'
    'opengrc'                   = 'https://github.com/LeeMangold/OpenGRC.git'
    'oscal-content'             = 'https://github.com/usnistgov/oscal-content.git'
    'attack-stix-data'          = 'https://github.com/mitre-attack/attack-stix-data.git'
    'compliance-as-code'        = 'https://github.com/ComplianceAsCode/content.git'
    'asvs'                      = 'https://github.com/OWASP/ASVS.git'
    'owasp-top10'               = 'https://github.com/OWASP/Top10.git'
    'secure-controls-framework' = 'https://github.com/securecontrolsframework/securecontrolsframework.git'
    'juice-shop'                = 'https://github.com/juice-shop/juice-shop.git'
}

$results = @()
$failed = 0

foreach ($name in $sources.Keys) {
    $url = $sources[$name]
    $dir = Join-Path $root $name

    if (-not (Test-Path (Join-Path $dir '.git'))) {
        if (Test-Path $dir) {
            $results += [pscustomobject]@{ Repo = $name; LastCommit = '-'; Status = 'SKIPPED (exists, not a git repo)' }
            continue
        }
        git clone --depth 1 --single-branch --quiet $url $dir 2>$null
        if ($LASTEXITCODE -eq 0) {
            $last = git -C $dir log -1 --format='%cs' 2>$null
            $results += [pscustomobject]@{ Repo = $name; LastCommit = $last; Status = "cloned from origin" }
        } else {
            $failed++
            $results += [pscustomobject]@{ Repo = $name; LastCommit = '-'; Status = 'CLONE FAILED' }
        }
        continue
    }

    $before = git -C $dir rev-parse --short HEAD 2>$null
    git -C $dir pull --ff-only --quiet 2>$null
    $pullOk = $LASTEXITCODE -eq 0
    $after = git -C $dir rev-parse --short HEAD 2>$null
    $last = git -C $dir log -1 --format='%cs' 2>$null
    if (-not $pullOk) {
        $failed++
        $status = 'PULL FAILED (diverged or offline)'
    } elseif ($before -ne $after) {
        $status = "updated $before -> $after"
    } else {
        $status = 'up to date'
    }
    $results += [pscustomobject]@{ Repo = $name; LastCommit = $last; Status = $status }
}

$results | Format-Table -AutoSize

# Tool inventory (informational; install separately if missing)
$tools = @('checkov', 'semgrep', 'trivy', 'osv-scanner')
$toolRows = foreach ($t in $tools) {
    $cmd = Get-Command $t -ErrorAction SilentlyContinue
    if ($cmd) {
        $ver = (& $t --version 2>$null | Select-Object -First 1)
        [pscustomobject]@{ Tool = $t; Status = "installed $(($ver | Out-String).Trim())" }
    } else {
        [pscustomobject]@{ Tool = $t; Status = 'NOT INSTALLED' }
    }
}
$toolRows | Format-Table -AutoSize

if (-not $SkipSync) {
    Write-Host '--- Regenerating framework metadata ---'
    python (Join-Path $PSScriptRoot 'sync_frameworks.py')
    if ($LASTEXITCODE -ne 0) { $failed++ }
}

if ($failed -gt 0) { exit 1 }
exit 0
