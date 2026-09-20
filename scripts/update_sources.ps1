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
    'atlas-data'                = 'https://github.com/mitre-atlas/atlas-data.git'
    'd3fend-ontology'           = 'https://github.com/d3fend/d3fend-ontology.git'
    'compliance-as-code'        = 'https://github.com/ComplianceAsCode/content.git'
    'asvs'                      = 'https://github.com/OWASP/ASVS.git'
    'owasp-top10'               = 'https://github.com/OWASP/Top10.git'
    'owasp-api-security'        = 'https://github.com/OWASP/API-Security.git'
    'owasp-mobile-top10'        = 'https://github.com/OWASP/Mobile-Top-10.git'
    'owasp-llm-top10'           = 'https://github.com/OWASP/www-project-top-10-for-large-language-model-applications.git'
    'owasp-mcp-top10'           = 'https://github.com/OWASP/www-project-mcp-top-10.git'
    'owasp-k8s-top10'           = 'https://github.com/OWASP/www-project-kubernetes-top-ten.git'
    'owasp-cicd-top10'          = 'https://github.com/OWASP/www-project-top-10-ci-cd-security-risks.git'
    'owasp-masvs'               = 'https://github.com/OWASP/owasp-masvs.git'
    'secure-controls-framework' = 'https://github.com/securecontrolsframework/securecontrolsframework.git'
    'fedramp-rules'             = 'https://github.com/FedRAMP/rules.git'
    'mitre-saf-cis/aws-foundations-cis-baseline'   = 'https://github.com/mitre/aws-foundations-cis-baseline.git'
    'mitre-saf-cis/azure-foundations-cis-baseline' = 'https://github.com/mitre/azure-foundations-cis-baseline.git'
    'mitre-saf-cis/eks-cis-cluster-baseline'       = 'https://github.com/mitre/eks-cis-cluster-baseline.git'
    'mitre-saf-cis/gcp-cis-benchmark'                = 'https://github.com/mitre/inspec-gcp-cis-benchmark.git'
    'mitre-saf-cis/gke-cis-benchmark'                = 'https://github.com/mitre/inspec-gke-cis-benchmark.git'
    'mitre-saf-cis/rhel8-stig-baseline'              = 'https://github.com/mitre/redhat-enterprise-linux-8-stig-baseline.git'
    'mitre-saf-cis/rhel9-stig-baseline'              = 'https://github.com/mitre/redhat-enterprise-linux-9-stig-baseline.git'
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
        $parent = Split-Path $dir -Parent
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
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

# Direct downloads (no git remote): versioned "latest" URLs refreshed in
# place - skipped when the file already exists, never pinned snapshots.
# CWE/CAPEC are MITRE free downloads (no registration); the AI RMF PDF is
# US public-domain work. All three land under references/ (parsers activate
# only when the files are present) and stay uncommitted like the other
# drop-ins (see .gitignore).
$directDownloads = [ordered]@{
    'references/cwe/cwec_latest.xml.zip'         = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
    'references/capec/capec_latest.xml'          = 'https://capec.mitre.org/data/xml/capec_latest.xml'
    'references/nist-ai-rmf/NIST.AI.100-1.pdf'   = 'https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf'
    'references/c2m2/C2M2-Version-2.1.pdf'          = 'https://www.energy.gov/sites/default/files/2022-06/C2M2%20Version%202.1%20June%202022.pdf'
}

foreach ($rel in $directDownloads.Keys) {
    $url = $directDownloads[$rel]
    $dest = Join-Path $root $rel
    $parent = Split-Path $dest -Parent
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    if (Test-Path $dest) {
        $results += [pscustomobject]@{ Repo = $rel; LastCommit = '-'; Status = 'up to date (direct download present)' }
        continue
    }
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
        $results += [pscustomobject]@{ Repo = $rel; LastCommit = '-'; Status = 'downloaded from origin' }
    } catch {
        $failed++
        $results += [pscustomobject]@{ Repo = $rel; LastCommit = '-'; Status = 'DOWNLOAD FAILED' }
    }
}

$results | Format-Table -AutoSize

# Tool inventory (informational; install separately if missing)
$tools = @('checkov', 'semgrep', 'trivy', 'osv-scanner', 'nuclei', 'scorecard', 'trufflehog')
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
