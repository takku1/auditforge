# Primary metric: root_stray_artifacts (lower = better; target 0).
# Counts regular files at the workspace root outside the known-good allowlist.
$root = $PSScriptRoot
while ($root -and -not (Test-Path (Join-Path $root '.git'))) { $root = Split-Path $root -Parent }
$allow = @('.env.example', '.gitignore', 'CLAUDE.md', 'GEMINI.md',
           'requirements.txt', 'ROADMAP.md')

$strays = Get-ChildItem $root -File |
    Where-Object { $_.Name -notin $allow } |
    Select-Object -ExpandProperty Name

@{ metric = 'root_stray_artifacts'; value = @($strays).Count; direction = 'lower';
   target = 0; strays = $strays } | ConvertTo-Json -Compress | Write-Output
exit 0
