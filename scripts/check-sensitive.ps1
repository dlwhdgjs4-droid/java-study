param(
    [switch]$Staged
)

$ErrorActionPreference = "Stop"

function Add-Finding {
    param(
        [string]$Rule,
        [string]$Path,
        [int]$Line = 0,
        [string]$Preview = ""
    )

    $script:Findings += [pscustomobject]@{
        Rule = $Rule
        Path = $Path
        Line = $Line
        Preview = $Preview
    }
}

$root = (& git rev-parse --show-toplevel 2>$null)
if (-not $root) {
    Write-Error "Not inside a Git repository."
    exit 2
}

Set-Location $root

if ($Staged) {
    $files = & git diff --cached --name-only --diff-filter=ACMR
} else {
    $files = & git ls-files --cached --others --exclude-standard
}

$files = $files | Sort-Object -Unique
$script:Findings = @()

$blockedNamePatterns = @(
    '(^|/)\.env(\..*)?$',
    '(^|/).*\.pem$',
    '(^|/).*\.key$',
    '(^|/).*\.p12$',
    '(^|/).*\.pfx$',
    '(^|/).*\.jks$',
    '(^|/).*\.keystore$',
    '(^|/)id_(rsa|dsa|ed25519)$',
    '(^|/)credentials.*\.json$',
    '(^|/)serviceAccount.*\.json$',
    '(^|/)application-(local|secret)\.(properties|ya?ml)$',
    '(^|/)secrets/',
    '(^|/)config/secrets/'
)

$textExtensions = @(
    '.java', '.kt', '.gradle', '.properties', '.yml', '.yaml', '.xml', '.json',
    '.md', '.txt', '.html', '.css', '.js', '.ts', '.sql', '.sh', '.ps1',
    '.gitignore', '.gitattributes'
)

$secretRules = @(
    @{ Name = 'Private key block'; Pattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----' },
    @{ Name = 'AWS access key'; Pattern = 'AKIA[0-9A-Z]{16}' },
    @{ Name = 'GitHub token'; Pattern = 'gh[pousr]_[A-Za-z0-9_]{20,}' },
    @{ Name = 'GitHub fine-grained token'; Pattern = 'github_pat_[A-Za-z0-9_]{20,}' },
    @{ Name = 'Google API key'; Pattern = 'AIza[0-9A-Za-z\-_]{35}' },
    @{ Name = 'Slack token'; Pattern = 'xox[baprs]-[A-Za-z0-9-]{10,}' },
    @{ Name = 'Bearer token'; Pattern = 'Bearer\s+[A-Za-z0-9\-._~+/]+=*' },
    @{ Name = 'Likely secret assignment'; Pattern = '(?i)\b(api[_-]?key|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|passwd|pwd)\b\s*[:=]\s*[''"]?[A-Za-z0-9_\-./+=]{12,}' }
)

foreach ($file in $files) {
    if (-not $file) {
        continue
    }

    $normalized = $file -replace '\\', '/'

    if ($normalized -eq 'scripts/check-sensitive.ps1') {
        continue
    }

    foreach ($pattern in $blockedNamePatterns) {
        if ($normalized -match $pattern) {
            Add-Finding -Rule "Sensitive filename/path" -Path $file
        }
    }

    $fullPath = Join-Path $root $file
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        continue
    }

    $name = [System.IO.Path]::GetFileName($fullPath)
    $ext = [System.IO.Path]::GetExtension($fullPath)
    $isTextCandidate = ($textExtensions -contains $ext) -or ($textExtensions -contains $name) -or ([string]::IsNullOrWhiteSpace($ext))

    if (-not $isTextCandidate) {
        continue
    }

    $item = Get-Item -LiteralPath $fullPath
    if ($item.Length -gt 1MB) {
        continue
    }

    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $fullPath -ErrorAction Stop) {
        $lineNumber++
        foreach ($rule in $secretRules) {
            if ($line -match $rule.Pattern) {
                $preview = $line.Trim()
                if ($preview.Length -gt 120) {
                    $preview = $preview.Substring(0, 120) + "..."
                }
                Add-Finding -Rule $rule.Name -Path $file -Line $lineNumber -Preview $preview
            }
        }
    }
}

if ($Findings.Count -gt 0) {
    Write-Host "Sensitive information check FAILED." -ForegroundColor Red
    foreach ($finding in $Findings) {
        if ($finding.Line -gt 0) {
            Write-Host ("- [{0}] {1}:{2} {3}" -f $finding.Rule, $finding.Path, $finding.Line, $finding.Preview)
        } else {
            Write-Host ("- [{0}] {1}" -f $finding.Rule, $finding.Path)
        }
    }
    Write-Host ""
    Write-Host "Commit/push blocked. Remove secrets or move them to ignored local files." -ForegroundColor Yellow
    exit 1
}

Write-Host "Sensitive information check passed."
exit 0
