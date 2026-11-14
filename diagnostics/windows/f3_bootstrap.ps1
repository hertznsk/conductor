# Bootstrap only the ordinary reporter; pytest owns test outcomes and process status.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Run')]
    [string]$Phase
)

$ErrorActionPreference = 'Stop'
$root = Join-Path $env:RUNNER_TEMP 'windows-preflight-reporting'

switch ($Phase) {
    'Prepare' {
        try {
            New-Item -ItemType Directory -Path "$root/records" -Force | Out-Null
            $env:GIT_MASTER = '1'
            $head = git rev-parse HEAD
            if ($LASTEXITCODE -ne 0 -or $head -ne $env:GITHUB_SHA) {
                throw 'F3_REPORT_INCOMPLETE: reporting service checkout identity mismatch.'
            }
            Copy-Item "$PSScriptRoot/f3_report.py" "$root/f3_report.py"
            Copy-Item "$PSScriptRoot/f3_bootstrap.ps1" "$root/f3_bootstrap.ps1"
        } catch {
            Write-Warning 'F3_REPORT_INCOMPLETE: reporter setup failed; baseline pytest still runs.'
            throw
        }
    }
    'Run' {
        $env:PYTHONPATH = $root
        $env:F3_REPORT_DIR = Join-Path $root 'records'
        uv run pytest -p no:cacheprovider -n 2 --dist loadfile --cov=src/conductor --cov-report=xml --cov-report=term-missing -m "not real_api and not install_scripts and not performance and not docker_integration" -p f3_report
        exit $LASTEXITCODE
    }
}
