<#
.SYNOPSIS
Master Orchestrator for the Antigravity-ElevatedExecution Programmatic Non-Elevated Verification Suite.
Runs Areas 1-6 across Tiers 1-4 in either -SelfTest mode or -RepoRoot integration mode.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [switch]$SelfTest,
    [string]$AgyNodePath = (Join-Path $env:APPDATA 'Antigravity\bin\agy-node.cmd'),
    [string]$JsonReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$overallSw = [System.Diagnostics.Stopwatch]::StartNew()

if ($RepoRoot) {
    if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
        Write-Error "RepoRoot directory does not exist: $RepoRoot"
        exit 1
    }
    $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
}

if (-not (Test-Path -LiteralPath $AgyNodePath -PathType Leaf)) {
    Write-Error "agy-node.cmd not found at: $AgyNodePath"
    exit 1
}

$loaderPath = Join-Path $HOME '.gemini\antigravity\lib\node_modules\sidecar_sdk\register_loader.js'
if (-not (Test-Path -LiteralPath $loaderPath -PathType Leaf)) {
    Write-Error "sidecar_sdk register_loader.js not found at: $loaderPath"
    exit 1
}
$loaderUrl = ([System.Uri]::new($loaderPath)).AbsoluteUri

$modeLabel = if ($RepoRoot) { "Repository Integration + Full Suite ($RepoRoot)" } else { 'Self-Test / Fixture Mode' }
Write-Host '========================================================================'
Write-Host "Antigravity-ElevatedExecution Programmatic Verification Suite"
Write-Host "Mode      : $modeLabel"
Write-Host "PSVersion : $($PSVersionTable.PSVersion)"
Write-Host "NodeCmd   : $AgyNodePath"
Write-Host "SuiteRoot : $PSScriptRoot"
Write-Host '========================================================================'

$tempReportDir = Join-Path $env:TEMP ("ae-suite-rep-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempReportDir -Force | Out-Null

$allResults = New-Object 'System.Collections.Generic.List[object]'
$moduleStatuses = New-Object 'System.Collections.Generic.List[object]'

try {
    $psModules = @(
        'Test-EncodingAndSyntax.ps1',
        'Test-ManifestAndSecurity.ps1',
        'Test-CliAndSubsystem.ps1',
        'Test-Decoder.ps1',
        'Test-CrossFeatureAndWorkloads.ps1'
    )

    foreach ($mod in $psModules) {
        $modPath = Join-Path $PSScriptRoot $mod
        if (-not (Test-Path -LiteralPath $modPath -PathType Leaf)) {
            throw "Missing test module: $modPath"
        }
        $repFile = Join-Path $tempReportDir ($mod + '.json')
        Write-Host ""
        Write-Host ">>> Running $mod ..."

        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $modPath, '-AgyNodePath', $AgyNodePath, '-JsonReport', $repFile)
        if ($SelfTest -or -not $RepoRoot) { $argList += '-SelfTest' }
        if ($RepoRoot) { $argList += @('-RepoRoot', $RepoRoot) }

        & powershell.exe @argList
        $exitCode = $LASTEXITCODE
        $modData = $null
        if (Test-Path -LiteralPath $repFile -PathType Leaf) {
            $modData = (Get-Content -LiteralPath $repFile -Raw -Encoding UTF8) | ConvertFrom-Json
            foreach ($r in $modData.results) {
                $allResults.Add($r) | Out-Null
            }
        }
        $moduleStatuses.Add([pscustomobject]@{
            module   = $mod
            exitCode = $exitCode
            total    = if ($modData) { [int]$modData.summary.total } else { 0 }
            passed   = if ($modData) { [int]$modData.summary.passed } else { 0 }
            failed   = if ($modData) { [int]$modData.summary.failed } else { 1 }
        }) | Out-Null
    }

    # Run Node ESM Area 5 suite (Test-BrokerIpc.mjs)
    $mjsPath = Join-Path $PSScriptRoot 'Test-BrokerIpc.mjs'
    if (-not (Test-Path -LiteralPath $mjsPath -PathType Leaf)) {
        throw "Missing test module: $mjsPath"
    }
    $mjsRepFile = Join-Path $tempReportDir 'Test-BrokerIpc.mjs.json'
    Write-Host ""
    Write-Host ">>> Running Test-BrokerIpc.mjs ..."

    $nodeArgs = @("--import=$loaderUrl", $mjsPath, '--json-report', $mjsRepFile)
    if ($SelfTest -or -not $RepoRoot) { $nodeArgs += '--self-test' }
    if ($RepoRoot) { $nodeArgs += @('--repo-root', $RepoRoot) }

    & $AgyNodePath @nodeArgs
    $nodeExit = $LASTEXITCODE
    $nodeData = $null
    if (Test-Path -LiteralPath $mjsRepFile -PathType Leaf) {
        $nodeData = (Get-Content -LiteralPath $mjsRepFile -Raw -Encoding UTF8) | ConvertFrom-Json
        foreach ($r in $nodeData.results) {
            $allResults.Add($r) | Out-Null
        }
    }
    $moduleStatuses.Add([pscustomobject]@{
        module   = 'Test-BrokerIpc.mjs'
        exitCode = $nodeExit
        total    = if ($nodeData) { [int]$nodeData.summary.total } else { 0 }
        passed   = if ($nodeData) { [int]$nodeData.summary.passed } else { 0 }
        failed   = if ($nodeData) { [int]$nodeData.summary.failed } else { 1 }
    }) | Out-Null
}
finally {
    if (Test-Path -LiteralPath $tempReportDir) {
        Remove-Item -LiteralPath $tempReportDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$overallSw.Stop()

# Summaries per Area & Tier
$areaSummary = @()
foreach ($grp in ($allResults | Group-Object area | Sort-Object Name)) {
    $p = @($grp.Group | Where-Object { $_.passed }).Count
    $f = $grp.Count - $p
    $areaSummary += [pscustomobject]@{ area = $grp.Name; total = $grp.Count; passed = $p; failed = $f }
}

$tierSummary = @()
foreach ($t in @(1, 2, 3, 4)) {
    $items = @($allResults | Where-Object { [int]$_.tier -eq $t })
    $p = @($items | Where-Object { $_.passed }).Count
    $f = $items.Count - $p
    $tierSummary += [pscustomobject]@{ tier = $t; total = $items.Count; passed = $p; failed = $f }
}

$totalTests = $allResults.Count
$totalPassed = @($allResults | Where-Object { $_.passed }).Count
$totalFailed = $totalTests - $totalPassed
$badModules = @($moduleStatuses | Where-Object { $_.exitCode -ne 0 -or $_.failed -gt 0 })

$t1Count = ($tierSummary | Where-Object { $_.tier -eq 1 }).total
$t2Count = ($tierSummary | Where-Object { $_.tier -eq 2 }).total
$t3Count = ($tierSummary | Where-Object { $_.tier -eq 3 }).total
$t4Count = ($tierSummary | Where-Object { $_.tier -eq 4 }).total
$thresholdsMet = ($t1Count -ge 30 -and $t2Count -ge 30 -and $t3Count -ge 6 -and $t4Count -ge 6 -and $totalTests -ge 72)

Write-Host ""
Write-Host '========================================================================'
Write-Host 'PER-AREA SUMMARY'
foreach ($a in $areaSummary) {
    Write-Host ("  Area {0,-13}: {1}/{2} passed ({3} failed)" -f $a.area, $a.passed, $a.total, $a.failed)
}
Write-Host 'PER-TIER SUMMARY'
foreach ($ts in $tierSummary) {
    Write-Host ("  Tier {0,-13}: {1}/{2} passed ({3} failed)" -f $ts.tier, $ts.passed, $ts.total, $ts.failed)
}
Write-Host 'MODULE EXIT STATUS'
foreach ($ms in $moduleStatuses) {
    Write-Host ("  {0,-32} exit={1} ({2}/{3} passed)" -f $ms.module, $ms.exitCode, $ms.passed, $ms.total)
}
Write-Host '------------------------------------------------------------------------'
Write-Host ("TOTAL: {0}/{1} passed ({2} failed) | ThresholdsMet={3} | Elapsed={4} ms" -f $totalPassed, $totalTests, $totalFailed, $thresholdsMet, $overallSw.ElapsedMilliseconds)
Write-Host '========================================================================'

if ($JsonReport) {
    $reportDir = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($JsonReport))
    if ($reportDir -and -not (Test-Path -LiteralPath $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    $fullReport = [pscustomobject]@{
        mode          = $modeLabel
        repoRoot      = $RepoRoot
        psVersion     = $PSVersionTable.PSVersion.ToString()
        elapsedMs     = $overallSw.ElapsedMilliseconds
        thresholdsMet = $thresholdsMet
        totals        = [pscustomobject]@{ total = $totalTests; passed = $totalPassed; failed = $totalFailed }
        byArea        = $areaSummary
        byTier        = $tierSummary
        modules       = $moduleStatuses
        results       = $allResults
    }
    $utf8NoBomOut = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($JsonReport, ($fullReport | ConvertTo-Json -Depth 7), $utf8NoBomOut)
    Write-Host "Wrote JSON report: $JsonReport"
}

if ($totalFailed -gt 0 -or $badModules.Count -gt 0 -or -not $thresholdsMet) {
    exit 1
}
exit 0
