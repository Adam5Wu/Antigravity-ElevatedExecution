#Requires -Version 5.1
<#
.SYNOPSIS
    Installs or updates elevated-exec in Antigravity's global plugins directory
    and installs the AgentTooling\Invoke-Elevated.ps1 forwarding shim.

.DESCRIPTION
    By default, copies a complete, self-contained plugin bundle (manifest, README,
    assets, client CLI, skill, and sidecar broker/helper/UI) into
    `$HOME\.gemini\config\plugins\elevated-exec`, stamps `sidecars\broker\sidecar.json`
    (UTF-8 without BOM) with `ELEVATED_EXEC_SYNCED_AT`, and writes the
    `$HOME\Documents\AgentTooling\Invoke-Elevated.ps1` forwarding shim (UTF-8 with BOM).

    Pass `-LinkSource` during active development in a worktree to point `sidecar.json`
    directly at this checkout's `sidecars/broker/main.mjs`.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [Alias('PluginDir')]
    [string]$PluginRoot = (Join-Path $HOME '.gemini\config\plugins\elevated-exec'),

    [Parameter(Mandatory = $false)]
    [string]$AgentToolingDir = (Join-Path $HOME 'Documents\AgentTooling'),

    [Parameter(Mandatory = $false)]
    [switch]$LinkSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$srcRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)).Path
$regDir = [System.IO.Path]::GetFullPath($PluginRoot)
$sameLocation = $srcRoot.TrimEnd('\', '/').Equals($regDir.TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$utf8WithBom = New-Object System.Text.UTF8Encoding($true)

if (-not $sameLocation) {
    $requiredSourceRelPaths = New-Object 'System.Collections.Generic.List[string]'
    $requiredSourceRelPaths.Add('plugin.json') | Out-Null
    $requiredSourceRelPaths.Add('tools\Invoke-Elevated.ps1') | Out-Null
    $requiredSourceRelPaths.Add('skills\elevated-execution\SKILL.md') | Out-Null
    if ($LinkSource) {
        $requiredSourceRelPaths.Add('sidecars\broker\main.mjs') | Out-Null
    }
    else {
        foreach ($f in @('package.json', 'main.mjs', 'broker_helper.ps1', 'index.html', 'styles.css', 'app.js')) {
            $requiredSourceRelPaths.Add("sidecars\broker\$f") | Out-Null
        }
    }
    foreach ($rel in $requiredSourceRelPaths) {
        $fullSrc = Join-Path $srcRoot $rel
        if (-not (Test-Path -LiteralPath $fullSrc -PathType Leaf)) {
            throw "Required plugin source file not found: $fullSrc"
        }
    }

    $dirsToEnsure = @(
        $regDir,
        (Join-Path $regDir 'assets'),
        (Join-Path $regDir 'tools'),
        (Join-Path $regDir 'skills\elevated-execution'),
        (Join-Path $regDir 'sidecars\broker')
    )
    foreach ($d in $dirsToEnsure) {
        if (-not (Test-Path -LiteralPath $d -PathType Container)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }

    Copy-Item -LiteralPath (Join-Path $srcRoot 'plugin.json') -Destination (Join-Path $regDir 'plugin.json') -Force
    if (Test-Path -LiteralPath (Join-Path $srcRoot 'README.md') -PathType Leaf) {
        Copy-Item -LiteralPath (Join-Path $srcRoot 'README.md') -Destination (Join-Path $regDir 'README.md') -Force
    }
    $srcAssetsDir = Join-Path $srcRoot 'assets'
    if (Test-Path -LiteralPath $srcAssetsDir -PathType Container) {
        $destAssetsDir = Join-Path $regDir 'assets'
        Get-ChildItem -LiteralPath $srcAssetsDir -File | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $destAssetsDir $_.Name) -Force
        }
    }
    Copy-Item -LiteralPath (Join-Path $srcRoot 'tools\Invoke-Elevated.ps1') -Destination (Join-Path $regDir 'tools\Invoke-Elevated.ps1') -Force
    Copy-Item -LiteralPath (Join-Path $srcRoot 'skills\elevated-execution\SKILL.md') -Destination (Join-Path $regDir 'skills\elevated-execution\SKILL.md') -Force

    if ($LinkSource) {
        $normSrcRoot = $srcRoot -replace '\\', '/'
        $sidecarArgs = @("$normSrcRoot/sidecars/broker/main.mjs")
        $targetDesc = "$normSrcRoot/sidecars/broker/main.mjs (linked)"
    }
    else {
        foreach ($f in @('package.json', 'main.mjs', 'broker_helper.ps1', 'index.html', 'styles.css', 'app.js')) {
            Copy-Item -LiteralPath (Join-Path $srcRoot "sidecars\broker\$f") -Destination (Join-Path $regDir "sidecars\broker\$f") -Force
        }
        $sidecarArgs = @('main.mjs')
        $targetDesc = (Join-Path $regDir 'sidecars\broker\main.mjs') + ' (self-contained)'
    }

    $srcSidecarPath = Join-Path $srcRoot 'sidecars\broker\sidecar.json'
    $sidecarEnv = [ordered]@{}
    $displayName = 'Elevated Execution'
    $description = 'Interactive two-click UAC elevation broker and Auxiliary Side Pane for Google Antigravity on Windows.'
    $viewTitle = 'Elevated Execution'
    $viewPath = '/'
    $viewEntrypoint = 'SIDECAR_UI_ENTRYPOINT_AUX_PANE'

    if (Test-Path -LiteralPath $srcSidecarPath -PathType Leaf) {
        $srcSidecarJson = [System.IO.File]::ReadAllText($srcSidecarPath, (New-Object System.Text.UTF8Encoding($false, $true)))
        $parsedSidecar = $srcSidecarJson | ConvertFrom-Json
        if ($parsedSidecar) {
            if ($parsedSidecar.PSObject.Properties['display_name'] -and $parsedSidecar.display_name) {
                $displayName = [string]$parsedSidecar.display_name
            }
            if ($parsedSidecar.PSObject.Properties['description'] -and $parsedSidecar.description) {
                $description = [string]$parsedSidecar.description
            }
            if ($parsedSidecar.PSObject.Properties['env'] -and $parsedSidecar.env) {
                foreach ($prop in $parsedSidecar.env.PSObject.Properties) {
                    $sidecarEnv[$prop.Name] = [string]$prop.Value
                }
            }
            if ($parsedSidecar.PSObject.Properties['ui_config'] -and $parsedSidecar.ui_config -and $parsedSidecar.ui_config.PSObject.Properties['views'] -and $null -ne $parsedSidecar.ui_config.views) {
                $viewsArr = @($parsedSidecar.ui_config.views)
                if ($viewsArr.Count -gt 0) {
                    $firstView = $viewsArr[0]
                    if ($firstView) {
                        if ($firstView.PSObject.Properties['path'] -and $firstView.path) { $viewPath = [string]$firstView.path }
                        if ($firstView.PSObject.Properties['entrypoint'] -and $firstView.entrypoint) { $viewEntrypoint = [string]$firstView.entrypoint }
                        if ($firstView.PSObject.Properties['title'] -and $firstView.title) { $viewTitle = [string]$firstView.title }
                    }
                }
            }
        }
    }

    $sidecarEnv['ELEVATED_EXEC_SYNCED_AT'] = [DateTime]::UtcNow.ToString('o')

    $sidecarObj = [ordered]@{
        command        = 'node'
        args           = @($sidecarArgs)
        restart_policy = 'always'
        env            = $sidecarEnv
        display_name   = $displayName
        description    = $description
        has_web_ui     = $true
        ui_config      = [ordered]@{
            display_name = $displayName
            views        = @(
                [ordered]@{
                    path       = $viewPath
                    entrypoint = $viewEntrypoint
                    title      = $viewTitle
                }
            )
        }
    }

    $regSidecarPath = Join-Path $regDir 'sidecars\broker\sidecar.json'
    [System.IO.File]::WriteAllText($regSidecarPath, ($sidecarObj | ConvertTo-Json -Depth 6), $utf8NoBom)
    Write-Host "Registered plugin 'elevated-exec' -> $targetDesc" -ForegroundColor Green
}
else {
    Write-Host "Repository is already located at '$regDir'; skipping bundle copy." -ForegroundColor Green
}

if (-not [string]::IsNullOrWhiteSpace($AgentToolingDir)) {
    $toolingDirFull = [System.IO.Path]::GetFullPath($AgentToolingDir)
    if (-not (Test-Path -LiteralPath $toolingDirFull -PathType Container)) {
        New-Item -ItemType Directory -Path $toolingDirFull -Force | Out-Null
    }

    $targetCliPath = Join-Path $regDir 'tools\Invoke-Elevated.ps1'
    $qTargetCli = $targetCliPath -replace "'", "''"

    $shimLines = @(
        '#Requires -Version 5.1'
        '<#'
        '.SYNOPSIS'
        '    Forwarding shim to the registered elevated-exec Invoke-Elevated.ps1 CLI.'
        '#>'
        "[CmdletBinding(DefaultParameterSetName = 'ScriptBlock')]"
        'param('
        "    [Parameter(Mandatory = `$true, Position = 0, ParameterSetName = 'ScriptBlock')]"
        '    [scriptblock]$ScriptBlock,'
        ''
        "    [Parameter(Mandatory = `$true, ParameterSetName = 'ScriptText')]"
        '    [string]$ScriptText,'
        ''
        "    [Parameter(Mandatory = `$true, ParameterSetName = 'ScriptFile')]"
        '    [string]$ScriptFile,'
        ''
        "    [Parameter(Mandatory = `$true, ParameterSetName = 'FilePath')]"
        '    [string]$FilePath,'
        ''
        "    [Parameter(Mandatory = `$false, ParameterSetName = 'ScriptFile')]"
        "    [Parameter(Mandatory = `$false, ParameterSetName = 'FilePath')]"
        '    [string[]]$ArgumentList = @(),'
        ''
        "    [Parameter(Mandatory = `$true)]"
        '    [string]$Reason,'
        ''
        "    [Parameter(Mandatory = `$false)]"
        '    [string]$WorkDir,'
        ''
        "    [Parameter(Mandatory = `$false)]"
        "    [ValidateSet('auto', 'utf8', 'oem', 'utf16')]"
        "    [string]`$Encoding = 'auto',"
        ''
        "    [Parameter(Mandatory = `$false)]"
        '    [switch]$NormalWindow'
        ')'
        ''
        'Set-StrictMode -Version Latest'
        '$ErrorActionPreference = ''Stop'''
        ''
        "`$targetScript = '$qTargetCli'"
        'if (-not (Test-Path -LiteralPath $targetScript -PathType Leaf)) {'
        '    [Console]::Error.WriteLine("SIDECAR_UNAVAILABLE (1203): Registered CLI not found: $targetScript")'
        '    [Console]::Error.Flush()'
        "    [Console]::Out.WriteLine('[elevated-exec] OUTCOME=SIDECAR_UNAVAILABLE EXIT=1203')"
        '    [Console]::Out.Flush()'
        '    exit 1203'
        '}'
        ''
        '$forwardParams = @{}'
        'foreach ($kv in $PSBoundParameters.GetEnumerator()) {'
        '    $forwardParams[$kv.Key] = $kv.Value'
        '}'
        "if (-not `$forwardParams.ContainsKey('WorkDir')) {"
        "    `$forwardParams['WorkDir'] = (Get-Location).ProviderPath"
        '}'
        ''
        '$global:LASTEXITCODE = 0'
        'try {'
        '    & $targetScript @forwardParams'
        '}'
        'catch {'
        '    [Console]::Error.WriteLine("SIDECAR_UNAVAILABLE (1203): $($_.Exception.Message)")'
        '    [Console]::Error.Flush()'
        "    [Console]::Out.WriteLine('[elevated-exec] OUTCOME=SIDECAR_UNAVAILABLE EXIT=1203')"
        '    [Console]::Out.Flush()'
        '    exit 1203'
        '}'
        '$exitCode = if (Test-Path -LiteralPath ''Variable:\LASTEXITCODE'') { [int]$global:LASTEXITCODE } else { 0 }'
        'exit $exitCode'
    )

    $shimContent = ($shimLines -join "`r`n") + "`r`n"
    $shimPath = Join-Path $toolingDirFull 'Invoke-Elevated.ps1'
    [System.IO.File]::WriteAllText($shimPath, $shimContent, $utf8WithBom)
    Write-Host "Installed forwarding shim -> $shimPath" -ForegroundColor Green
}
