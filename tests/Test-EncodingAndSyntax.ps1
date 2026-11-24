<#
.SYNOPSIS
Area 1: Encoding, UTF-8 BOM / No-BOM, Strict UTF-8, JSON, Node --check, and PS 5.1 Syntax Verification.
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

$results = New-Object 'System.Collections.Generic.List[object]'

function Add-TestResult {
    param(
        [string]$Id,
        [string]$Area,
        [int]$Tier,
        [string]$Name,
        [bool]$Passed,
        [string]$Detail,
        [long]$DurationMs
    )
    $results.Add([pscustomobject]@{
        id         = $Id
        area       = $Area
        tier       = $Tier
        name       = $Name
        passed     = $Passed
        detail     = $Detail
        durationMs = $DurationMs
    }) | Out-Null
    $tag = if ($Passed) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1} (Area {2} / Tier {3}) {4} - {5} ({6} ms)" -f $tag, $Id, $Area, $Tier, $Name, $Detail, $DurationMs)
}

function Invoke-TestCase {
    param(
        [string]$Id,
        [string]$Area,
        [int]$Tier,
        [string]$Name,
        [scriptblock]$Body
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $passed = $false
    $detail = ''
    try {
        $detail = & $Body
        if ($null -eq $detail) { $detail = 'OK' }
        $passed = $true
    }
    catch {
        $passed = $false
        $detail = $_.Exception.Message
    }
    finally {
        $sw.Stop()
    }
    Add-TestResult -Id $Id -Area $Area -Tier $Tier -Name $Name -Passed $passed -Detail ([string]$detail) -DurationMs $sw.ElapsedMilliseconds
}

function Test-FileEncodingAndSyntax {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$RequireBom,
        [string]$NodeCmdPath
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "File not found: $Path"
    }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)

    if ($RequireBom -and -not $hasBom) {
        throw "Missing required UTF-8 BOM (EF BB BF): $Path"
    }
    if (-not $RequireBom -and $hasBom) {
        throw "Unexpected UTF-8 BOM (EF BB BF) found: $Path"
    }

    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $offset = if ($hasBom) { 3 } else { 0 }
    $text = $strictUtf8.GetString($bytes, $offset, $bytes.Length - $offset)

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($ext) {
        '.ps1' {
            $tokens = $null
            $parseErrors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
            if ($null -ne $parseErrors -and $parseErrors.Count -gt 0) {
                $msgs = ($parseErrors | ForEach-Object { "L$($_.Extent.StartLineNumber): $($_.Message)" }) -join '; '
                throw "PS 5.1 syntax error(s) in ${Path}: $msgs"
            }
        }
        '.json' {
            try {
                $null = $text | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                throw "Invalid JSON in ${Path}: $($_.Exception.Message)"
            }
        }
        '.mjs' {
            if ($NodeCmdPath -and (Test-Path -LiteralPath $NodeCmdPath -PathType Leaf)) {
                $prevEap = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try {
                    $out = & $NodeCmdPath --check $Path 2>&1
                    $code = $LASTEXITCODE
                }
                finally {
                    $ErrorActionPreference = $prevEap
                }
                if ($code -ne 0) {
                    throw "Node --check failed for ${Path} (exit $code): $($out -join ' ')"
                }
            }
            else {
                throw "Node executable not found for --check: $NodeCmdPath"
            }
        }
        '.js' {
            if ($NodeCmdPath -and (Test-Path -LiteralPath $NodeCmdPath -PathType Leaf)) {
                $prevEap = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try {
                    $out = & $NodeCmdPath --check $Path 2>&1
                    $code = $LASTEXITCODE
                }
                finally {
                    $ErrorActionPreference = $prevEap
                }
                if ($code -ne 0) {
                    throw "Node --check failed for ${Path} (exit $code): $($out -join ' ')"
                }
            }
        }
    }

    return [pscustomobject]@{
        Path   = $Path
        Bytes  = $bytes.Length
        HasBom = $hasBom
        Text   = $text
    }
}

$tempRoot = Join-Path $env:TEMP ("ae-area1-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    # --- TIER 1: Positive Core ---
    Invoke-TestCase -Id 'A1-T1-01' -Area '1' -Tier 1 -Name 'Valid .ps1 with UTF-8 BOM and zh-CN/em-dash/arrow literals' -Body {
        $f = Join-Path $tempRoot 'valid_bom.ps1'
        $src = "# comment — → 状态`r`nWrite-Output '状态/系统/目录/未知/小'`r`n"
        [System.IO.File]::WriteAllText($f, $src, $utf8WithBom)
        $r = Test-FileEncodingAndSyntax -Path $f -RequireBom $true -NodeCmdPath $AgyNodePath
        if (-not $r.HasBom) { throw 'Expected HasBom = true' }
        return "Parsed cleanly with BOM ($($r.Bytes) bytes)"
    }

    Invoke-TestCase -Id 'A1-T1-02' -Area '1' -Tier 1 -Name 'Valid .json without BOM passes strict UTF-8 and ConvertFrom-Json' -Body {
        $f = Join-Path $tempRoot 'valid.json'
        $src = '{"name":"elevated-exec","label":"状态/系统/目录/未知/小","port":12345}'
        [System.IO.File]::WriteAllText($f, $src, $utf8NoBom)
        $r = Test-FileEncodingAndSyntax -Path $f -RequireBom $false -NodeCmdPath $AgyNodePath
        return "JSON valid without BOM ($($r.Bytes) bytes)"
    }

    Invoke-TestCase -Id 'A1-T1-03' -Area '1' -Tier 1 -Name 'Valid .mjs ESM without BOM passes agy-node.cmd --check' -Body {
        $f = Join-Path $tempRoot 'valid.mjs'
        $src = "import path from 'node:path';`nexport const msg = '状态/系统';`n"
        [System.IO.File]::WriteAllText($f, $src, $utf8NoBom)
        $r = Test-FileEncodingAndSyntax -Path $f -RequireBom $false -NodeCmdPath $AgyNodePath
        return "Node --check exit 0 without BOM ($($r.Bytes) bytes)"
    }

    Invoke-TestCase -Id 'A1-T1-04' -Area '1' -Tier 1 -Name 'Valid .js, .html, .css, .md, .svg without BOM pass encoding checks' -Body {
        $fixtures = @{
            'app.js'     = "const title = 'Elevated Execution'; console.log(title);`n"
            'index.html' = "<!doctype html><html><body><h1>状态</h1></body></html>`n"
            'styles.css' = ":root { --accent: #4c8bf5; }`n"
            'README.md'  = "# Elevated Execution — 状态`n"
            'logo.svg'   = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'></svg>`n"
        }
        foreach ($kv in $fixtures.GetEnumerator()) {
            $fp = Join-Path $tempRoot $kv.Key
            [System.IO.File]::WriteAllText($fp, $kv.Value, $utf8NoBom)
            $null = Test-FileEncodingAndSyntax -Path $fp -RequireBom $false -NodeCmdPath $AgyNodePath
        }
        return "Validated $($fixtures.Count) non-PS1 asset types without BOM"
    }

    Invoke-TestCase -Id 'A1-T1-05' -Area '1' -Tier 1 -Name 'Test suite self-compliance scan (tests\ BOM and syntax)' -Body {
        $testFiles = Get-ChildItem -LiteralPath $PSScriptRoot -File | Sort-Object Name
        $ps1Count = 0
        $otherCount = 0
        foreach ($tf in $testFiles) {
            if ($tf.Extension -ieq '.ps1') {
                $null = Test-FileEncodingAndSyntax -Path $tf.FullName -RequireBom $true -NodeCmdPath $AgyNodePath
                $ps1Count++
            }
            elseif ($tf.Extension -in @('.mjs', '.json', '.js', '.html', '.css', '.md', '.svg')) {
                $null = Test-FileEncodingAndSyntax -Path $tf.FullName -RequireBom $false -NodeCmdPath $AgyNodePath
                $otherCount++
            }
        }
        if ($ps1Count -lt 1) { throw "Expected at least 1 .ps1 file in $PSScriptRoot" }
        return "Self-compliant: $ps1Count .ps1 (BOM+PS5.1), $otherCount non-.ps1 (no-BOM)"
    }

    # --- TIER 2: Negative / Boundary / Adversarial ---
    Invoke-TestCase -Id 'A1-T2-01' -Area '1' -Tier 2 -Name 'Reject BOM-less .ps1 with zh-CN literal (catches PS 5.1 CP936 parse failure)' -Body {
        $f = Join-Path $tempRoot 'nobom_zh.ps1'
        $src = "# comment — → 状态`r`nWrite-Output '状态/系统/目录/未知/小'`r`n"
        [System.IO.File]::WriteAllText($f, $src, $utf8NoBom)

        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tokens, [ref]$parseErrors)
        if ($null -eq $parseErrors -or $parseErrors.Count -eq 0) {
            throw 'Expected PS 5.1 Parser to fail on BOM-less UTF-8 zh-CN script under ACP=936'
        }

        $rejectedByValidator = $false
        try {
            $null = Test-FileEncodingAndSyntax -Path $f -RequireBom $true -NodeCmdPath $AgyNodePath
        }
        catch {
            $rejectedByValidator = $true
        }
        if (-not $rejectedByValidator) { throw 'Expected validator to reject BOM-less .ps1' }
        return "Caught PS5.1 parse error ($($parseErrors[0].Message)) and BOM rejection"
    }

    Invoke-TestCase -Id 'A1-T2-02' -Area '1' -Tier 2 -Name 'Reject .ps1 with UTF-8 BOM containing syntax error' -Body {
        $f = Join-Path $tempRoot 'broken_syntax.ps1'
        $src = "function broken { if (`$true) { Write-Host 'unclosed' `r`n"
        [System.IO.File]::WriteAllText($f, $src, $utf8WithBom)
        $threw = $false
        try {
            $null = Test-FileEncodingAndSyntax -Path $f -RequireBom $true -NodeCmdPath $AgyNodePath
        }
        catch {
            $threw = $true
            if ($_.Exception.Message -notmatch 'syntax error') { throw "Unexpected error: $($_.Exception.Message)" }
        }
        if (-not $threw) { throw 'Expected syntax error rejection' }
        return 'Syntax error caught cleanly on BOM-present .ps1'
    }

    Invoke-TestCase -Id 'A1-T2-03' -Area '1' -Tier 2 -Name 'Reject unwanted UTF-8 BOM on .json, .mjs, .css, .html, .md, .svg' -Body {
        $badFiles = @{
            'bom.json' = '{"ok":true}'
            'bom.mjs'  = 'export const ok = true;'
            'bom.css'  = 'body { margin: 0; }'
            'bom.html' = '<html></html>'
            'bom.md'   = '# Title'
            'bom.svg'  = '<svg></svg>'
        }
        foreach ($kv in $badFiles.GetEnumerator()) {
            $fp = Join-Path $tempRoot $kv.Key
            [System.IO.File]::WriteAllText($fp, $kv.Value, $utf8WithBom)
            $rejected = $false
            try {
                $null = Test-FileEncodingAndSyntax -Path $fp -RequireBom $false -NodeCmdPath $AgyNodePath
            }
            catch {
                $rejected = ($_.Exception.Message -match 'Unexpected UTF-8 BOM')
            }
            if (-not $rejected) { throw "Failed to reject BOM on $($kv.Key)" }
        }
        return "Rejected unwanted BOM on all $($badFiles.Count) non-PS1 file types"
    }

    Invoke-TestCase -Id 'A1-T2-04' -Area '1' -Tier 2 -Name 'Reject invalid JSON (trailing comma) without BOM' -Body {
        $f = Join-Path $tempRoot 'trailing_comma.json'
        [System.IO.File]::WriteAllText($f, '{"a":1,}', $utf8NoBom)
        $rejected = $false
        try {
            $null = Test-FileEncodingAndSyntax -Path $f -RequireBom $false -NodeCmdPath $AgyNodePath
        }
        catch {
            $rejected = ($_.Exception.Message -match 'Invalid JSON')
        }
        if (-not $rejected) { throw 'Expected JSON parse failure on trailing comma' }
        return 'Rejected malformed JSON cleanly'
    }

    Invoke-TestCase -Id 'A1-T2-05' -Area '1' -Tier 2 -Name 'Reject invalid UTF-8 byte sequences (0xFF/0xFE, 0xC3/0x28, CP936 D6 D0 CE C4)' -Body {
        $vectors = @(
            @{ Name = 'utf16_bom.txt'; Bytes = [byte[]](0xFF, 0xFE, 0x41, 0x00) },
            @{ Name = 'bad_utf8.txt'; Bytes = [byte[]](0xC3, 0x28) },
            @{ Name = 'cp936_raw.txt'; Bytes = [byte[]](0xD6, 0xD0, 0xCE, 0xC4) }
        )
        foreach ($v in $vectors) {
            $fp = Join-Path $tempRoot $v.Name
            [System.IO.File]::WriteAllBytes($fp, $v.Bytes)
            $rejected = $false
            try {
                $null = Test-FileEncodingAndSyntax -Path $fp -RequireBom $false -NodeCmdPath $AgyNodePath
            }
            catch {
                $rejected = $true
            }
            if (-not $rejected) { throw "Expected strict UTF-8 rejection on $($v.Name)" }
        }
        return "Rejected all $($vectors.Count) invalid UTF-8 byte vectors"
    }

    Invoke-TestCase -Id 'A1-T2-06' -Area '1' -Tier 2 -Name 'Reject invalid .mjs ESM syntax via agy-node.cmd --check' -Body {
        $f = Join-Path $tempRoot 'broken.mjs'
        [System.IO.File]::WriteAllText($f, "export const x = ;`n", $utf8NoBom)
        $rejected = $false
        try {
            $null = Test-FileEncodingAndSyntax -Path $f -RequireBom $false -NodeCmdPath $AgyNodePath
        }
        catch {
            $rejected = ($_.Exception.Message -match 'Node --check failed')
        }
        if (-not $rejected) { throw 'Expected Node --check failure on broken ESM' }
        return 'Node --check rejected invalid ESM syntax'
    }

    # --- REPO INTEGRATION (-RepoRoot) ---
    if ($RepoRoot) {
        Invoke-TestCase -Id 'A1-REPO-01' -Area '1' -Tier 1 -Name 'Repo §3.1 completeness, BOM/no-BOM, PS 5.1, JSON, and Node --check scan' -Body {
            if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
                throw "RepoRoot not found: $RepoRoot"
            }
            $ps1Required = @(
                'Register-Plugin.ps1',
                'Install-ElevationRunner.ps1',
                'runner\Invoke-ElevatedRunner.ps1',
                'sidecars\broker\broker_helper.ps1',
                'tools\Invoke-Elevated.ps1'
            )
            $noBomRequired = @(
                'plugin.json',
                'README.md',
                'assets\logo.svg',
                'sidecars\broker\sidecar.json',
                'sidecars\broker\package.json',
                'sidecars\broker\main.mjs',
                'sidecars\broker\index.html',
                'sidecars\broker\styles.css',
                'sidecars\broker\app.js',
                'skills\elevated-execution\SKILL.md'
            )

            foreach ($rel in $ps1Required) {
                $full = Join-Path $RepoRoot $rel
                $null = Test-FileEncodingAndSyntax -Path $full -RequireBom $true -NodeCmdPath $AgyNodePath
            }
            foreach ($rel in $noBomRequired) {
                $full = Join-Path $RepoRoot $rel
                $null = Test-FileEncodingAndSyntax -Path $full -RequireBom $false -NodeCmdPath $AgyNodePath
            }
            return "Verified all $($ps1Required.Count) .ps1 (BOM+PS5.1) and $($noBomRequired.Count) non-.ps1 (no-BOM) §3.1 files"
        }

        Invoke-TestCase -Id 'A1-REPO-02' -Area '1' -Tier 1 -Name 'Repo plugin.json, sidecar.json, and package.json schema contracts' -Body {
            $plugin = (Get-Content -LiteralPath (Join-Path $RepoRoot 'plugin.json') -Raw -Encoding UTF8) | ConvertFrom-Json
            if ($plugin.name -ne 'elevated-exec') { throw "Unexpected plugin.json name: $($plugin.name)" }

            $sidecar = (Get-Content -LiteralPath (Join-Path $RepoRoot 'sidecars\broker\sidecar.json') -Raw -Encoding UTF8) | ConvertFrom-Json
            if ($sidecar.command -ne 'node') { throw "Unexpected sidecar command: $($sidecar.command)" }
            if ($sidecar.restart_policy -ne 'always') { throw "Unexpected restart_policy: $($sidecar.restart_policy)" }
            if (-not ($sidecar.args -contains 'main.mjs')) { throw 'sidecar.json args must include main.mjs' }
            if (-not $sidecar.has_web_ui) { throw 'sidecar.json has_web_ui must be true' }
            $entryPoints = @($sidecar.ui_config.views | ForEach-Object { $_.entrypoint })
            if (-not ($entryPoints -contains 'SIDECAR_UI_ENTRYPOINT_AUX_PANE')) {
                throw 'sidecar.json missing SIDECAR_UI_ENTRYPOINT_AUX_PANE view'
            }

            $pkg = (Get-Content -LiteralPath (Join-Path $RepoRoot 'sidecars\broker\package.json') -Raw -Encoding UTF8) | ConvertFrom-Json
            if ($pkg.type -ne 'module') { throw "package.json type must be 'module', got: $($pkg.type)" }

            return 'Verified plugin.json, sidecar.json, and package.json schemas'
        }
    }
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$total = $results.Count
$passedCount = @($results | Where-Object { $_.passed }).Count
$failedCount = $total - $passedCount

if ($JsonReport) {
    $reportObj = [pscustomobject]@{
        module  = 'Test-EncodingAndSyntax.ps1'
        summary = [pscustomobject]@{ total = $total; passed = $passedCount; failed = $failedCount }
        results = $results
    }
    $utf8NoBomOut = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($JsonReport, ($reportObj | ConvertTo-Json -Depth 6), $utf8NoBomOut)
}

Write-Host ("Area 1 Summary: {0}/{1} passed ({2} failed)" -f $passedCount, $total, $failedCount)
if ($failedCount -gt 0) { exit 1 }
exit 0
