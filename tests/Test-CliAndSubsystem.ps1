<#
.SYNOPSIS
Area 3: PE Subsystem Inspection (e_lfanew + 92), -FilePath Allowlist, System32/HKLM PATH Isolation, Wrapper Generation, and Invoke-Elevated.ps1 Opaque-Box IPC Checks.
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

function Get-PeSubsystemInfo {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "PE file not found: $Path"
    }
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        if ($fs.Length -lt 64) {
            throw "File too small for DOS header (<64 bytes): $($fs.Length)"
        }
        $br = New-Object System.IO.BinaryReader($fs)
        $mz = $br.ReadUInt16()
        if ($mz -ne 0x5A4D) {
            throw ("Invalid DOS signature: 0x{0:X4}" -f $mz)
        }
        $fs.Position = 0x3C
        $eLfanew = $br.ReadInt32()
        if ($eLfanew -lt 0 -or ($eLfanew + 94) -gt $fs.Length) {
            throw "Invalid e_lfanew offset $eLfanew for file length $($fs.Length)"
        }
        $fs.Position = $eLfanew
        $peSig = $br.ReadUInt32()
        if ($peSig -ne 0x00004550) {
            throw ("Invalid PE signature: 0x{0:X8}" -f $peSig)
        }
        $fs.Position = $eLfanew + 24
        $magic = $br.ReadUInt16()
        if ($magic -ne 0x010B -and $magic -ne 0x020B) {
            throw ("Unsupported PE OptionalHeader magic: 0x{0:X4}" -f $magic)
        }
        $fs.Position = $eLfanew + 92
        $subsystem = $br.ReadUInt16()
        return [pscustomobject]@{
            Path      = $Path
            Magic     = $magic
            Bitness   = if ($magic -eq 0x020B) { 64 } else { 32 }
            Subsystem = $subsystem
            Kind      = switch ($subsystem) { 2 { 'GUI' } 3 { 'CUI' } default { "OTHER($subsystem)" } }
        }
    }
    finally {
        $fs.Dispose()
    }
}

function New-SyntheticPeFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [uint16]$Magic = 0x020B,
        [uint16]$Subsystem = 3
    )
    $buf = New-Object byte[] 160
    $buf[0] = 0x4D; $buf[1] = 0x5A # MZ
    $eLfanew = 0x40
    [System.Buffer]::BlockCopy([BitConverter]::GetBytes([int32]$eLfanew), 0, $buf, 0x3C, 4)
    $buf[$eLfanew + 0] = 0x50; $buf[$eLfanew + 1] = 0x45 # PE\0\0
    [System.Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]$Magic), 0, $buf, $eLfanew + 24, 2)
    [System.Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]$Subsystem), 0, $buf, $eLfanew + 92, 2)
    [System.IO.File]::WriteAllBytes($Path, $buf)
}

function Escape-PsSingleQuoted {
    param([string]$Value)
    return ($Value -replace "'", "''")
}

function Resolve-AllowedElevatedTarget {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string]$WorkDir
    )
    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        throw 'INVALID_ARGS (1206): FilePath is empty'
    }
    if ($FilePath -match '^[a-zA-Z][a-zA-Z0-9+.-]*://' -or ($FilePath -match '^[a-zA-Z][a-zA-Z0-9+.-]+:' -and $FilePath -notmatch '^[a-zA-Z]:') -or $FilePath.Contains('::')) {
        throw "INVALID_ARGS (1206): URI schemes are not allowed in -FilePath: $FilePath"
    }
    if ($FilePath -match '^\s*[\\/]{2}' -or $FilePath -match '^\s*\\\?\?\\') {
        throw "INVALID_ARGS (1206): UNC and device paths are not allowed in -FilePath: $FilePath"
    }
    if ($FilePath -match '^\s*([A-Za-z]):') {
        $driveInfo = New-Object System.IO.DriveInfo(($Matches[1].ToUpperInvariant() + ':\'))
        if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network -or $driveInfo.DriveType -eq [System.IO.DriveType]::Unknown) {
            throw "INVALID_ARGS (1206): Network or unknown drive paths are not allowed in -FilePath: $FilePath"
        }
    }
    if ($FilePath -like '*.ps1') {
        throw "INVALID_ARGS (1206): PowerShell scripts (.ps1) must use -ScriptFile instead of -FilePath: $FilePath"
    }

    $allowedExts = @('.exe', '.com', '.msc', '.cpl', '.msi')
    $hasSeparator = ($FilePath.Contains('\') -or $FilePath.Contains('/'))
    $resolved = $null

    if ($hasSeparator) {
        if (Test-Path -LiteralPath $FilePath -PathType Container) {
            throw "INVALID_ARGS (1206): Directory path not allowed in -FilePath: $FilePath"
        }
        if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
            throw "INVALID_ARGS (1206): Target file not found: $FilePath"
        }
        $resolved = (Resolve-Path -LiteralPath $FilePath).Path
    }
    else {
        # Strictly resolve unqualified names against System32 and HKLM PATH — NEVER workDir or current dir
        $sys32 = Join-Path $env:SystemRoot 'System32'
        $hklmPathRaw = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name 'Path').Path
        $hklmExpanded = [System.Environment]::ExpandEnvironmentVariables($hklmPathRaw)
        $searchDirs = New-Object 'System.Collections.Generic.List[string]'
        $searchDirs.Add($sys32) | Out-Null
        foreach ($d in ($hklmExpanded -split ';')) {
            $trimmed = $d.Trim()
            if ($trimmed -and ($searchDirs -notcontains $trimmed)) {
                $searchDirs.Add($trimmed) | Out-Null
            }
        }
        foreach ($dir in $searchDirs) {
            $candidate = Join-Path $dir $FilePath
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $resolved = (Resolve-Path -LiteralPath $candidate).Path
                break
            }
        }
        if (-not $resolved) {
            throw "INVALID_ARGS (1206): Unqualified target '$FilePath' not found in System32 or HKLM PATH"
        }
    }

    $ext = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
    if ($ext -eq '.ps1') {
        throw "INVALID_ARGS (1206): Use -ScriptFile for .ps1 scripts: $resolved"
    }
    if ($allowedExts -notcontains $ext) {
        throw "INVALID_ARGS (1206): Disallowed extension '$ext' (allowed: $($allowedExts -join ', '))"
    }

    $subsystemTag = switch ($ext) {
        '.msc' { 'MSC' }
        '.cpl' { 'CPL' }
        '.msi' { 'MSI' }
        default {
            $pe = Get-PeSubsystemInfo -Path $resolved
            if ($pe.Subsystem -eq 3) { 'CUI' }
            elseif ($pe.Subsystem -eq 2) { 'GUI' }
            else { throw "INVALID_ARGS (1206): Unsupported PE subsystem $($pe.Subsystem) on $resolved" }
        }
    }

    $sig = Get-AuthenticodeSignature -LiteralPath $resolved
    $publisher = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'Unsigned' }

    return [pscustomobject]@{
        CanonicalPath = $resolved
        Extension     = $ext
        Subsystem     = $subsystemTag
        Publisher     = $publisher
    }
}

function New-ElevatedWrapperScript {
    param(
        [Parameter(Mandatory = $true)]$TargetMeta,
        [string[]]$ArgumentList = @()
    )
    $qPath = Escape-PsSingleQuoted $TargetMeta.CanonicalPath
    switch ($TargetMeta.Subsystem) {
        'CUI' {
            if ($ArgumentList -and $ArgumentList.Count -gt 0) {
                $argTokens = ($ArgumentList | ForEach-Object { "'" + (Escape-PsSingleQuoted $_) + "'" }) -join ' '
                return "& '$qPath' $argTokens`r`nexit `$LASTEXITCODE"
            }
            return "& '$qPath'`r`nexit `$LASTEXITCODE"
        }
        { $_ -in @('GUI', 'MSC', 'CPL') } {
            if ($ArgumentList -and $ArgumentList.Count -gt 0) {
                $argTokens = ($ArgumentList | ForEach-Object { "'" + (Escape-PsSingleQuoted $_) + "'" }) -join ', '
                return "`$p = Start-Process -FilePath '$qPath' -ArgumentList @($argTokens) -Wait -PassThru`r`nexit `$p.ExitCode"
            }
            return "`$p = Start-Process -FilePath '$qPath' -Wait -PassThru`r`nexit `$p.ExitCode"
        }
        'MSI' {
            $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
            $qMsi = Escape-PsSingleQuoted $msiexec
            $allArgs = @('/i', $TargetMeta.CanonicalPath)
            if ($ArgumentList) { $allArgs += $ArgumentList }
            $argTokens = ($allArgs | ForEach-Object { "'" + (Escape-PsSingleQuoted $_) + "'" }) -join ', '
            return "`$p = Start-Process -FilePath '$qMsi' -ArgumentList @($argTokens) -Wait -PassThru`r`nexit `$p.ExitCode"
        }
        default {
            throw "Unsupported subsystem: $($TargetMeta.Subsystem)"
        }
    }
}

$tempRoot = Join-Path $env:TEMP ("ae-area3-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$origLocation = Get-Location

try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    # --- TIER 1: Positive Core ---
    Invoke-TestCase -Id 'A3-T1-01' -Area '3' -Tier 1 -Name 'PE subsystem parser on real Windows System32, Windows, and SysWOW64 binaries' -Body {
        $expected = @(
            @{ Path = "$env:SystemRoot\System32\whoami.exe"; Sub = 3; Bit = 64 },
            @{ Path = "$env:SystemRoot\System32\cmd.exe"; Sub = 3; Bit = 64 },
            @{ Path = "$env:SystemRoot\System32\sc.exe"; Sub = 3; Bit = 64 },
            @{ Path = "$env:SystemRoot\System32\notepad.exe"; Sub = 2; Bit = 64 },
            @{ Path = "$env:SystemRoot\System32\msiexec.exe"; Sub = 2; Bit = 64 },
            @{ Path = "$env:SystemRoot\regedit.exe"; Sub = 2; Bit = 64 },
            @{ Path = "$env:SystemRoot\SysWOW64\cmd.exe"; Sub = 3; Bit = 32 },
            @{ Path = "$env:SystemRoot\SysWOW64\notepad.exe"; Sub = 2; Bit = 32 }
        )
        foreach ($item in $expected) {
            $info = Get-PeSubsystemInfo -Path $item.Path
            if ($info.Subsystem -ne $item.Sub -or $info.Bitness -ne $item.Bit) {
                throw "PE mismatch for $($item.Path): got Sub=$($info.Subsystem) Bit=$($info.Bitness)"
            }
        }
        return "Verified PE32/PE32+ subsystems across all $($expected.Count) real Windows binaries"
    }

    Invoke-TestCase -Id 'A3-T1-02' -Area '3' -Tier 1 -Name 'Allowlist accepts .exe, .com, .msc, .cpl, and .msi targets' -Body {
        $dummyCom = Join-Path $tempRoot 'tool.com'
        New-SyntheticPeFile -Path $dummyCom -Magic 0x020B -Subsystem 3
        $dummyMsi = Join-Path $tempRoot 'installer.msi'
        [System.IO.File]::WriteAllBytes($dummyMsi, [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1))

        $targets = @(
            @{ In = "$env:SystemRoot\System32\whoami.exe"; Sub = 'CUI' },
            @{ In = $dummyCom; Sub = 'CUI' },
            @{ In = "$env:SystemRoot\System32\certmgr.msc"; Sub = 'MSC' },
            @{ In = "$env:SystemRoot\System32\appwiz.cpl"; Sub = 'CPL' },
            @{ In = $dummyMsi; Sub = 'MSI' }
        )
        foreach ($t in $targets) {
            $meta = Resolve-AllowedElevatedTarget -FilePath $t.In
            if ($meta.Subsystem -ne $t.Sub) { throw "Expected $($t.Sub) for $($t.In), got $($meta.Subsystem)" }
        }
        return "Accepted all 5 allowlisted extensions (.exe, .com, .msc, .cpl, .msi)"
    }

    Invoke-TestCase -Id 'A3-T1-03' -Area '3' -Tier 1 -Name 'Unqualified System32/HKLM PATH resolution and Authenticode publisher extraction' -Body {
        $t1 = Resolve-AllowedElevatedTarget -FilePath 'whoami.exe'
        if ($t1.CanonicalPath -ine "$env:SystemRoot\System32\whoami.exe") { throw "Unexpected path: $($t1.CanonicalPath)" }
        if ($t1.Publisher -notmatch 'Microsoft') { throw "Expected Microsoft publisher, got: $($t1.Publisher)" }

        $t2 = Resolve-AllowedElevatedTarget -FilePath 'regedit.exe'
        if ($t2.CanonicalPath -ine "$env:SystemRoot\regedit.exe" -or $t2.Subsystem -ne 'GUI') {
            throw "Unexpected regedit resolution: $($t2 | ConvertTo-Json -Compress)"
        }
        return "Resolved whoami.exe ($($t1.Publisher)) and regedit.exe via System32/HKLM PATH"
    }

    Invoke-TestCase -Id 'A3-T1-04' -Area '3' -Tier 1 -Name 'Wrapper script generation for CUI, GUI, .msc, .cpl, and .msi targets' -Body {
        $dummyMsi = Join-Path $tempRoot 'setup.msi'
        [System.IO.File]::WriteAllBytes($dummyMsi, [byte[]](0xD0, 0xCF, 0x11, 0xE0))

        $wCui = New-ElevatedWrapperScript -TargetMeta (Resolve-AllowedElevatedTarget -FilePath 'sc.exe') -ArgumentList @('query', 'Appinfo')
        if ($wCui -notmatch "^& '.*sc\.exe' 'query' 'Appinfo'\r?\nexit \`$LASTEXITCODE$") {
            throw "Unexpected CUI wrapper: $wCui"
        }

        $wGui = New-ElevatedWrapperScript -TargetMeta (Resolve-AllowedElevatedTarget -FilePath 'notepad.exe') -ArgumentList @('C:\temp\a.txt')
        if ($wGui -notmatch "Start-Process -FilePath '.*notepad\.exe' -ArgumentList @\('C:\\temp\\a\.txt'\) -Wait -PassThru") {
            throw "Unexpected GUI wrapper: $wGui"
        }

        $wMsc = New-ElevatedWrapperScript -TargetMeta (Resolve-AllowedElevatedTarget -FilePath 'certmgr.msc')
        if ($wMsc -notmatch "Start-Process -FilePath '.*certmgr\.msc' -Wait -PassThru") {
            throw "Unexpected MSC wrapper: $wMsc"
        }

        $wMsi = New-ElevatedWrapperScript -TargetMeta (Resolve-AllowedElevatedTarget -FilePath $dummyMsi) -ArgumentList @('/qn')
        if ($wMsi -notmatch "msiexec\.exe' -ArgumentList @\('/i', '.*setup\.msi', '/qn'\) -Wait -PassThru") {
            throw "Unexpected MSI wrapper: $wMsi"
        }
        return 'Verified exact wrapper patterns for CUI, GUI, MSC, and MSI'
    }

    Invoke-TestCase -Id 'A3-T1-05' -Area '3' -Tier 1 -Name 'Synthetic PE32 (0x10B) and PE32+ (0x20B) minimal 160-byte fixtures parse accurately' -Body {
        $pe32Gui = Join-Path $tempRoot 'syn32_gui.exe'
        $pe64Cui = Join-Path $tempRoot 'syn64_cui.exe'
        New-SyntheticPeFile -Path $pe32Gui -Magic 0x010B -Subsystem 2
        New-SyntheticPeFile -Path $pe64Cui -Magic 0x020B -Subsystem 3
        $i1 = Get-PeSubsystemInfo -Path $pe32Gui
        $i2 = Get-PeSubsystemInfo -Path $pe64Cui
        if ($i1.Bitness -ne 32 -or $i1.Subsystem -ne 2) { throw "PE32 mismatch" }
        if ($i2.Bitness -ne 64 -or $i2.Subsystem -ne 3) { throw "PE32+ mismatch" }
        return 'Parsed synthetic PE32 (GUI=2) and PE32+ (CUI=3)'
    }

    # --- TIER 2: Negative / Boundary / Adversarial ---
    Invoke-TestCase -Id 'A3-T2-01' -Area '3' -Tier 2 -Name 'Reject disallowed extensions (.bat, .cmd, .lnk, .vbs, .js) with INVALID_ARGS' -Body {
        $badExts = @('run.bat', 'run.cmd', 'shortcut.lnk', 'script.vbs', 'helper.js')
        foreach ($name in $badExts) {
            $fp = Join-Path $tempRoot $name
            [System.IO.File]::WriteAllText($fp, 'echo hi', $utf8NoBom)
            $rejected = $false
            try {
                $null = Resolve-AllowedElevatedTarget -FilePath $fp
            }
            catch {
                $rejected = ($_.Exception.Message -match 'INVALID_ARGS \(1206\)')
            }
            if (-not $rejected) { throw "Failed to reject $name" }
        }
        return "Rejected all $($badExts.Count) disallowed extensions"
    }

    Invoke-TestCase -Id 'A3-T2-02' -Area '3' -Tier 2 -Name 'Reject directories, URIs (https/file), empty string, and missing files' -Body {
        $subDir = Join-Path $tempRoot 'folder_target'
        New-Item -ItemType Directory -Path $subDir -Force | Out-Null
        $inputs = @($subDir, 'https://example.com/setup.exe', 'file:///C:/Windows/System32/whoami.exe', '   ', (Join-Path $tempRoot 'nonexistent.exe'))
        foreach ($inp in $inputs) {
            $rejected = $false
            try {
                $null = Resolve-AllowedElevatedTarget -FilePath $inp
            }
            catch {
                $rejected = ($_.Exception.Message -match 'INVALID_ARGS \(1206\)')
            }
            if (-not $rejected) { throw "Failed to reject input: [$inp]" }
        }
        return "Rejected all $($inputs.Count) non-file/URI/missing inputs"
    }

    Invoke-TestCase -Id 'A3-T2-03' -Area '3' -Tier 2 -Name 'Reject .ps1 in -FilePath with explicit -ScriptFile redirect guidance' -Body {
        $psFile = Join-Path $tempRoot 'my_script.ps1'
        [System.IO.File]::WriteAllText($psFile, 'Write-Host hi', $utf8NoBom)
        $rejected = $false
        try {
            $null = Resolve-AllowedElevatedTarget -FilePath $psFile
        }
        catch {
            $rejected = ($_.Exception.Message -match '-ScriptFile')
        }
        if (-not $rejected) { throw 'Expected -ScriptFile redirect message for .ps1' }
        return 'Rejected .ps1 with explicit -ScriptFile redirect message'
    }

    Invoke-TestCase -Id 'A3-T2-04' -Area '3' -Tier 2 -Name 'Rogue workDir binary isolation (ignores planted workDir\whoami.exe)' -Body {
        $rogueDir = Join-Path $tempRoot 'rogue_workdir'
        New-Item -ItemType Directory -Path $rogueDir -Force | Out-Null
        $rogueWhoami = Join-Path $rogueDir 'whoami.exe'
        New-SyntheticPeFile -Path $rogueWhoami -Magic 0x020B -Subsystem 2 # GUI decoy!

        Set-Location -LiteralPath $rogueDir
        $meta = Resolve-AllowedElevatedTarget -FilePath 'whoami.exe' -WorkDir $rogueDir
        if ($meta.CanonicalPath -ine "$env:SystemRoot\System32\whoami.exe" -or $meta.Subsystem -ne 'CUI') {
            throw "Rogue workDir binary hijacked resolution! Got $($meta.CanonicalPath) ($($meta.Subsystem))"
        }
        return "Ignored rogue $rogueWhoami; resolved $($meta.CanonicalPath)"
    }

    Invoke-TestCase -Id 'A3-T2-05' -Area '3' -Tier 2 -Name 'Reject malformed, truncated, non-MZ, bad-e_lfanew, and NATIVE PE binaries' -Body {
        $nonMz = Join-Path $tempRoot 'non_mz.exe'
        [System.IO.File]::WriteAllBytes($nonMz, ([byte[]](0x00) * 160))

        $trunc = Join-Path $tempRoot 'trunc.exe'
        [System.IO.File]::WriteAllBytes($trunc, [byte[]](0x4D, 0x5A, 0x90, 0x00))

        $badOffset = Join-Path $tempRoot 'bad_lfanew.exe'
        $b = New-Object byte[] 128
        $b[0] = 0x4D; $b[1] = 0x5A
        [System.Buffer]::BlockCopy([BitConverter]::GetBytes([int32]99999), 0, $b, 0x3C, 4)
        [System.IO.File]::WriteAllBytes($badOffset, $b)

        $badMagic = Join-Path $tempRoot 'bad_magic.exe'
        New-SyntheticPeFile -Path $badMagic -Magic 0x9999 -Subsystem 3

        $nativeSub = Join-Path $tempRoot 'native_sub.exe'
        New-SyntheticPeFile -Path $nativeSub -Magic 0x020B -Subsystem 1

        foreach ($f in @($nonMz, $trunc, $badOffset, $badMagic)) {
            $rejected = $false
            try { $null = Get-PeSubsystemInfo -Path $f } catch { $rejected = $true }
            if (-not $rejected) { throw "PE parser failed to reject corrupt binary $f" }
        }
        $nativeRejected = $false
        try { $null = Resolve-AllowedElevatedTarget -FilePath $nativeSub } catch { $nativeRejected = $true }
        if (-not $nativeRejected) { throw 'Failed to reject Subsystem=1 (NATIVE)' }
        return 'Rejected all 5 malformed/unsupported PE binaries'
    }

    Invoke-TestCase -Id 'A3-T2-06' -Area '3' -Tier 2 -Name 'Wrapper single-quote escaping parses cleanly in PS 5.1 [Parser]::ParseInput' -Body {
        $quotedDir = Join-Path $tempRoot "O'Reilly Dir"
        New-Item -ItemType Directory -Path $quotedDir -Force | Out-Null
        $quotedExe = Join-Path $quotedDir "app'1.exe"
        New-SyntheticPeFile -Path $quotedExe -Magic 0x020B -Subsystem 3

        $meta = Resolve-AllowedElevatedTarget -FilePath $quotedExe
        $wrapper = New-ElevatedWrapperScript -TargetMeta $meta -ArgumentList @("it's", "a'b")
        $tokens = $null; $errs = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($wrapper, [ref]$tokens, [ref]$errs)
        if ($null -ne $errs -and $errs.Count -gt 0) {
            throw "Generated wrapper failed PS 5.1 parse: $($errs[0].Message) in [$wrapper]"
        }
        return 'Single-quoted wrapper path and args parsed with 0 syntax errors'
    }

    Invoke-TestCase -Id 'A3-T2-07' -Area '3' -Tier 2 -Name 'Reject UNC (\\ and //), Win32 device (\\?\ and \\.\), and provider paths with INVALID_ARGS' -Body {
        $uncAndDeviceInputs = @(
            '\\127.0.0.1\c$\Windows\System32\whoami.exe',
            '//127.0.0.1/c$/Windows/System32/whoami.exe',
            '\/127.0.0.1\c$\Windows\System32\whoami.exe',
            '\\?\C:\Windows\System32\whoami.exe',
            '\\.\pipe\foo',
            'Microsoft.PowerShell.Core\FileSystem::\\127.0.0.1\c$\Windows\System32\whoami.exe'
        )
        foreach ($inp in $uncAndDeviceInputs) {
            $rejected = $false
            try {
                $null = Resolve-AllowedElevatedTarget -FilePath $inp
            }
            catch {
                $rejected = ($_.Exception.Message -match 'INVALID_ARGS \(1206\)')
            }
            if (-not $rejected) { throw "Failed to reject UNC/device input: [$inp]" }
        }
        return "Rejected all $($uncAndDeviceInputs.Count) UNC/device/provider inputs with INVALID_ARGS (1206)"
    }

    # --- REPO INTEGRATION (-RepoRoot\tools\Invoke-Elevated.ps1) ---
    if ($RepoRoot) {
        Invoke-TestCase -Id 'A3-REPO-01' -Area '3' -Tier 2 -Name 'Repo tools\Invoke-Elevated.ps1 negative rejections (.bat/.cmd/.lnk/dir/URI/.ps1/missing sidecar)' -Body {
            $cliPath = Join-Path $RepoRoot 'tools\Invoke-Elevated.ps1'
            if (-not (Test-Path -LiteralPath $cliPath -PathType Leaf)) {
                throw "Missing Invoke-Elevated.ps1: $cliPath"
            }

            $emptyAppData = Join-Path $tempRoot 'empty_appdata'
            New-Item -ItemType Directory -Path $emptyAppData -Force | Out-Null

            $batFile = Join-Path $tempRoot 'repo_test.bat'
            [System.IO.File]::WriteAllText($batFile, "@echo off`r`n", $utf8NoBom)
            $cmdFile = Join-Path $tempRoot 'repo_test.cmd'
            [System.IO.File]::WriteAllText($cmdFile, "@echo off`r`n", $utf8NoBom)
            $lnkFile = Join-Path $tempRoot 'repo_test.lnk'
            [System.IO.File]::WriteAllText($lnkFile, "dummy-lnk`r`n", $utf8NoBom)
            $dirTarget = Join-Path $tempRoot 'repo_dir_target'
            New-Item -ItemType Directory -Path $dirTarget -Force | Out-Null
            $psFile = Join-Path $tempRoot 'repo_test.ps1'
            [System.IO.File]::WriteAllText($psFile, "Write-Output 'ok'`r`n", $utf8NoBom)

            $runCli = {
                param([string]$ArgLine, [string]$AppDataDir)
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'powershell.exe'
                $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$cliPath`" $ArgLine"
                $psi.UseShellExecute = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
                $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
                $psi.EnvironmentVariables['ANTIGRAVITY_APP_DATA_DIR'] = $AppDataDir
                $p = [System.Diagnostics.Process]::Start($psi)
                $so = $p.StandardOutput.ReadToEnd()
                $se = $p.StandardError.ReadToEnd()
                if (-not $p.WaitForExit(10000)) {
                    $p.Kill()
                    throw "Invoke-Elevated.ps1 timed out for args: $ArgLine"
                }
                return [pscustomobject]@{ ExitCode = $p.ExitCode; Stdout = $so; Stderr = $se }
            }

            $rejectedInputs = @(
                @{ Label = '.bat'; Target = $batFile },
                @{ Label = '.cmd'; Target = $cmdFile },
                @{ Label = '.lnk'; Target = $lnkFile },
                @{ Label = 'directory'; Target = $dirTarget },
                @{ Label = 'URI'; Target = 'https://example.com/setup.exe' }
            )
            foreach ($item in $rejectedInputs) {
                $rNeg = & $runCli "-FilePath `"$($item.Target)`" -Reason `"test $($item.Label)`"" $emptyAppData
                $combined = $rNeg.Stdout + "`n" + $rNeg.Stderr
                if ($rNeg.ExitCode -ne 1206 -or $combined -notmatch 'INVALID_ARGS') {
                    throw "Expected ExitCode=1206 and INVALID_ARGS for $($item.Label) ($($item.Target)), got exit=$($rNeg.ExitCode) out=$($rNeg.Stdout) err=$($rNeg.Stderr)"
                }
            }

            $rPs1 = & $runCli "-FilePath `"$psFile`" -Reason `"test ps1`"" $emptyAppData
            $psCombined = $rPs1.Stdout + "`n" + $rPs1.Stderr
            if ($rPs1.ExitCode -ne 1206 -or $psCombined -notmatch 'INVALID_ARGS' -or $psCombined -notmatch 'ScriptFile') {
                throw "Expected ExitCode=1206 + INVALID_ARGS + ScriptFile hint for .ps1, got exit=$($rPs1.ExitCode) out=$($rPs1.Stdout) err=$($rPs1.Stderr)"
            }

            $rNoSidecar = & $runCli "-ScriptText `"Write-Output 1`" -Reason `"test no sidecar`"" $emptyAppData
            if ($rNoSidecar.ExitCode -ne 1203 -or $rNoSidecar.Stdout -notmatch 'OUTCOME=SIDECAR_UNAVAILABLE EXIT=1203') {
                throw "Expected 1203 SIDECAR_UNAVAILABLE, got exit=$($rNoSidecar.ExitCode) out=$($rNoSidecar.Stdout) err=$($rNoSidecar.Stderr)"
            }

            return 'Verified ExitCode=1206 INVALID_ARGS on .bat/.cmd/.lnk/dir/URI/.ps1 (-ScriptFile hint), and SIDECAR_UNAVAILABLE (1203)'
        }

        Invoke-TestCase -Id 'A3-REPO-02' -Area '3' -Tier 1 -Name 'Repo tools\Invoke-Elevated.ps1 opaque-box IPC payloads (CUI, GUI, MSC, CPL, MSI, rogue workDir, BOM-less zh-CN)' -Body {
            if (-not (Test-Path -LiteralPath $AgyNodePath -PathType Leaf)) {
                throw "agy-node.cmd missing: $AgyNodePath"
            }
            $cliPath = Join-Path $RepoRoot 'tools\Invoke-Elevated.ps1'
            $mockAppData = Join-Path $tempRoot 'mock_appdata'
            $brokerData = Join-Path $mockAppData 'sidecar_data\elevated-exec\broker\data'
            New-Item -ItemType Directory -Path $brokerData -Force | Out-Null
            $capturedPath = Join-Path $tempRoot 'captured_requests.json'

            $mockServerJs = @'
import http from 'node:http';
import fs from 'node:fs';
import crypto from 'node:crypto';

const dataDir = process.env.MOCK_DATA_DIR;
const capturedFile = process.env.CAPTURED_FILE;
const token = crypto.randomBytes(32).toString('hex');
const captured = [];

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/ipc/requests') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const auth = req.headers.authorization || '';
      if (auth !== `Bearer ${token}`) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      captured.push(body);
      fs.writeFileSync(capturedFile, JSON.stringify(captured, null, 2), 'utf8');

      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      });
      res.flushHeaders();
      const rid = 'req-' + captured.length;
      res.write(`event: pending\ndata: ${JSON.stringify({ requestId: rid, state: 'AWAITING_CLICK1' })}\n\n`);
      res.write(`event: stdout\ndata: ${JSON.stringify({ text: 'MOCK_OK:' + body.mode + '\n' })}\n\n`);
      res.write(`event: outcome\ndata: ${JSON.stringify({ outcome: 'COMPLETED', exitCode: 0, message: 'done' })}\n\n`);
      res.end();
    });
    return;
  }
  res.writeHead(404);
  res.end();
});

server.listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  const rt = { port, token, pid: process.pid, startedAt: new Date().toISOString() };
  fs.writeFileSync(`${dataDir}\\runtime.json`, JSON.stringify(rt), 'utf8');
  console.log(`READY:${port}`);
});
'@
            $mockServerFile = Join-Path $tempRoot 'mock_broker.mjs'
            [System.IO.File]::WriteAllText($mockServerFile, $mockServerJs, $utf8NoBom)

            # Spawn Electron/Node directly or via cmd; read Antigravity.exe path from agy-node or run agy-node
            $psiNode = New-Object System.Diagnostics.ProcessStartInfo
            $psiNode.FileName = 'cmd.exe'
            $psiNode.Arguments = "/c `"`"$AgyNodePath`" `"$mockServerFile`"`""
            $psiNode.UseShellExecute = $false
            $psiNode.RedirectStandardOutput = $true
            $psiNode.RedirectStandardError = $true
            $psiNode.EnvironmentVariables['MOCK_DATA_DIR'] = $brokerData
            $psiNode.EnvironmentVariables['CAPTURED_FILE'] = $capturedPath
            $mockProc = [System.Diagnostics.Process]::Start($psiNode)

            try {
                $readyLine = $mockProc.StandardOutput.ReadLine()
                if ($readyLine -notlike 'READY:*') {
                    $errTxt = $mockProc.StandardError.ReadToEnd()
                    throw "Mock broker failed to start: out=$readyLine err=$errTxt"
                }

                # Fix PID in runtime.json to a live process PID (cmd.exe PID is alive)
                $rtPath = Join-Path $brokerData 'runtime.json'
                $rt = (Get-Content -LiteralPath $rtPath -Raw) | ConvertFrom-Json
                if (-not (Get-Process -Id $rt.pid -ErrorAction SilentlyContinue)) {
                    $rt.pid = $mockProc.Id
                    [System.IO.File]::WriteAllText($rtPath, ($rt | ConvertTo-Json -Compress), $utf8NoBom)
                }

                $rogueDir = Join-Path $tempRoot 'rogue_cli_dir'
                New-Item -ItemType Directory -Path $rogueDir -Force | Out-Null
                New-SyntheticPeFile -Path (Join-Path $rogueDir 'whoami.exe') -Magic 0x020B -Subsystem 2

                $dummyMsi = Join-Path $tempRoot 'pkg.msi'
                [System.IO.File]::WriteAllBytes($dummyMsi, [byte[]](0xD0, 0xCF, 0x11, 0xE0))

                $zhScriptFile = Join-Path $tempRoot 'zh_nobom.ps1'
                [System.IO.File]::WriteAllText($zhScriptFile, "Write-Output '状态/系统/目录/未知/小'`r`n", $utf8NoBom)

                $invocations = @(
                    "-FilePath `"whoami.exe`" -ArgumentList `"/groups`" -WorkDir `"$rogueDir`" -Reason `"CUI test`"",
                    "-FilePath `"$env:SystemRoot\System32\notepad.exe`" -Reason `"GUI test`"",
                    "-FilePath `"$env:SystemRoot\System32\certmgr.msc`" -Reason `"MSC test`"",
                    "-FilePath `"$env:SystemRoot\System32\appwiz.cpl`" -Reason `"CPL test`"",
                    "-FilePath `"$dummyMsi`" -Reason `"MSI test`"",
                    "-ScriptFile `"$zhScriptFile`" -Reason `"UTF8 no-BOM zh-CN test`""
                )

                foreach ($argStr in $invocations) {
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName = 'powershell.exe'
                    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$cliPath`" $argStr"
                    $psi.UseShellExecute = $false
                    $psi.RedirectStandardOutput = $true
                    $psi.RedirectStandardError = $true
                    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
                    $psi.EnvironmentVariables['ANTIGRAVITY_APP_DATA_DIR'] = $mockAppData
                    $p = [System.Diagnostics.Process]::Start($psi)
                    $so = $p.StandardOutput.ReadToEnd()
                    $se = $p.StandardError.ReadToEnd()
                    if (-not $p.WaitForExit(15000)) {
                        $p.Kill()
                        throw "Invoke-Elevated.ps1 timed out for: $argStr"
                    }
                    if ($p.ExitCode -ne 0 -or $so -notmatch 'ELEVATION_PENDING:' -or $so -notmatch '\[elevated-exec\] OUTCOME=COMPLETED EXIT=0') {
                        throw "CLI failed for [$argStr]: exit=$($p.ExitCode) out=$so err=$se"
                    }
                }

                $reqs = (Get-Content -LiteralPath $capturedPath -Raw -Encoding UTF8) | ConvertFrom-Json
                if ($reqs.Count -ne 6) { throw "Expected 6 captured requests, got $($reqs.Count)" }
                if ($reqs[0].targetMeta.canonicalPath -ine "$env:SystemRoot\System32\whoami.exe" -or $reqs[0].targetMeta.subsystem -ne 'CUI') {
                    throw "Req 0 rogue isolation/CUI failed: $($reqs[0].targetMeta | ConvertTo-Json -Compress)"
                }
                if ($reqs[1].targetMeta.subsystem -ne 'GUI' -or $reqs[2].targetMeta.subsystem -ne 'MSC' -or $reqs[3].targetMeta.subsystem -ne 'CPL' -or $reqs[4].targetMeta.subsystem -ne 'MSI') {
                    throw 'Subsystem metadata mismatch on GUI/MSC/CPL/MSI'
                }
                if ($reqs[5].script -notmatch '状态/系统/目录/未知/小') {
                    throw "Req 5 zh-CN BOM-less ScriptFile corrupted: $($reqs[5].script)"
                }
                return 'Verified all 6 live opaque-box Invoke-Elevated.ps1 -> loopback SSE contracts'
            }
            finally {
                try {
                    if (-not $mockProc.HasExited) {
                        $null = cmd /c "taskkill /F /T /PID $($mockProc.Id) >nul 2>&1"
                    }
                } catch {}
            }
        }

        Invoke-TestCase -Id 'A3-REPO-03' -Area '3' -Tier 2 -Name 'Repo tools\Invoke-Elevated.ps1 rejects UNC/device paths across -FilePath, -ScriptFile, -WorkDir, and non-FileSystem CWD' -Body {
            $cliPath = Join-Path $RepoRoot 'tools\Invoke-Elevated.ps1'
            $emptyAppData = Join-Path $tempRoot 'empty_appdata_unc'
            New-Item -ItemType Directory -Path $emptyAppData -Force | Out-Null

            $runCliCommand = {
                param([string]$PsCommand, [string]$AppDataDir)
                $wrapped = "$PsCommand; exit `$LASTEXITCODE"
                $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($wrapped))
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'powershell.exe'
                $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -OutputFormat Text -EncodedCommand $encoded"
                $psi.UseShellExecute = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
                $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
                $psi.EnvironmentVariables['ANTIGRAVITY_APP_DATA_DIR'] = $AppDataDir
                $p = [System.Diagnostics.Process]::Start($psi)
                $so = $p.StandardOutput.ReadToEnd()
                $se = $p.StandardError.ReadToEnd()
                if (-not $p.WaitForExit(10000)) {
                    $p.Kill()
                    throw "Invoke-Elevated.ps1 timed out for command: $PsCommand"
                }
                return [pscustomobject]@{ ExitCode = $p.ExitCode; Stdout = $so; Stderr = $se }
            }

            $qCli = Escape-PsSingleQuoted $cliPath
            $probes = @(
                @{ Label = 'FilePath UNC'; Cmd = "& '$qCli' -FilePath '\\127.0.0.1\c$\Windows\System32\whoami.exe' -Reason 'unc test'" },
                @{ Label = 'FilePath fwd UNC'; Cmd = "& '$qCli' -FilePath '//127.0.0.1/c$/Windows/System32/whoami.exe' -Reason 'fwd unc test'" },
                @{ Label = 'FilePath mixed UNC'; Cmd = "& '$qCli' -FilePath '\/127.0.0.1\c$\Windows\System32\whoami.exe' -Reason 'mixed unc test'" },
                @{ Label = 'FilePath Win32 device'; Cmd = "& '$qCli' -FilePath '\\?\C:\Windows\System32\whoami.exe' -Reason 'device test'" },
                @{ Label = 'FilePath pipe device'; Cmd = "& '$qCli' -FilePath '\\.\pipe\foo' -Reason 'pipe test'" },
                @{ Label = 'FilePath provider UNC'; Cmd = "& '$qCli' -FilePath 'Microsoft.PowerShell.Core\FileSystem::\\127.0.0.1\c$\Windows\System32\whoami.exe' -Reason 'provider test'" },
                @{ Label = 'ScriptFile UNC'; Cmd = "& '$qCli' -ScriptFile '\\127.0.0.1\c$\nonexistent.ps1' -Reason 'script unc test'" },
                @{ Label = 'ScriptFile fwd UNC'; Cmd = "& '$qCli' -ScriptFile '//127.0.0.1/c$/nonexistent.ps1' -Reason 'script fwd unc test'" },
                @{ Label = 'ScriptFile Win32 device'; Cmd = "& '$qCli' -ScriptFile '\\?\C:\nonexistent.ps1' -Reason 'script device test'" },
                @{ Label = 'WorkDir UNC'; Cmd = "& '$qCli' -ScriptBlock { Write-Output 'hi' } -WorkDir '\\127.0.0.1\c$\Windows' -Reason 'workdir unc test'" },
                @{ Label = 'WorkDir fwd UNC'; Cmd = "& '$qCli' -ScriptBlock { Write-Output 'hi' } -WorkDir '//127.0.0.1/c$/Windows' -Reason 'workdir fwd unc test'" },
                @{ Label = 'WorkDir Win32 device'; Cmd = "& '$qCli' -ScriptBlock { Write-Output 'hi' } -WorkDir '\\?\C:\Windows' -Reason 'workdir device test'" },
                @{ Label = 'Relative FilePath from HKLM CWD'; Cmd = "Set-Location 'HKLM:\'; & '$qCli' -FilePath '.\whoami.exe' -WorkDir 'C:\Windows' -Reason 'cwd hklm filepath'" },
                @{ Label = 'Relative ScriptFile from HKLM CWD'; Cmd = "Set-Location 'HKLM:\'; & '$qCli' -ScriptFile '.\test.ps1' -WorkDir 'C:\Windows' -Reason 'cwd hklm scriptfile'" },
                @{ Label = 'Relative WorkDir from HKLM CWD'; Cmd = "Set-Location 'HKLM:\'; & '$qCli' -ScriptBlock { Write-Output 'hi' } -WorkDir '.' -Reason 'cwd hklm workdir'" },
                @{ Label = 'Default WorkDir from HKLM CWD'; Cmd = "Set-Location 'HKLM:\'; & '$qCli' -ScriptBlock { Write-Output 'hi' } -Reason 'cwd hklm default workdir'" }
            )

            foreach ($pr in $probes) {
                $res = & $runCliCommand $pr.Cmd $emptyAppData
                if ($res.ExitCode -ne 1206 -or $res.Stdout -notmatch '\[elevated-exec\] OUTCOME=INVALID_ARGS EXIT=1206') {
                    throw "Probe '$($pr.Label)' expected ExitCode=1206 and OUTCOME=INVALID_ARGS EXIT=1206, got exit=$($res.ExitCode) out=$($res.Stdout) err=$($res.Stderr)"
                }
            }

            return "Verified all $($probes.Count) UNC/device/CWD negative CLI probes returned INVALID_ARGS (1206) synchronously"
        }
    }
}
finally {
    Set-Location -LiteralPath $origLocation
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$total = $results.Count
$passedCount = @($results | Where-Object { $_.passed }).Count
$failedCount = $total - $passedCount

if ($JsonReport) {
    $reportObj = [pscustomobject]@{
        module  = 'Test-CliAndSubsystem.ps1'
        summary = [pscustomobject]@{ total = $total; passed = $passedCount; failed = $failedCount }
        results = $results
    }
    $utf8NoBomOut = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($JsonReport, ($reportObj | ConvertTo-Json -Depth 6), $utf8NoBomOut)
}

Write-Host ("Area 3 Summary: {0}/{1} passed ({2} failed)" -f $passedCount, $total, $failedCount)
if ($failedCount -gt 0) { exit 1 }
exit 0
