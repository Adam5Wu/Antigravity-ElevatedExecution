#Requires -Version 5.1
<#
.SYNOPSIS
    Thin CLI client for the elevated-exec Antigravity sidecar broker.

.DESCRIPTION
    Submits elevated PowerShell scripts or allowlisted native executables to the
    elevated-exec sidecar over authenticated loopback HTTP/SSE, streaming live
    UTF-8 output and emitting a deterministic [elevated-exec] OUTCOME=... EXIT=...
    contract.
#>
[CmdletBinding(DefaultParameterSetName = 'ScriptBlock')]
param(
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ScriptBlock')]
    [scriptblock]$ScriptBlock,

    [Parameter(Mandatory = $true, ParameterSetName = 'ScriptText')]
    [string]$ScriptText,

    [Parameter(Mandatory = $true, ParameterSetName = 'ScriptFile')]
    [string]$ScriptFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'FilePath')]
    [string]$FilePath,

    [Parameter(Mandatory = $false, ParameterSetName = 'ScriptFile')]
    [Parameter(Mandatory = $false, ParameterSetName = 'FilePath')]
    [string[]]$ArgumentList = @(),

    [Parameter(Mandatory = $true)]
    [string]$Reason,

    [Parameter(Mandatory = $false)]
    [string]$WorkDir,

    [Parameter(Mandatory = $false)]
    [ValidateSet('auto', 'utf8', 'oem', 'utf16')]
    [string]$Encoding = 'auto',

    [Parameter(Mandatory = $false)]
    [switch]$NormalWindow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Console]::IsOutputRedirected) {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
}

function Exit-WithOutcome {
    param(
        [Parameter(Mandatory = $true)][string]$Outcome,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [string]$Diagnostic = ''
    )
    if (-not [string]::IsNullOrWhiteSpace($Diagnostic)) {
        [Console]::Error.WriteLine($Diagnostic)
        [Console]::Error.Flush()
    }
    [Console]::Out.WriteLine(("[elevated-exec] OUTCOME={0} EXIT={1}" -f $Outcome, $ExitCode))
    [Console]::Out.Flush()
    exit $ExitCode
}

function Escape-PsSingleQuoted {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    return ($Value -replace "'", "''")
}

function Get-PeSubsystemInfo {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "INVALID_ARGS (1206): PE file not found: $Path"
    }
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        if ($fs.Length -lt 64) {
            throw ("INVALID_ARGS (1206): Target binary too small for DOS header ({0} bytes): {1}" -f $fs.Length, $Path)
        }
        $br = New-Object System.IO.BinaryReader($fs)
        $mz = $br.ReadUInt16()
        if ($mz -ne 0x5A4D) {
            throw ("INVALID_ARGS (1206): Invalid DOS signature (0x{0:X4}) in {1}" -f $mz, $Path)
        }
        $fs.Position = 0x3C
        $eLfanew = $br.ReadInt32()
        if ($eLfanew -lt 0 -or ($eLfanew + 94) -gt $fs.Length) {
            throw ("INVALID_ARGS (1206): Invalid PE header offset {0} for {1}" -f $eLfanew, $Path)
        }
        $fs.Position = $eLfanew
        $peSig = $br.ReadUInt32()
        if ($peSig -ne 0x00004550) {
            throw ("INVALID_ARGS (1206): Invalid PE signature (0x{0:X8}) in {1}" -f $peSig, $Path)
        }
        $fs.Position = $eLfanew + 24
        $magic = $br.ReadUInt16()
        if ($magic -ne 0x010B -and $magic -ne 0x020B) {
            throw ("INVALID_ARGS (1206): Unsupported PE OptionalHeader magic (0x{0:X4}) in {1}" -f $magic, $Path)
        }
        $fs.Position = $eLfanew + 92
        $subsystem = $br.ReadUInt16()
        return [pscustomobject]@{
            Magic     = $magic
            Subsystem = $subsystem
        }
    }
    finally {
        $fs.Dispose()
    }
}

function Assert-LocalPathPreCheck {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $true)][string]$ParamName,
        [switch]$CheckCwdForRelative
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "INVALID_ARGS (1206): $ParamName must not be empty or whitespace."
    }
    if ($Path -match '^[a-zA-Z][a-zA-Z0-9+.-]*://' -or ($Path -match '^[a-zA-Z][a-zA-Z0-9+.-]+:' -and $Path -notmatch '^[a-zA-Z]:') -or $Path.Contains('::')) {
        throw "INVALID_ARGS (1206): URI schemes are not allowed in ${ParamName}: $Path"
    }
    if ($Path -match '^\s*[\\/]{2}' -or $Path -match '^\s*\\\?\?\\') {
        throw "INVALID_ARGS (1206): UNC and device paths are not allowed in ${ParamName}: $Path"
    }

    if ($Path -match '^\s*([A-Za-z]):') {
        $driveRoot = ($Matches[1].ToUpperInvariant() + ':\')
        $driveInfo = New-Object System.IO.DriveInfo($driveRoot)
        if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network -or $driveInfo.DriveType -eq [System.IO.DriveType]::Unknown) {
            throw "INVALID_ARGS (1206): Network or unknown drive paths are not allowed in ${ParamName}: $Path"
        }
    }

    if ($CheckCwdForRelative -and ($Path -notmatch '^\s*[A-Za-z]:[\\/]')) {
        $loc = Get-Location
        if ($null -eq $loc -or $null -eq $loc.Provider -or $loc.Provider.Name -ne 'FileSystem') {
            throw "INVALID_ARGS (1206): Non-filesystem current working directory is not allowed for relative path in ${ParamName}: $Path"
        }
        $cwdPath = [string]$loc.ProviderPath
        if ($cwdPath -match '^\s*[\\/]{2}' -or $cwdPath -notmatch '^[A-Za-z]:\\') {
            throw "INVALID_ARGS (1206): UNC or non-drive current working directory ($cwdPath) is not allowed for relative path in ${ParamName}: $Path"
        }
        $cwdRoot = [System.IO.Path]::GetPathRoot($cwdPath)
        if ($cwdRoot -notmatch '^[A-Za-z]:\\$') {
            throw "INVALID_ARGS (1206): Unsupported current drive root '$cwdRoot' for relative path in ${ParamName}: $Path"
        }
        $cwdDrive = New-Object System.IO.DriveInfo($cwdRoot)
        if ($cwdDrive.DriveType -eq [System.IO.DriveType]::Network -or $cwdDrive.DriveType -eq [System.IO.DriveType]::Unknown) {
            throw "INVALID_ARGS (1206): Network or unknown current drive ($cwdRoot) is not allowed for relative path in ${ParamName}: $Path"
        }
    }
}

function Assert-ResolvedLocalPath {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ResolvedPath,
        [Parameter(Mandatory = $true)][string]$ParamName
    )

    if ([string]::IsNullOrWhiteSpace($ResolvedPath) -or $ResolvedPath -match '^\s*[\\/]{2}' -or $ResolvedPath -notmatch '^[A-Za-z]:\\') {
        throw "INVALID_ARGS (1206): Resolved path must be a local drive path in ${ParamName}: $ResolvedPath"
    }
    $root = [System.IO.Path]::GetPathRoot($ResolvedPath)
    if ($root -notmatch '^[A-Za-z]:\\$') {
        throw "INVALID_ARGS (1206): Unsupported drive root '$root' in ${ParamName}: $ResolvedPath"
    }
    $driveInfo = New-Object System.IO.DriveInfo($root)
    if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network -or $driveInfo.DriveType -eq [System.IO.DriveType]::Unknown) {
        throw "INVALID_ARGS (1206): Network or unknown drive paths are not allowed in ${ParamName}: $ResolvedPath"
    }
}

function Resolve-AllowedElevatedTarget {
    param([Parameter(Mandatory = $true)][string]$TargetPath)

    if ([string]::IsNullOrWhiteSpace($TargetPath)) {
        throw 'INVALID_ARGS (1206): -FilePath must not be empty or whitespace.'
    }
    $isQualified = ($TargetPath.Contains('\') -or $TargetPath.Contains('/') -or ($TargetPath -match '^\s*[A-Za-z]:'))
    Assert-LocalPathPreCheck -Path $TargetPath -ParamName '-FilePath' -CheckCwdForRelative:$isQualified
    if ($TargetPath -imatch '\.ps1$') {
        throw "INVALID_ARGS (1206): PowerShell scripts (.ps1) must use -ScriptFile instead of -FilePath: $TargetPath"
    }

    $allowedExts = @('.exe', '.com', '.msc', '.cpl', '.msi')
    $resolved = $null

    if ($isQualified) {
        if (Test-Path -LiteralPath $TargetPath -PathType Container) {
            throw "INVALID_ARGS (1206): Directory path is not allowed in -FilePath: $TargetPath"
        }
        if (-not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
            throw "INVALID_ARGS (1206): Target file not found: $TargetPath"
        }
        $resolvedItem = Resolve-Path -LiteralPath $TargetPath
        if ($resolvedItem.Provider.Name -ne 'FileSystem') {
            throw "INVALID_ARGS (1206): Non-filesystem path is not allowed in -FilePath: $TargetPath"
        }
        $resolved = $resolvedItem.ProviderPath
    }
    else {
        # Strictly resolve unqualified names against System32 and HKLM PATH — NEVER WorkDir or cwd.
        $sys32 = Join-Path $env:SystemRoot 'System32'
        $envRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        $hklmEnv = Get-ItemProperty -LiteralPath $envRegPath
        $hklmPathRaw = if ($hklmEnv.PSObject.Properties['Path']) { [string]$hklmEnv.Path } else { '' }
        $hklmExpanded = [System.Environment]::ExpandEnvironmentVariables($hklmPathRaw)

        $searchDirs = New-Object 'System.Collections.Generic.List[string]'
        $seenDirs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        if ($seenDirs.Add($sys32)) {
            $searchDirs.Add($sys32) | Out-Null
        }
        foreach ($entry in ($hklmExpanded -split ';')) {
            $trimmed = $entry.Trim()
            if ($trimmed -and $seenDirs.Add($trimmed)) {
                $searchDirs.Add($trimmed) | Out-Null
            }
        }

        $hasExt = -not [string]::IsNullOrEmpty([System.IO.Path]::GetExtension($TargetPath))
        $probeNames = New-Object 'System.Collections.Generic.List[string]'
        if ($hasExt) {
            $probeNames.Add($TargetPath) | Out-Null
        }
        else {
            $probeNames.Add($TargetPath) | Out-Null
            $pathextRaw = if ($hklmEnv.PSObject.Properties['PATHEXT']) { [string]$hklmEnv.PATHEXT } else { '.COM;.EXE;.BAT;.CMD;.MSC;.CPL;.MSI' }
            $seenExts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($pe in ($pathextRaw -split ';')) {
                $tpe = $pe.Trim()
                if ($tpe -and $seenExts.Add($tpe)) {
                    $probeNames.Add(($TargetPath + $tpe)) | Out-Null
                }
            }
            foreach ($extraExt in @('.MSC', '.CPL', '.MSI')) {
                if ($seenExts.Add($extraExt)) {
                    $probeNames.Add(($TargetPath + $extraExt)) | Out-Null
                }
            }
        }

        foreach ($dir in $searchDirs) {
            if ($dir -match '^\s*[\\/]{2}' -or $dir -notmatch '^[A-Za-z]:\\') {
                continue
            }
            $dirDrive = New-Object System.IO.DriveInfo(([System.IO.Path]::GetPathRoot($dir)))
            if ($dirDrive.DriveType -eq [System.IO.DriveType]::Network -or $dirDrive.DriveType -eq [System.IO.DriveType]::Unknown) {
                continue
            }
            if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
                continue
            }
            foreach ($probe in $probeNames) {
                $candidate = Join-Path $dir $probe
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    $resolved = (Resolve-Path -LiteralPath $candidate).ProviderPath
                    break
                }
            }
            if ($resolved) { break }
        }

        if (-not $resolved) {
            throw "INVALID_ARGS (1206): Unqualified target '$TargetPath' not found in System32 or HKLM PATH."
        }
    }

    Assert-ResolvedLocalPath -ResolvedPath $resolved -ParamName '-FilePath'

    if (Test-Path -LiteralPath $resolved -PathType Container) {
        throw "INVALID_ARGS (1206): Directory path is not allowed in -FilePath: $resolved"
    }

    $ext = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
    if ($ext -eq '.ps1') {
        throw "INVALID_ARGS (1206): PowerShell scripts (.ps1) must use -ScriptFile instead of -FilePath: $resolved"
    }
    if ($allowedExts -notcontains $ext) {
        throw ("INVALID_ARGS (1206): Disallowed extension '{0}' (allowed: {1}): {2}" -f $ext, ($allowedExts -join ', '), $resolved)
    }

    $subsystemTag = switch ($ext) {
        '.msc' { 'MSC' }
        '.cpl' { 'CPL' }
        '.msi' { 'MSI' }
        default {
            $pe = Get-PeSubsystemInfo -Path $resolved
            if ($pe.Subsystem -eq 3) { 'CUI' }
            elseif ($pe.Subsystem -eq 2) { 'GUI' }
            else { throw ("INVALID_ARGS (1206): Unsupported PE subsystem ({0}) on {1}" -f $pe.Subsystem, $resolved) }
        }
    }

    $publisher = 'Unsigned'
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $resolved
        if ($sig -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject) {
            $publisher = [string]$sig.SignerCertificate.Subject
        }
    }
    catch {
        $publisher = 'Unsigned'
    }

    return [ordered]@{
        originalPath  = $TargetPath
        canonicalPath = $resolved
        extension     = $ext
        subsystem     = $subsystemTag
        publisher     = $publisher
    }
}

function New-ElevatedWrapperScript {
    param(
        [Parameter(Mandatory = $true)]$TargetMeta,
        [string[]]$ArgList = @()
    )
    $qPath = Escape-PsSingleQuoted $TargetMeta.canonicalPath
    switch ($TargetMeta.subsystem) {
        'CUI' {
            if ($ArgList -and $ArgList.Count -gt 0) {
                $argTokens = ($ArgList | ForEach-Object { "'" + (Escape-PsSingleQuoted $_) + "'" }) -join ' '
                return "& '$qPath' $argTokens`r`nexit `$LASTEXITCODE"
            }
            return "& '$qPath'`r`nexit `$LASTEXITCODE"
        }
        { $_ -in @('GUI', 'MSC', 'CPL') } {
            if ($ArgList -and $ArgList.Count -gt 0) {
                $argTokens = ($ArgList | ForEach-Object { "'" + (Escape-PsSingleQuoted $_) + "'" }) -join ', '
                return "`$p = Start-Process -FilePath '$qPath' -ArgumentList @($argTokens) -Wait -PassThru`r`nexit `$p.ExitCode"
            }
            return "`$p = Start-Process -FilePath '$qPath' -Wait -PassThru`r`nexit `$p.ExitCode"
        }
        'MSI' {
            $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
            $qMsi = Escape-PsSingleQuoted $msiexec
            $allArgs = New-Object 'System.Collections.Generic.List[string]'
            $allArgs.Add('/i') | Out-Null
            $allArgs.Add($TargetMeta.canonicalPath) | Out-Null
            if ($ArgList) {
                foreach ($a in $ArgList) {
                    $allArgs.Add([string]$a) | Out-Null
                }
            }
            $argTokens = ($allArgs | ForEach-Object { "'" + (Escape-PsSingleQuoted $_) + "'" }) -join ', '
            return "`$p = Start-Process -FilePath '$qMsi' -ArgumentList @($argTokens) -Wait -PassThru`r`nexit `$p.ExitCode"
        }
        default {
            throw "INVALID_ARGS (1206): Unsupported subsystem '$($TargetMeta.subsystem)'."
        }
    }
}

function Read-ScriptFileStrict {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$EncodingHint
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'INVALID_ARGS (1206): -ScriptFile must not be empty or whitespace.'
    }
    Assert-LocalPathPreCheck -Path $Path -ParamName '-ScriptFile' -CheckCwdForRelative
    if (Test-Path -LiteralPath $Path -PathType Container) {
        throw "INVALID_ARGS (1206): Directory path is not allowed in -ScriptFile: $Path"
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "INVALID_ARGS (1206): ScriptFile not found: $Path"
    }

    $resolvedItem = Resolve-Path -LiteralPath $Path
    if ($resolvedItem.Provider.Name -ne 'FileSystem') {
        throw "INVALID_ARGS (1206): Non-filesystem path is not allowed in -ScriptFile: $Path"
    }
    $resolvedPath = $resolvedItem.ProviderPath
    Assert-ResolvedLocalPath -ResolvedPath $resolvedPath -ParamName '-ScriptFile'

    $bytes = [System.IO.File]::ReadAllBytes($resolvedPath)
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)

    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $text = $strictUtf8.GetString($bytes, 3, $bytes.Length - 3)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $text = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    elseif ($EncodingHint -eq 'utf16') {
        $text = [System.Text.Encoding]::Unicode.GetString($bytes)
    }
    elseif ($EncodingHint -eq 'oem') {
        $oemCp = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage
        if ($oemCp -le 0) { $oemCp = 936 }
        $text = [System.Text.Encoding]::GetEncoding($oemCp).GetString($bytes)
    }
    else {
        try {
            $text = $strictUtf8.GetString($bytes)
        }
        catch [System.Text.DecoderFallbackException] {
            throw "INVALID_ARGS (1206): -ScriptFile '$resolvedPath' contains invalid UTF-8 bytes (use UTF-8 or pass -Encoding oem for CP936)."
        }
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "INVALID_ARGS (1206): -ScriptFile is empty: $resolvedPath"
    }
    return $text
}

function Get-SanitizedSourceMetadata {
    $conversationId = ''
    $stepIndex = 0
    $toolCallId = ''

    $raw = [Environment]::GetEnvironmentVariable('ANTIGRAVITY_SOURCE_METADATA')
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        try {
            $parsed = $raw | ConvertFrom-Json
            if ($parsed) {
                $toolObj = if ($parsed.PSObject.Properties['tool'] -and $parsed.tool) { $parsed.tool } else { $parsed }
                if ($toolObj.PSObject.Properties['conversationId'] -and $null -ne $toolObj.conversationId) {
                    $conversationId = [string]$toolObj.conversationId
                }
                if ($toolObj.PSObject.Properties['stepIndex'] -and $null -ne $toolObj.stepIndex) {
                    $tmpStep = 0
                    if ([int]::TryParse([string]$toolObj.stepIndex, [ref]$tmpStep)) {
                        $stepIndex = $tmpStep
                    }
                }
                if ($toolObj.PSObject.Properties['toolCall'] -and $toolObj.toolCall -and $toolObj.toolCall.PSObject.Properties['id'] -and $null -ne $toolObj.toolCall.id) {
                    $toolCallId = [string]$toolObj.toolCall.id
                }
                elseif ($toolObj.PSObject.Properties['toolCallId'] -and $null -ne $toolObj.toolCallId) {
                    $toolCallId = [string]$toolObj.toolCallId
                }
            }
        }
        catch {
            # Ignore malformed ANTIGRAVITY_SOURCE_METADATA
        }
    }

    if ([string]::IsNullOrWhiteSpace($conversationId)) {
        $envConv = [Environment]::GetEnvironmentVariable('ANTIGRAVITY_CONVERSATION_ID')
        if (-not [string]::IsNullOrWhiteSpace($envConv)) {
            $conversationId = $envConv.Trim()
        }
    }

    return [ordered]@{
        conversationId = $conversationId
        stepIndex      = $stepIndex
        toolCallId     = $toolCallId
    }
}

function Get-BrokerRuntimeInfo {
    $execDataDir = [Environment]::GetEnvironmentVariable('ANTIGRAVITY_EXECUTABLE_DATA_DIR')
    if (-not [string]::IsNullOrWhiteSpace($execDataDir)) {
        $runtimePath = Join-Path $execDataDir 'runtime.json'
    }
    else {
        $appDataDir = [Environment]::GetEnvironmentVariable('ANTIGRAVITY_APP_DATA_DIR')
        if ([string]::IsNullOrWhiteSpace($appDataDir)) {
            $appDataDir = Join-Path $HOME '.gemini\antigravity'
        }
        $runtimePath = Join-Path $appDataDir 'sidecar_data\elevated-exec\broker\data\runtime.json'
    }

    if (-not (Test-Path -LiteralPath $runtimePath -PathType Leaf)) {
        return $null
    }

    try {
        $raw = [System.IO.File]::ReadAllText($runtimePath, (New-Object System.Text.UTF8Encoding($false, $true)))
        $rt = $raw | ConvertFrom-Json
        if (-not $rt) { return $null }
        $port = 0
        $brokerPid = 0
        if (-not $rt.PSObject.Properties['port'] -or -not [int]::TryParse([string]$rt.port, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
            return $null
        }
        if (-not $rt.PSObject.Properties['token'] -or [string]::IsNullOrWhiteSpace([string]$rt.token)) {
            return $null
        }
        if (-not $rt.PSObject.Properties['pid'] -or -not [int]::TryParse([string]$rt.pid, [ref]$brokerPid) -or $brokerPid -le 0) {
            return $null
        }
        $proc = Get-Process -Id $brokerPid -ErrorAction SilentlyContinue
        if (-not $proc) {
            return $null
        }
        return [pscustomobject]@{
            Port  = $port
            Token = [string]$rt.token
            Pid   = $brokerPid
        }
    }
    catch {
        return $null
    }
}

# --- 1. Validate arguments & build request payload ---
$mode = $PSCmdlet.ParameterSetName
$scriptBody = ''
$payloadArgs = [string[]]@()
$targetMeta = $null
$resolvedWorkDir = ''

try {
    if ([string]::IsNullOrWhiteSpace($Reason)) {
        throw 'INVALID_ARGS (1206): -Reason must not be empty or whitespace.'
    }

    if ($PSBoundParameters.ContainsKey('WorkDir')) {
        if ([string]::IsNullOrWhiteSpace($WorkDir)) {
            throw 'INVALID_ARGS (1206): -WorkDir must not be empty or whitespace when specified.'
        }
        Assert-LocalPathPreCheck -Path $WorkDir -ParamName '-WorkDir' -CheckCwdForRelative
        if (-not (Test-Path -LiteralPath $WorkDir -PathType Container)) {
            throw "INVALID_ARGS (1206): -WorkDir does not exist or is not a directory: $WorkDir"
        }
        $wdItem = Resolve-Path -LiteralPath $WorkDir
        if ($wdItem.Provider.Name -ne 'FileSystem') {
            throw "INVALID_ARGS (1206): -WorkDir must be a local filesystem directory: $WorkDir"
        }
        $resolvedWorkDir = $wdItem.ProviderPath
        Assert-ResolvedLocalPath -ResolvedPath $resolvedWorkDir -ParamName '-WorkDir'
    }
    else {
        $loc = Get-Location
        if ($null -eq $loc -or $null -eq $loc.Provider -or $loc.Provider.Name -ne 'FileSystem') {
            throw 'INVALID_ARGS (1206): Current working directory must be a local filesystem directory.'
        }
        $resolvedWorkDir = $loc.ProviderPath
        Assert-ResolvedLocalPath -ResolvedPath $resolvedWorkDir -ParamName '-WorkDir'
    }

    if (-not [System.IO.Directory]::Exists($resolvedWorkDir)) {
        throw "INVALID_ARGS (1206): -WorkDir is not an accessible directory: $resolvedWorkDir"
    }

    switch ($mode) {
        'ScriptBlock' {
            $scriptBody = $ScriptBlock.ToString()
            if ([string]::IsNullOrWhiteSpace($scriptBody)) {
                throw 'INVALID_ARGS (1206): -ScriptBlock must not be empty.'
            }
            $payloadArgs = [string[]]@()
            $targetMeta = $null
        }
        'ScriptText' {
            $scriptBody = $ScriptText
            if ([string]::IsNullOrWhiteSpace($scriptBody)) {
                throw 'INVALID_ARGS (1206): -ScriptText must not be empty or whitespace.'
            }
            $payloadArgs = [string[]]@()
            $targetMeta = $null
        }
        'ScriptFile' {
            $scriptBody = Read-ScriptFileStrict -Path $ScriptFile -EncodingHint $Encoding
            $payloadArgs = if ($null -ne $ArgumentList) { [string[]]$ArgumentList } else { [string[]]@() }
            $targetMeta = $null
        }
        'FilePath' {
            $targetMeta = Resolve-AllowedElevatedTarget -TargetPath $FilePath
            $argSlice = if ($null -ne $ArgumentList) { [string[]]$ArgumentList } else { [string[]]@() }
            $scriptBody = New-ElevatedWrapperScript -TargetMeta $targetMeta -ArgList $argSlice
            $payloadArgs = [string[]]@()
        }
        default {
            throw "INVALID_ARGS (1206): Unknown parameter set '$mode'."
        }
    }
}
catch {
    Exit-WithOutcome -Outcome 'INVALID_ARGS' -ExitCode 1206 -Diagnostic $_.Exception.Message
}

# --- 2. Locate and verify live sidecar broker ---
$runtime = Get-BrokerRuntimeInfo
if ($null -eq $runtime) {
    Exit-WithOutcome -Outcome 'SIDECAR_UNAVAILABLE' -ExitCode 1203 -Diagnostic 'SIDECAR_UNAVAILABLE (1203): elevated-exec sidecar broker is not running or runtime.json is unavailable.'
}

# --- 3. Serialize payload & POST over .NET 4.8 HttpWebRequest ---
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$sourceMeta = Get-SanitizedSourceMetadata

$payload = [ordered]@{
    mode         = $mode
    reason       = $Reason
    script       = $scriptBody
    args         = @($payloadArgs)
    workDir      = $resolvedWorkDir
    encoding     = $Encoding
    normalWindow = [bool]$NormalWindow
    targetMeta   = $targetMeta
    sourceMeta   = $sourceMeta
}

$jsonBody = $payload | ConvertTo-Json -Depth 6 -Compress
$bodyBytes = $utf8NoBom.GetBytes($jsonBody)

$url = "http://127.0.0.1:$($runtime.Port)/ipc/requests"
$req = [System.Net.HttpWebRequest]::Create($url)
$req.Method = 'POST'
$req.ContentType = 'application/json; charset=utf-8'
$req.Accept = 'text/event-stream'
$req.Headers.Add('Authorization', "Bearer $($runtime.Token)")
$req.Proxy = $null
$req.ServicePoint.Expect100Continue = $false
$req.Timeout = [System.Threading.Timeout]::Infinite
$req.ReadWriteTimeout = [System.Threading.Timeout]::Infinite
$req.ContentLength = $bodyBytes.Length

$resp = $null
try {
    $reqStream = $req.GetRequestStream()
    try {
        $reqStream.Write($bodyBytes, 0, $bodyBytes.Length)
    }
    finally {
        $reqStream.Close()
    }
    $resp = $req.GetResponse()
}
catch [System.Net.WebException] {
    $webEx = $_.Exception
    if ($null -eq $webEx.Response) {
        Exit-WithOutcome -Outcome 'SIDECAR_UNAVAILABLE' -ExitCode 1203 -Diagnostic ("SIDECAR_UNAVAILABLE (1203): Failed to connect to elevated-exec broker: {0}" -f $webEx.Message)
    }

    $errResp = [System.Net.HttpWebResponse]$webEx.Response
    $statusCode = [int]$errResp.StatusCode
    $errBody = ''
    try {
        $errStream = $errResp.GetResponseStream()
        if ($null -ne $errStream) {
            $errReader = New-Object System.IO.StreamReader($errStream, $utf8NoBom)
            try {
                $errBody = $errReader.ReadToEnd()
            }
            finally {
                $errReader.Dispose()
            }
        }
    }
    catch {
        $errBody = ''
    }
    finally {
        $errResp.Close()
    }

    if ($statusCode -eq 409) {
        try {
            $errJson = $errBody | ConvertFrom-Json
            if ($errJson -and $errJson.PSObject.Properties['outcome'] -and $errJson.PSObject.Properties['exitCode']) {
                $msg = if ($errJson.PSObject.Properties['message'] -and $errJson.message) { [string]$errJson.message } else { '' }
                Exit-WithOutcome -Outcome ([string]$errJson.outcome) -ExitCode ([int]$errJson.exitCode) -Diagnostic $msg
            }
        }
        catch {
            # Fall through to default 409 handling below
        }
        Exit-WithOutcome -Outcome 'SESSION_NOT_INTERACTIVE' -ExitCode 1202 -Diagnostic $errBody
    }
    elseif ($statusCode -eq 401) {
        Exit-WithOutcome -Outcome 'SIDECAR_UNAVAILABLE' -ExitCode 1203 -Diagnostic 'SIDECAR_UNAVAILABLE (1203): Broker rejected bearer token (HTTP 401).'
    }
    elseif ($statusCode -eq 400 -or $statusCode -eq 413) {
        $msg = $errBody
        try {
            $errJson = $errBody | ConvertFrom-Json
            if ($errJson -and $errJson.PSObject.Properties['message'] -and $errJson.message) {
                $msg = [string]$errJson.message
            }
        }
        catch {}
        Exit-WithOutcome -Outcome 'INVALID_ARGS' -ExitCode 1206 -Diagnostic $msg
    }
    else {
        Exit-WithOutcome -Outcome 'SIDECAR_UNAVAILABLE' -ExitCode 1203 -Diagnostic ("SIDECAR_UNAVAILABLE (1203): Unexpected broker HTTP {0}: {1}" -f $statusCode, $errBody)
    }
}
catch {
    Exit-WithOutcome -Outcome 'SIDECAR_UNAVAILABLE' -ExitCode 1203 -Diagnostic ("SIDECAR_UNAVAILABLE (1203): IPC request error: {0}" -f $_.Exception.Message)
}

# --- 4. Stream SSE events line-by-line ---
$finalOutcome = $null
$finalExitCode = $null
$finalMessage = ''

$dispatchSseEvent = {
    param([string]$EventName, [string]$DataPayload)
    if ([string]::IsNullOrWhiteSpace($DataPayload)) { return }
    $evt = $null
    try {
        $evt = $DataPayload | ConvertFrom-Json
    }
    catch {
        return
    }
    if (-not $evt) { return }

    switch ($EventName) {
        'pending' {
            $reqId = if ($evt.PSObject.Properties['requestId']) { [string]$evt.requestId } else { '' }
            [Console]::Out.WriteLine("ELEVATION_PENDING: $reqId")
            [Console]::Out.Flush()
        }
        'stdout' {
            if ($evt.PSObject.Properties['text'] -and $null -ne $evt.text) {
                $txt = [string]$evt.text
                if ($txt.Length -gt 0) {
                    [Console]::Out.Write($txt)
                    [Console]::Out.Flush()
                }
            }
        }
        'stderr' {
            if ($evt.PSObject.Properties['text'] -and $null -ne $evt.text) {
                $txt = [string]$evt.text
                if ($txt.Length -gt 0) {
                    [Console]::Error.Write($txt)
                    [Console]::Error.Flush()
                }
            }
        }
        'outcome' {
            if ($evt.PSObject.Properties['outcome'] -and $null -ne $evt.outcome) {
                $script:finalOutcome = [string]$evt.outcome
            }
            if ($evt.PSObject.Properties['exitCode'] -and $null -ne $evt.exitCode) {
                $script:finalExitCode = [int]$evt.exitCode
            }
            if ($evt.PSObject.Properties['message'] -and $null -ne $evt.message) {
                $script:finalMessage = [string]$evt.message
            }
        }
    }
}

try {
    $respStream = $resp.GetResponseStream()
    $sr = New-Object System.IO.StreamReader($respStream, $utf8NoBom)
    try {
        $currentEvent = ''
        $dataLines = New-Object 'System.Collections.Generic.List[string]'

        while ($null -ne ($line = $sr.ReadLine())) {
            if ($line -eq '') {
                if ($dataLines.Count -gt 0) {
                    $evtName = if ($currentEvent) { $currentEvent } else { 'message' }
                    $evtData = $dataLines -join "`n"
                    & $dispatchSseEvent $evtName $evtData
                    $currentEvent = ''
                    $dataLines.Clear()
                }
                continue
            }
            if ($line.StartsWith(':')) {
                continue
            }
            if ($line.StartsWith('event:')) {
                $currentEvent = $line.Substring(6).Trim()
            }
            elseif ($line.StartsWith('data:')) {
                $val = $line.Substring(5)
                if ($val.StartsWith(' ')) {
                    $val = $val.Substring(1)
                }
                $dataLines.Add($val) | Out-Null
            }
        }

        if ($dataLines.Count -gt 0) {
            $evtName = if ($currentEvent) { $currentEvent } else { 'message' }
            $evtData = $dataLines -join "`n"
            & $dispatchSseEvent $evtName $evtData
        }
    }
    finally {
        $sr.Dispose()
    }
}
catch [System.IO.IOException], [System.Net.WebException], [Exception] {
    if ($null -eq $finalOutcome -or $null -eq $finalExitCode) {
        Exit-WithOutcome -Outcome 'SIDECAR_UNAVAILABLE' -ExitCode 1203 -Diagnostic ("SIDECAR_UNAVAILABLE (1203): SSE stream interrupted: {0}" -f $_.Exception.Message)
    }
}
finally {
    if ($null -ne $resp) {
        $resp.Close()
    }
}

if ($null -ne $finalOutcome -and $null -ne $finalExitCode) {
    $diag = ''
    if ($finalOutcome -ne 'COMPLETED' -and $finalExitCode -ne 0 -and -not [string]::IsNullOrWhiteSpace($finalMessage)) {
        $diag = $finalMessage
    }
    Exit-WithOutcome -Outcome $finalOutcome -ExitCode $finalExitCode -Diagnostic $diag
}

Exit-WithOutcome -Outcome 'SIDECAR_UNAVAILABLE' -ExitCode 1203 -Diagnostic 'SIDECAR_UNAVAILABLE (1203): SSE stream ended without an outcome event.'
