<#
.SYNOPSIS
Areas 2 & 6: Manifest Freezing, SHA-256 Parity, Tamper/Size/Reparse Rejection, Win32 Pre-Flight, Raw-SID ACLs, Pipe SDDL, and unchecked((int)code).
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

# Compile Win32 Pre-Flight + Integer Cast C# helper
$win32Source = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AeTestWin32 {
    public static class Probe {
        private const uint DESKTOP_READOBJECTS = 0x0001;
        private const int UOI_NAME = 2;
        private const int WTS_CURRENT_SESSION = -1;
        private const int WTSConnectState = 8;
        private const int WTSSessionInfoEx = 25;

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetThreadDesktop(uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetUserObjectInformationW(
            IntPtr hObj, int nIndex, StringBuilder pvInfo, int nLength, out int lpnLengthNeeded);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WTSQuerySessionInformationW(
            IntPtr hServer, int sessionId, int wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        private static string GetObjectName(IntPtr handle) {
            if (handle == IntPtr.Zero) return null;
            int needed = 0;
            StringBuilder sb = new StringBuilder(256);
            if (!GetUserObjectInformationW(handle, UOI_NAME, sb, sb.Capacity * 2, out needed)) {
                return null;
            }
            return sb.ToString();
        }

        public static string GetWinStationName() {
            return GetObjectName(GetProcessWindowStation());
        }

        public static string GetThreadDesktopName() {
            return GetObjectName(GetThreadDesktop(GetCurrentThreadId()));
        }

        public static void QueryInputDesktop(out bool ok, out string name, out int win32Error) {
            ok = false;
            name = null;
            win32Error = 0;
            IntPtr hDesk = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);
            if (hDesk == IntPtr.Zero) {
                win32Error = Marshal.GetLastWin32Error();
                return;
            }
            try {
                name = GetObjectName(hDesk);
                ok = !string.IsNullOrEmpty(name);
                if (!ok) win32Error = Marshal.GetLastWin32Error();
            } finally {
                CloseDesktop(hDesk);
            }
        }

        public static void QueryWtsState(
            out bool connectOk, out int connectState,
            out bool infoExOk, out int infoExBytes, out int level, out int sessionFlags) {
            connectOk = false;
            connectState = -1;
            infoExOk = false;
            infoExBytes = 0;
            level = -1;
            sessionFlags = -1;

            IntPtr pConn = IntPtr.Zero;
            int connBytes = 0;
            if (WTSQuerySessionInformationW(IntPtr.Zero, WTS_CURRENT_SESSION, WTSConnectState, out pConn, out connBytes)) {
                try {
                    if (connBytes >= 4 && pConn != IntPtr.Zero) {
                        connectState = Marshal.ReadInt32(pConn, 0);
                        connectOk = true;
                    }
                } finally {
                    WTSFreeMemory(pConn);
                }
            }

            IntPtr pEx = IntPtr.Zero;
            int exBytes = 0;
            if (WTSQuerySessionInformationW(IntPtr.Zero, WTS_CURRENT_SESSION, WTSSessionInfoEx, out pEx, out exBytes)) {
                try {
                    infoExBytes = exBytes;
                    if (exBytes >= 20 && pEx != IntPtr.Zero) {
                        level = Marshal.ReadInt32(pEx, 0);
                        sessionFlags = Marshal.ReadInt32(pEx, 16);
                        infoExOk = true;
                    }
                } finally {
                    WTSFreeMemory(pEx);
                }
            }
        }

        public static int UncheckedCastUInt32(uint code) {
            return unchecked((int)code);
        }
    }
}
'@
Add-Type -TypeDefinition $win32Source -Language CSharp

function Get-Sha256HexFromBytes {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
        return ([System.BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant())
    }
    finally {
        $sha.Dispose()
    }
}

function Quote-ArgWin32 {
    param([string]$Arg)
    if ($null -eq $Arg -or $Arg.Length -eq 0) { return '""' }
    if ($Arg -notmatch '[\s"]') { return $Arg }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('"')
    $bsCount = 0
    for ($i = 0; $i -lt $Arg.Length; $i++) {
        $ch = $Arg[$i]
        if ($ch -eq '\') {
            $bsCount++
        }
        elseif ($ch -eq '"') {
            if ($bsCount -gt 0) { $null = $sb.Append('\', $bsCount * 2) }
            $bsCount = 0
            $null = $sb.Append('\"')
        }
        else {
            if ($bsCount -gt 0) { $null = $sb.Append('\', $bsCount); $bsCount = 0 }
            $null = $sb.Append($ch)
        }
    }
    if ($bsCount -gt 0) { $null = $sb.Append('\', $bsCount * 2) }
    $null = $sb.Append('"')
    return $sb.ToString()
}

function Test-NoReparsePointChain {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [string]$StopAtRoot
    )
    $full = [System.IO.Path]::GetFullPath($TargetPath)
    $cur = $full
    while ($cur) {
        if (Test-Path -LiteralPath $cur) {
            $attr = [System.IO.File]::GetAttributes($cur)
            if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "ReparsePoint detected at path segment: $cur"
            }
        }
        if ($StopAtRoot -and ($cur.TrimEnd('\') -ieq $StopAtRoot.TrimEnd('\'))) {
            break
        }
        $parent = [System.IO.Path]::GetDirectoryName($cur)
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
}

function Invoke-VerifiedManifestRead {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestFile,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [int]$MaxBytes = 10485760,
        [string]$ReparseStopRoot
    )
    if (-not (Test-Path -LiteralPath $ManifestFile -PathType Leaf)) {
        throw "RUNNER_ERROR: ManifestFile not found: $ManifestFile"
    }
    Test-NoReparsePointChain -TargetPath $ManifestFile -StopAtRoot $ReparseStopRoot

    $fi = New-Object System.IO.FileInfo($ManifestFile)
    if ($fi.Length -gt $MaxBytes) {
        throw "RUNNER_ERROR: ManifestFile exceeds $MaxBytes bytes ($($fi.Length) bytes)"
    }

    $bytes = [System.IO.File]::ReadAllBytes($ManifestFile)
    if ($bytes.Length -gt $MaxBytes) {
        throw "RUNNER_ERROR: Manifest bytes exceed $MaxBytes"
    }
    $actualSha = Get-Sha256HexFromBytes -Bytes $bytes
    if ($actualSha -ine $ExpectedSha256) {
        throw "SHA256_MISMATCH: expected=$ExpectedSha256 actual=$actualSha"
    }

    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $jsonText = $strictUtf8.GetString($bytes)
    $manifest = $jsonText | ConvertFrom-Json -ErrorAction Stop
    if (-not $manifest.workDir -or -not (Test-Path -LiteralPath $manifest.workDir -PathType Container)) {
        throw "RUNNER_ERROR: Invalid workDir container: $($manifest.workDir)"
    }
    return [pscustomobject]@{
        Sha256   = $actualSha
        BytesLen = $bytes.Length
        Manifest = $manifest
    }
}

function Evaluate-PreflightState {
    param(
        [int]$SessionId,
        [string]$WinSta,
        [string]$ThreadDesktop,
        [bool]$RequireDefaultThreadDesktop = $true,
        [bool]$ConnectOk,
        [int]$ConnectState,
        [bool]$InfoExOk,
        [int]$InfoExBytes,
        [int]$Level,
        [int]$SessionFlags,
        [bool]$InputDesktopOk,
        [string]$InputDesktopName,
        [int]$InputDesktopError
    )
    if ($SessionId -eq 0) {
        return [pscustomobject]@{ ok = $false; code = 'E_SESSION_NOT_INTERACTIVE'; exitCode = 1202; detail = 'SessionId is 0 (Services)' }
    }
    if ($WinSta -cne 'WinSta0') {
        return [pscustomobject]@{ ok = $false; code = 'E_SESSION_NOT_INTERACTIVE'; exitCode = 1202; detail = "WinSta=$WinSta (expected WinSta0)" }
    }
    if ($RequireDefaultThreadDesktop -and ($ThreadDesktop -cne 'Default')) {
        return [pscustomobject]@{ ok = $false; code = 'E_SESSION_NOT_INTERACTIVE'; exitCode = 1202; detail = "ThreadDesktop=$ThreadDesktop (expected Default)" }
    }
    if (-not $ConnectOk -or $ConnectState -ne 0) {
        return [pscustomobject]@{ ok = $false; code = 'E_SESSION_NOT_INTERACTIVE'; exitCode = 1202; detail = "WTSConnectState=$ConnectState (expected 0 WTSActive)" }
    }
    if (-not $InfoExOk -or $InfoExBytes -lt 20 -or $Level -ne 1 -or $SessionFlags -ne 1) {
        return [pscustomobject]@{ ok = $false; code = 'E_SESSION_NOT_INTERACTIVE'; exitCode = 1202; detail = "WTSSessionInfoEx invalid (ok=$InfoExOk bytes=$InfoExBytes level=$Level flags=$SessionFlags)" }
    }
    if (-not $InputDesktopOk -or $InputDesktopName -cne 'Default') {
        return [pscustomobject]@{ ok = $false; code = 'E_SESSION_NOT_INTERACTIVE'; exitCode = 1202; detail = "OpenInputDesktop failed or non-Default (name=$InputDesktopName err=$InputDesktopError)" }
    }
    return [pscustomobject]@{ ok = $true; code = 'OK'; exitCode = 0; detail = 'Interactive WinSta0\Default unlocked' }
}

function Test-RawSidDirectorySecurity {
    param(
        [Parameter(Mandatory = $true)][string]$DirPath,
        [Parameter(Mandatory = $true)][string[]]$TrustedOwnerSids,
        [bool]$RequireProtected = $true,
        [string]$StopAtRoot
    )
    if (-not (Test-Path -LiteralPath $DirPath -PathType Container)) {
        throw "E_RUNNER_INVALID: Directory missing: $DirPath"
    }
    Test-NoReparsePointChain -TargetPath $DirPath -StopAtRoot $StopAtRoot

    $acl = [System.IO.Directory]::GetAccessControl($DirPath)
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($TrustedOwnerSids -notcontains $ownerSid) {
        throw "E_RUNNER_INVALID: Untrusted owner SID $ownerSid on $DirPath"
    }
    if ($RequireProtected -and -not $acl.AreAccessRulesProtected) {
        throw "E_RUNNER_INVALID: Inheritance must be disabled on $DirPath"
    }

    $trustedWriteSids = @(
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
    $dangerousRights = (
        [System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    )

    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $rule.IdentityReference.Value
        if ($trustedWriteSids -contains $sid) { continue }
        # Ignore InheritOnly on CREATOR OWNER (S-1-3-0)
        if ($sid -eq 'S-1-3-0' -and (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)) {
            continue
        }
        if (($rule.FileSystemRights -band $dangerousRights) -ne 0) {
            throw "E_RUNNER_INVALID: Non-admin write/ACL ACE for SID $sid ($($rule.FileSystemRights)) on $DirPath"
        }
    }
    return $ownerSid
}

function New-HardenedPipeSecurity {
    $ps = New-Object System.IO.Pipes.PipeSecurity
    $ps.SetAccessRuleProtection($true, $false)

    $sidNet = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-2')
    $sidOw = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4')
    $sidSys = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $sidBa = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')

    $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($sidNet, [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Deny)))
    $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($sidOw, [System.IO.Pipes.PipeAccessRights]::Synchronize, [System.Security.AccessControl.AccessControlType]::Allow)))
    $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($sidSys, [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
    $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($sidBa, [System.IO.Pipes.PipeAccessRights]::ReadWrite, [System.Security.AccessControl.AccessControlType]::Allow)))
    return $ps
}

$tempRoot = Join-Path $env:TEMP ("ae-area26-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$junctionsToCleanup = New-Object 'System.Collections.Generic.List[string]'

try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    # ==================== AREA 2: MANIFEST & SHA-256 ====================

    Invoke-TestCase -Id 'A2-T1-01' -Area '2' -Tier 1 -Name 'Canonical manifest freezing produces 64-hex SHA-256 and parses cleanly' -Body {
        $work = Join-Path $tempRoot 'work_t1'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $manifestPath = Join-Path $tempRoot 'manifest_t1.json'
        $obj = [ordered]@{
            script   = "Write-Output 'ok'`nexit 0"
            args     = @('-Name', 'AIMtkRD')
            workDir  = $work
            encoding = 'auto'
        }
        $json = $obj | ConvertTo-Json -Compress
        [System.IO.File]::WriteAllText($manifestPath, $json, $utf8NoBom)
        $sha = Get-Sha256HexFromBytes -Bytes ([System.IO.File]::ReadAllBytes($manifestPath))
        if ($sha -notmatch '^[0-9a-f]{64}$') { throw "Invalid SHA-256 format: $sha" }
        $v = Invoke-VerifiedManifestRead -ManifestFile $manifestPath -ExpectedSha256 $sha -ReparseStopRoot $tempRoot
        if ($v.Manifest.encoding -ne 'auto') { throw 'Encoding mismatch' }
        return "Verified 64-hex SHA-256: $sha"
    }

    Invoke-TestCase -Id 'A2-T1-02' -Area '2' -Tier 1 -Name 'Node vs PS 5.1 SHA-256 parity on zh-CN and special HTML/shell chars' -Body {
        if (-not (Test-Path -LiteralPath $AgyNodePath -PathType Leaf)) {
            throw "agy-node.cmd not found at $AgyNodePath"
        }
        $work = Join-Path $tempRoot 'space dir'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $manifestPath = Join-Path $tempRoot 'node_frozen.json'

        $nodeScript = @"
import fs from 'node:fs';
import crypto from 'node:crypto';
const payload = {
  script: "Write-Output '状态/系统/目录/未知/小' # a & b < c > d 'e'",
  args: ['-DriverName', 'AIMtkRD'],
  workDir: $(($work | ConvertTo-Json)),
  encoding: 'auto'
};
const buf = Buffer.from(JSON.stringify(payload), 'utf8');
fs.writeFileSync($(($manifestPath | ConvertTo-Json)), buf);
process.stdout.write(crypto.createHash('sha256').update(buf).digest('hex'));
"@
        $nodeFile = Join-Path $tempRoot 'freeze.mjs'
        [System.IO.File]::WriteAllText($nodeFile, $nodeScript, $utf8NoBom)
        $nodeSha = (& $AgyNodePath $nodeFile | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $nodeSha -notmatch '^[0-9a-f]{64}$') {
            throw "Node hash script failed: exit=$LASTEXITCODE out=$nodeSha"
        }

        $psSha = Get-Sha256HexFromBytes -Bytes ([System.IO.File]::ReadAllBytes($manifestPath))
        if ($nodeSha -cne $psSha) {
            throw "Cross-runtime SHA-256 mismatch: Node=$nodeSha PS51=$psSha"
        }
        $v = Invoke-VerifiedManifestRead -ManifestFile $manifestPath -ExpectedSha256 $psSha -ReparseStopRoot $tempRoot
        if ($v.Manifest.script -notmatch 'a & b < c > d') { throw 'Special characters corrupted' }
        return "Exact Node == PS51 SHA-256 parity: $psSha"
    }

    Invoke-TestCase -Id 'A2-T1-03' -Area '2' -Tier 1 -Name 'Case-insensitive hex SHA-256 verification and single-read contract' -Body {
        $work = Join-Path $tempRoot 'work_case'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $manifestPath = Join-Path $tempRoot 'manifest_case.json'
        $json = '{"script":"exit 0","args":[],"workDir":' + ($work | ConvertTo-Json) + ',"encoding":"auto"}'
        [System.IO.File]::WriteAllText($manifestPath, $json, $utf8NoBom)
        $shaUpper = (Get-Sha256HexFromBytes -Bytes ([System.IO.File]::ReadAllBytes($manifestPath))).ToUpperInvariant()
        $v = Invoke-VerifiedManifestRead -ManifestFile $manifestPath -ExpectedSha256 $shaUpper -ReparseStopRoot $tempRoot
        return "Accepted uppercase hex hash ($($v.BytesLen) bytes)"
    }

    Invoke-TestCase -Id 'A2-T1-04' -Area '2' -Tier 1 -Name 'BOM-less UTF-8 -ScriptFile preserves #requires, param(), line numbers, and zh-CN' -Body {
        $srcFile = Join-Path $tempRoot 'input_nobom.ps1'
        $scriptBody = "#requires -Version 5.1`r`nparam([string]`$Name = 'default')`r`nWrite-Output `"状态/系统/目录/未知/小:`$Name`"`r`n"
        [System.IO.File]::WriteAllText($srcFile, $scriptBody, $utf8NoBom)

        $rawBytes = [System.IO.File]::ReadAllBytes($srcFile)
        if ($rawBytes[0] -eq 0xEF -and $rawBytes[1] -eq 0xBB) { throw 'Fixture must be BOM-less' }

        $readText = [System.IO.File]::ReadAllText($srcFile, $strictUtf8)
        if ($readText -cne $scriptBody) { throw 'Read text did not match original UTF-8 text' }

        $stagedJson = Join-Path $tempRoot 'staged_sf.json'
        $work = Join-Path $tempRoot 'work_sf'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $frozen = '{"script":' + ($readText | ConvertTo-Json) + ',"args":["-Name","测试"],"workDir":' + ($work | ConvertTo-Json) + ',"encoding":"auto"}'
        [System.IO.File]::WriteAllText($stagedJson, $frozen, $utf8NoBom)
        $sha = Get-Sha256HexFromBytes -Bytes ([System.IO.File]::ReadAllBytes($stagedJson))

        $verified = Invoke-VerifiedManifestRead -ManifestFile $stagedJson -ExpectedSha256 $sha -ReparseStopRoot $tempRoot
        $runnerScript = Join-Path $tempRoot 'script.ps1'
        [System.IO.File]::WriteAllText($runnerScript, $verified.Manifest.script, $utf8WithBom)

        $outBytes = [System.IO.File]::ReadAllBytes($runnerScript)
        if ($outBytes[0] -ne 0xEF -or $outBytes[1] -ne 0xBB -or $outBytes[2] -ne 0xBF) {
            throw 'Output script.ps1 missing UTF-8 BOM'
        }
        $tokens = $null
        $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($runnerScript, [ref]$tokens, [ref]$errs)
        if ($null -ne $errs -and $errs.Count -gt 0) {
            throw "Parse error on output script.ps1: $($errs[0].Message)"
        }
        if ($ast.ScriptRequirements.RequiredPSVersion.Major -ne 5) {
            throw 'Lost #requires -Version 5.1'
        }
        if ($ast.ParamBlock.Extent.StartLineNumber -ne 2) {
            throw "Expected param() on line 2 (zero prelude), got line $($ast.ParamBlock.Extent.StartLineNumber)"
        }
        return 'BOM-less zh-CN ScriptFile preserved #requires L1 + param() L2 with UTF-8 BOM output'
    }

    Invoke-TestCase -Id 'A2-T1-05' -Area '2' -Tier 1 -Name 'CommandLineToArgvW escaping preserves spaces, quotes, trailing backslashes in child PS5.1' -Body {
        $echoScript = Join-Path $tempRoot 'echo_args.ps1'
        $code = "foreach (`$a in `$args) { [Console]::Out.WriteLine('ARG=' + `$a) }`r`n"
        [System.IO.File]::WriteAllText($echoScript, $code, $utf8WithBom)

        $testArgs = @(
            'simple',
            'C:\temp\space dir\',
            'value with "quotes"',
            'C:\path with spaces\and "quote"\'
        )
        $escaped = ($testArgs | ForEach-Object { Quote-ArgWin32 $_ }) -join ' '
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell.exe'
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$echoScript`" $escaped"
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $p = [System.Diagnostics.Process]::Start($psi)
        $stdout = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        if ($p.ExitCode -ne 0) { throw "Child exited $($p.ExitCode)" }

        $lines = @($stdout -split "`r?`n" | Where-Object { $_ -like 'ARG=*' })
        if ($lines.Count -ne $testArgs.Count) { throw "Expected $($testArgs.Count) args, got $($lines.Count): $stdout" }
        for ($i = 0; $i -lt $testArgs.Count; $i++) {
            $got = $lines[$i].Substring(4)
            if ($got -cne $testArgs[$i]) {
                throw "Arg $i mismatch: expected [$($testArgs[$i])] got [$got]"
            }
        }
        return "All $($testArgs.Count) complex Win32 args round-tripped identically"
    }

    Invoke-TestCase -Id 'A2-T2-01' -Area '2' -Tier 2 -Name 'Single-byte tamper rejection (SHA256_MISMATCH) across script, args, workDir, encoding' -Body {
        $work = Join-Path $tempRoot 'work_tamper'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $orig = [ordered]@{
            script   = 'Write-Output "ALPHA"'
            args     = @('arg1')
            workDir  = $work
            encoding = 'auto'
        }
        $origJson = $orig | ConvertTo-Json -Compress
        $origBytes = $utf8NoBom.GetBytes($origJson)
        $origSha = Get-Sha256HexFromBytes -Bytes $origBytes

        $tamperTargets = @('ALPHA', 'arg1', 'work_tamper', 'auto')
        foreach ($needle in $tamperTargets) {
            $idx = $origJson.IndexOf($needle)
            if ($idx -lt 0) { throw "Missing needle $needle" }
            $mutBytes = [byte[]]$origBytes.Clone()
            $mutBytes[$idx] = [byte]([int]$mutBytes[$idx] -bxor 0x01)
            $tf = Join-Path $tempRoot "tamper_$needle.json"
            [System.IO.File]::WriteAllBytes($tf, $mutBytes)

            $rejected = $false
            try {
                $null = Invoke-VerifiedManifestRead -ManifestFile $tf -ExpectedSha256 $origSha -ReparseStopRoot $tempRoot
            }
            catch {
                $rejected = ($_.Exception.Message -match '^SHA256_MISMATCH:')
            }
            if (-not $rejected) { throw "Failed to reject single-byte tamper in $needle" }
        }
        return "Rejected single-byte tamper in all $($tamperTargets.Count) manifest fields"
    }

    Invoke-TestCase -Id 'A2-T2-02' -Area '2' -Tier 2 -Name '10 MB manifest size cap BVA (10485760 accepted vs 10485761 rejected)' -Body {
        $work = Join-Path $tempRoot 'work_bva'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $cap = 10 * 1024 * 1024 # 10485760

        $prefix = '{"script":"'
        $suffix = '","args":[],"workDir":' + ($work | ConvertTo-Json) + ',"encoding":"auto"}'
        $padLen = $cap - ($utf8NoBom.GetByteCount($prefix) + $utf8NoBom.GetByteCount($suffix))
        if ($padLen -le 0) { throw 'Invalid pad calculation' }

        $exactFile = Join-Path $tempRoot 'exact_10mb.json'
        $exactJson = $prefix + ('a' * $padLen) + $suffix
        [System.IO.File]::WriteAllText($exactFile, $exactJson, $utf8NoBom)
        $exactBytes = [System.IO.File]::ReadAllBytes($exactFile)
        if ($exactBytes.Length -ne $cap) { throw "Expected $cap bytes, got $($exactBytes.Length)" }
        $exactSha = Get-Sha256HexFromBytes -Bytes $exactBytes
        $v = Invoke-VerifiedManifestRead -ManifestFile $exactFile -ExpectedSha256 $exactSha -ReparseStopRoot $tempRoot
        if ($v.BytesLen -ne $cap) { throw 'Size mismatch' }

        $overFile = Join-Path $tempRoot 'over_10mb.json'
        $overJson = $prefix + ('a' * ($padLen + 1)) + $suffix
        [System.IO.File]::WriteAllText($overFile, $overJson, $utf8NoBom)
        $overBytes = [System.IO.File]::ReadAllBytes($overFile)
        if ($overBytes.Length -ne ($cap + 1)) { throw "Expected $($cap + 1) bytes, got $($overBytes.Length)" }
        $overSha = Get-Sha256HexFromBytes -Bytes $overBytes

        $rejected = $false
        try {
            $null = Invoke-VerifiedManifestRead -ManifestFile $overFile -ExpectedSha256 $overSha -ReparseStopRoot $tempRoot
        }
        catch {
            $rejected = ($_.Exception.Message -match 'exceeds 10485760')
        }
        if (-not $rejected) { throw 'Failed to reject 10485761-byte manifest' }
        return 'BVA passed: 10485760 bytes accepted, 10485761 bytes rejected'
    }

    Invoke-TestCase -Id 'A2-T2-03' -Area '2' -Tier 2 -Name 'ReparsePoint junction rejection on manifest path and safe unlink cleanup' -Body {
        $realDir = Join-Path $tempRoot 'real_staged'
        $juncDir = Join-Path $tempRoot 'junc_staged'
        $work = Join-Path $tempRoot 'work_junc'
        New-Item -ItemType Directory -Path $realDir, $work -Force | Out-Null

        $realFile = Join-Path $realDir 'm.json'
        $json = '{"script":"exit 0","args":[],"workDir":' + ($work | ConvertTo-Json) + ',"encoding":"auto"}'
        [System.IO.File]::WriteAllText($realFile, $json, $utf8NoBom)
        $sha = Get-Sha256HexFromBytes -Bytes ([System.IO.File]::ReadAllBytes($realFile))

        $mkOut = cmd /c mklink /J "`"$juncDir`"" "`"$realDir`"" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "mklink /J failed: $mkOut" }
        $junctionsToCleanup.Add($juncDir) | Out-Null

        $juncFile = Join-Path $juncDir 'm.json'
        $rejected = $false
        try {
            $null = Invoke-VerifiedManifestRead -ManifestFile $juncFile -ExpectedSha256 $sha -ReparseStopRoot $tempRoot
        }
        catch {
            $rejected = ($_.Exception.Message -match 'ReparsePoint detected')
        }
        if (-not $rejected) { throw 'Failed to reject manifest under junction directory' }

        [System.IO.Directory]::Delete($juncDir, $false)
        $null = $junctionsToCleanup.Remove($juncDir)
        if (-not (Test-Path -LiteralPath $realFile -PathType Leaf)) {
            throw 'Unlinking junction deleted target file!'
        }
        return 'Junction ReparsePoint rejected and safely unlinked without deleting target'
    }

    Invoke-TestCase -Id 'A2-T2-04' -Area '2' -Tier 2 -Name 'Reject missing/file workDir and invalid UTF-8 bytes in manifest or ScriptFile' -Body {
        $missingWork = Join-Path $tempRoot 'does_not_exist'
        $fileAsWork = Join-Path $tempRoot 'not_a_dir.txt'
        [System.IO.File]::WriteAllText($fileAsWork, 'hi', $utf8NoBom)

        foreach ($badW in @($missingWork, $fileAsWork)) {
            $mf = Join-Path $tempRoot ("badwork_" + [Guid]::NewGuid().ToString('N') + '.json')
            $json = '{"script":"exit 0","args":[],"workDir":' + ($badW | ConvertTo-Json) + ',"encoding":"auto"}'
            [System.IO.File]::WriteAllText($mf, $json, $utf8NoBom)
            $sha = Get-Sha256HexFromBytes -Bytes ([System.IO.File]::ReadAllBytes($mf))
            $rejected = $false
            try {
                $null = Invoke-VerifiedManifestRead -ManifestFile $mf -ExpectedSha256 $sha -ReparseStopRoot $tempRoot
            }
            catch {
                $rejected = ($_.Exception.Message -match 'Invalid workDir')
            }
            if (-not $rejected) { throw "Expected invalid workDir rejection for $badW" }
        }

        $badBytesFile = Join-Path $tempRoot 'invalid_utf8_script.ps1'
        [System.IO.File]::WriteAllBytes($badBytesFile, [byte[]](0xC3, 0x28, 0x0A))
        $utf8Rejected = $false
        try {
            $null = [System.IO.File]::ReadAllText($badBytesFile, $strictUtf8)
        }
        catch {
            $utf8Rejected = $true
        }
        if (-not $utf8Rejected) { throw 'Expected strict UTF-8 rejection on invalid ScriptFile bytes' }
        return 'Rejected missing/file workDir and invalid UTF-8 ScriptFile bytes'
    }

    Invoke-TestCase -Id 'A2-T2-05' -Area '2' -Tier 2 -Name 'PS 5.1 ConvertTo-Json escapes &<>'' and reorders keys (proves raw-byte hash contract)' -Body {
        $ht = @{ script = "a & b < c > d 'e'"; args = @('1'); workDir = 'C:\Windows'; encoding = 'auto' }
        $psJson = $ht | ConvertTo-Json -Compress
        if ($psJson -notmatch '\\u0026' -or $psJson -notmatch '\\u0027') {
            throw "Expected PS 5.1 ConvertTo-Json to escape & and ', got: $psJson"
        }
        return 'Confirmed PS 5.1 ConvertTo-Json escapes HTML chars and requires raw-byte hashing'
    }

    if ($RepoRoot) {
        Invoke-TestCase -Id 'A2-REPO-01' -Area '2' -Tier 2 -Name 'Repo Invoke-ElevatedRunner.ps1 manifest contract & non-elevated fail-closed check' -Body {
            $runnerPath = Join-Path $RepoRoot 'runner\Invoke-ElevatedRunner.ps1'
            if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
                throw "Missing runner: $runnerPath"
            }
            $runnerSrc = [System.IO.File]::ReadAllText($runnerPath, $strictUtf8)
            foreach ($needle in @('SHA256_MISMATCH', 'ReparsePoint', 'CallerPid', 'CallerStart', 'OutputFormat')) {
                if ($runnerSrc -notmatch [regex]::Escape($needle)) {
                    throw "Runner missing expected security/contract token: $needle"
                }
            }
            if ($runnerSrc -notmatch '(RedirectStandardInput|STD_INPUT_HANDLE|CreateProcessW)') {
                throw 'Runner missing expected stdin isolation/child-process token: RedirectStandardInput|STD_INPUT_HANDLE|CreateProcessW'
            }
            $hasJobLimitStruct = ($runnerSrc -match 'LimitFlags|JOB_OBJECT_EXTENDED_LIMIT_INFORMATION')
            $badJobLines = @($runnerSrc -split "`r?`n" | Where-Object {
                $_ -notmatch '^\s*(#|//)' -and (
                    $_ -match 'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE' -or
                    ($hasJobLimitStruct -and $_ -match '\b0x0*2000\b')
                )
            })
            if ($badJobLines.Count -gt 0) {
                throw "Runner must NOT enable JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: $($badJobLines[0].Trim())"
            }

            # Invoke runner non-elevated with dummy pipe/manifest -> must fail closed (non-zero)
            $dummyMf = Join-Path $tempRoot 'dummy_manifest.json'
            [System.IO.File]::WriteAllText($dummyMf, '{"script":"Write-Host SHOULD_NOT_RUN","args":[],"workDir":"C:\\Windows","encoding":"auto"}', $utf8NoBom)
            $dummySha = Get-Sha256HexFromBytes -Bytes ([System.IO.File]::ReadAllBytes($dummyMf))
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'powershell.exe'
            $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$runnerPath`" -PipeName `"ag-elev-00000000000000000000000000000000`" -CallerPid $PID -CallerStart 1 -ManifestFile `"$dummyMf`" -ManifestSha256 `"$dummySha`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            $out = $p.StandardOutput.ReadToEnd()
            $err = $p.StandardError.ReadToEnd()
            $null = $p.WaitForExit(10000)
            if (-not $p.HasExited) {
                $p.Kill()
                throw 'Runner hung >10s during non-elevated fail-closed probe'
            }
            if ($p.ExitCode -eq 0 -or $out -match 'SHOULD_NOT_RUN') {
                throw "Runner failed to fail closed! exit=$($p.ExitCode) out=$out err=$err"
            }
            return "Runner verified structurally and failed closed non-elevated (exit=$($p.ExitCode))"
        }
    }

    # ==================== AREA 6: PRE-FLIGHT, ACL, PIPE SDDL ====================

    Invoke-TestCase -Id 'A6-T1-01' -Area '6' -Tier 1 -Name 'Live Windows Win32 pre-flight API probe (Session, WinSta0, WTS, OpenInputDesktop)' -Body {
        $sessId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        $winSta = [AeTestWin32.Probe]::GetWinStationName()
        $threadDesk = [AeTestWin32.Probe]::GetThreadDesktopName()

        $connOk = $false; $connState = -1
        $exOk = $false; $exBytes = 0; $lvl = -1; $flags = -1
        [AeTestWin32.Probe]::QueryWtsState([ref]$connOk, [ref]$connState, [ref]$exOk, [ref]$exBytes, [ref]$lvl, [ref]$flags)

        $inOk = $false; $inName = $null; $inErr = 0
        [AeTestWin32.Probe]::QueryInputDesktop([ref]$inOk, [ref]$inName, [ref]$inErr)

        if ($sessId -eq 0) { throw "Unexpected SessionId=0" }
        if ($winSta -cne 'WinSta0') { throw "Expected WinSta0, got $winSta" }
        if (-not $connOk -or $connState -ne 0) { throw "Expected WTSActive(0), got ok=$connOk state=$connState" }
        if (-not $exOk -or $exBytes -lt 20 -or $lvl -ne 1 -or $flags -ne 1) {
            throw "Expected WTSSessionInfoEx unlocked (bytes>=20,lvl=1,flags=1), got ok=$exOk bytes=$exBytes lvl=$lvl flags=$flags"
        }
        if (-not $inOk -or $inName -cne 'Default') { throw "Expected InputDesktop=Default, got ok=$inOk name=$inName err=$inErr" }
        if ($threadDesk -ne 'Default' -and $threadDesk -notlike 'exebox-*') {
            throw "Unexpected ThreadDesktop: $threadDesk"
        }
        return "Session=$sessId WinSta=$winSta ThreadDesk=$threadDesk InputDesk=$inName WTSFlags=$flags"
    }

    Invoke-TestCase -Id 'A6-T1-02' -Area '6' -Tier 1 -Name 'Deterministic pre-flight evaluator accepts valid WinSta0\Default unlocked state' -Body {
        $res = Evaluate-PreflightState -SessionId 1 -WinSta 'WinSta0' -ThreadDesktop 'Default' `
            -ConnectOk $true -ConnectState 0 -InfoExOk $true -InfoExBytes 232 -Level 1 -SessionFlags 1 `
            -InputDesktopOk $true -InputDesktopName 'Default' -InputDesktopError 0
        if (-not $res.ok -or $res.exitCode -ne 0 -or $res.code -ne 'OK') {
            throw "Expected OK/0, got $($res | ConvertTo-Json -Compress)"
        }
        return 'Evaluator accepted valid WinSta0\Default unlocked state'
    }

    Invoke-TestCase -Id 'A6-T1-03' -Area '6' -Tier 1 -Name 'Raw-SID ACL check on hardened temp dir (incl. S-1-3-0 InheritOnly & S-1-15-2-2 unmapped SID)' -Body {
        $aclDir = Join-Path $tempRoot 'hardened_dir'
        New-Item -ItemType Directory -Path $aclDir -Force | Out-Null
        try {
            $acl = (Get-Item -LiteralPath $aclDir).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($r in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
                $null = $acl.RemoveAccessRule($r)
            }

            $rulesToAdd = @(
                (New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')),
                (New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')),
                (New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')),
                (New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-3-0')), 'FullControl', 'ContainerInherit,ObjectInherit', 'InheritOnly', 'Allow')),
                (New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-15-2-2')), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
            )
            foreach ($ar in $rulesToAdd) { $acl.AddAccessRule($ar) }
            [System.IO.Directory]::SetAccessControl($aclDir, $acl)

            $owner = Test-RawSidDirectorySecurity -DirPath $aclDir -TrustedOwnerSids @($currentUserSid, 'S-1-5-32-544', 'S-1-5-18') -RequireProtected $true -StopAtRoot $tempRoot
            # Also verify real C:\Program Files raw-SID scan never throws IdentityNotMappedException
            $pfOwner = Test-RawSidDirectorySecurity -DirPath "$env:ProgramFiles" -TrustedOwnerSids @('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-5-32-544', 'S-1-5-18') -RequireProtected $false
            return "Temp owner=$owner; C:\Program Files owner=$pfOwner (zero IdentityNotMappedException)"
        }
        finally {
            if (Test-Path -LiteralPath $aclDir) {
                try {
                    $restoreAcl = [System.IO.Directory]::GetAccessControl($aclDir, [System.Security.AccessControl.AccessControlSections]::Access)
                    $restoreAcl.SetAccessRuleProtection($false, $false)
                    $restoreAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($currentUserSid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
                    [System.IO.Directory]::SetAccessControl($aclDir, $restoreAcl)
                } catch {}
            }
        }
    }

    Invoke-TestCase -Id 'A6-T1-04' -Area '6' -Tier 1 -Name 'Hardened PipeSecurity SDDL exactness and NamedPipeServerStream (inBuffer=65536) creation' -Body {
        $ps = New-HardenedPipeSecurity
        $sddl = $ps.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
        $expectedSddl = 'D:P(D;;0x1f019f;;;NU)(A;;0x100000;;;OW)(A;;0x1f019f;;;SY)(A;;0x12019b;;;BA)'
        if ($sddl -cne $expectedSddl) {
            throw "SDDL mismatch: expected=$expectedSddl actual=$sddl"
        }

        $pipeName = 'ag-elev-' + ([Guid]::NewGuid().ToString('N'))
        $server = New-Object System.IO.Pipes.NamedPipeServerStream(
            $pipeName,
            [System.IO.Pipes.PipeDirection]::In,
            1,
            [System.IO.Pipes.PipeTransmissionMode]::Byte,
            [System.IO.Pipes.PipeOptions]::Asynchronous,
            65536,
            0,
            $ps
        )
        try {
            if (-not $server) { throw 'Failed to create NamedPipeServerStream' }
        }
        finally {
            $server.Dispose()
        }
        return "Exact SDDL verified and NamedPipeServerStream($pipeName) created non-elevated"
    }

    Invoke-TestCase -Id 'A6-T1-05' -Area '6' -Tier 1 -Name 'C# unchecked((int)code) handles 0xC000013A and 0x80070005 without Int32 OverflowException' -Body {
        $c1 = [AeTestWin32.Probe]::UncheckedCastUInt32([uint32]3221225786) # 0xC000013A
        if ($c1 -ne -1073741510) { throw "Expected -1073741510, got $c1" }

        $u2 = [uint32]::Parse('80070005', [System.Globalization.NumberStyles]::HexNumber)
        $c2 = [AeTestWin32.Probe]::UncheckedCastUInt32($u2)
        if ($c2 -ne -2147024891) { throw "Expected -2147024891, got $c2" }
        return "0xC000013A -> $c1, 0x80070005 -> $c2"
    }

    Invoke-TestCase -Id 'A6-T2-01' -Area '6' -Tier 2 -Name 'Pre-flight evaluator negative BVA (Session 0, exebox-*, Disconnected, Locked, UNKNOWN, AccessDenied)' -Body {
        $negatives = @(
            @{ Label = 'Session0'; Args = @{ SessionId = 0; WinSta = 'WinSta0'; ThreadDesktop = 'Default'; ConnectOk = $true; ConnectState = 0; InfoExOk = $true; InfoExBytes = 232; Level = 1; SessionFlags = 1; InputDesktopOk = $true; InputDesktopName = 'Default'; InputDesktopError = 0 } },
            @{ Label = 'ServiceWinSta'; Args = @{ SessionId = 1; WinSta = 'Service-0x0-3e7$'; ThreadDesktop = 'Default'; ConnectOk = $true; ConnectState = 0; InfoExOk = $true; InfoExBytes = 232; Level = 1; SessionFlags = 1; InputDesktopOk = $true; InputDesktopName = 'Default'; InputDesktopError = 0 } },
            @{ Label = 'ExeboxDesktop'; Args = @{ SessionId = 1; WinSta = 'WinSta0'; ThreadDesktop = 'exebox-6ZXR4U'; ConnectOk = $true; ConnectState = 0; InfoExOk = $true; InfoExBytes = 232; Level = 1; SessionFlags = 1; InputDesktopOk = $true; InputDesktopName = 'Default'; InputDesktopError = 0 } },
            @{ Label = 'WTSDisconnected'; Args = @{ SessionId = 1; WinSta = 'WinSta0'; ThreadDesktop = 'Default'; ConnectOk = $true; ConnectState = 4; InfoExOk = $true; InfoExBytes = 232; Level = 1; SessionFlags = 1; InputDesktopOk = $true; InputDesktopName = 'Default'; InputDesktopError = 0 } },
            @{ Label = 'SessionLocked'; Args = @{ SessionId = 1; WinSta = 'WinSta0'; ThreadDesktop = 'Default'; ConnectOk = $true; ConnectState = 0; InfoExOk = $true; InfoExBytes = 232; Level = 1; SessionFlags = 0; InputDesktopOk = $true; InputDesktopName = 'Default'; InputDesktopError = 0 } },
            @{ Label = 'SessionFlagsUnknown'; Args = @{ SessionId = 1; WinSta = 'WinSta0'; ThreadDesktop = 'Default'; ConnectOk = $true; ConnectState = 0; InfoExOk = $true; InfoExBytes = 232; Level = 1; SessionFlags = -1; InputDesktopOk = $true; InputDesktopName = 'Default'; InputDesktopError = 0 } },
            @{ Label = 'ShortInfoExBytes'; Args = @{ SessionId = 1; WinSta = 'WinSta0'; ThreadDesktop = 'Default'; ConnectOk = $true; ConnectState = 0; InfoExOk = $true; InfoExBytes = 16; Level = 1; SessionFlags = 1; InputDesktopOk = $true; InputDesktopName = 'Default'; InputDesktopError = 0 } },
            @{ Label = 'WinlogonAccessDenied'; Args = @{ SessionId = 1; WinSta = 'WinSta0'; ThreadDesktop = 'Default'; ConnectOk = $true; ConnectState = 0; InfoExOk = $true; InfoExBytes = 232; Level = 1; SessionFlags = 1; InputDesktopOk = $false; InputDesktopName = $null; InputDesktopError = 5 } }
        )
        foreach ($n in $negatives) {
            $p = $n.Args
            $r = Evaluate-PreflightState @p
            if ($r.ok -or $r.exitCode -ne 1202 -or $r.code -ne 'E_SESSION_NOT_INTERACTIVE') {
                throw "Negative case $($n.Label) was not rejected as 1202: $($r | ConvertTo-Json -Compress)"
            }
        }
        return "All $($negatives.Count) negative pre-flight states failed closed with 1202"
    }

    Invoke-TestCase -Id 'A6-T2-02' -Area '6' -Tier 2 -Name 'Raw-SID ACL validator rejects inherited ACLs (AreAccessRulesProtected = false)' -Body {
        $inhDir = Join-Path $tempRoot 'inherited_dir'
        New-Item -ItemType Directory -Path $inhDir -Force | Out-Null
        $acl = (Get-Item -LiteralPath $inhDir).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        $acl.SetAccessRuleProtection($false, $true)
        [System.IO.Directory]::SetAccessControl($inhDir, $acl)

        $rejected = $false
        try {
            $null = Test-RawSidDirectorySecurity -DirPath $inhDir -TrustedOwnerSids @($currentUserSid) -RequireProtected $true -StopAtRoot $tempRoot
        }
        catch {
            $rejected = ($_.Exception.Message -match 'Inheritance must be disabled')
        }
        if (-not $rejected) { throw 'Failed to reject inherited ACL' }
        return 'Rejected inherited ACL cleanly'
    }

    Invoke-TestCase -Id 'A6-T2-03' -Area '6' -Tier 2 -Name 'Raw-SID ACL validator rejects non-admin write ACE (S-1-5-32-545) and non-InheritOnly S-1-3-0' -Body {
        $badWriteDir = Join-Path $tempRoot 'bad_write_ace'
        New-Item -ItemType Directory -Path $badWriteDir -Force | Out-Null
        $acl = (Get-Item -LiteralPath $badWriteDir).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($r in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
            $null = $acl.RemoveAccessRule($r)
        }
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        [System.IO.Directory]::SetAccessControl($badWriteDir, $acl)

        $rejectedWrite = $false
        try {
            $null = Test-RawSidDirectorySecurity -DirPath $badWriteDir -TrustedOwnerSids @($currentUserSid) -RequireProtected $true -StopAtRoot $tempRoot
        }
        catch {
            $rejectedWrite = ($_.Exception.Message -match 'Non-admin write/ACL ACE')
        }
        if (-not $rejectedWrite) { throw 'Failed to reject Users Modify ACE' }

        # Test S-1-3-0 without InheritOnly
        $badCreatorDir = Join-Path $tempRoot 'bad_creator_owner'
        New-Item -ItemType Directory -Path $badCreatorDir -Force | Out-Null
        $acl2 = (Get-Item -LiteralPath $badCreatorDir).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        $acl2.SetAccessRuleProtection($true, $false)
        foreach ($r in @($acl2.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
            $null = $acl2.RemoveAccessRule($r)
        }
        $acl2.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-3-0')), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        [System.IO.Directory]::SetAccessControl($badCreatorDir, $acl2)

        $rejectedCreator = $false
        try {
            $null = Test-RawSidDirectorySecurity -DirPath $badCreatorDir -TrustedOwnerSids @($currentUserSid) -RequireProtected $true -StopAtRoot $tempRoot
        }
        catch {
            $rejectedCreator = ($_.Exception.Message -match 'Non-admin write/ACL ACE')
        }
        if (-not $rejectedCreator) { throw 'Failed to reject non-InheritOnly S-1-3-0 ACE (grants creator FullControl)' }
        return 'Rejected Users Modify ACE and non-InheritOnly S-1-3-0 ACE'
    }

    Invoke-TestCase -Id 'A6-T2-04' -Area '6' -Tier 2 -Name 'Raw-SID ACL validator rejects untrusted owner SID (non-admin user vs SYSTEM/Admins/TrustedInstaller)' -Body {
        $dir = Join-Path $tempRoot 'untrusted_owner'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $strictOwners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        if ($strictOwners -contains $currentUserSid) {
            return 'Skipped: running as SYSTEM/Admin already'
        }
        $rejected = $false
        try {
            $null = Test-RawSidDirectorySecurity -DirPath $dir -TrustedOwnerSids $strictOwners -RequireProtected $false -StopAtRoot $tempRoot
        }
        catch {
            $rejected = ($_.Exception.Message -match "Untrusted owner SID $currentUserSid")
        }
        if (-not $rejected) { throw 'Failed to reject untrusted user owner SID' }
        return "Rejected untrusted owner SID $currentUserSid"
    }

    Invoke-TestCase -Id 'A6-T2-05' -Area '6' -Tier 2 -Name 'ReparsePoint rejection on intermediate parent directory junction (parentJunc\sub\runner)' -Body {
        $targetParent = Join-Path $tempRoot 'target_parent'
        $subInTarget = Join-Path $targetParent 'sub'
        New-Item -ItemType Directory -Path $subInTarget -Force | Out-Null
        $juncParent = Join-Path $tempRoot 'junc_parent'
        $mkOut = cmd /c mklink /J "`"$juncParent`"" "`"$targetParent`"" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "mklink /J failed: $mkOut" }
        $junctionsToCleanup.Add($juncParent) | Out-Null

        $nestedPath = Join-Path $juncParent 'sub\Invoke-ElevatedRunner.ps1'
        $rejected = $false
        try {
            Test-NoReparsePointChain -TargetPath $nestedPath -StopAtRoot $tempRoot
        }
        catch {
            $rejected = ($_.Exception.Message -match 'ReparsePoint detected')
        }
        if (-not $rejected) { throw 'Failed to detect intermediate parent junction ReparsePoint' }

        [System.IO.Directory]::Delete($juncParent, $false)
        $null = $junctionsToCleanup.Remove($juncParent)
        if (-not (Test-Path -LiteralPath $subInTarget -PathType Container)) {
            throw 'Junction cleanup removed target sub directory!'
        }
        return 'Detected intermediate junction segment and safely unlinked'
    }

    Invoke-TestCase -Id 'A6-T2-06' -Area '6' -Tier 2 -Name 'PipeSecurity negative check and FILE_FLAG_FIRST_PIPE_INSTANCE (maxInstances=1) enforcement' -Body {
        $weakPs = New-Object System.IO.Pipes.PipeSecurity
        $weakPs.SetAccessRuleProtection($true, $false)
        $weakPs.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4')), [System.IO.Pipes.PipeAccessRights]::ReadWrite, [System.Security.AccessControl.AccessControlType]::Allow)))
        $weakSddl = $weakPs.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
        $expectedSddl = 'D:P(D;;0x1f019f;;;NU)(A;;0x100000;;;OW)(A;;0x1f019f;;;SY)(A;;0x12019b;;;BA)'
        if ($weakSddl -ceq $expectedSddl) { throw 'Weak PipeSecurity matched expected hardened SDDL' }

        $hardPs = New-HardenedPipeSecurity
        $pipeName = 'ag-elev-' + ([Guid]::NewGuid().ToString('N'))
        $s1 = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::In, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous, 65536, 0, $hardPs)
        try {
            $dupBlocked = $false
            try {
                $s2 = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::In, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous, 65536, 0, $hardPs)
                $s2.Dispose()
            }
            catch {
                $dupBlocked = $true
            }
            if (-not $dupBlocked) { throw 'Second pipe server instance was not blocked by maxNumberOfServerInstances=1' }
        }
        finally {
            $s1.Dispose()
        }
        return 'Weak SDDL distinguished and duplicate pipe instance blocked'
    }

    Invoke-TestCase -Id 'A6-T2-07' -Area '6' -Tier 2 -Name 'Node windowsHide:true SW_HIDE pre-Run consumption keeps TopMost WinForms modal WS_VISIBLE' -Body {
        if (-not (Test-Path -LiteralPath $AgyNodePath -PathType Leaf)) {
            throw "agy-node.cmd not found at $AgyNodePath"
        }
        $selfCs = Join-Path $tempRoot 'swhide_selftest.cs'
        $selfPs1 = Join-Path $tempRoot 'swhide_selftest.ps1'
        $selfMjs = Join-Path $tempRoot 'swhide_selftest.mjs'
        $csCode = @'
using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public static class SwHideSelfProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOW
    {
        public uint cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle;
        public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
        public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute;
        public uint dwFlags; public ushort wShowWindow; public ushort cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [DllImport("kernel32.dll")]
    private static extern void GetStartupInfoW(out STARTUPINFOW lpStartupInfo);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongW")]
    private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);

    private static long GetLong(IntPtr h, int idx)
    {
        return IntPtr.Size == 8 ? GetWindowLongPtr64(h, idx).ToInt64() : (long)GetWindowLong32(h, idx);
    }

    public static string Run()
    {
        STARTUPINFOW si = new STARTUPINFOW();
        si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOW));
        GetStartupInfoW(out si);
        long consoleHwnd = GetConsoleWindow().ToInt64();

        Form f = new Form();
        f.Text = "SelfTest SW_HIDE Probe";
        f.TopMost = true;
        f.StartPosition = FormStartPosition.CenterScreen;
        f.Size = new Size(320, 200);
        IntPtr createdHwnd = f.Handle;
        ShowWindow(createdHwnd, 0);

        int shownCount = 0;
        bool vis = false;
        long style = 0;
        long exStyle = 0;
        f.Shown += (s, e) =>
        {
            shownCount++;
            if (!IsWindowVisible(f.Handle)) ShowWindow(f.Handle, 1);
            vis = IsWindowVisible(f.Handle);
            style = GetLong(f.Handle, -16);
            exStyle = GetLong(f.Handle, -20);
            f.BeginInvoke(new Action(() => f.Close()));
        };
        Application.Run(f);
        f.Dispose();

        return string.Format("{{\"dwFlags\":{0},\"wShowWindow\":{1},\"consoleHwnd\":{2},\"shownCount\":{3},\"visible\":{4},\"style\":{5},\"exStyle\":{6}}}",
            si.dwFlags, si.wShowWindow, consoleHwnd, shownCount, vis ? "true" : "false", style, exStyle);
    }
}
'@
        $psCode = @'
param([Parameter(Mandatory = $true)][string]$CsPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$csSrc = [System.IO.File]::ReadAllText($CsPath, [System.Text.Encoding]::UTF8)
Add-Type -TypeDefinition $csSrc -Language CSharp -ReferencedAssemblies @('System.Windows.Forms', 'System.Drawing')
[Console]::Out.WriteLine([SwHideSelfProbe]::Run())
'@
        $mjsCode = @'
import { spawn } from 'node:child_process';
const ps1 = process.argv[2];
const csPath = process.argv[3];
const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1, '-CsPath', csPath], {
  windowsHide: true,
  stdio: ['pipe', 'pipe', 'pipe']
});
let out = '';
let err = '';
child.stdout.on('data', d => { out += d.toString('utf8'); });
child.stderr.on('data', d => { err += d.toString('utf8'); });
const timer = setTimeout(() => { try { child.kill(); } catch {} }, 12000);
child.on('close', code => {
  clearTimeout(timer);
  if (code !== 0) {
    console.error('ERR=' + err);
    console.error('OUT=' + out);
    process.exit(code || 1);
  }
  process.stdout.write(out);
});
'@
        [System.IO.File]::WriteAllText($selfCs, $csCode, $utf8NoBom)
        [System.IO.File]::WriteAllText($selfPs1, $psCode, $utf8WithBom)
        [System.IO.File]::WriteAllText($selfMjs, $mjsCode, $utf8NoBom)

        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $raw = & $AgyNodePath $selfMjs $selfPs1 $selfCs 2>&1
            $code = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
        if ($code -ne 0) { throw "SW_HIDE self-test Node driver exited ${code}: $($raw -join ' ')" }
        $line = (($raw | Out-String).Trim() -split "`r?`n")[-1]
        $obj = $line | ConvertFrom-Json -ErrorAction Stop
        if (([int64]$obj.dwFlags -band 1) -eq 0 -or [int]$obj.wShowWindow -ne 0 -or [int64]$obj.consoleHwnd -ne 0) {
            throw "Expected STARTF_USESHOWWINDOW + SW_HIDE + consoleHwnd=0, got: $line"
        }
        if ([int]$obj.shownCount -ne 1 -or -not [bool]$obj.visible) {
            throw "Expected shownCount=1 and IsWindowVisible=true, got: $line"
        }
        if (([int64]$obj.style -band 0x10000000) -eq 0 -or ([int64]$obj.exStyle -band 0x8) -eq 0) {
            throw "Expected WS_VISIBLE (0x10000000) and WS_EX_TOPMOST (0x8), got: $line"
        }
        return "Verified windowsHide:true (dwFlags=$($obj.dwFlags) wShow=$($obj.wShowWindow)) -> IsWindowVisible=True, WS_VISIBLE, WS_EX_TOPMOST, shownCount=1"
    }

    if ($RepoRoot) {
        Invoke-TestCase -Id 'A6-REPO-01' -Area '6' -Tier 1 -Name 'Repo broker_helper.ps1 -PreflightOnly <4s SLA, JSON contract, and Win32/SDDL checks' -Body {
            $helperPath = Join-Path $RepoRoot 'sidecars\broker\broker_helper.ps1'
            if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
                throw "Missing broker_helper.ps1: $helperPath"
            }
            $helperSrc = [System.IO.File]::ReadAllText($helperPath, $strictUtf8)
            $expectedSddl = 'D:P(D;;0x1f019f;;;NU)(A;;0x100000;;;OW)(A;;0x1f019f;;;SY)(A;;0x12019b;;;BA)'
            $hasLiteralSddl = ($helperSrc -match [regex]::Escape($expectedSddl))
            $hasPipeSecBuilder = (
                $helperSrc -match 'PipeSecurity' -and
                $helperSrc -match 'SetAccessRuleProtection' -and
                $helperSrc -match 'S-1-5-2' -and
                $helperSrc -match 'S-1-3-4' -and
                $helperSrc -match 'S-1-5-18' -and
                $helperSrc -match 'S-1-5-32-544'
            )
            if (-not ($hasLiteralSddl -or $hasPipeSecBuilder)) {
                throw 'broker_helper.ps1 missing hardened PipeSecurity SDDL or PipeAccessRule construction (S-1-5-2, S-1-3-4, S-1-5-18, S-1-5-32-544)'
            }
            foreach ($needle in @(
                'SetProcessDpiAwarenessContext',
                'ApartmentState',
                'STA',
                'CompareExchange',
                'WTSSessionInfoEx',
                'OpenInputDesktop'
            )) {
                if ($helperSrc -notmatch [regex]::Escape($needle)) {
                    throw "broker_helper.ps1 missing expected contract element: $needle"
                }
            }

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'powershell.exe'
            $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$helperPath`" -PreflightOnly -RunnerPath `"C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $p = [System.Diagnostics.Process]::Start($psi)
            $out = $p.StandardOutput.ReadToEnd()
            $err = $p.StandardError.ReadToEnd()
            if (-not $p.WaitForExit(4500)) {
                $p.Kill()
                throw 'broker_helper.ps1 -PreflightOnly exceeded 4500 ms'
            }
            $sw.Stop()
            if ($sw.ElapsedMilliseconds -ge 4000) {
                throw "broker_helper.ps1 -PreflightOnly took $($sw.ElapsedMilliseconds) ms (>= 4000 ms SLA)"
            }
            $line = ($out.Trim() -split "`r?`n")[-1]
            $obj = $line | ConvertFrom-Json -ErrorAction Stop
            $td = [AeTestWin32.Probe]::GetThreadDesktopName()
            if ($td -like 'exebox-*') {
                if ($obj.ok -or $obj.code -ne 'E_SESSION_NOT_INTERACTIVE' -or $obj.exitCode -ne 1202) {
                    throw "Under exebox-* expected 1202 E_SESSION_NOT_INTERACTIVE, got: $line (err=$err)"
                }
            }
            else {
                if ($obj.code -notin @('OK', 'E_RUNNER_INVALID')) {
                    throw "On Default desktop expected OK or E_RUNNER_INVALID, got: $line"
                }
            }
            return "PreflightOnly completed in $($sw.ElapsedMilliseconds) ms: code=$($obj.code) exit=$($obj.exitCode)"
        }

        Invoke-TestCase -Id 'A6-REPO-02' -Area '6' -Tier 2 -Name 'Repo BrokerEngine Click1Form & ReminderForm visible under Node windowsHide:true (SW_HIDE regression)' -Body {
            if (-not (Test-Path -LiteralPath $AgyNodePath -PathType Leaf)) {
                throw "agy-node.cmd not found at $AgyNodePath"
            }
            $helperPath = Join-Path $RepoRoot 'sidecars\broker\broker_helper.ps1'
            if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
                throw "Missing broker_helper.ps1: $helperPath"
            }

            $probeCsFile = Join-Path $tempRoot 'broker_vis_probe.cs'
            $probePs1 = Join-Path $tempRoot 'broker_vis_probe.ps1'
            $driverMjs = Join-Path $tempRoot 'broker_vis_driver.mjs'

            $probeCsCode = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace AeBrokerVisProbe
{
    public static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOW
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern void GetStartupInfoW(out STARTUPINFOW lpStartupInfo);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", EntryPoint = "GetWindowLongW")]
        private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
        private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextLengthW(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        private static long GetWindowLongAny(IntPtr hWnd, int nIndex)
        {
            return IntPtr.Size == 8 ? GetWindowLongPtr64(hWnd, nIndex).ToInt64() : (long)GetWindowLong32(hWnd, nIndex);
        }

        public static Dictionary<string, object> GetStartupInfoDict()
        {
            STARTUPINFOW si = new STARTUPINFOW();
            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOW));
            GetStartupInfoW(out si);
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["event"] = "startup_info";
            d["dwFlags"] = unchecked((int)si.dwFlags);
            d["wShowWindow"] = (int)si.wShowWindow;
            d["consoleHwnd"] = GetConsoleWindow().ToInt64();
            return d;
        }

        public static List<Dictionary<string, object>> ProbeOwnWindows(string titleContains)
        {
            uint selfPid = GetCurrentProcessId();
            List<Dictionary<string, object>> matches = new List<Dictionary<string, object>>();
            EnumWindows((hWnd, lParam) =>
            {
                uint pid = 0;
                GetWindowThreadProcessId(hWnd, out pid);
                if (pid != selfPid) return true;
                int len = GetWindowTextLengthW(hWnd);
                string title = string.Empty;
                if (len > 0)
                {
                    StringBuilder sb = new StringBuilder(len + 1);
                    GetWindowTextW(hWnd, sb, sb.Capacity);
                    title = sb.ToString();
                }
                if (!string.IsNullOrEmpty(titleContains) && title.IndexOf(titleContains, StringComparison.Ordinal) < 0)
                {
                    return true;
                }
                long style = GetWindowLongAny(hWnd, -16);
                long exStyle = GetWindowLongAny(hWnd, -20);
                Dictionary<string, object> item = new Dictionary<string, object>();
                item["hwnd"] = hWnd.ToInt64();
                item["title"] = title;
                item["visible"] = IsWindowVisible(hWnd);
                item["style"] = style;
                item["exStyle"] = exStyle;
                matches.Add(item);
                return true;
            }, IntPtr.Zero);
            return matches;
        }
    }

    public sealed class StdinProxyReader : TextReader
    {
        private readonly StreamReader _inner;
        private readonly string _titleFilter;

        public StdinProxyReader(string titleFilter)
        {
            _inner = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
            _titleFilter = titleFilter ?? string.Empty;
        }

        public override string ReadLine()
        {
            while (true)
            {
                string line = _inner.ReadLine();
                if (line == null) return null;
                if (line.Trim() == "__PROBE_WIN__")
                {
                    Dictionary<string, object> res = new Dictionary<string, object>();
                    res["event"] = "probe_result";
                    res["windows"] = Native.ProbeOwnWindows(_titleFilter);
                    MethodInfo emit = null;
                    foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
                    {
                        Type t = asm.GetType("AgentElevation.BrokerEngine", false);
                        if (t != null)
                        {
                            emit = t.GetMethod("EmitJson", BindingFlags.Public | BindingFlags.Static);
                            if (emit != null) break;
                        }
                    }
                    if (emit == null) throw new InvalidOperationException("BrokerEngine.EmitJson not found");
                    emit.Invoke(null, new object[] { res });
                    continue;
                }
                return line;
            }
        }
    }
}
'@

            $probeCode = @'
param(
    [Parameter(Mandatory = $true)][string]$HelperPath,
    [Parameter(Mandatory = $true)][string]$CsPath,
    [Parameter(Mandatory = $true)][ValidateSet('click1', 'reminder')][string]$Mode
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. $HelperPath
Initialize-InteractiveBrokerTypes

$probeCsSrc = [System.IO.File]::ReadAllText($CsPath, [System.Text.Encoding]::UTF8)
Add-Type -TypeDefinition $probeCsSrc -Language CSharp

[AgentElevation.BrokerEngine]::EmitJson([AeBrokerVisProbe.Native]::GetStartupInfoDict())

$engine = New-BrokerEngine `
    -PreflightOverride { param($rp) [pscustomobject]@{ ok = $true; code = 'OK'; exitCode = 0; detail = 'Regression test mock preflight' } } `
    -UacLauncherOverride { param($reqData, $pipeName, $pipeSec, $hwnd) return 1223 }

$filterTitle = if ($Mode -eq 'click1') { 'Elevation Request' } else { 'Pending Elevation Queue' }
$proxy = New-Object AeBrokerVisProbe.StdinProxyReader($filterTitle)
$engine.StartStdinReaderThread($proxy)
$rc = $engine.RunMainLoop()
exit $rc
'@

            $driverCode = @'
import { spawn } from 'node:child_process';

const probePs1 = process.argv[2];
const helperPath = process.argv[3];
const csPath = process.argv[4];
const mode = process.argv[5];

const child = spawn(
  'powershell.exe',
  ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', probePs1, '-HelperPath', helperPath, '-CsPath', csPath, '-Mode', mode],
  { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }
);

let buf = '';
let stderrText = '';
let startupInfo = null;
let shownCount = 0;
let probeResult = null;
let decisionEvent = null;
let sentCommand = false;
let sentTeardown = false;

const killTimer = setTimeout(() => {
  try { child.kill(); } catch {}
  console.error('TIMEOUT mode=' + mode + ' stderr=' + stderrText);
  process.exit(2);
}, 15000);

function handleEvent(ev) {
  if (ev.event === 'startup_info') {
    startupInfo = ev;
    if (!sentCommand) {
      sentCommand = true;
      if (mode === 'click1') {
        child.stdin.write(JSON.stringify({
          cmd: 'start_request',
          requestId: 'req-vis-click1',
          runnerPath: 'C:\\Program Files\\AgentElevation\\Invoke-ElevatedRunner.ps1',
          manifestFile: 'C:\\Windows\\Temp\\nonexistent.json',
          manifestSha256: '0000000000000000000000000000000000000000000000000000000000000000',
          normalWindow: false,
          click1TimeoutSeconds: 30,
          reason: 'Regression test Click1 SW_HIDE visibility',
          workDir: 'C:\\Windows',
          args: [],
          scriptPreview: 'Write-Output "visibility-regression-test"',
          scriptTruncated: false
        }) + '\n');
      } else {
        child.stdin.write(JSON.stringify({
          cmd: 'show_reminder',
          activeSummary: 'Regression test active task',
          queueCount: 2
        }) + '\n');
      }
    }
  } else if ((mode === 'click1' && ev.event === 'click1_shown') || (mode === 'reminder' && ev.event === 'reminder_shown')) {
    shownCount++;
    if (shownCount === 1) {
      child.stdin.write('__PROBE_WIN__\n');
    }
  } else if (ev.event === 'probe_result') {
    probeResult = ev;
    if (!sentTeardown) {
      sentTeardown = true;
      if (mode === 'click1') {
        child.stdin.write(JSON.stringify({ cmd: 'deny', requestId: 'req-vis-click1' }) + '\n');
      }
      child.stdin.write(JSON.stringify({ cmd: 'shutdown' }) + '\n');
      child.stdin.end();
    }
  } else if (ev.event === 'click1_decision') {
    decisionEvent = ev;
  }
}

child.stdout.on('data', chunk => {
  buf += chunk.toString('utf8');
  let idx;
  while ((idx = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    try {
      handleEvent(JSON.parse(line));
    } catch {}
  }
});

child.stderr.on('data', chunk => {
  stderrText += chunk.toString('utf8');
});

child.on('close', code => {
  clearTimeout(killTimer);
  if (code !== 0) {
    console.error('CHILD_EXIT=' + code + ' STDERR=' + stderrText);
    process.exit(code || 1);
  }
  const summary = { mode, startupInfo, shownCount, probeResult, decisionEvent };
  process.stdout.write(JSON.stringify(summary) + '\n');
});
'@

            [System.IO.File]::WriteAllText($probeCsFile, $probeCsCode, $utf8NoBom)
            [System.IO.File]::WriteAllText($probePs1, $probeCode, $utf8WithBom)
            [System.IO.File]::WriteAllText($driverMjs, $driverCode, $utf8NoBom)

            $summaries = @()
            foreach ($mode in @('click1', 'reminder')) {
                $prevEap = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try {
                    $rawOut = & $AgyNodePath $driverMjs $probePs1 $helperPath $probeCsFile $mode 2>&1
                    $exitCode = $LASTEXITCODE
                }
                finally {
                    $ErrorActionPreference = $prevEap
                }
                if ($exitCode -ne 0) {
                    throw "BrokerEngine $mode visibility probe failed (exit=$exitCode): $($rawOut -join ' ')"
                }
                $jsonLine = (($rawOut | Out-String).Trim() -split "`r?`n")[-1]
                $res = $jsonLine | ConvertFrom-Json -ErrorAction Stop

                if (-not $res.startupInfo -or (([int64]$res.startupInfo.dwFlags -band 1) -eq 0) -or [int]$res.startupInfo.wShowWindow -ne 0 -or [int64]$res.startupInfo.consoleHwnd -ne 0) {
                    throw "$mode did not reproduce STARTF_USESHOWWINDOW + SW_HIDE + consoleHwnd=0: $jsonLine"
                }
                if ([int]$res.shownCount -ne 1) {
                    throw "$mode expected shownCount=1, got $($res.shownCount): $jsonLine"
                }
                if (-not $res.probeResult -or $res.probeResult.windows.Count -ne 1) {
                    throw "$mode expected 1 probed form window, got: $jsonLine"
                }
                $win = $res.probeResult.windows[0]
                if (-not [bool]$win.visible) {
                    throw "$mode IsWindowVisible was false! $jsonLine"
                }
                if (([int64]$win.style -band 0x10000000) -eq 0) {
                    throw "$mode missing WS_VISIBLE (0x10000000), style=0x$(([int64]$win.style).ToString('X')): $jsonLine"
                }
                if (([int64]$win.exStyle -band 0x8) -eq 0) {
                    throw "$mode missing WS_EX_TOPMOST (0x8), exStyle=0x$(([int64]$win.exStyle).ToString('X')): $jsonLine"
                }
                if ($mode -eq 'click1' -and (-not $res.decisionEvent -or $res.decisionEvent.decision -ne 'deny')) {
                    throw "click1 expected clean deny teardown, got: $jsonLine"
                }
                $summaries += "$mode(hwnd=$($win.hwnd),vis=$($win.visible),style=0x$(([int64]$win.style).ToString('X')),ex=0x$(([int64]$win.exStyle).ToString('X')))"
            }

            return "Verified BrokerEngine under Node windowsHide:true (SW_HIDE): $($summaries -join '; ')"
        }

        Invoke-TestCase -Id 'A6-REPO-03' -Area '6' -Tier 2 -Name 'Repo BrokerEngine BuildReminderForm AutoScaleMode.None, Panel scrollHost, 96/144 DPI zero crop, and AutoScroll clamp' -Body {
            $helperPath = Join-Path $RepoRoot 'sidecars\broker\broker_helper.ps1'
            if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
                throw "Missing broker_helper.ps1: $helperPath"
            }

            $probePs1 = Join-Path $tempRoot 'reminder_layout_probe.ps1'
            $probeScript = @'
param(
    [Parameter(Mandatory = $true)][string]$HelperPath,
    [Parameter(Mandatory = $true)][string]$OutJsonPath,
    [int]$UseDpiAwareness = 0
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. $HelperPath
Initialize-InteractiveBrokerTypes
if ($UseDpiAwareness -ne 0) {
    [AgentElevation.BrokerEngine]::EnsureDpiAwareness()
}

$dpiScale = [double][AgentElevation.BrokerEngine]::GetSystemDpiScale()
$engine = New-BrokerEngine `
    -PreflightOverride { param($rp) [pscustomobject]@{ ok = $true; code = 'OK'; exitCode = 0; detail = 'Layout test' } } `
    -UacLauncherOverride { param($reqData, $pipeName, $pipeSec, $hwnd) return 1223 }

$extremeLines = 1..45 | ForEach-Object { "Line $_`: Verify extreme multi-line active task summary clamps at 75% working area height with AutoScroll enabled and zero button explosion" }
$cases = @(
    @{ Name = 'short'; Summary = 'Short task (req-short001)'; QueueCount = 1 },
    @{ Name = 'long_multiline'; Summary = "Long multi-line elevated task reason wrapping across several lines at 144 DPI without bottom label cropping`nSecond line: C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1 -Verify (req-long000001)"; QueueCount = 3 },
    @{ Name = 'clamped_extreme'; Summary = ($extremeLines -join "`n"); QueueCount = 5 }
)

$records = @()
foreach ($c in $cases) {
    $form = $engine.BuildReminderForm([string]$c.Summary, [int]$c.QueueCount)
    $handleBeforeShow = $form.IsHandleCreated
    $form.Opacity = 0.0

    $captured = $null
    $shownError = $null
    $timedOut = $false
    $failTimer = New-Object System.Windows.Forms.Timer
    $failTimer.Interval = 20000
    $failTimer.Add_Tick({
        $script:timedOut = $true
        $failTimer.Stop()
        try { $form.Close() } catch {}
    })

    $form.Add_Shown({
        try {
            $form.PerformLayout()
            [System.Windows.Forms.Application]::DoEvents()

            $root = @($form.Controls | Where-Object { $_ -is [System.Windows.Forms.TableLayoutPanel] -and $_.Name -eq 'root' })[0]
            if ($null -eq $root) { throw 'ReminderForm root TableLayoutPanel not found' }

            $scrollHost = @($root.Controls | Where-Object { $_ -is [System.Windows.Forms.Panel] -and $_.Name -eq 'scrollHost' })[0]
            if ($null -eq $scrollHost) { throw 'ReminderForm scrollHost Panel not found' }

            $contentTable = @($scrollHost.Controls | Where-Object { $_ -is [System.Windows.Forms.TableLayoutPanel] -and $_.Name -eq 'contentTable' })[0]
            if ($null -eq $contentTable) { throw 'ReminderForm contentTable TableLayoutPanel not found' }

            $rootRowTypes = @($root.RowStyles | ForEach-Object { $_.SizeType.ToString() })
            $rootRowHeights = @($root.GetRowHeights())
            $contentRowTypes = @($contentTable.RowStyles | ForEach-Object { $_.SizeType.ToString() })
            $contentRowHeights = @($contentTable.GetRowHeights())
            $contentPref = $contentTable.GetPreferredSize((New-Object System.Drawing.Size($contentTable.Width, 0)))

            $labels = @($contentTable.Controls | Where-Object { $_ -is [System.Windows.Forms.Label] })
            $lblTitle = @($labels | Where-Object { $_.Name -eq 'lblTitle' })[0]
            $lblActive = @($labels | Where-Object { $_.Name -eq 'lblActive' })[0]
            $lblHint = @($labels | Where-Object { $_.Name -eq 'lblHint' })[0]
            $btnPanel = @($root.Controls | Where-Object { $_ -is [System.Windows.Forms.FlowLayoutPanel] -and $_.Name -eq 'btnPanel' })[0]
            $btnDismiss = if ($btnPanel) { @($btnPanel.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Name -eq 'btnDismiss' })[0] } else { $null }

            $hintPref = if ($lblHint) { $lblHint.GetPreferredSize((New-Object System.Drawing.Size($lblHint.MaximumSize.Width, 0))) } else { [System.Drawing.Size]::Empty }
            $activePref = if ($lblActive) { $lblActive.GetPreferredSize((New-Object System.Drawing.Size($lblActive.MaximumSize.Width, 0))) } else { [System.Drawing.Size]::Empty }

            $btnDismissInBoundsPre = if ($btnDismiss) { $form.ClientRectangle.Contains($form.RectangleToClient($btnDismiss.RectangleToScreen($btnDismiss.ClientRectangle))) } else { $false }
            if ($scrollHost.AutoScroll) {
                $scrollHost.AutoScrollPosition = New-Object System.Drawing.Point(0, $scrollHost.DisplayRectangle.Height)
                $form.PerformLayout()
                [System.Windows.Forms.Application]::DoEvents()
            }
            $btnDismissInBoundsPost = if ($btnDismiss) { $form.ClientRectangle.Contains($form.RectangleToClient($btnDismiss.RectangleToScreen($btnDismiss.ClientRectangle))) } else { $false }
            $btnPanelInBoundsPost = if ($btnPanel) { $form.ClientRectangle.Contains($form.RectangleToClient($btnPanel.RectangleToScreen($btnPanel.ClientRectangle))) } else { $false }
            $lblHintInScrollHostPost = if ($lblHint) { $scrollHost.ClientRectangle.Contains($scrollHost.RectangleToClient($lblHint.RectangleToScreen($lblHint.ClientRectangle))) } else { $false }

            $script:captured = [ordered]@{
                dpiAware                = ($UseDpiAwareness -ne 0)
                caseName                = $c.Name
                dpiScale                = $dpiScale
                handleBeforeShow        = $handleBeforeShow
                autoScaleMode           = $form.AutoScaleMode.ToString()
                formSize                = @{ w = $form.Size.Width; h = $form.Size.Height }
                minimumSize             = @{ w = $form.MinimumSize.Width; h = $form.MinimumSize.Height }
                clientSize              = @{ w = $form.ClientSize.Width; h = $form.ClientSize.Height }
                rootClientSize          = @{ w = $root.ClientSize.Width; h = $root.ClientSize.Height }
                rootAutoScroll          = $root.AutoScroll
                contentAutoScroll       = $contentTable.AutoScroll
                rootRowCount            = $root.RowCount
                rootRowTypes            = $rootRowTypes
                rootRowHeights          = $rootRowHeights
                contentRowCount         = $contentTable.RowCount
                contentRowTypes         = $contentRowTypes
                contentRowHeights       = $contentRowHeights
                contentPrefHeight       = $contentPref.Height
                contentBottom           = $contentTable.Bottom
                scrollHostAutoScroll    = $scrollHost.AutoScroll
                scrollHostClientSize    = @{ w = $scrollHost.ClientSize.Width; h = $scrollHost.ClientSize.Height }
                scrollHostDispSize      = @{ w = $scrollHost.DisplayRectangle.Width; h = $scrollHost.DisplayRectangle.Height }
                scrollHostBottom        = $scrollHost.Bottom
                verticalScrollVis       = $scrollHost.VerticalScroll.Visible
                horizontalScrollVis     = $scrollHost.HorizontalScroll.Visible
                verticalScrollMax       = $scrollHost.VerticalScroll.Maximum
                lblTitleBottom          = if ($lblTitle) { $lblTitle.Bottom } else { -1 }
                lblActiveTop            = if ($lblActive) { $lblActive.Top } else { -1 }
                lblActiveBottom         = if ($lblActive) { $lblActive.Bottom } else { -1 }
                lblActiveHeight         = if ($lblActive) { $lblActive.Height } else { -1 }
                lblActivePrefHeight     = $activePref.Height
                lblHintText             = if ($lblHint) { $lblHint.Text } else { '' }
                lblHintTop              = if ($lblHint) { $lblHint.Top } else { -1 }
                lblHintBottom           = if ($lblHint) { $lblHint.Bottom } else { -1 }
                lblHintHeight           = if ($lblHint) { $lblHint.Height } else { -1 }
                lblHintPrefHeight       = $hintPref.Height
                btnPanelDock            = if ($btnPanel) { $btnPanel.Dock.ToString() } else { '' }
                btnPanelAnchor          = if ($btnPanel) { $btnPanel.Anchor.ToString() } else { '' }
                btnPanelTop             = if ($btnPanel) { $btnPanel.Top } else { -1 }
                btnPanelBottom          = if ($btnPanel) { $btnPanel.Bottom } else { -1 }
                btnPanelHeight          = if ($btnPanel) { $btnPanel.Height } else { -1 }
                btnDismissBottom        = if ($btnDismiss) { $btnDismiss.Bottom } else { -1 }
                btnDismissInBoundsPre   = $btnDismissInBoundsPre
                btnDismissInBoundsPost  = $btnDismissInBoundsPost
                btnPanelInBoundsPost    = $btnPanelInBoundsPost
                lblHintInScrollHostPost = $lblHintInScrollHostPost
                workingAreaHeight       = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height
            }
        }
        catch {
            $script:shownError = $_.Exception.ToString()
        }
        finally {
            $failTimer.Stop()
            $null = $form.BeginInvoke([System.Action]{ $form.Close() })
        }
    })

    $failTimer.Start()
    [System.Windows.Forms.Application]::Run($form)
    $failTimer.Dispose()
    $form.Dispose()
    if ($null -ne $shownError) { throw "ReminderForm Shown handler failed for $($c.Name): $shownError" }
    if ($timedOut) { throw "ReminderForm Shown handler timed out (>20000ms) for $($c.Name)" }
    if ($null -eq $captured) { throw "ReminderForm Shown handler did not run for $($c.Name)" }
    $records += $captured
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutJsonPath, ($records | ConvertTo-Json -Depth 6), $utf8NoBom)
'@
            [System.IO.File]::WriteAllText($probePs1, $probeScript, $utf8WithBom)

            $allSummaries = @()
            foreach ($dpiFlag in @(0, 1)) {
                $outJson = Join-Path $tempRoot ("reminder_layout_out_{0}.json" -f $dpiFlag)
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'powershell.exe'
                $psi.Arguments = "-NoProfile -Sta -ExecutionPolicy Bypass -File `"$probePs1`" -HelperPath `"$helperPath`" -OutJsonPath `"$outJson`" -UseDpiAwareness $dpiFlag"
                $psi.UseShellExecute = $false
                $psi.CreateNoWindow = $true
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $p = [System.Diagnostics.Process]::Start($psi)
                $outTask = $p.StandardOutput.ReadToEndAsync()
                $errTask = $p.StandardError.ReadToEndAsync()
                if (-not $p.WaitForExit(45000)) {
                    $p.Kill()
                    throw "ReminderForm layout probe (dpiFlag=$dpiFlag) timed out (>45s)"
                }
                $out = $outTask.GetAwaiter().GetResult()
                $err = $errTask.GetAwaiter().GetResult()
                if ($p.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $outJson -PathType Leaf)) {
                    throw "ReminderForm layout probe (dpiFlag=$dpiFlag) failed (exit=$($p.ExitCode)): out=$out err=$err"
                }

                $recs = @((Get-Content -LiteralPath $outJson -Raw -Encoding UTF8) | ConvertFrom-Json | ForEach-Object { $_ })
                if ($recs.Count -ne 3) { throw "Expected 3 ReminderForm test records (dpiFlag=$dpiFlag), got $($recs.Count)" }

                if ($dpiFlag -eq 0 -and [Math]::Abs([double]$recs[0].dpiScale - 1.0) -gt 0.01) {
                    throw "Expected 96 DPI (scale=1.0) without EnsureDpiAwareness(), got $($recs[0].dpiScale)"
                }
                if ($dpiFlag -eq 1 -and [double]$recs[0].dpiScale -lt 1.0) {
                    throw "Expected dpiScale >= 1.0 with EnsureDpiAwareness(), got $($recs[0].dpiScale)"
                }

                foreach ($r in $recs) {
                    $tag = "dpi=$($r.dpiScale)/$($r.caseName)"
                    if ($r.handleBeforeShow) {
                        throw "${tag}: BuildReminderForm created form Handle prematurely (must not call CreateGraphics before Handle)"
                    }
                    if ($r.autoScaleMode -ne 'None') {
                        throw "${tag}: expected AutoScaleMode=None, got $($r.autoScaleMode)"
                    }
                    if ($r.rootAutoScroll -or $r.contentAutoScroll) {
                        throw "${tag}: TableLayoutPanel must NOT enable AutoScroll directly (root=$($r.rootAutoScroll), content=$($r.contentAutoScroll))"
                    }
                    if ($r.rootRowCount -ne 2 -or $r.rootRowTypes.Count -ne 2 -or $r.rootRowTypes[0] -ne 'Percent' -or $r.rootRowTypes[1] -ne 'AutoSize') {
                        throw "${tag}: expected root 2 rows [Percent, AutoSize], got [$($r.rootRowTypes -join ', ')]"
                    }
                    if ($r.contentRowCount -ne 3 -or $r.contentRowTypes.Count -ne 3 -or (@($r.contentRowTypes | Where-Object { $_ -ne 'AutoSize' }).Count -gt 0)) {
                        throw "${tag}: expected all 3 contentTable rows to be AutoSize, got [$($r.contentRowTypes -join ', ')]"
                    }
                    $maxBtnRowH = [int][Math]::Ceiling(200 * [double]$r.dpiScale)
                    if ([int]$r.rootRowHeights[1] -gt $maxBtnRowH) {
                        throw "${tag}: btnPanel row height exploded ($($r.rootRowHeights[1]) px > $maxBtnRowH)"
                    }
                    if ($r.btnPanelDock -ne 'None' -or $r.btnPanelAnchor -notmatch 'Top' -or $r.btnPanelAnchor -notmatch 'Right') {
                        throw "${tag}: expected btnPanel Dock=None and Anchor=Top,Right, got Dock=$($r.btnPanelDock) Anchor=$($r.btnPanelAnchor)"
                    }
                    if ($r.btnPanelHeight -gt $maxBtnRowH) {
                        throw "${tag}: btnPanel height exploded ($($r.btnPanelHeight) px > $maxBtnRowH)"
                    }
                    if ($r.lblTitleBottom -gt $r.lblActiveTop) {
                        throw "${tag}: lblTitle ($($r.lblTitleBottom)) overlapped lblActive ($($r.lblActiveTop))"
                    }
                    if ($r.lblActiveBottom -gt $r.lblHintTop) {
                        throw "${tag}: lblActive ($($r.lblActiveBottom)) overlapped lblHint ($($r.lblHintTop))"
                    }
                    if ($r.scrollHostBottom -gt $r.btnPanelTop) {
                        throw "${tag}: scrollHost ($($r.scrollHostBottom)) overlapped btnPanel ($($r.btnPanelTop))"
                    }
                    if ($r.lblHintHeight -lt $r.lblHintPrefHeight) {
                        throw "${tag}: lblHint height ($($r.lblHintHeight)) < PreferredHeight ($($r.lblHintPrefHeight))"
                    }
                    if ($r.lblHintText -notlike 'Queued requests will present Click-1 approval*' -or
                        $r.lblHintText -notmatch [regex]::Escape('Closes automatically when the active task finishes or the queue clears.')) {
                        throw "${tag}: lblHint missing expected queue/auto-close copy: '$($r.lblHintText)'"
                    }
                    if ($r.lblActiveHeight -lt $r.lblActivePrefHeight) {
                        throw "${tag}: lblActive height ($($r.lblActiveHeight)) < PreferredHeight ($($r.lblActivePrefHeight))"
                    }
                    if ($r.horizontalScrollVis -or ([int]$r.scrollHostDispSize.w -gt [int]$r.scrollHostClientSize.w)) {
                        throw "${tag}: unexpected horizontal scroll overflow (hVis=$($r.horizontalScrollVis), dispW=$($r.scrollHostDispSize.w), clientW=$($r.scrollHostClientSize.w))"
                    }
                    if (-not $r.btnDismissInBoundsPre -or -not $r.btnDismissInBoundsPost -or -not $r.btnPanelInBoundsPost) {
                        throw "${tag}: [Dismiss] button out of client bounds (pre=$r.btnDismissInBoundsPre, post=$r.btnDismissInBoundsPost, panelPost=$r.btnPanelInBoundsPost)"
                    }
                    if (-not $r.lblHintInScrollHostPost) {
                        throw "${tag}: lblHint not cleanly visible in scrollHost after scrolling to bottom"
                    }

                    if ($r.caseName -eq 'clamped_extreme') {
                        if (-not $r.scrollHostAutoScroll -or -not $r.verticalScrollVis) {
                            throw "${tag}: expected scrollHost.AutoScroll=True and VerticalScroll.Visible=True on clamped extreme summary (auto=$($r.scrollHostAutoScroll), vVis=$($r.verticalScrollVis))"
                        }
                        $maxAllowedH = [Math]::Max([int][Math]::Ceiling(240 * [double]$r.dpiScale), [int]([double]$r.workingAreaHeight * 0.75))
                        if ($r.clientSize.h -gt $maxAllowedH) {
                            throw "${tag}: clamped ClientSize.Height ($($r.clientSize.h)) exceeded 75% working area cap ($maxAllowedH)"
                        }
                        $maxDispH = [int]$r.contentPrefHeight + [int][Math]::Ceiling(50 * [double]$r.dpiScale)
                        if ([int]$r.scrollHostDispSize.h -gt $maxDispH) {
                            throw "${tag}: scrollHost DisplayRectangle.Height exploded ($($r.scrollHostDispSize.h) > $maxDispH; pref=$($r.contentPrefHeight))"
                        }
                    }
                    else {
                        if ($r.scrollHostAutoScroll -or $r.verticalScrollVis) {
                            throw "${tag}: unexpected AutoScroll/scrollbar on normal ReminderForm"
                        }
                        if ($r.lblHintBottom -gt $r.scrollHostClientSize.h) {
                            throw "${tag}: lblHint cropped! lblHint.Bottom=$($r.lblHintBottom) > scrollHost.ClientSize.Height=$($r.scrollHostClientSize.h)"
                        }
                        if ($r.btnPanelBottom -gt $r.rootClientSize.h) {
                            throw "${tag}: btnPanel ($($r.btnPanelBottom)) exceeded root.ClientSize.Height ($($r.rootClientSize.h))"
                        }
                    }
                }

                $allSummaries += ("dpiFlag=$dpiFlag(scale=$($recs[0].dpiScale)): " + (($recs | ForEach-Object { "$($_.caseName)=$($_.rootClientSize.w)x$($_.rootClientSize.h),dispH=$($_.scrollHostDispSize.h),btnRow=$($_.rootRowHeights[1]),scroll=$($_.scrollHostAutoScroll)" }) -join ', '))
            }

            return "Verified BuildReminderForm at 96/144 DPI: $($allSummaries -join ' | ')"
        }

        Invoke-TestCase -Id 'A6-REPO-04' -Area '6' -Tier 2 -Name 'Repo BrokerEngine BuildClick1Form prominent -Reason banner, 96/144 DPI zero overlap, preview >= S(140), and resize' -Body {
            $helperPath = Join-Path $RepoRoot 'sidecars\broker\broker_helper.ps1'
            if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
                throw "Missing broker_helper.ps1: $helperPath"
            }

            $probePs1 = Join-Path $tempRoot 'click1_layout_probe.ps1'
            $probeScript = @'
param(
    [Parameter(Mandatory = $true)][string]$HelperPath,
    [Parameter(Mandatory = $true)][string]$OutJsonPath,
    [int]$UseDpiAwareness = 0
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. $HelperPath
Initialize-InteractiveBrokerTypes
if ($UseDpiAwareness -ne 0) {
    [AgentElevation.BrokerEngine]::EnsureDpiAwareness()
}

$dpiScale = [double][AgentElevation.BrokerEngine]::GetSystemDpiScale()
$minPreviewScaled = [int][Math]::Ceiling(140 * $dpiScale)

# Verify ParseRequestData is public static
$parsedDict = New-Object 'System.Collections.Generic.Dictionary[string,object]'
$parsedDict['requestId'] = 'req-parse-check'
$parsedDict['reason'] = 'Parsed reason check'
$parsedCheck = [AgentElevation.BrokerEngine]::ParseRequestData($parsedDict)
if ($parsedCheck.Reason -ne 'Parsed reason check') {
    throw "ParseRequestData failed: got '$($parsedCheck.Reason)'"
}

function Get-AllDescendants {
    param([System.Windows.Forms.Control]$Root)
    $list = New-Object 'System.Collections.Generic.List[System.Windows.Forms.Control]'
    foreach ($ch in $Root.Controls) {
        $list.Add($ch)
        foreach ($sub in (Get-AllDescendants -Root $ch)) {
            $list.Add($sub)
        }
    }
    return $list
}

function Get-ClientBoundsInForm {
    param([System.Windows.Forms.Form]$Form, [System.Windows.Forms.Control]$Ctrl)
    $scr = $Ctrl.Parent.RectangleToScreen($Ctrl.Bounds)
    $cli = $Form.RectangleToClient($scr)
    return [ordered]@{ x = $cli.X; y = $cli.Y; w = $cli.Width; h = $cli.Height; top = $cli.Top; bottom = $cli.Bottom; right = $cli.Right }
}

$reqShort = New-Object AgentElevation.BrokerRequestData
$reqShort.RequestId = 'req-layout-short'
$reqShort.Reason = 'Short elevation reason for layout verification'
$reqShort.WorkDir = 'C:\Windows\System32'
$reqShort.Args = @('-Check')
$reqShort.ManifestSha256 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$reqShort.Click1TimeoutSeconds = 0
$reqShort.ScriptPreview = 'Write-Output "short-reason-test"'

$reqLong = New-Object AgentElevation.BrokerRequestData
$reqLong.RequestId = 'req-layout-long'
$reqLong.Reason = "Verify prominent Click-1 reason banner renders multi-line -Reason cleanly above metaPanel without overlapping WorkDir/Args/Target/ManifestSha256 at 144 DPI.`nLine 2: Long path C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1 --validate-all-acls-and-registry-keys"
$reqLong.WorkDir = 'C:\Workspace\Antigravity-ElevatedExecution'
$reqLong.Args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Target', 'C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1', '-Verbose')
$reqLong.HasTargetMeta = $true
$reqLong.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$reqLong.TargetSubsystem = 'CUI'
$reqLong.TargetPublisher = 'Microsoft Windows'
$reqLong.ManifestSha256 = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
$reqLong.Click1TimeoutSeconds = 0
$reqLong.ScriptTruncated = $true
$reqLong.ScriptPreview = "1..40 | ForEach-Object { `"Line `$_`" }"

$extremeReasonLines = 1..30 | ForEach-Object { "Reason line $_`: Testing topScrollHost overflow containment while preserving preview >= S(140) and visible action buttons." }
$reqExtreme = New-Object AgentElevation.BrokerRequestData
$reqExtreme.RequestId = 'req-layout-extreme'
$reqExtreme.Reason = ($extremeReasonLines -join "`n")
$reqExtreme.WorkDir = 'C:\Workspace\Antigravity-ElevatedExecution'
$reqExtreme.Args = @('-NoProfile', '-ExecutionPolicy', 'Bypass')
$reqExtreme.HasTargetMeta = $true
$reqExtreme.TargetPath = 'C:\Windows\System32\cmd.exe'
$reqExtreme.TargetSubsystem = 'CUI'
$reqExtreme.TargetPublisher = ''
$reqExtreme.ManifestSha256 = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
$reqExtreme.Click1TimeoutSeconds = 0
$reqExtreme.ScriptPreview = 'Write-Output "extreme"'

$cases = @(
    @{ Name = 'short'; Req = $reqShort },
    @{ Name = 'long_multiline'; Req = $reqLong },
    @{ Name = 'extreme_scroll'; Req = $reqExtreme }
)

$records = @()
$lightTheme = [AgentElevation.DialogTheme]::Create([AgentElevation.DialogThemeMode]::Light)
foreach ($c in $cases) {
    $engine = New-BrokerEngine `
        -PreflightOverride { param($rp) [pscustomobject]@{ ok = $true; code = 'OK'; exitCode = 0; detail = 'Layout test' } } `
        -UacLauncherOverride { param($reqData, $pipeName, $pipeSec, $hwnd) return 1223 }

    $form = $engine.BuildClick1Form($c.Req, $lightTheme)
    $handleBeforeShow = $form.IsHandleCreated
    $form.Opacity = 0.0

    $captured = $null
    $shownError = $null
    $timedOut = $false
    $failTimer = New-Object System.Windows.Forms.Timer
    $failTimer.Interval = 20000
    $failTimer.Add_Tick({
        $script:timedOut = $true
        $failTimer.Stop()
        try { $form.Close() } catch {}
    })

    $measureSnapshot = {
        param([string]$Phase)
        $form.PerformLayout()
        [System.Windows.Forms.Application]::DoEvents()

        $all = Get-AllDescendants -Root $form
        $topScrollHost = @($all | Where-Object { $_.Name -eq 'topScrollHost' })[0]
        if ($null -eq $topScrollHost) { throw "$($c.Name) ($Phase): topScrollHost not found" }

        $reasonBanner = @($all | Where-Object { $_.Name -eq 'reasonBanner' })[0]
        $reasonAccent = @($all | Where-Object { $_.Name -eq 'reasonAccent' })[0]
        $reasonContent = @($all | Where-Object { $_.Name -eq 'reasonContent' })[0]
        $lblCaption = @($all | Where-Object { $_.Name -eq 'lblReasonCaption' -and $_.Text -eq 'REASON FOR ELEVATION' })[0]
        $lblReason = @($all | Where-Object { $_.Name -eq 'lblReason' -and $_.Text -eq $c.Req.Reason })[0]
        if ($null -eq $reasonBanner -or $null -eq $reasonAccent -or $null -eq $reasonContent -or $null -eq $lblCaption -or $null -eq $lblReason) {
            throw "$($c.Name) ($Phase): missing reasonBanner hierarchy controls"
        }

        $metaPanel = @($all | Where-Object { $_.Name -eq 'metaPanel' -and $_ -is [System.Windows.Forms.TableLayoutPanel] })[0]
        if ($null -eq $metaPanel) { throw "$($c.Name) ($Phase): metaPanel not found" }

        $hasLegacyReasonRow = (@($metaPanel.Controls | Where-Object { $_ -is [System.Windows.Forms.Label] -and $_.Text -eq 'Reason:' }).Count -gt 0)
        $lblPreviewHdr = @($all | Where-Object { $_.Name -eq 'lblPreviewHdr' -and $_ -is [System.Windows.Forms.Label] })[0]
        $txtPreview = @($all | Where-Object { $_.Name -eq 'txtPreview' -and $_ -is [System.Windows.Forms.TextBox] })[0]
        $btnDeny = @($all | Where-Object { $_.Name -eq 'btnDeny' -and $_ -is [System.Windows.Forms.Button] })[0]
        $btnProceed = @($all | Where-Object { $_.Name -eq 'btnProceed' -and $_ -is [System.Windows.Forms.Button] })[0]
        if ($null -eq $lblPreviewHdr -or $null -eq $txtPreview -or $null -eq $btnDeny -or $null -eq $btnProceed) {
            throw "$($c.Name) ($Phase): lblPreviewHdr/txtPreview/btnDeny/btnProceed not found"
        }

        $reasonPref = $lblReason.GetPreferredSize((New-Object System.Drawing.Size($lblReason.MaximumSize.Width, 0)))
        $hdrConstraintW = if ($lblPreviewHdr.MaximumSize.Width -gt 0) { $lblPreviewHdr.MaximumSize.Width } else { 0 }
        $previewHdrPref = $lblPreviewHdr.GetPreferredSize((New-Object System.Drawing.Size($hdrConstraintW, 0)))

        return [ordered]@{
            phase                = $Phase
            clientSize           = @{ w = $form.ClientSize.Width; h = $form.ClientSize.Height }
            formSize             = @{ w = $form.Size.Width; h = $form.Size.Height }
            topScrollAutoScroll  = $topScrollHost.AutoScroll
            reasonMaxW           = $lblReason.MaximumSize.Width
            reasonBold           = $lblReason.Font.Bold
            reasonPt             = [double]$lblReason.Font.SizeInPoints
            reasonHeight         = $lblReason.Height
            reasonPrefHeight     = $reasonPref.Height
            previewHdrText       = $lblPreviewHdr.Text
            previewHdrMaxW       = $lblPreviewHdr.MaximumSize.Width
            previewHdrHeight     = $lblPreviewHdr.Height
            previewHdrPrefHeight = $previewHdrPref.Height
            previewHdrRect       = Get-ClientBoundsInForm -Form $form -Ctrl $lblPreviewHdr
            accentColorHex       = ('#{0:X2}{1:X2}{2:X2}' -f $reasonAccent.BackColor.R, $reasonAccent.BackColor.G, $reasonAccent.BackColor.B)
            contentBgHex         = ('#{0:X2}{1:X2}{2:X2}' -f $reasonContent.BackColor.R, $reasonContent.BackColor.G, $reasonContent.BackColor.B)
            hasLegacyReasonRow   = $hasLegacyReasonRow
            topHostRect          = Get-ClientBoundsInForm -Form $form -Ctrl $topScrollHost
            bannerRect           = Get-ClientBoundsInForm -Form $form -Ctrl $reasonBanner
            metaRect             = Get-ClientBoundsInForm -Form $form -Ctrl $metaPanel
            previewRect          = Get-ClientBoundsInForm -Form $form -Ctrl $txtPreview
            denyRect             = Get-ClientBoundsInForm -Form $form -Ctrl $btnDeny
            proceedRect          = Get-ClientBoundsInForm -Form $form -Ctrl $btnProceed
        }
    }

    $form.Add_Shown({
        try {
            $initSnap = & $measureSnapshot 'initial'
            $form.Size = $form.MinimumSize
            $minSnap = & $measureSnapshot 'resized_min'

            $script:captured = [ordered]@{
                dpiAware         = ($UseDpiAwareness -ne 0)
                caseName         = $c.Name
                dpiScale         = $dpiScale
                minPreviewScaled = $minPreviewScaled
                handleBeforeShow = $handleBeforeShow
                autoScaleMode    = $form.AutoScaleMode.ToString()
                minimumSize      = @{ w = $form.MinimumSize.Width; h = $form.MinimumSize.Height }
                initial          = $initSnap
                resized          = $minSnap
            }
        }
        catch {
            $script:shownError = $_.Exception.ToString()
        }
        finally {
            $failTimer.Stop()
            $null = $form.BeginInvoke([System.Action]{ $form.Close() })
        }
    })

    $failTimer.Start()
    [System.Windows.Forms.Application]::Run($form)
    $failTimer.Dispose()
    $form.Dispose()
    if ($null -ne $shownError) { throw "Click1Form Shown handler failed for $($c.Name): $shownError" }
    if ($timedOut) { throw "Click1Form Shown handler timed out (>20000ms) for $($c.Name)" }
    if ($null -eq $captured) { throw "Click1Form Shown handler did not run for $($c.Name)" }
    $records += $captured
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutJsonPath, ($records | ConvertTo-Json -Depth 7), $utf8NoBom)
'@
            [System.IO.File]::WriteAllText($probePs1, $probeScript, $utf8WithBom)

            $allSummaries = @()
            foreach ($dpiFlag in @(0, 1)) {
                $outJson = Join-Path $tempRoot ("click1_layout_out_{0}.json" -f $dpiFlag)
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'powershell.exe'
                $psi.Arguments = "-NoProfile -Sta -ExecutionPolicy Bypass -File `"$probePs1`" -HelperPath `"$helperPath`" -OutJsonPath `"$outJson`" -UseDpiAwareness $dpiFlag"
                $psi.UseShellExecute = $false
                $psi.CreateNoWindow = $true
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $p = [System.Diagnostics.Process]::Start($psi)
                $outTask = $p.StandardOutput.ReadToEndAsync()
                $errTask = $p.StandardError.ReadToEndAsync()
                if (-not $p.WaitForExit(45000)) {
                    $p.Kill()
                    throw "Click1Form layout probe (dpiFlag=$dpiFlag) timed out (>45s)"
                }
                $out = $outTask.GetAwaiter().GetResult()
                $err = $errTask.GetAwaiter().GetResult()
                if ($p.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $outJson -PathType Leaf)) {
                    throw "Click1Form layout probe (dpiFlag=$dpiFlag) failed (exit=$($p.ExitCode)): out=$out err=$err"
                }

                $recs = @((Get-Content -LiteralPath $outJson -Raw -Encoding UTF8) | ConvertFrom-Json | ForEach-Object { $_ })
                if ($recs.Count -ne 3) { throw "Expected 3 Click1Form test records (dpiFlag=$dpiFlag), got $($recs.Count)" }

                if ($dpiFlag -eq 0 -and [Math]::Abs([double]$recs[0].dpiScale - 1.0) -gt 0.01) {
                    throw "Expected 96 DPI (scale=1.0) without EnsureDpiAwareness(), got $($recs[0].dpiScale)"
                }
                if ($dpiFlag -eq 1 -and [double]$recs[0].dpiScale -lt 1.0) {
                    throw "Expected dpiScale >= 1.0 with EnsureDpiAwareness(), got $($recs[0].dpiScale)"
                }

                foreach ($r in $recs) {
                    $tag = "dpi=$($r.dpiScale)/$($r.caseName)"
                    if ($r.handleBeforeShow) {
                        throw "${tag}: BuildClick1Form created form Handle prematurely (must not call CreateGraphics before Handle)"
                    }
                    if ($r.autoScaleMode -ne 'None') {
                        throw "${tag}: expected AutoScaleMode=None, got $($r.autoScaleMode)"
                    }
                    if ($r.caseName -eq 'extreme_scroll' -and -not $r.initial.topScrollAutoScroll) {
                        throw "${tag}: expected topScrollHost.AutoScroll=True on extreme_scroll"
                    }

                    foreach ($snap in @($r.initial, $r.resized)) {
                        $stag = "${tag}/$($snap.phase)"
                        if ($snap.hasLegacyReasonRow) {
                            throw "${stag}: metaPanel still contains legacy Reason: row"
                        }
                        if ($snap.accentColorHex -ne '#007ACC' -or $snap.contentBgHex -ne '#F0F6FC') {
                            throw "${stag}: unexpected reasonBanner colors accent=$($snap.accentColorHex) bg=$($snap.contentBgHex)"
                        }
                        if (-not $snap.reasonBold -or $snap.reasonPt -lt 10.0) {
                            throw "${stag}: reason banner font should be bold >=10pt, got bold=$($snap.reasonBold) pt=$($snap.reasonPt)"
                        }
                        if ($snap.reasonHeight -lt $snap.reasonPrefHeight) {
                            throw "${stag}: reason label cropped ($($snap.reasonHeight) < $($snap.reasonPrefHeight))"
                        }
                        if ($snap.bannerRect.bottom -gt $snap.metaRect.top) {
                            throw "${stag}: banner ($($snap.bannerRect.bottom)) overlaps metaPanel ($($snap.metaRect.top))"
                        }
                        if ($snap.topHostRect.bottom -gt $snap.previewRect.top) {
                            throw "${stag}: topScrollHost ($($snap.topHostRect.bottom)) overlaps txtPreview ($($snap.previewRect.top))"
                        }
                        if ($snap.previewHdrMaxW -le 0) {
                            throw "${stag}: expected lblPreviewHdr.MaximumSize.Width > 0, got $($snap.previewHdrMaxW)"
                        }
                        if ($r.caseName -eq 'long_multiline' -and $snap.previewHdrText -notmatch 'truncated above 64 KB') {
                            throw "${stag}: expected truncated preview header for long_multiline, got '$($snap.previewHdrText)'"
                        }
                        if ($r.caseName -eq 'short' -and $snap.previewHdrText -notmatch 'verbatim UTF-8') {
                            throw "${stag}: expected verbatim preview header for short, got '$($snap.previewHdrText)'"
                        }
                        if ($snap.previewHdrHeight -lt $snap.previewHdrPrefHeight) {
                            throw "${stag}: lblPreviewHdr height ($($snap.previewHdrHeight)) < PreferredHeight ($($snap.previewHdrPrefHeight))"
                        }
                        if ($snap.previewHdrRect.right -gt $snap.clientSize.w) {
                            throw "${stag}: lblPreviewHdr right ($($snap.previewHdrRect.right)) exceeded ClientSize.Width ($($snap.clientSize.w))"
                        }
                        if ($snap.topHostRect.bottom -gt $snap.previewHdrRect.top) {
                            throw "${stag}: topScrollHost ($($snap.topHostRect.bottom)) overlaps lblPreviewHdr ($($snap.previewHdrRect.top))"
                        }
                        if ($snap.previewHdrRect.bottom -gt $snap.previewRect.top) {
                            throw "${stag}: lblPreviewHdr ($($snap.previewHdrRect.bottom)) overlaps txtPreview ($($snap.previewRect.top))"
                        }
                        if (-not $snap.topScrollAutoScroll -and $snap.metaRect.bottom -gt $snap.previewRect.top) {
                            throw "${stag}: metaPanel ($($snap.metaRect.bottom)) overlaps txtPreview ($($snap.previewRect.top))"
                        }
                        if ($snap.previewRect.h -lt $r.minPreviewScaled) {
                            throw "${stag}: txtPreview.Height ($($snap.previewRect.h)) < S(140) ($($r.minPreviewScaled))"
                        }
                        foreach ($btnName in @('denyRect', 'proceedRect')) {
                            $b = $snap.$btnName
                            if ($b.top -lt $snap.previewRect.bottom) {
                                throw "${stag}: $btnName ($($b.top)) overlaps txtPreview ($($snap.previewRect.bottom))"
                            }
                            if ($b.bottom -gt $snap.clientSize.h -or $b.right -gt $snap.clientSize.w -or $b.x -lt 0) {
                                throw "${stag}: $btnName out of client bounds ($($b.x),$($b.top)-$($b.right),$($b.bottom)) vs $($snap.clientSize.w)x$($snap.clientSize.h)"
                            }
                        }
                    }
                    if ($r.resized.clientSize.w -lt $r.initial.clientSize.w -and $r.resized.reasonMaxW -ge $r.initial.reasonMaxW) {
                        throw "${tag}: resize did not update reason label MaximumSize ($($r.initial.reasonMaxW) -> $($r.resized.reasonMaxW))"
                    }
                    if ($r.resized.clientSize.w -lt $r.initial.clientSize.w -and $r.resized.previewHdrMaxW -ge $r.initial.previewHdrMaxW) {
                        throw "${tag}: resize did not shrink lblPreviewHdr.MaximumSize.Width ($($r.initial.previewHdrMaxW) -> $($r.resized.previewHdrMaxW))"
                    }
                }

                $allSummaries += ("dpiFlag=$dpiFlag(scale=$($recs[0].dpiScale)): " + (($recs | ForEach-Object { "$($_.caseName)(initPrev=$($_.initial.previewRect.h),minPrev=$($_.resized.previewRect.h))" }) -join ', '))
            }

            return "Verified BuildClick1Form prominent -Reason banner at 96/144 DPI: $($allSummaries -join ' | ')"
        }

        Invoke-TestCase -Id 'A6-REPO-05' -Area '6' -Tier 2 -Name 'Repo BrokerEngine Click1Form click1DeadlineAt on click1_shown and UTC deadline countdown' -Body {
            $helperPath = Join-Path $RepoRoot 'sidecars\broker\broker_helper.ps1'
            if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
                throw "Missing broker_helper.ps1: $helperPath"
            }

            $probePs1 = Join-Path $tempRoot 'click1_countdown_probe.ps1'
            $outJson = Join-Path $tempRoot 'click1_countdown_out.json'
            $probeScript = @'
param(
    [Parameter(Mandatory = $true)][string]$HelperPath,
    [Parameter(Mandatory = $true)][string]$OutJsonPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. $HelperPath
Initialize-InteractiveBrokerTypes
[AgentElevation.BrokerEngine]::EnsureDpiAwareness()

function Get-ControlByName {
    param([System.Windows.Forms.Control]$Root, [string]$Name)
    foreach ($ch in $Root.Controls) {
        if ($ch.Name -eq $Name) { return $ch }
        $sub = Get-ControlByName -Root $ch -Name $Name
        if ($null -ne $sub) { return $sub }
    }
    return $null
}

# Case 1: Click1TimeoutSeconds = 0 -> no click1DeadlineAt
$engine0 = New-BrokerEngine `
    -PreflightOverride { param($rp) [pscustomobject]@{ ok = $true; code = 'OK'; exitCode = 0; detail = 'Countdown test' } } `
    -UacLauncherOverride { param($reqData, $pipeName, $pipeSec, $hwnd) return 1223 }

$req0 = New-Object AgentElevation.BrokerRequestData
$req0.RequestId = 'req-countdown-0'
$req0.Reason = 'Verify zero timeout omits click1DeadlineAt'
$req0.WorkDir = 'C:\Windows'
$req0.ManifestSha256 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$req0.Click1TimeoutSeconds = 0
$req0.ScriptPreview = 'Write-Output 0'

$form0 = $engine0.BuildClick1Form($req0)
$form0.Opacity = 0.0
$form0.ShowInTaskbar = $false
$lblCd0 = Get-ControlByName -Root $form0 -Name 'lblCountdown'
if ($null -eq $lblCd0) { throw 'lblCountdown not found for case0' }
$initCd0 = $lblCd0.Text
$shownCd0 = $null
$shownErr0 = $null
$timedOut0 = $false

$failTimer0 = New-Object System.Windows.Forms.Timer
$failTimer0.Interval = 12000
$failTimer0.Add_Tick({
    $script:timedOut0 = $true
    $failTimer0.Stop()
    try { $form0.Close() } catch {}
})
$form0.Add_Shown({
    try {
        $script:shownCd0 = $lblCd0.Text
    }
    catch {
        $script:shownErr0 = $_.Exception.ToString()
    }
    finally {
        $failTimer0.Stop()
        $null = $form0.BeginInvoke([System.Action]{ $form0.Close() })
    }
})
$failTimer0.Start()
[System.Windows.Forms.Application]::Run($form0)
$failTimer0.Dispose()
$form0.Dispose()
if ($null -ne $shownErr0) { throw "Case0 Shown failed: $shownErr0" }
if ($timedOut0) { throw "Case0 timed out (>12000ms)" }

# Case 2: Click1TimeoutSeconds = 2 with 1200ms pre-Run delay -> deadline anchored at Form.Shown
$engine2 = New-BrokerEngine `
    -PreflightOverride { param($rp) [pscustomobject]@{ ok = $true; code = 'OK'; exitCode = 0; detail = 'Countdown test' } } `
    -UacLauncherOverride { param($reqData, $pipeName, $pipeSec, $hwnd) return 1223 }

$req2 = New-Object AgentElevation.BrokerRequestData
$req2.RequestId = 'req-countdown-2s'
$req2.Reason = 'Verify UTC deadline anchored at Form.Shown'
$req2.WorkDir = 'C:\Windows'
$req2.ManifestSha256 = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
$req2.Click1TimeoutSeconds = 2
$req2.ScriptPreview = 'Write-Output 2'

$form2 = $engine2.BuildClick1Form($req2)
$form2.Opacity = 0.0
$form2.ShowInTaskbar = $false
$lblCd2 = Get-ControlByName -Root $form2 -Name 'lblCountdown'
if ($null -eq $lblCd2) { throw 'lblCountdown not found for case2' }
$initCd2 = $lblCd2.Text
$countdownTexts = New-Object 'System.Collections.Generic.List[string]'
$countdownTexts.Add($initCd2) | Out-Null
$lblCd2.Add_TextChanged({
    $script:countdownTexts.Add($lblCd2.Text) | Out-Null
})

# Deliberate pre-Run delay: must NOT shorten the 2s countdown
Start-Sleep -Milliseconds 1200

$shownErr2 = $null
$timedOut2 = $false
$afterShownUtcMs = 0L

$failTimer2 = New-Object System.Windows.Forms.Timer
$failTimer2.Interval = 12000
$failTimer2.Add_Tick({
    $script:timedOut2 = $true
    $failTimer2.Stop()
    try { $form2.Close() } catch {}
})
$form2.Add_Shown({
    try {
        $script:afterShownUtcMs = [AgentElevation.BrokerEngine]::GetUtcNowMs()
    }
    catch {
        $script:shownErr2 = $_.Exception.ToString()
        $failTimer2.Stop()
        $null = $form2.BeginInvoke([System.Action]{ $form2.Close() })
    }
})

$beforeShowUtcMs = [AgentElevation.BrokerEngine]::GetUtcNowMs()
$failTimer2.Start()
[System.Windows.Forms.Application]::Run($form2)
$afterTimeoutUtcMs = [AgentElevation.BrokerEngine]::GetUtcNowMs()
$failTimer2.Dispose()
$form2.Dispose()

if ($null -ne $shownErr2) { throw "Case2 Shown failed: $shownErr2" }
if ($timedOut2) { throw "Case2 countdown did not expire naturally within 12000ms" }

$payload = [ordered]@{
    initCd0           = $initCd0
    shownCd0          = $shownCd0
    initCd2           = $initCd2
    beforeShowUtcMs   = $beforeShowUtcMs
    afterShownUtcMs   = $afterShownUtcMs
    afterTimeoutUtcMs = $afterTimeoutUtcMs
    countdownTexts    = @($countdownTexts)
}
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutJsonPath, ($payload | ConvertTo-Json -Depth 5), $utf8NoBom)
'@
            [System.IO.File]::WriteAllText($probePs1, $probeScript, $utf8WithBom)

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'powershell.exe'
            $psi.Arguments = "-NoProfile -Sta -ExecutionPolicy Bypass -File `"$probePs1`" -HelperPath `"$helperPath`" -OutJsonPath `"$outJson`""
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            $outTask = $p.StandardOutput.ReadToEndAsync()
            $errTask = $p.StandardError.ReadToEndAsync()
            if (-not $p.WaitForExit(30000)) {
                $p.Kill()
                throw "Click1 countdown probe timed out (>30s)"
            }
            $out = $outTask.GetAwaiter().GetResult()
            $err = $errTask.GetAwaiter().GetResult()
            if ($p.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $outJson -PathType Leaf)) {
                throw "Click1 countdown probe failed (exit=$($p.ExitCode)): out=$out err=$err"
            }

            $res = (Get-Content -LiteralPath $outJson -Raw -Encoding UTF8) | ConvertFrom-Json
            if ($res.initCd0 -ne 'No timeout' -or $res.shownCd0 -ne 'No timeout') {
                throw "Case0 expected 'No timeout', got init='$($res.initCd0)' shown='$($res.shownCd0)'"
            }
            if ($res.initCd2 -ne 'Auto-cancels in 00:02') {
                throw "Case2 expected initial 'Auto-cancels in 00:02', got '$($res.initCd2)'"
            }

            $events = @()
            foreach ($line in ($out -split "`r?`n")) {
                $t = $line.Trim()
                if (-not $t) { continue }
                try { $events += ($t | ConvertFrom-Json) } catch {}
            }

            $shown0 = @($events | Where-Object { $_.event -eq 'click1_shown' -and $_.requestId -eq 'req-countdown-0' })[0]
            if ($null -eq $shown0) { throw "Missing click1_shown for req-countdown-0. out=$out" }
            if ($shown0.PSObject.Properties['click1DeadlineAt'] -and $null -ne $shown0.click1DeadlineAt) {
                throw "Expected null/absent click1DeadlineAt when Click1TimeoutSeconds=0, got $($shown0.click1DeadlineAt)"
            }

            $shown2 = @($events | Where-Object { $_.event -eq 'click1_shown' -and $_.requestId -eq 'req-countdown-2s' })[0]
            if ($null -eq $shown2) { throw "Missing click1_shown for req-countdown-2s. out=$out" }
            if (-not $shown2.PSObject.Properties['click1DeadlineAt'] -or [int64]$shown2.click1DeadlineAt -le 0) {
                throw "Expected positive click1DeadlineAt on click1_shown for req-countdown-2s: $($shown2 | ConvertTo-Json -Compress)"
            }

            $deadline = [int64]$shown2.click1DeadlineAt
            $minDeadline = [int64]$res.beforeShowUtcMs + 1800
            $maxDeadline = [int64]$res.afterShownUtcMs + 2500
            if ($deadline -lt $minDeadline -or $deadline -gt $maxDeadline) {
                throw "click1DeadlineAt=$deadline outside Form.Shown anchor window [$minDeadline, $maxDeadline]"
            }

            $dec2 = @($events | Where-Object { $_.event -eq 'click1_decision' -and $_.requestId -eq 'req-countdown-2s' })[0]
            if ($null -eq $dec2 -or $dec2.decision -ne 'timeout') {
                throw "Expected click1_decision=timeout for req-countdown-2s, got: $out"
            }

            $afterTimeout = [int64]$res.afterTimeoutUtcMs
            if ($afterTimeout -lt ($deadline - 250) -or ($afterTimeout - $deadline) -gt 1500) {
                throw "Timeout closed at $afterTimeout vs deadline $deadline (delta=$($afterTimeout - $deadline) ms)"
            }

            $texts = @($res.countdownTexts)
            if ($texts -notcontains 'Auto-cancels in 00:02' -or $texts -notcontains 'Auto-cancels in 00:01' -or $texts[-1] -ne 'Auto-cancels in 00:00') {
                throw "Unexpected countdown text progression: [$($texts -join ', ')]"
            }

            return "Verified Click1Form UTC countdown anchor: deadline=$deadline, deltaClose=$($afterTimeout - $deadline)ms, progression=[$($texts -join ' -> ')]"
        }

        Invoke-TestCase -Id 'A6-REPO-06' -Area '6' -Tier 1 -Name 'Repo DialogTheme palette resolution, HighContrast precedence, and ABGR AccentColor parsing' -Body {
            $helperPath = Join-Path $RepoRoot 'sidecars\broker\broker_helper.ps1'
            if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
                throw "Missing broker_helper.ps1: $helperPath"
            }

            $probePs1 = Join-Path $tempRoot 'theme_palette_probe.ps1'
            $probeScript = @'
param([Parameter(Mandatory = $true)][string]$HelperPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. $HelperPath
Initialize-InteractiveBrokerTypes

function Assert-ColorHex {
    param([System.Drawing.Color]$Actual, [string]$ExpectedHex, [string]$Label)
    $hex = ('#{0:X2}{1:X2}{2:X2}' -f $Actual.R, $Actual.G, $Actual.B)
    if ($hex -ne $ExpectedHex) {
        throw "${Label}: expected $ExpectedHex, got $hex"
    }
    if ($Actual.A -ne 255) {
        throw "${Label}: expected alpha 255, got $($Actual.A)"
    }
}

function Assert-ColorEq {
    param([System.Drawing.Color]$Actual, [System.Drawing.Color]$Expected, [string]$Label)
    if ($Actual.ToArgb() -ne $Expected.ToArgb()) {
        throw "${Label}: expected $($Expected.Name) ($($Expected.R),$($Expected.G),$($Expected.B)), got $($Actual.Name) ($($Actual.R),$($Actual.G),$($Actual.B))"
    }
}

# 1. HighContrast precedence overrides AppsUseLightTheme=0 and DWM AccentColor
$hc = [AgentElevation.DialogTheme]::FromRegistryValues($true, [int]0, [int]-2852864)
if ($hc.Mode -ne [AgentElevation.DialogThemeMode]::HighContrast -or $hc.IsDark -or -not $hc.IsHighContrast -or $hc.UseDarkChrome -or $hc.UseFlatButtons) {
    throw "HighContrast flags invalid: Mode=$($hc.Mode) IsDark=$($hc.IsDark) UseDarkChrome=$($hc.UseDarkChrome)"
}
Assert-ColorEq $hc.FormBackColor ([System.Drawing.SystemColors]::Control) 'HC FormBackColor'
Assert-ColorEq $hc.FormForeColor ([System.Drawing.SystemColors]::ControlText) 'HC FormForeColor'
Assert-ColorEq $hc.PreviewBackColor ([System.Drawing.SystemColors]::Window) 'HC PreviewBackColor'
Assert-ColorEq $hc.PreviewForeColor ([System.Drawing.SystemColors]::WindowText) 'HC PreviewForeColor'
Assert-ColorEq $hc.ReasonAccentColor ([System.Drawing.SystemColors]::Highlight) 'HC ReasonAccentColor'
Assert-ColorEq $hc.ReasonBannerBackColor ([System.Drawing.SystemColors]::Control) 'HC ReasonBannerBackColor'
Assert-ColorEq $hc.TargetSignedForeColor ([System.Drawing.SystemColors]::ControlText) 'HC TargetSignedForeColor'
Assert-ColorEq $hc.TargetUnsignedForeColor ([System.Drawing.SystemColors]::ControlText) 'HC TargetUnsignedForeColor'

# 2. Light mode defaults & non-int/absent AppsUseLightTheme fallback
foreach ($lightVal in @([int]1, $null, '0', 'invalid')) {
    $lt = [AgentElevation.DialogTheme]::FromRegistryValues($false, $lightVal, $null)
    if ($lt.Mode -ne [AgentElevation.DialogThemeMode]::Light -or $lt.IsDark -or $lt.IsHighContrast -or $lt.UseDarkChrome -or $lt.UseFlatButtons) {
        throw "Light fallback failed for value '$lightVal': Mode=$($lt.Mode)"
    }
    Assert-ColorHex $lt.ReasonAccentColor '#007ACC' 'Light fallback ReasonAccentColor'
    Assert-ColorHex $lt.ReasonBannerBackColor '#F0F6FC' 'Light ReasonBannerBackColor'
    Assert-ColorHex $lt.ReasonCaptionForeColor '#005FA8' 'Light ReasonCaptionForeColor'
    Assert-ColorEq $lt.TargetSignedForeColor ([System.Drawing.Color]::DarkGreen) 'Light TargetSignedForeColor'
    Assert-ColorEq $lt.TargetUnsignedForeColor ([System.Drawing.Color]::DarkGoldenrod) 'Light TargetUnsignedForeColor'
}

# 3. Dark mode fallback (absent, zero-RGB, invalid accent)
foreach ($badAccent in @($null, [int]0, 'not-a-dword')) {
    $dk = [AgentElevation.DialogTheme]::FromRegistryValues($false, [int]0, $badAccent)
    if ($dk.Mode -ne [AgentElevation.DialogThemeMode]::Dark -or -not $dk.IsDark -or $dk.IsHighContrast -or -not $dk.UseDarkChrome -or -not $dk.UseFlatButtons) {
        throw "Dark flags failed for accent '$badAccent': Mode=$($dk.Mode)"
    }
    Assert-ColorHex $dk.FormBackColor '#202020' 'Dark FormBackColor'
    Assert-ColorHex $dk.PreviewBackColor '#1A1A1A' 'Dark PreviewBackColor'
    Assert-ColorHex $dk.FormForeColor '#F3F3F3' 'Dark FormForeColor'
    Assert-ColorHex $dk.PreviewForeColor '#F3F3F3' 'Dark PreviewForeColor'
    Assert-ColorHex $dk.ReasonAccentColor '#4CC2FF' 'Dark fallback ReasonAccentColor'
    Assert-ColorHex $dk.ReasonBannerBackColor '#1D2733' 'Dark ReasonBannerBackColor'
    Assert-ColorHex $dk.ReasonCaptionForeColor '#60CDFF' 'Dark ReasonCaptionForeColor'
    if ($dk.TargetSignedForeColor.GetBrightness() -lt 0.5 -or $dk.TargetUnsignedForeColor.GetBrightness() -lt 0.5) {
        throw "Dark Target publisher colors not bright enough: signed=$($dk.TargetSignedForeColor.GetBrightness()) unsigned=$($dk.TargetUnsignedForeColor.GetBrightness())"
    }
}

# 4. Signed negative Int32 & unsigned ABGR -> RGB parsing
$dkWin11 = [AgentElevation.DialogTheme]::FromRegistryValues($false, [int]0, [int]-2852864) # 0xFFD47800 -> #0078D4
Assert-ColorHex $dkWin11.ReasonAccentColor '#0078D4' 'ABGR -2852864 (0xFFD47800)'

$ltAbgr = [AgentElevation.DialogTheme]::FromRegistryValues($false, [int]1, [int]0x7F112233)
Assert-ColorHex $ltAbgr.ReasonAccentColor '#332211' 'ABGR 0x7F112233'

$uintAccent = [uint32]::Parse('FF334455', [System.Globalization.NumberStyles]::HexNumber)
$dkUInt = [AgentElevation.DialogTheme]::FromRegistryValues($false, [int]0, $uintAccent)
Assert-ColorHex $dkUInt.ReasonAccentColor '#554433' 'ABGR uint32 0xFF334455'

Write-Output 'THEME_PALETTE_OK'
'@
            [System.IO.File]::WriteAllText($probePs1, $probeScript, $utf8WithBom)

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'powershell.exe'
            $psi.Arguments = "-NoProfile -Sta -ExecutionPolicy Bypass -File `"$probePs1`" -HelperPath `"$helperPath`""
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            $out = $p.StandardOutput.ReadToEnd()
            $err = $p.StandardError.ReadToEnd()
            if (-not $p.WaitForExit(20000)) {
                $p.Kill()
                throw 'DialogTheme palette probe timed out (>20s)'
            }
            if ($p.ExitCode -ne 0 -or $out -notmatch 'THEME_PALETTE_OK') {
                throw "DialogTheme palette probe failed (exit=$($p.ExitCode)): out=$out err=$err"
            }
            return 'Verified DialogTheme HighContrast precedence, Light/Dark palettes, and signed/unsigned ABGR->RGB AccentColor parsing'
        }

        Invoke-TestCase -Id 'A6-REPO-07' -Area '6' -Tier 2 -Name 'Repo Click1Form & ReminderForm Dark/Light/HighContrast styling, Flat buttons, disabled Paint contrast, 1px wrapper, and HandleCreated' -Body {
            $helperPath = Join-Path $RepoRoot 'sidecars\broker\broker_helper.ps1'
            if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
                throw "Missing broker_helper.ps1: $helperPath"
            }

            $probePs1 = Join-Path $tempRoot 'theme_forms_probe.ps1'
            $probeScript = @'
param([Parameter(Mandatory = $true)][string]$HelperPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. $HelperPath
Initialize-InteractiveBrokerTypes

function Get-AllDescendants {
    param([System.Windows.Forms.Control]$Root)
    $list = New-Object 'System.Collections.Generic.List[System.Windows.Forms.Control]'
    foreach ($ch in $Root.Controls) {
        $list.Add($ch)
        foreach ($sub in (Get-AllDescendants -Root $ch)) {
            $list.Add($sub)
        }
    }
    return $list
}

function Assert-Hex {
    param([System.Drawing.Color]$Color, [string]$ExpectedHex, [string]$Label)
    $hex = ('#{0:X2}{1:X2}{2:X2}' -f $Color.R, $Color.G, $Color.B)
    if ($hex -ne $ExpectedHex) {
        throw "${Label}: expected $ExpectedHex, got $hex"
    }
}

$engine = New-BrokerEngine `
    -PreflightOverride { param($rp) [pscustomobject]@{ ok = $true; code = 'OK'; exitCode = 0; detail = 'Theme form test' } } `
    -UacLauncherOverride { param($reqData, $pipeName, $pipeSec, $hwnd) return 1223 }

$reqSigned = New-Object AgentElevation.BrokerRequestData
$reqSigned.RequestId = 'req-theme-signed'
$reqSigned.Reason = 'Verify Dark/Light/HighContrast modal styling'
$reqSigned.WorkDir = 'C:\Windows\System32'
$reqSigned.Args = @('-NoProfile')
$reqSigned.HasTargetMeta = $true
$reqSigned.TargetPath = 'C:\Windows\System32\cmd.exe'
$reqSigned.TargetSubsystem = 'CUI'
$reqSigned.TargetPublisher = 'Microsoft Windows'
$reqSigned.ManifestSha256 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$reqSigned.Click1TimeoutSeconds = 0
$reqSigned.ScriptPreview = "Write-Output 'hello'`nWrite-Output 'world'"

$reqUnsigned = New-Object AgentElevation.BrokerRequestData
$reqUnsigned.RequestId = 'req-theme-unsigned'
$reqUnsigned.Reason = 'Verify unsigned publisher warning color'
$reqUnsigned.WorkDir = 'C:\Windows\System32'
$reqUnsigned.HasTargetMeta = $true
$reqUnsigned.TargetPath = 'C:\Tools\unsigned.exe'
$reqUnsigned.TargetSubsystem = 'CUI'
$reqUnsigned.TargetPublisher = ''
$reqUnsigned.ManifestSha256 = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
$reqUnsigned.Click1TimeoutSeconds = 0
$reqUnsigned.ScriptPreview = 'Write-Output 1'

$themeSpecs = @(
    @{ Name = 'DarkFallback'; Theme = ([AgentElevation.DialogTheme]::Create([AgentElevation.DialogThemeMode]::Dark)); ExpectedAccent = '#4CC2FF' },
    @{ Name = 'DarkCustom'; Theme = ([AgentElevation.DialogTheme]::Create([AgentElevation.DialogThemeMode]::Dark, [System.Drawing.Color]::FromArgb(0, 120, 212))); ExpectedAccent = '#0078D4' },
    @{ Name = 'Light'; Theme = ([AgentElevation.DialogTheme]::Create([AgentElevation.DialogThemeMode]::Light)); ExpectedAccent = '#007ACC' },
    @{ Name = 'HighContrast'; Theme = ([AgentElevation.DialogTheme]::Create([AgentElevation.DialogThemeMode]::HighContrast)); ExpectedAccent = '' }
)

foreach ($spec in $themeSpecs) {
    $t = $spec.Theme
    $f1 = $engine.BuildClick1Form($reqSigned, $t)
    try {
        if ($f1.IsHandleCreated) { throw "$($spec.Name) Click1Form created handle prematurely" }
        $all1 = Get-AllDescendants -Root $f1
        $topHost = @($all1 | Where-Object { $_.Name -eq 'topScrollHost' })[0]
        $reasonAccent = @($all1 | Where-Object { $_.Name -eq 'reasonAccent' })[0]
        $reasonContent = @($all1 | Where-Object { $_.Name -eq 'reasonContent' })[0]
        $lblCaption = @($all1 | Where-Object { $_.Name -eq 'lblReasonCaption' })[0]
        $lblReason = @($all1 | Where-Object { $_.Name -eq 'lblReason' })[0]
        $previewWrapper = @($all1 | Where-Object { $_.Name -eq 'previewWrapper' -and $_ -is [System.Windows.Forms.Panel] })[0]
        $txtPreview = @($all1 | Where-Object { $_.Name -eq 'txtPreview' -and $_ -is [System.Windows.Forms.TextBox] })[0]
        $lblBadge = @($all1 | Where-Object { $_.Name -eq 'metaVal_2' -and $_ -is [System.Windows.Forms.Label] })[0]
        $btnDeny = @($all1 | Where-Object { $_.Name -eq 'btnDeny' -and $_ -is [System.Windows.Forms.Button] })[0]
        $btnProceed = @($all1 | Where-Object { $_.Name -eq 'btnProceed' -and $_ -is [System.Windows.Forms.Button] })[0]

        if ($null -eq $previewWrapper -or $txtPreview.Parent -ne $previewWrapper) {
            throw "$($spec.Name): txtPreview must be parented inside previewWrapper Panel"
        }
        if ($previewWrapper.Padding.Left -ne 1 -or $previewWrapper.Padding.Top -ne 1 -or $previewWrapper.Padding.Right -ne 1 -or $previewWrapper.Padding.Bottom -ne 1) {
            throw "$($spec.Name): previewWrapper padding expected (1,1,1,1), got $($previewWrapper.Padding)"
        }
        if ($txtPreview.BorderStyle -ne [System.Windows.Forms.BorderStyle]::None) {
            throw "$($spec.Name): txtPreview.BorderStyle expected None, got $($txtPreview.BorderStyle)"
        }

        if ($t.IsDark) {
            Assert-Hex $f1.BackColor '#202020' "$($spec.Name) Click1Form BackColor"
            Assert-Hex $f1.ForeColor '#F3F3F3' "$($spec.Name) Click1Form ForeColor"
            Assert-Hex $txtPreview.BackColor '#1A1A1A' "$($spec.Name) txtPreview BackColor"
            Assert-Hex $txtPreview.ForeColor '#F3F3F3' "$($spec.Name) txtPreview ForeColor"
            Assert-Hex $previewWrapper.BackColor '#3F3F46' "$($spec.Name) previewWrapper BackColor"
            Assert-Hex $reasonAccent.BackColor $spec.ExpectedAccent "$($spec.Name) reasonAccent"
            Assert-Hex $reasonContent.BackColor '#1D2733' "$($spec.Name) reasonContent"
            Assert-Hex $lblCaption.ForeColor '#60CDFF' "$($spec.Name) lblReasonCaption"
            Assert-Hex $lblReason.ForeColor '#F3F3F3' "$($spec.Name) lblReason"
            Assert-Hex $lblBadge.ForeColor '#4ADE80' "$($spec.Name) signed badge"

            foreach ($b in @($btnDeny, $btnProceed)) {
                if ($b.FlatStyle -ne [System.Windows.Forms.FlatStyle]::Flat -or $b.UseVisualStyleBackColor) {
                    throw "$($spec.Name) $($b.Name): expected FlatStyle.Flat and UseVisualStyleBackColor=false"
                }
                if ($b.FlatAppearance.BorderSize -ne 1) {
                    throw "$($spec.Name) $($b.Name): expected BorderSize=1"
                }
                Assert-Hex $b.BackColor '#2D2D30' "$($spec.Name) $($b.Name) BackColor"
                Assert-Hex $b.ForeColor '#F3F3F3' "$($spec.Name) $($b.Name) ForeColor"
                Assert-Hex $b.FlatAppearance.BorderColor '#48484D' "$($spec.Name) $($b.Name) BorderColor"
                Assert-Hex $b.FlatAppearance.MouseOverBackColor '#3E3E42' "$($spec.Name) $($b.Name) MouseOverBackColor"
                Assert-Hex $b.FlatAppearance.MouseDownBackColor '#505055' "$($spec.Name) $($b.Name) MouseDownBackColor"
            }

            # Verify disabled button Paint handler renders readable text (not dark-on-dark)
            $f1.CreateControl()
            $bmp = New-Object System.Drawing.Bitmap($btnProceed.Width, $btnProceed.Height)
            try {
                $btnProceed.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $btnProceed.Width, $btnProceed.Height)))
                $maxTextLum = 0
                for ($y = 2; $y -lt ($bmp.Height - 2); $y++) {
                    for ($x = 2; $x -lt ($bmp.Width - 2); $x++) {
                        $px = $bmp.GetPixel($x, $y)
                        $lum = [Math]::Max($px.R, [Math]::Max($px.G, $px.B))
                        if ($lum -gt $maxTextLum) { $maxTextLum = $lum }
                    }
                }
                if ($maxTextLum -lt 120) {
                    throw "$($spec.Name): disabled btnProceed text unreadable (max luminance=$maxTextLum < 120)"
                }
            }
            finally {
                $bmp.Dispose()
            }
        }
        elseif ($t.IsHighContrast) {
            if ($f1.BackColor.ToArgb() -ne [System.Drawing.SystemColors]::Control.ToArgb() -or
                $f1.ForeColor.ToArgb() -ne [System.Drawing.SystemColors]::ControlText.ToArgb() -or
                $txtPreview.BackColor.ToArgb() -ne [System.Drawing.SystemColors]::Window.ToArgb() -or
                $txtPreview.ForeColor.ToArgb() -ne [System.Drawing.SystemColors]::WindowText.ToArgb() -or
                $reasonAccent.BackColor.ToArgb() -ne [System.Drawing.SystemColors]::Highlight.ToArgb() -or
                $reasonContent.BackColor.ToArgb() -ne [System.Drawing.SystemColors]::Control.ToArgb() -or
                $lblBadge.ForeColor.ToArgb() -ne [System.Drawing.SystemColors]::ControlText.ToArgb()) {
                throw "HighContrast failed to preserve SystemColors on Click1Form"
            }
            foreach ($b in @($btnDeny, $btnProceed)) {
                if ($b.FlatStyle -ne [System.Windows.Forms.FlatStyle]::Standard -or -not $b.UseVisualStyleBackColor) {
                    throw "HighContrast $($b.Name) must keep FlatStyle.Standard"
                }
            }
        }
        else {
            Assert-Hex $reasonAccent.BackColor '#007ACC' 'Light reasonAccent'
            Assert-Hex $reasonContent.BackColor '#F0F6FC' 'Light reasonContent'
            if ($lblBadge.ForeColor.ToArgb() -ne [System.Drawing.Color]::DarkGreen.ToArgb()) {
                throw "Light signed badge expected DarkGreen"
            }
            foreach ($b in @($btnDeny, $btnProceed)) {
                if ($b.FlatStyle -ne [System.Windows.Forms.FlatStyle]::Standard) {
                    throw "Light $($b.Name) must keep FlatStyle.Standard"
                }
            }
        }

        # Exercise HandleCreated across all modes without ShowDialog()
        $f1.CreateControl()
        $null = $f1.Handle
        $null = $topHost.Handle
        $null = $txtPreview.Handle
        if (-not $f1.IsHandleCreated -or -not $topHost.IsHandleCreated -or -not $txtPreview.IsHandleCreated) {
            throw "$($spec.Name): Click1Form handles not created on CreateControl()"
        }
    }
    finally {
        $f1.Dispose()
    }

    # Unsigned target check + ReminderForm check
    $fUns = $engine.BuildClick1Form($reqUnsigned, $t)
    try {
        $allU = Get-AllDescendants -Root $fUns
        $lblBadgeU = @($allU | Where-Object { $_.Name -eq 'metaVal_2' -and $_ -is [System.Windows.Forms.Label] })[0]
        if ($t.IsDark) {
            Assert-Hex $lblBadgeU.ForeColor '#FBBF24' "$($spec.Name) unsigned badge"
        }
        elseif ($t.IsHighContrast) {
            if ($lblBadgeU.ForeColor.ToArgb() -ne [System.Drawing.SystemColors]::ControlText.ToArgb()) {
                throw "HighContrast unsigned badge must keep SystemColors.ControlText"
            }
        }
        else {
            if ($lblBadgeU.ForeColor.ToArgb() -ne [System.Drawing.Color]::DarkGoldenrod.ToArgb()) {
                throw "Light unsigned badge expected DarkGoldenrod"
            }
        }
    }
    finally {
        $fUns.Dispose()
    }

    $rf = $engine.BuildReminderForm('Active task summary', 2, $t)
    try {
        if ($rf.IsHandleCreated) { throw "$($spec.Name) ReminderForm created handle prematurely" }
        $allR = Get-AllDescendants -Root $rf
        $scrollHost = @($allR | Where-Object { $_.Name -eq 'scrollHost' -and $_ -is [System.Windows.Forms.Panel] })[0]
        $btnDismiss = @($allR | Where-Object { $_.Name -eq 'btnDismiss' -and $_ -is [System.Windows.Forms.Button] })[0]
        if ($t.IsDark) {
            Assert-Hex $rf.BackColor '#202020' "$($spec.Name) ReminderForm BackColor"
            Assert-Hex $rf.ForeColor '#F3F3F3' "$($spec.Name) ReminderForm ForeColor"
            if ($btnDismiss.FlatStyle -ne [System.Windows.Forms.FlatStyle]::Flat) {
                throw "$($spec.Name) btnDismiss expected FlatStyle.Flat"
            }
            Assert-Hex $btnDismiss.BackColor '#2D2D30' "$($spec.Name) btnDismiss BackColor"
        }
        elseif ($t.IsHighContrast) {
            if ($rf.BackColor.ToArgb() -ne [System.Drawing.SystemColors]::Control.ToArgb() -or
                $btnDismiss.FlatStyle -ne [System.Windows.Forms.FlatStyle]::Standard) {
                throw "HighContrast ReminderForm must preserve SystemColors & Standard button"
            }
        }
        else {
            if ($btnDismiss.FlatStyle -ne [System.Windows.Forms.FlatStyle]::Standard) {
                throw "Light ReminderForm btnDismiss must keep FlatStyle.Standard"
            }
        }
        $rf.CreateControl()
        $null = $rf.Handle
        $null = $scrollHost.Handle
        if (-not $rf.IsHandleCreated -or -not $scrollHost.IsHandleCreated) {
            throw "$($spec.Name): ReminderForm handles not created on CreateControl()"
        }
    }
    finally {
        $rf.Dispose()
    }
}

Write-Output 'THEME_FORMS_OK'
'@
            [System.IO.File]::WriteAllText($probePs1, $probeScript, $utf8WithBom)

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'powershell.exe'
            $psi.Arguments = "-NoProfile -Sta -ExecutionPolicy Bypass -File `"$probePs1`" -HelperPath `"$helperPath`""
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            $out = $p.StandardOutput.ReadToEnd()
            $err = $p.StandardError.ReadToEnd()
            if (-not $p.WaitForExit(30000)) {
                $p.Kill()
                throw 'Theme forms probe timed out (>30s)'
            }
            if ($p.ExitCode -ne 0 -or $out -notmatch 'THEME_FORMS_OK') {
                throw "Theme forms probe failed (exit=$($p.ExitCode)): out=$out err=$err"
            }
            return 'Verified Click1Form & ReminderForm Dark/Light/HighContrast styling, FlatStyle.Flat + disabled Paint contrast, 1px previewWrapper, and HandleCreated without ShowDialog or HKCU mutation'
        }

        Invoke-TestCase -Id 'A6-REPO-08' -Area '6' -Tier 1 -Name 'Repo broker_helper.ps1 M6f DWM 20/19, DarkMode_Explorer SetWindowTheme, HighContrast-first, BOM, and Stage-1 isolation checks' -Body {
            $helperPath = Join-Path $RepoRoot 'sidecars\broker\broker_helper.ps1'
            if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
                throw "Missing broker_helper.ps1: $helperPath"
            }

            $bytes = [System.IO.File]::ReadAllBytes($helperPath)
            if ($bytes.Length -lt 3 -or $bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) {
                throw 'broker_helper.ps1 is missing UTF-8 BOM (EF BB BF)'
            }

            $parseErrs = $null
            $parseToks = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($helperPath, [ref]$parseToks, [ref]$parseErrs)
            if ($parseErrs.Count -gt 0) {
                throw "broker_helper.ps1 PS 5.1 parse errors: $($parseErrs.Count)"
            }

            $helperSrc = [System.IO.File]::ReadAllText($helperPath, $strictUtf8)
            $stage2Idx = $helperSrc.IndexOf('function Initialize-InteractiveBrokerTypes')
            if ($stage2Idx -le 0) { throw 'Could not locate Initialize-InteractiveBrokerTypes' }
            $stage1Src = $helperSrc.Substring(0, $stage2Idx)
            if ($stage1Src -match 'System\.Windows\.Forms' -or $stage1Src -match 'DialogTheme' -or $stage1Src -match 'DwmSetWindowAttribute') {
                throw 'Stage 1 Initialize-PreflightNative must remain WinForms-free and theme-free'
            }

            foreach ($pattern in @(
                'DwmSetWindowAttribute\s*\(',
                'DWMWA_USE_IMMERSIVE_DARK_MODE\s*=\s*20',
                'DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1\s*=\s*19',
                'dwmapi\.dll',
                'uxtheme\.dll',
                'SetWindowTheme\s*\(',
                'DarkMode_Explorer',
                'ApplyDarkTitleBar\s*\(\s*form\s*,\s*effectiveTheme\s*\)',
                'ApplyDarkControlScrollbars\s*\(\s*topScrollHost\s*,\s*effectiveTheme\s*\)',
                'ApplyDarkControlScrollbars\s*\(\s*txtPreview\s*,\s*effectiveTheme\s*\)',
                'ApplyDarkControlScrollbars\s*\(\s*scrollHost\s*,\s*effectiveTheme\s*\)'
            )) {
                if ($helperSrc -notmatch $pattern) {
                    throw "broker_helper.ps1 missing M6f Win32 chrome contract pattern: $pattern"
                }
            }

            $resolveIdx = $helperSrc.IndexOf('public static DialogTheme ResolveSystem()')
            if ($resolveIdx -lt 0) { throw 'ResolveSystem() not found' }
            $resolveSlice = $helperSrc.Substring($resolveIdx, [Math]::Min(1200, $helperSrc.Length - $resolveIdx))
            $hcIdx = $resolveSlice.IndexOf('SystemInformation.HighContrast')
            $regIdx = $resolveSlice.IndexOf('AppsUseLightTheme')
            if ($hcIdx -lt 0 -or $regIdx -lt 0 -or $hcIdx -gt $regIdx) {
                throw "ResolveSystem() must check SystemInformation.HighContrast ($hcIdx) before AppsUseLightTheme ($regIdx)"
            }

            return 'Verified broker_helper.ps1 UTF-8 BOM, PS 5.1 syntax, Stage-1 isolation, DwmSetWindowAttribute(20/19), SetWindowTheme(DarkMode_Explorer), and HighContrast-first ordering'
        }
    }
}
finally {
    foreach ($j in $junctionsToCleanup) {
        if (Test-Path -LiteralPath $j) {
            try { [System.IO.Directory]::Delete($j, $false) } catch {}
        }
    }
    if (Test-Path -LiteralPath $tempRoot) {
        try {
            Get-ChildItem -LiteralPath $tempRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $dAcl = [System.IO.Directory]::GetAccessControl($_.FullName, [System.Security.AccessControl.AccessControlSections]::Access)
                    if ($dAcl.AreAccessRulesProtected) {
                        $dAcl.SetAccessRuleProtection($false, $false)
                        $dAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($currentUserSid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
                        [System.IO.Directory]::SetAccessControl($_.FullName, $dAcl)
                    }
                } catch {}
            }
        } catch {}
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$total = $results.Count
$passedCount = @($results | Where-Object { $_.passed }).Count
$failedCount = $total - $passedCount

if ($JsonReport) {
    $reportObj = [pscustomobject]@{
        module  = 'Test-ManifestAndSecurity.ps1'
        summary = [pscustomobject]@{ total = $total; passed = $passedCount; failed = $failedCount }
        results = $results
    }
    $utf8NoBomOut = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($JsonReport, ($reportObj | ConvertTo-Json -Depth 6), $utf8NoBomOut)
}

Write-Host ("Areas 2 & 6 Summary: {0}/{1} passed ({2} failed)" -f $passedCount, $total, $failedCount)
if ($failedCount -gt 0) { exit 1 }
exit 0
