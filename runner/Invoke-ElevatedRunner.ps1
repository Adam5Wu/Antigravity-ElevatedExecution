#Requires -Version 5.1
<#
.SYNOPSIS
    Unified High-IL PowerShell 5.1 execution runner for Antigravity elevated tasks.
.DESCRIPTION
    Hardens process environment and isolated temp storage before Add-Type, connects
    to the Medium-IL Named Pipe server, verifies caller PID and StartTime, reads and
    SHA-256-verifies the frozen manifest once, writes script.ps1 verbatim with UTF-8
    BOM, runs child powershell.exe inside a Win32 Job Object (without
    KILL_ON_JOB_CLOSE), pumps stdout/stderr with per-line and idle-flush zh-CN
    decoding plus 500 ms heartbeats, and terminates the full job tree on pipe Kill.
#>
[CmdletBinding()]
param(
    [string]$PipeName = '',
    [int]$CallerPid = 0,
    [long]$CallerStart = 0,
    [string]$ManifestFile = '',
    [string]$ManifestSha256 = ''
)

Set-StrictMode -Version Latest

$script:ProductionAgentElevationDir = 'C:\ProgramData\AgentElevation'
$script:ProductionTmpRoot           = 'C:\ProgramData\AgentElevation\tmp'
$script:ProductionLastErrorLog      = 'C:\ProgramData\AgentElevation\tmp\last-error.log'
$script:MaxManifestBytes            = 10485760
$script:StaleRunAgeHours            = 24

function Test-PathSegmentChainNoReparsePoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$RequireLeafDirectory
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'RUNNER_ERROR:Path must not be empty.'
    }
    if ($Path -notmatch '^[A-Za-z]:\\' -or -not [System.IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) {
        throw "RUNNER_ERROR:Path '$Path' must be a rooted local non-UNC path."
    }

    $rawParts = $Path.Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($rawParts -contains '..') {
        throw "RUNNER_ERROR:Path '$Path' must not contain '..' traversal segments."
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($root -notmatch '^[A-Za-z]:\\$') {
        throw "RUNNER_ERROR:Unsupported drive root '$root' for path '$Path'."
    }

    $driveInfo = New-Object System.IO.DriveInfo($root)
    if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network -or $driveInfo.DriveType -eq [System.IO.DriveType]::Unknown) {
        throw "RUNNER_ERROR:Path '$Path' resides on disallowed drive type '$($driveInfo.DriveType)'."
    }

    $segments = New-Object System.Collections.Generic.List[string]
    $segments.Add($root)
    if ($fullPath.Length -gt $root.Length) {
        $rel = $fullPath.Substring($root.Length)
        $parts = @($rel.Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries))
        $acc = $root.TrimEnd('\')
        foreach ($part in $parts) {
            $acc = "$acc\$part"
            $segments.Add($acc)
        }
    }

    for ($i = 0; $i -lt $segments.Count; $i++) {
        $seg = $segments[$i]
        $isDir = [System.IO.Directory]::Exists($seg)
        $isFile = [System.IO.File]::Exists($seg)
        if (-not $isDir -and -not $isFile) {
            throw "RUNNER_ERROR:Path segment does not exist: '$seg'."
        }

        $attrs = [System.IO.File]::GetAttributes($seg)
        if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "RUNNER_ERROR:ReparsePoint detected at '$seg'."
        }

        $isLast = ($i -eq ($segments.Count - 1))
        if (-not $isLast -or $RequireLeafDirectory) {
            if (-not $isDir) {
                throw "RUNNER_ERROR:Expected directory at '$seg'."
            }
        } else {
            if ($isDir) {
                throw "RUNNER_ERROR:Expected regular file at '$seg', found directory."
            }
        }
    }
}

function Test-RunnerTmpDirectory {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string]$TmpRoot = $script:ProductionTmpRoot,
        [string]$AgentElevationDir = $script:ProductionAgentElevationDir,
        [string[]]$ExpectedOwnerSids = @('S-1-5-18', 'S-1-5-32-544'),
        [string[]]$ExpectedAccessSids = @('S-1-5-18', 'S-1-5-32-544')
    )

    Test-PathSegmentChainNoReparsePoint -Path $AgentElevationDir -RequireLeafDirectory
    Test-PathSegmentChainNoReparsePoint -Path $TmpRoot -RequireLeafDirectory

    foreach ($dirPath in @($AgentElevationDir, $TmpRoot)) {
        $acl = [System.IO.Directory]::GetAccessControl(
            $dirPath,
            [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Access
        )

        if (-not $acl.AreAccessRulesProtected) {
            throw "RUNNER_ERROR:Directory '$dirPath' does not have ACL inheritance disabled."
        }

        $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($ExpectedOwnerSids -notcontains $ownerSid) {
            throw "RUNNER_ERROR:Directory '$dirPath' owner '$ownerSid' is not in allowed admin/SYSTEM set."
        }

        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        if ($rules.Count -eq 0) {
            throw "RUNNER_ERROR:Directory '$dirPath' has zero access rules."
        }

        $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
        $requiredInherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $satisfiedSids = @{}

        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                throw "RUNNER_ERROR:Directory '$dirPath' contains non-Allow ACE ($($rule.AccessControlType))."
            }
            $sid = $rule.IdentityReference.Value
            if ($ExpectedAccessSids -notcontains $sid) {
                throw "RUNNER_ERROR:Directory '$dirPath' contains unauthorized SID '$sid'."
            }

            $isEffectiveOnSelf = (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0)
            $noPropagate = (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) -ne 0)
            $hasFullInherit = (($rule.InheritanceFlags -band $requiredInherit) -eq $requiredInherit)
            $hasFullRights = (($rule.FileSystemRights -band $fullControl) -eq $fullControl)

            if ($isEffectiveOnSelf -and (-not $noPropagate) -and $hasFullInherit -and $hasFullRights) {
                $satisfiedSids[$sid] = $true
            }
        }

        foreach ($reqSid in $ExpectedAccessSids) {
            if (-not $satisfiedSids.ContainsKey($reqSid)) {
                throw "RUNNER_ERROR:Directory '$dirPath' is missing required inheritable FullControl ACE for SID '$reqSid'."
            }
        }
    }

    return $true
}

function Invoke-SweepStaleRunnerTempDirs {
    [CmdletBinding()]
    param(
        [string]$TmpRoot = $script:ProductionTmpRoot,
        [int]$MaxAgeHours = $script:StaleRunAgeHours
    )

    if (-not [System.IO.Directory]::Exists($TmpRoot)) {
        return
    }

    $cutoff = [System.DateTime]::UtcNow.AddHours(-$MaxAgeHours)
    $rootInfo = New-Object System.IO.DirectoryInfo($TmpRoot)
    foreach ($subDir in $rootInfo.GetDirectories()) {
        if (($subDir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            continue
        }
        if ($subDir.LastWriteTimeUtc -lt $cutoff) {
            try {
                Remove-Item -LiteralPath $subDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                # Best-effort sweep; ignore active/locked subdirectories
            }
        }
    }
}

function New-IsolatedRunnerTempDir {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$TmpRoot = $script:ProductionTmpRoot
    )

    $runId = [System.Guid]::NewGuid().ToString('N')
    $runDir = [System.IO.Path]::Combine($TmpRoot, $runId)
    [System.IO.Directory]::CreateDirectory($runDir) | Out-Null

    $attrs = [System.IO.File]::GetAttributes($runDir)
    if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "RUNNER_ERROR:Created run temp directory '$runDir' is unexpectedly a ReparsePoint."
    }

    return $runDir
}

function Set-LockedRunnerEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunTempDir
    )

    $env:TEMP = $RunTempDir
    $env:TMP = $RunTempDir
    [System.Environment]::SetEnvironmentVariable('TEMP', $RunTempDir, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable('TMP', $RunTempDir, [System.EnvironmentVariableTarget]::Process)

    $hklmPath = ''
    $hklmPathExt = ''
    $envKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $false)
    if ($null -ne $envKey) {
        try {
            $rawPath = $envKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::None)
            if ($null -ne $rawPath) { $hklmPath = [string]$rawPath }
            $rawPathExt = $envKey.GetValue('PATHEXT', '', [Microsoft.Win32.RegistryValueOptions]::None)
            if ($null -ne $rawPathExt) { $hklmPathExt = [string]$rawPathExt }
        } finally {
            $envKey.Close()
        }
    }

    if ([string]::IsNullOrWhiteSpace($hklmPath)) {
        $sysRoot = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows)
        $hklmPath = "$sysRoot\system32;$sysRoot;$sysRoot\System32\Wbem;$sysRoot\System32\WindowsPowerShell\v1.0\"
    }
    if ([string]::IsNullOrWhiteSpace($hklmPathExt)) {
        $hklmPathExt = '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC'
    }

    $progFiles = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
    $sysDir = [System.Environment]::SystemDirectory
    $lockedPsModulePath = "$progFiles\WindowsPowerShell\Modules;$sysDir\WindowsPowerShell\v1.0\Modules"

    $env:PATH = $hklmPath
    $env:PATHEXT = $hklmPathExt
    $env:PSModulePath = $lockedPsModulePath
    [System.Environment]::SetEnvironmentVariable('PATH', $hklmPath, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable('PATHEXT', $hklmPathExt, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable('PSModulePath', $lockedPsModulePath, [System.EnvironmentVariableTarget]::Process)

    return [PSCustomObject]@{
        Temp         = $env:TEMP
        Tmp          = $env:TMP
        Path         = $env:PATH
        PathExt      = $env:PATHEXT
        PSModulePath = $env:PSModulePath
    }
}

function Write-RunnerLastErrorLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [string]$PipeName = '',
        [int]$CallerPid = 0,
        [string]$Phase = 'unknown',
        [string]$Message = ''
    )

    try {
        $ts = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $cleanMsg = ($Message -replace "[\r\n]+", ' ').Trim()
        $line = "[$ts] pid=$PID pipe=$PipeName callerPid=$CallerPid phase=$Phase error=$cleanMsg`r`n"
        [System.IO.File]::AppendAllText($LogPath, $line, (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        # Never mask primary failure if forensic append fails
    }
}

function Read-VerifiedManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestFile,

        [Parameter(Mandatory = $true)]
        [string]$ManifestSha256,

        [int]$MaxBytes = $script:MaxManifestBytes
    )

    if ($ManifestSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw "RUNNER_ERROR:Invalid ManifestSha256 format."
    }

    Test-PathSegmentChainNoReparsePoint -Path $ManifestFile

    $rawBytes = $null
    $fs = [System.IO.File]::Open($ManifestFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($fs.Length -lt 1 -or $fs.Length -gt $MaxBytes) {
            throw "RUNNER_ERROR:Manifest length $($fs.Length) out of allowed bounds (1..$MaxBytes)."
        }
        $len = [int]$fs.Length
        $rawBytes = New-Object byte[] $len
        $offset = 0
        while ($offset -lt $len) {
            $read = $fs.Read($rawBytes, $offset, $len - $offset)
            if ($read -le 0) {
                throw 'RUNNER_ERROR:Unexpected EOF while reading manifest file.'
            }
            $offset += $read
        }
    } finally {
        $fs.Dispose()
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash($rawBytes)
    } finally {
        $sha.Dispose()
    }
    $actualSha = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
    if (-not $actualSha.Equals($ManifestSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA256_MISMATCH:Expected $($ManifestSha256.ToLowerInvariant()), actual $actualSha."
    }

    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $jsonText = $strictUtf8.GetString($rawBytes)
    if ($jsonText.Length -gt 0 -and $jsonText[0] -eq [char]0xFEFF) {
        $jsonText = $jsonText.Substring(1)
    }

    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = 16777216
    $parsed = $serializer.DeserializeObject($jsonText)

    if ($null -eq $parsed -or -not ($parsed -is [System.Collections.Generic.IDictionary[string, object]])) {
        throw 'RUNNER_ERROR:Manifest JSON root must be an object.'
    }

    if (-not $parsed.ContainsKey('script') -or $null -eq $parsed['script']) {
        throw 'RUNNER_ERROR:Manifest missing required "script" field.'
    }
    $scriptText = [string]$parsed['script']

    if (-not $parsed.ContainsKey('workDir') -or [string]::IsNullOrWhiteSpace([string]$parsed['workDir'])) {
        throw 'RUNNER_ERROR:Manifest missing required "workDir" field.'
    }
    $workDir = [string]$parsed['workDir']
    if (-not [System.IO.Directory]::Exists($workDir) -or -not (Test-Path -LiteralPath $workDir -PathType Container)) {
        throw "RUNNER_ERROR:Manifest workDir does not exist or is not a directory: '$workDir'."
    }

    $encoding = 'auto'
    if ($parsed.ContainsKey('encoding') -and -not [string]::IsNullOrWhiteSpace([string]$parsed['encoding'])) {
        $encoding = ([string]$parsed['encoding']).ToLowerInvariant()
    }
    if ($encoding -notin @('auto', 'utf8', 'oem', 'utf16')) {
        throw "RUNNER_ERROR:Unsupported manifest encoding '$encoding'."
    }

    $argList = New-Object System.Collections.Generic.List[string]
    if ($parsed.ContainsKey('args') -and $null -ne $parsed['args']) {
        foreach ($item in @($parsed['args'])) {
            if ($null -eq $item) {
                $argList.Add('')
            } else {
                $argList.Add([string]$item)
            }
        }
    }

    return [PSCustomObject]@{
        Script   = $scriptText
        Args     = [string[]]$argList.ToArray()
        WorkDir  = $workDir
        Encoding = $encoding
        Sha256   = $actualSha
    }
}

function Write-VerbatimScriptFile {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ScriptText,

        [Parameter(Mandatory = $true)]
        [string]$DestPath
    )

    $textToWrite = $ScriptText
    if ($textToWrite.Length -gt 0 -and $textToWrite[0] -eq [char]0xFEFF) {
        $textToWrite = $textToWrite.Substring(1)
    }

    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($DestPath, $textToWrite, $utf8Bom)
    return $DestPath
}

function Initialize-RunnerNativeTypes {
    [CmdletBinding()]
    param()

    if ('AgentElevation.RunnerNative' -as [type]) {
        return
    }

    $csharp = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace AgentElevation
{
    public static class RunnerNative
    {
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(SafePipeHandle Pipe, out uint ServerProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(
            IntPtr hProcess,
            out long lpCreationTime,
            out long lpExitTime,
            out long lpKernelTime,
            out long lpUserTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public static void VerifyPipeServerIdentity(SafePipeHandle pipeHandle, int expectedPid, long expectedCreationFileTime)
        {
            if (pipeHandle == null || pipeHandle.IsInvalid)
            {
                throw new InvalidOperationException("RUNNER_ERROR:Pipe handle is invalid.");
            }

            uint serverPid;
            if (!GetNamedPipeServerProcessId(pipeHandle, out serverPid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetNamedPipeServerProcessId failed.");
            }

            if (unchecked((int)serverPid) != expectedPid)
            {
                throw new UnauthorizedAccessException(
                    string.Format("Pipe server PID mismatch: expected {0}, actual {1}.", expectedPid, serverPid));
            }

            IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, serverPid);
            if (hProc == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess on pipe server PID failed.");
            }

            try
            {
                long creationTime;
                long exitTime;
                long kernelTime;
                long userTime;
                if (!GetProcessTimes(hProc, out creationTime, out exitTime, out kernelTime, out userTime))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcessTimes on pipe server PID failed.");
                }

                if (creationTime != expectedCreationFileTime)
                {
                    throw new UnauthorizedAccessException(
                        string.Format("Pipe server StartTime mismatch: expected {0}, actual {1}.", expectedCreationFileTime, creationTime));
                }
            }
            finally
            {
                CloseHandle(hProc);
            }
        }

        public static string QuoteCommandLineArg(string arg)
        {
            if (string.IsNullOrEmpty(arg))
            {
                return "\"\"";
            }

            bool needsQuotes = false;
            for (int i = 0; i < arg.Length; i++)
            {
                char c = arg[i];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '"')
                {
                    needsQuotes = true;
                    break;
                }
            }

            if (!needsQuotes)
            {
                return arg;
            }

            StringBuilder sb = new StringBuilder();
            sb.Append('"');
            int backslashes = 0;
            for (int i = 0; i < arg.Length; i++)
            {
                char c = arg[i];
                if (c == '\\')
                {
                    backslashes++;
                }
                else if (c == '"')
                {
                    sb.Append('\\', backslashes * 2 + 1);
                    sb.Append('"');
                    backslashes = 0;
                }
                else
                {
                    if (backslashes > 0)
                    {
                        sb.Append('\\', backslashes);
                        backslashes = 0;
                    }
                    sb.Append(c);
                }
            }

            if (backslashes > 0)
            {
                sb.Append('\\', backslashes * 2);
            }
            sb.Append('"');
            return sb.ToString();
        }

        public static string BuildCommandLineArgs(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                return string.Empty;
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < args.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(QuoteCommandLineArg(args[i]));
            }
            return sb.ToString();
        }

        public static void WriteFrame(Stream pipe, byte frameType, byte[] payload)
        {
            int payloadLen = (payload == null) ? 0 : payload.Length;
            byte[] frame = new byte[5 + payloadLen];
            frame[0] = frameType;
            uint ulen = unchecked((uint)payloadLen);
            frame[1] = (byte)(ulen & 0xFF);
            frame[2] = (byte)((ulen >> 8) & 0xFF);
            frame[3] = (byte)((ulen >> 16) & 0xFF);
            frame[4] = (byte)((ulen >> 24) & 0xFF);
            if (payloadLen > 0)
            {
                Buffer.BlockCopy(payload, 0, frame, 5, payloadLen);
            }
            pipe.Write(frame, 0, frame.Length);
            pipe.Flush();
        }

        public static void WriteErrorFrame(Stream pipe, string message)
        {
            if (pipe == null) return;
            byte[] payload = Encoding.UTF8.GetBytes(message ?? string.Empty);
            WriteFrame(pipe, 4, payload);
        }

        public static void WriteExitCodeFrame(Stream pipe, int exitCode)
        {
            if (pipe == null) return;
            byte[] payload = new byte[4];
            uint u = unchecked((uint)exitCode);
            payload[0] = (byte)(u & 0xFF);
            payload[1] = (byte)((u >> 8) & 0xFF);
            payload[2] = (byte)((u >> 16) & 0xFF);
            payload[3] = (byte)((u >> 24) & 0xFF);
            WriteFrame(pipe, 3, payload);
        }
    }

    public sealed class LineDecoder
    {
        public const int MaxLineBytes = 65536;

        public readonly object SyncRoot = new object();

        private readonly string _mode;
        private readonly Action<string> _onText;
        private readonly List<byte> _buf = new List<byte>(4096);

        private readonly UTF8Encoding _utf8Strict = new UTF8Encoding(false, true);
        private readonly Encoding _cp936Strict;
        private readonly Encoding _cp936Replace;
        private readonly Encoding _utf16Le;

        private long _lastByteMs;
        private bool _utf16BomStream;
        private bool _streamStarted;
        private bool _lineSawMultiByteUtf8;

        public LineDecoder(string encodingMode, Action<string> onText)
        {
            _mode = string.IsNullOrEmpty(encodingMode) ? "auto" : encodingMode.ToLowerInvariant();
            _onText = onText;
            _cp936Strict = Encoding.GetEncoding(936, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
            _cp936Replace = Encoding.GetEncoding(936);
            _utf16Le = new UnicodeEncoding(false, false, false);
        }

        public int PendingCount
        {
            get
            {
                lock (SyncRoot)
                {
                    return _buf.Count;
                }
            }
        }

        public void Feed(byte[] data, int offset, int count, long nowMs)
        {
            if (data == null || count <= 0) return;

            List<string> emitted = new List<string>();
            lock (SyncRoot)
            {
                _lastByteMs = nowMs;
                for (int i = 0; i < count; i++)
                {
                    byte b = data[offset + i];
                    _buf.Add(b);

                    if (IsUtf16BufferActive())
                    {
                        int n = _buf.Count;
                        if (n >= 2 && (n % 2) == 0 && _buf[n - 2] == 0x0A && _buf[n - 1] == 0x00)
                        {
                            string s = DecodeBufferSlice(n, true);
                            _buf.Clear();
                            _lineSawMultiByteUtf8 = false;
                            if (!string.IsNullOrEmpty(s)) emitted.Add(s);
                            continue;
                        }
                    }
                    else
                    {
                        if (b == 0x0A)
                        {
                            string s = DecodeBufferSlice(_buf.Count, false);
                            _buf.Clear();
                            _lineSawMultiByteUtf8 = false;
                            if (!string.IsNullOrEmpty(s)) emitted.Add(s);
                            continue;
                        }
                    }

                    if (_buf.Count >= MaxLineBytes)
                    {
                        int holdback = ComputeHoldback(_buf);
                        int emitLen = _buf.Count - holdback;
                        if (emitLen > 0)
                        {
                            string s = DecodeBufferSlice(emitLen, IsUtf16BufferActive());
                            _buf.RemoveRange(0, emitLen);
                            _lineSawMultiByteUtf8 = false;
                            if (!string.IsNullOrEmpty(s)) emitted.Add(s);
                        }
                    }
                }
            }

            if (_onText != null)
            {
                for (int i = 0; i < emitted.Count; i++)
                {
                    _onText(emitted[i]);
                }
            }
        }

        public void FlushIfIdle(long nowMs, int idleThresholdMs)
        {
            string emitted = null;
            lock (SyncRoot)
            {
                if (_buf.Count == 0) return;
                if ((nowMs - _lastByteMs) < idleThresholdMs) return;

                bool isUtf16 = IsUtf16BufferActive();
                int holdback = ComputeHoldback(_buf);
                int emitLen = _buf.Count - holdback;
                if (emitLen > 0)
                {
                    emitted = DecodeBufferSlice(emitLen, isUtf16);
                    _buf.RemoveRange(0, emitLen);
                }
            }

            if (_onText != null && !string.IsNullOrEmpty(emitted))
            {
                _onText(emitted);
            }
        }

        public void FlushEof()
        {
            string emitted = null;
            lock (SyncRoot)
            {
                if (_buf.Count == 0) return;
                bool isUtf16 = IsUtf16BufferActive();
                emitted = DecodeBufferSlice(_buf.Count, isUtf16);
                _buf.Clear();
                _lineSawMultiByteUtf8 = false;
            }

            if (_onText != null && !string.IsNullOrEmpty(emitted))
            {
                _onText(emitted);
            }
        }

        private bool IsUtf16BufferActive()
        {
            if (_mode == "utf16") return true;
            if (_mode == "utf8" || _mode == "oem") return false;

            if (_buf.Count >= 2 && _buf[0] == 0xFF && _buf[1] == 0xFE)
            {
                _utf16BomStream = true;
                return true;
            }
            if (_utf16BomStream)
            {
                return true;
            }
            if (_buf.Count >= 2 && _buf[0] != 0x00 && _buf[1] == 0x00)
            {
                return true;
            }
            return false;
        }

        private string DecodeBufferSlice(int len, bool forceUtf16)
        {
            if (len <= 0) return string.Empty;
            _streamStarted = true;

            byte[] slice = new byte[len];
            _buf.CopyTo(0, slice, 0, len);

            if (_mode == "utf16" || (_mode == "auto" && forceUtf16))
            {
                int start = 0;
                if (len >= 2 && slice[0] == 0xFF && slice[1] == 0xFE)
                {
                    start = 2;
                }
                int usable = len - start;
                if (usable <= 0) return string.Empty;
                return _utf16Le.GetString(slice, start, usable);
            }

            if (_mode == "utf8")
            {
                int start = StripUtf8BomOffset(slice, len);
                return Encoding.UTF8.GetString(slice, start, len - start);
            }

            if (_mode == "oem")
            {
                return _cp936Replace.GetString(slice, 0, len);
            }

            // auto mode (non-UTF-16LE): strict UTF-8 -> 2-byte CJK CP936 heuristic -> CP936 fallback
            int utf8Start = StripUtf8BomOffset(slice, len);
            try
            {
                string utf8Text = _utf8Strict.GetString(slice, utf8Start, len - utf8Start);
                bool hasNonAscii = false;
                bool allTwoByte = true;
                for (int i = 0; i < utf8Text.Length; i++)
                {
                    char c = utf8Text[i];
                    if (c >= 0x80)
                    {
                        hasNonAscii = true;
                        if (c > '\u07FF' || char.IsSurrogate(c))
                        {
                            allTwoByte = false;
                            _lineSawMultiByteUtf8 = true;
                            break;
                        }
                    }
                }

                if (hasNonAscii && allTwoByte && !_lineSawMultiByteUtf8)
                {
                    try
                    {
                        string cpText = _cp936Strict.GetString(slice, 0, len);
                        if (ContainsCleanCjkIdeographs(cpText))
                        {
                            return cpText;
                        }
                    }
                    catch (DecoderFallbackException)
                    {
                        // Keep UTF-8 result
                    }
                }

                return utf8Text;
            }
            catch (DecoderFallbackException)
            {
                return _cp936Replace.GetString(slice, 0, len);
            }
        }

        private static int StripUtf8BomOffset(byte[] slice, int len)
        {
            if (len >= 3 && slice[0] == 0xEF && slice[1] == 0xBB && slice[2] == 0xBF)
            {
                return 3;
            }
            return 0;
        }

        private static bool ContainsCleanCjkIdeographs(string s)
        {
            bool hasCjk = false;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\uFFFD') return false;
                if (char.IsControl(c) && c != '\r' && c != '\n' && c != '\t') return false;
                if ((c >= '\u4E00' && c <= '\u9FFF') ||
                    (c >= '\u3400' && c <= '\u4DBF') ||
                    (c >= '\uF900' && c <= '\uFAFF'))
                {
                    hasCjk = true;
                }
            }
            return hasCjk;
        }

        private int ComputeHoldback(List<byte> buf)
        {
            if (_mode == "utf16" || (_mode == "auto" && IsUtf16BufferActive()))
            {
                int holdback = buf.Count % 2;
                int evenLen = buf.Count - holdback;
                if (evenLen >= 2)
                {
                    int lastUnit = buf[evenLen - 2] | (buf[evenLen - 1] << 8);
                    if (lastUnit >= 0xD800 && lastUnit <= 0xDBFF)
                    {
                        holdback += 2;
                    }
                }
                return holdback;
            }
            if (_mode == "utf8")
            {
                return ComputeUtf8TailHoldback(buf);
            }
            if (_mode == "oem")
            {
                return ComputeCp936TailHoldback(buf);
            }

            // auto mode: hold leading 0xFF until potential UTF-16LE BOM second byte 0xFE arrives
            if (!_streamStarted && buf.Count == 1 && buf[0] == 0xFF)
            {
                return 1;
            }

            // auto mode: test UTF-8 incomplete tail against strict UTF-8 prefix first
            int uTail = ComputeUtf8TailHoldback(buf);
            if (uTail > 0)
            {
                int prefixLen = buf.Count - uTail;
                byte[] prefix = new byte[prefixLen];
                if (prefixLen > 0)
                {
                    buf.CopyTo(0, prefix, 0, prefixLen);
                }

                int start = StripUtf8BomOffset(prefix, prefixLen);
                try
                {
                    string decodedPrefix = _utf8Strict.GetString(prefix, start, prefixLen - start);
                    bool prefixHasMultibyte3Plus = false;
                    for (int i = 0; i < decodedPrefix.Length; i++)
                    {
                        if (decodedPrefix[i] > '\u07FF' || char.IsSurrogate(decodedPrefix[i]))
                        {
                            prefixHasMultibyte3Plus = true;
                            break;
                        }
                    }

                    if (prefixHasMultibyte3Plus || _lineSawMultiByteUtf8 || uTail >= 2 || prefixLen == 0)
                    {
                        return uTail;
                    }
                    // For uTail == 1 with only ASCII/2-byte prefix, trailing byte is in 0xC2..0xF4,
                    // which is an incomplete lead byte in BOTH UTF-8 and CP936 (0x81..0xFE).
                    return 1;
                }
                catch (DecoderFallbackException)
                {
                    // Prefix is not valid UTF-8 -> fall through to CP936 pairing scan
                }
            }

            // If entire buffer fails strict UTF-8, check CP936 pairing tail holdback
            byte[] allBytes = buf.ToArray();
            int allStart = StripUtf8BomOffset(allBytes, allBytes.Length);
            try
            {
                _utf8Strict.GetString(allBytes, allStart, allBytes.Length - allStart);
                return 0;
            }
            catch (DecoderFallbackException)
            {
                return ComputeCp936TailHoldback(buf);
            }
        }

        private static int ComputeUtf8TailHoldback(List<byte> buf)
        {
            int n = buf.Count;
            if (n <= 0) return 0;

            byte b1 = buf[n - 1];
            if (b1 < 0x80) return 0;
            if (b1 >= 0xC2 && b1 <= 0xF4) return 1;

            if (b1 >= 0x80 && b1 <= 0xBF)
            {
                if (n >= 2)
                {
                    byte b2 = buf[n - 2];
                    if (b2 >= 0xE0 && b2 <= 0xEF)
                    {
                        if ((b2 == 0xE0 && b1 < 0xA0) || (b2 == 0xED && b1 > 0x9F)) return 0;
                        return 2;
                    }
                    if (b2 >= 0xF0 && b2 <= 0xF4)
                    {
                        if ((b2 == 0xF0 && b1 < 0x90) || (b2 == 0xF4 && b1 > 0x8F)) return 0;
                        return 2;
                    }
                    if (b2 >= 0x80 && b2 <= 0xBF && n >= 3)
                    {
                        byte b3 = buf[n - 3];
                        if (b3 >= 0xF0 && b3 <= 0xF4)
                        {
                            if ((b3 == 0xF0 && b2 < 0x90) || (b3 == 0xF4 && b2 > 0x8F)) return 0;
                            return 3;
                        }
                    }
                }
            }

            return 0;
        }

        private static int ComputeCp936TailHoldback(List<byte> buf)
        {
            int i = 0;
            int n = buf.Count;
            while (i < n)
            {
                byte b = buf[i];
                if (b <= 0x7F)
                {
                    i += 1;
                }
                else if (b >= 0x81 && b <= 0xFE)
                {
                    if (i + 1 < n)
                    {
                        byte b2 = buf[i + 1];
                        if (b2 >= 0x40 && b2 <= 0xFE && b2 != 0x7F)
                        {
                            i += 2;
                        }
                        else
                        {
                            i += 1;
                        }
                    }
                    else
                    {
                        return 1;
                    }
                }
                else
                {
                    i += 1;
                }
            }
            return 0;
        }
    }

    public static class JobProcessRunner
    {
        private const int STD_INPUT_HANDLE = -10;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const uint WAIT_OBJECT_0 = 0x00000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFOW
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwOptions);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            ref SECURITY_ATTRIBUTES lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(
            string lpApplicationName,
            StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOW lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private sealed class RunState
        {
            public volatile bool PipeBroken;
            public int JobTerminated;
        }

        public static int Run(Stream pipe, string exePath, string arguments, string workDir, string encodingMode)
        {
            return Run(pipe, exePath, arguments, workDir, encodingMode, 500, 200, 1000, true);
        }

        public static int Run(
            Stream pipe,
            string exePath,
            string arguments,
            string workDir,
            string encodingMode,
            int heartbeatMs,
            int idleFlushMs,
            int eofDrainMs,
            bool teeToConsole)
        {
            if (pipe == null) throw new ArgumentNullException("pipe");
            if (string.IsNullOrEmpty(exePath)) throw new ArgumentNullException("exePath");

            IntPtr outR = IntPtr.Zero;
            IntPtr outW = IntPtr.Zero;
            IntPtr errR = IntPtr.Zero;
            IntPtr errW = IntPtr.Zero;
            IntPtr ownedStdIn = IntPtr.Zero;
            IntPtr hJob = IntPtr.Zero;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            try
            {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = IntPtr.Zero;
                sa.bInheritHandle = true;

                if (!CreatePipe(out outR, out outW, ref sa, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreatePipe(stdout) failed.");
                if (!SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetHandleInformation(outR) failed.");

                if (!CreatePipe(out errR, out errW, ref sa, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreatePipe(stderr) failed.");
                if (!SetHandleInformation(errR, HANDLE_FLAG_INHERIT, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetHandleInformation(errR) failed.");

                IntPtr effectiveStdIn = IntPtr.Zero;
                IntPtr curStdIn = GetStdHandle(STD_INPUT_HANDLE);
                IntPtr invalidHandle = new IntPtr(-1);
                if (curStdIn != IntPtr.Zero && curStdIn != invalidHandle)
                {
                    uint stdInFlags;
                    if (GetHandleInformation(curStdIn, out stdInFlags))
                    {
                        if ((stdInFlags & HANDLE_FLAG_INHERIT) != 0)
                        {
                            effectiveStdIn = curStdIn;
                        }
                        else
                        {
                            IntPtr dupIn;
                            if (DuplicateHandle(GetCurrentProcess(), curStdIn, GetCurrentProcess(), out dupIn, 0, true, DUPLICATE_SAME_ACCESS))
                            {
                                ownedStdIn = dupIn;
                                effectiveStdIn = dupIn;
                            }
                        }
                    }
                }

                if (effectiveStdIn == IntPtr.Zero)
                {
                    IntPtr nulHandle = CreateFileW("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, ref sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                    if (nulHandle != IntPtr.Zero && nulHandle != invalidHandle)
                    {
                        ownedStdIn = nulHandle;
                        effectiveStdIn = nulHandle;
                    }
                }

                // Create Job Object WITHOUT JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                hJob = CreateJobObjectW(IntPtr.Zero, null);
                if (hJob == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObjectW failed.");

                STARTUPINFOW si = new STARTUPINFOW();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
                si.dwFlags = STARTF_USESTDHANDLES;
                si.hStdInput = effectiveStdIn;
                si.hStdOutput = outW;
                si.hStdError = errW;

                string fullCmd = "\"" + exePath + "\"" + (string.IsNullOrEmpty(arguments) ? string.Empty : (" " + arguments));
                StringBuilder cmdBuf = new StringBuilder(fullCmd);

                if (!CreateProcessW(
                    exePath,
                    cmdBuf,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    CREATE_SUSPENDED,
                    IntPtr.Zero,
                    workDir,
                    ref si,
                    out pi))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW failed.");
                }

                // Parent must close child write ends and any duplicated stdin immediately
                CloseHandle(outW); outW = IntPtr.Zero;
                CloseHandle(errW); errW = IntPtr.Zero;
                if (ownedStdIn != IntPtr.Zero) { CloseHandle(ownedStdIn); ownedStdIn = IntPtr.Zero; }

                if (!AssignProcessToJobObject(hJob, pi.hProcess))
                {
                    int err = Marshal.GetLastWin32Error();
                    TerminateProcess(pi.hProcess, 1);
                    throw new Win32Exception(err, "AssignProcessToJobObject failed.");
                }

                if (ResumeThread(pi.hThread) == 0xFFFFFFFF)
                {
                    int err = Marshal.GetLastWin32Error();
                    TerminateJobObject(hJob, 1);
                    throw new Win32Exception(err, "ResumeThread failed.");
                }
                CloseHandle(pi.hThread);
                pi.hThread = IntPtr.Zero;

                object pipeLock = new object();
                object consoleLock = new object();
                RunState state = new RunState();
                ManualResetEvent stopEvent = new ManualResetEvent(false);

                Action onPipeBroken = delegate
                {
                    state.PipeBroken = true;
                    if (Interlocked.Exchange(ref state.JobTerminated, 1) == 0)
                    {
                        TerminateJobObject(hJob, 1);
                    }
                    try
                    {
                        stopEvent.Set();
                    }
                    catch (ObjectDisposedException)
                    {
                    }
                };

                Action<byte, string> emitText = delegate(byte frameType, string text)
                {
                    if (string.IsNullOrEmpty(text)) return;

                    if (teeToConsole)
                    {
                        lock (consoleLock)
                        {
                            try { Console.Write(text); } catch { }
                        }
                    }

                    byte[] utf8 = Encoding.UTF8.GetBytes(text);
                    lock (pipeLock)
                    {
                        if (state.PipeBroken) return;
                        try
                        {
                            RunnerNative.WriteFrame(pipe, frameType, utf8);
                        }
                        catch (IOException)
                        {
                            onPipeBroken();
                        }
                        catch (ObjectDisposedException)
                        {
                            onPipeBroken();
                        }
                    }
                };

                Stopwatch sw = Stopwatch.StartNew();
                LineDecoder outDec = new LineDecoder(encodingMode, delegate(string text) { emitText(1, text); });
                LineDecoder errDec = new LineDecoder(encodingMode, delegate(string text) { emitText(2, text); });

                FileStream outStream = new FileStream(new SafeFileHandle(outR, true), FileAccess.Read, 4096, false);
                outR = IntPtr.Zero;
                FileStream errStream = new FileStream(new SafeFileHandle(errR, true), FileAccess.Read, 4096, false);
                errR = IntPtr.Zero;

                Thread stdoutThread = new Thread(delegate()
                {
                    byte[] buf = new byte[4096];
                    try
                    {
                        while (true)
                        {
                            int n = outStream.Read(buf, 0, buf.Length);
                            if (n <= 0) break;
                            outDec.Feed(buf, 0, n, sw.ElapsedMilliseconds);
                        }
                    }
                    catch { }
                });
                stdoutThread.IsBackground = true;

                Thread stderrThread = new Thread(delegate()
                {
                    byte[] buf = new byte[4096];
                    try
                    {
                        while (true)
                        {
                            int n = errStream.Read(buf, 0, buf.Length);
                            if (n <= 0) break;
                            errDec.Feed(buf, 0, n, sw.ElapsedMilliseconds);
                        }
                    }
                    catch { }
                });
                stderrThread.IsBackground = true;

                Thread timerThread = new Thread(delegate()
                {
                    long lastHbMs = 0;
                    try
                    {
                        while (!stopEvent.WaitOne(50))
                        {
                            long now = sw.ElapsedMilliseconds;
                            outDec.FlushIfIdle(now, idleFlushMs);
                            errDec.FlushIfIdle(now, idleFlushMs);

                            if ((now - lastHbMs) >= heartbeatMs)
                            {
                                lastHbMs = now;
                                lock (pipeLock)
                                {
                                    if (state.PipeBroken) break;
                                    try
                                    {
                                        RunnerNative.WriteFrame(pipe, 0, null);
                                    }
                                    catch (IOException)
                                    {
                                        onPipeBroken();
                                        break;
                                    }
                                    catch (ObjectDisposedException)
                                    {
                                        onPipeBroken();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    catch (ObjectDisposedException)
                    {
                    }
                });
                timerThread.IsBackground = true;

                stdoutThread.Start();
                stderrThread.Start();
                timerThread.Start();

                bool exited = false;
                while (!exited && !state.PipeBroken)
                {
                    uint wr = WaitForSingleObject(pi.hProcess, 100);
                    if (wr == WAIT_OBJECT_0)
                    {
                        exited = true;
                    }
                }

                if (state.PipeBroken && !exited)
                {
                    WaitForSingleObject(pi.hProcess, 1000);
                }

                uint rawExit = 1;
                GetExitCodeProcess(pi.hProcess, out rawExit);
                int exitCode = unchecked((int)rawExit);

                bool timerStopped;
                if (!state.PipeBroken)
                {
                    Stopwatch drainSw = Stopwatch.StartNew();
                    int rem1 = Math.Max(0, eofDrainMs - (int)drainSw.ElapsedMilliseconds);
                    bool outDone = stdoutThread.Join(rem1);
                    int rem2 = Math.Max(0, eofDrainMs - (int)drainSw.ElapsedMilliseconds);
                    bool errDone = stderrThread.Join(rem2);

                    try { stopEvent.Set(); } catch (ObjectDisposedException) { }
                    timerStopped = timerThread.Join(500);

                    outDec.FlushEof();
                    errDec.FlushEof();

                    if (outDone) { try { outStream.Dispose(); } catch { } }
                    if (errDone) { try { errStream.Dispose(); } catch { } }

                    lock (pipeLock)
                    {
                        if (!state.PipeBroken)
                        {
                            try
                            {
                                RunnerNative.WriteExitCodeFrame(pipe, exitCode);
                            }
                            catch (IOException) { }
                            catch (ObjectDisposedException) { }
                        }
                    }
                }
                else
                {
                    try { stopEvent.Set(); } catch (ObjectDisposedException) { }
                    timerStopped = timerThread.Join(500);
                }

                if (timerStopped)
                {
                    stopEvent.Close();
                }
                return exitCode;
            }
            finally
            {
                if (outW != IntPtr.Zero) CloseHandle(outW);
                if (errW != IntPtr.Zero) CloseHandle(errW);
                if (outR != IntPtr.Zero) CloseHandle(outR);
                if (errR != IntPtr.Zero) CloseHandle(errR);
                if (ownedStdIn != IntPtr.Zero) CloseHandle(ownedStdIn);
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                if (hJob != IntPtr.Zero) CloseHandle(hJob);
            }
        }
    }
}
'@

    Add-Type -TypeDefinition $csharp -Language CSharp -ReferencedAssemblies @('System.Core')
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$ErrorActionPreference = 'Stop'

# 1. Pure mscorlib verification of C:\ProgramData\AgentElevation\tmp\ BEFORE Add-Type
try {
    Test-RunnerTmpDirectory | Out-Null
} catch {
    [Console]::Error.WriteLine("FATAL: tmp directory validation failed: $($_.Exception.Message)")
    exit 1204
}

$runTempDir = $null
$pipeClient = $null
$phase = 'init'

try {
    # 2. Sweep >24h subdirs (skipping reparse points, keeping last-error.log), isolate TEMP/TMP, lock HKLM PATH/PATHEXT/PSModulePath
    $phase = 'env_lockdown'
    Invoke-SweepStaleRunnerTempDirs -TmpRoot $script:ProductionTmpRoot -MaxAgeHours $script:StaleRunAgeHours
    $runTempDir = New-IsolatedRunnerTempDir -TmpRoot $script:ProductionTmpRoot
    Set-LockedRunnerEnvironment -RunTempDir $runTempDir | Out-Null

    # 3. Validate mandatory CLI parameters
    $phase = 'validate_args'
    if ([string]::IsNullOrWhiteSpace($PipeName) -or $PipeName -notmatch '^ag-elev-[0-9a-fA-F]{32}$') {
        throw "Invalid -PipeName '$PipeName'."
    }
    if ($CallerPid -le 0) {
        throw "Invalid -CallerPid '$CallerPid'."
    }
    if ($CallerStart -le 0) {
        throw "Invalid -CallerStart '$CallerStart'."
    }
    if ([string]::IsNullOrWhiteSpace($ManifestFile) -or $ManifestFile -notmatch '^[A-Za-z]:\\' -or -not [System.IO.Path]::IsPathRooted($ManifestFile) -or $ManifestFile.StartsWith('\\')) {
        throw "Invalid -ManifestFile '$ManifestFile'."
    }
    if ([string]::IsNullOrWhiteSpace($ManifestSha256) -or $ManifestSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Invalid -ManifestSha256 '$ManifestSha256'."
    }

    # 4. Compile/load inline C# types AFTER TEMP/TMP and PATH lockdown
    $phase = 'add_type'
    Initialize-RunnerNativeTypes

    # 5. Connect to Medium-IL Named Pipe server and authenticate PID + CreationTime
    $phase = 'pipe_connect'
    $pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.',
        $PipeName,
        [System.IO.Pipes.PipeDirection]::Out,
        [System.IO.Pipes.PipeOptions]::None,
        [System.Security.Principal.TokenImpersonationLevel]::Anonymous
    )
    $pipeClient.Connect(5000)
    [AgentElevation.RunnerNative]::VerifyPipeServerIdentity($pipeClient.SafePipeHandle, $CallerPid, $CallerStart)

    # 6. Single-read manifest SHA-256 verification and JSON validation
    $phase = 'manifest'
    $manifest = Read-VerifiedManifest -ManifestFile $ManifestFile -ManifestSha256 $ManifestSha256 -MaxBytes $script:MaxManifestBytes

    # 7. Write verified script verbatim with UTF-8 BOM and zero injected prelude
    $phase = 'write_script'
    $scriptPath = [System.IO.Path]::Combine($runTempDir, 'script.ps1')
    Write-VerbatimScriptFile -ScriptText $manifest.Script -DestPath $scriptPath | Out-Null

    # 8. Execute child PS 5.1 in Job Object (no KILL_ON_JOB_CLOSE) with live stream pump
    $phase = 'execute'
    $childExe = [System.IO.Path]::Combine([System.Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\powershell.exe')
    $escapedScriptPath = [AgentElevation.RunnerNative]::QuoteCommandLineArg($scriptPath)
    $escapedArgs = [AgentElevation.RunnerNative]::BuildCommandLineArgs($manifest.Args)
    $childArgLine = "-NoProfile -ExecutionPolicy Bypass -OutputFormat Text -File $escapedScriptPath"
    if (-not [string]::IsNullOrEmpty($escapedArgs)) {
        $childArgLine = "$childArgLine $escapedArgs"
    }

    $exitCode = [AgentElevation.JobProcessRunner]::Run(
        $pipeClient,
        $childExe,
        $childArgLine,
        $manifest.WorkDir,
        $manifest.Encoding
    )

    exit $exitCode
} catch {
    $errMsg = $_.Exception.Message
    Write-RunnerLastErrorLog -LogPath $script:ProductionLastErrorLog -PipeName $PipeName -CallerPid $CallerPid -Phase $phase -Message $errMsg

    if ($null -ne $pipeClient -and $pipeClient.IsConnected) {
        try {
            $wireMsg = if ($errMsg -match '^(SHA256_MISMATCH|RUNNER_ERROR):') {
                $errMsg
            } else {
                "RUNNER_ERROR:$errMsg"
            }
            [AgentElevation.RunnerNative]::WriteErrorFrame($pipeClient, $wireMsg)
        } catch {
            # Ignore pipe write errors during fatal abort
        }
    }

    if ($errMsg -match '^SHA256_MISMATCH:') {
        exit 1205
    } elseif ($phase -eq 'validate_args') {
        exit 1206
    } else {
        exit 1204
    }
} finally {
    if ($null -ne $pipeClient) {
        try { $pipeClient.Dispose() } catch { }
    }
    if ($null -ne $runTempDir -and [System.IO.Directory]::Exists($runTempDir)) {
        try {
            Remove-Item -LiteralPath $runTempDir -Recurse -Force -ErrorAction SilentlyContinue
        } catch { }
    }
}
