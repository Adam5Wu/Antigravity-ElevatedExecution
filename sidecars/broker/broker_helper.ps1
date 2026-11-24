#Requires -Version 5.1
<#
.SYNOPSIS
    Medium-IL Win32 Pre-Flight Gate, Click-1/Reminder WinForms UI, STA UAC Launcher,
    and Hardened Output-Only Named Pipe Server for elevated-exec.
.DESCRIPTION
    Two-stage Add-Type architecture:
      Stage 1 (Initialize-PreflightNative): compact System-only P/Invoke for <4s -PreflightOnly SLA.
      Stage 2 (Initialize-InteractiveBrokerTypes): WinForms (PerMonitorV2), C# UTF-8 JSONL stdin
      reader, Interlocked single-winner arbitration, STA ShellExecuteExW("runas"), and hardened
      output-only Named Pipe server (loaded only when -PreflightOnly is not specified).
#>
[CmdletBinding()]
param(
    [switch]$PreflightOnly,
    [string]$RunnerPath = 'C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:ProductionTrustedAdminSids = @(
    'S-1-5-18',
    'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)

$script:ExpectedPipeSddl = 'D:P(D;;0x1f019f;;;NU)(A;;0x100000;;;OW)(A;;0x1f019f;;;SY)(A;;0x12019b;;;BA)'

function Initialize-PreflightNative {
    [CmdletBinding()]
    param()

    if ('AgentElevation.PreflightNative' -as [type]) {
        return
    }

    $csharp = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace AgentElevation
{
    public sealed class PreflightWin32State
    {
        public int SessionId;
        public string WinSta;
        public string ThreadDesktop;
        public bool ConnectOk;
        public int ConnectState;
        public bool InfoExOk;
        public int InfoExBytes;
        public int Level;
        public int SessionFlags;
        public bool InputDesktopOk;
        public string InputDesktopName;
        public int InputDesktopError;
    }

    public static class PreflightNative
    {
        private const int UOI_NAME = 2;
        private const int WTS_CURRENT_SESSION = -1;
        private const int WTSConnectState = 8;
        private const int WTSSessionInfoEx = 25;
        private const uint DESKTOP_READOBJECTS = 0x0001;
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_ALL = 0x00000007;
        private const uint OPEN_EXISTING = 3;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        private static readonly object StdoutLock = new object();
        private static Stream StdoutStream;
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetThreadDesktop(uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetUserObjectInformationW(
            IntPtr hObj,
            int nIndex,
            byte[] pvInfo,
            uint nLength,
            out uint lpnLengthNeeded);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WTSQuerySessionInformationW(
            IntPtr hServer,
            int sessionId,
            int wtsInfoClass,
            out IntPtr ppBuffer,
            out uint pBytesReturned);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static string GetUserObjectName(IntPtr hObj)
        {
            if (hObj == IntPtr.Zero) return string.Empty;
            byte[] buf = new byte[512];
            uint needed = 0;
            if (!GetUserObjectInformationW(hObj, UOI_NAME, buf, (uint)buf.Length, out needed))
            {
                if (needed > (uint)buf.Length && needed <= 65536)
                {
                    buf = new byte[needed];
                    if (!GetUserObjectInformationW(hObj, UOI_NAME, buf, (uint)buf.Length, out needed))
                    {
                        return string.Empty;
                    }
                }
                else
                {
                    return string.Empty;
                }
            }
            int charBytes = (int)needed;
            if (charBytes >= 2 && buf[charBytes - 2] == 0 && buf[charBytes - 1] == 0)
            {
                charBytes -= 2;
            }
            if (charBytes <= 0) return string.Empty;
            return Encoding.Unicode.GetString(buf, 0, charBytes);
        }

        public static PreflightWin32State ProbeSessionState()
        {
            PreflightWin32State st = new PreflightWin32State();
            st.SessionId = Process.GetCurrentProcess().SessionId;
            st.WinSta = GetUserObjectName(GetProcessWindowStation());
            st.ThreadDesktop = GetUserObjectName(GetThreadDesktop(GetCurrentThreadId()));

            IntPtr pConn = IntPtr.Zero;
            uint connBytes = 0;
            try
            {
                st.ConnectOk = WTSQuerySessionInformationW(IntPtr.Zero, WTS_CURRENT_SESSION, WTSConnectState, out pConn, out connBytes);
                if (st.ConnectOk && pConn != IntPtr.Zero && connBytes >= 4)
                {
                    st.ConnectState = Marshal.ReadInt32(pConn, 0);
                }
                else
                {
                    st.ConnectState = -1;
                }
            }
            finally
            {
                if (pConn != IntPtr.Zero) WTSFreeMemory(pConn);
            }

            IntPtr pEx = IntPtr.Zero;
            uint exBytes = 0;
            try
            {
                st.InfoExOk = WTSQuerySessionInformationW(IntPtr.Zero, WTS_CURRENT_SESSION, WTSSessionInfoEx, out pEx, out exBytes);
                st.InfoExBytes = unchecked((int)exBytes);
                if (st.InfoExOk && pEx != IntPtr.Zero && exBytes >= 20)
                {
                    st.Level = Marshal.ReadInt32(pEx, 0);
                    st.SessionFlags = Marshal.ReadInt32(pEx, 16);
                }
                else
                {
                    st.Level = -1;
                    st.SessionFlags = -1;
                }
            }
            finally
            {
                if (pEx != IntPtr.Zero) WTSFreeMemory(pEx);
            }

            IntPtr hInput = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);
            if (hInput == IntPtr.Zero)
            {
                st.InputDesktopOk = false;
                st.InputDesktopName = string.Empty;
                st.InputDesktopError = Marshal.GetLastWin32Error();
            }
            else
            {
                try
                {
                    st.InputDesktopOk = true;
                    st.InputDesktopName = GetUserObjectName(hInput);
                    st.InputDesktopError = 0;
                }
                finally
                {
                    CloseDesktop(hInput);
                }
            }

            return st;
        }

        public static bool HasZoneIdentifier(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;
            IntPtr h = CreateFileW(filePath + ":Zone.Identifier", GENERIC_READ, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h != INVALID_HANDLE_VALUE && h != IntPtr.Zero)
            {
                CloseHandle(h);
                return true;
            }
            return false;
        }

        public static void WriteStdoutUtf8Line(string line)
        {
            byte[] payload = Utf8NoBom.GetBytes((line ?? string.Empty) + "\n");
            lock (StdoutLock)
            {
                if (StdoutStream == null)
                {
                    StdoutStream = Console.OpenStandardOutput();
                }
                StdoutStream.Write(payload, 0, payload.Length);
                StdoutStream.Flush();
            }
        }

        public static string EscapeJsonString(string s)
        {
            if (s == null) return "null";
            StringBuilder sb = new StringBuilder(s.Length + 8);
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                        {
                            sb.AppendFormat("\\u{0:x4}", (int)c);
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        public static string FormatPreflightJson(bool ok, string code, int exitCode, string detail)
        {
            return string.Concat(
                "{\"ok\":", ok ? "true" : "false",
                ",\"code\":", EscapeJsonString(code ?? string.Empty),
                ",\"exitCode\":", exitCode.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ",\"detail\":", EscapeJsonString(detail ?? string.Empty),
                "}"
            );
        }
    }
}
'@

    Add-Type -TypeDefinition $csharp -Language CSharp
}

function Evaluate-PreflightState {
    [CmdletBinding()]
    param(
        [int]$SessionId,
        [AllowEmptyString()][string]$WinSta,
        [AllowEmptyString()][string]$ThreadDesktop,
        [bool]$ConnectOk,
        [int]$ConnectState,
        [bool]$InfoExOk,
        [int]$InfoExBytes,
        [int]$Level,
        [int]$SessionFlags,
        [bool]$InputDesktopOk,
        [AllowEmptyString()][string]$InputDesktopName,
        [int]$InputDesktopError
    )

    if ($SessionId -eq 0) {
        return [pscustomobject]@{
            ok       = $false
            code     = 'E_SESSION_NOT_INTERACTIVE'
            exitCode = 1202
            detail   = 'SessionId is 0 (non-interactive Services session).'
        }
    }
    if ($WinSta -cne 'WinSta0') {
        return [pscustomobject]@{
            ok       = $false
            code     = 'E_SESSION_NOT_INTERACTIVE'
            exitCode = 1202
            detail   = "Window station is '$WinSta' (expected 'WinSta0')."
        }
    }
    if ($ThreadDesktop -cne 'Default') {
        return [pscustomobject]@{
            ok       = $false
            code     = 'E_SESSION_NOT_INTERACTIVE'
            exitCode = 1202
            detail   = "Thread desktop is '$ThreadDesktop' (expected 'Default')."
        }
    }
    if (-not $ConnectOk -or $ConnectState -ne 0) {
        return [pscustomobject]@{
            ok       = $false
            code     = 'E_SESSION_NOT_INTERACTIVE'
            exitCode = 1202
            detail   = "WTSConnectState is $ConnectState (ok=$ConnectOk; expected 0 WTSActive)."
        }
    }
    if (-not $InfoExOk -or $InfoExBytes -lt 20 -or $Level -ne 1 -or $SessionFlags -ne 1) {
        $flagDesc = switch ($SessionFlags) {
            0 { '0 (WTS_SESSIONSTATE_LOCK)' }
            -1 { '0xFFFFFFFF (WTS_SESSIONSTATE_UNKNOWN)' }
            default { "$SessionFlags" }
        }
        return [pscustomobject]@{
            ok       = $false
            code     = 'E_SESSION_NOT_INTERACTIVE'
            exitCode = 1202
            detail   = "WTSSessionInfoEx validation failed (ok=$InfoExOk, bytes=$InfoExBytes, level=$Level, sessionFlags=$flagDesc)."
        }
    }
    if (-not $InputDesktopOk -or $InputDesktopName -cne 'Default') {
        $errNote = if ($InputDesktopError -eq 5) {
            'ERROR_ACCESS_DENIED (5): input desktop is locked on Winlogon or another Secure Desktop'
        } else {
            "name='$InputDesktopName', err=$InputDesktopError"
        }
        return [pscustomobject]@{
            ok       = $false
            code     = 'E_SESSION_NOT_INTERACTIVE'
            exitCode = 1202
            detail   = "OpenInputDesktop check failed ($errNote)."
        }
    }

    return [pscustomobject]@{
        ok       = $true
        code     = 'OK'
        exitCode = 0
        detail   = 'Interactive WinSta0\Default unlocked.'
    }
}

function Test-RunnerPathSecurity {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$RunnerPath,
        [string[]]$TrustedOwnerSids = $script:ProductionTrustedAdminSids,
        [string[]]$TrustedWriteSids = $script:ProductionTrustedAdminSids,
        [string[]]$ProgramFilesDirs = @($env:ProgramFiles, ${env:ProgramFiles(x86)})
    )

    $fail = {
        param([string]$msg)
        return [pscustomobject]@{
            ok       = $false
            code     = 'E_RUNNER_INVALID'
            exitCode = 1204
            detail   = $msg
        }
    }

    if ([string]::IsNullOrWhiteSpace($RunnerPath)) {
        return (& $fail 'RunnerPath must not be empty.')
    }
    if ($RunnerPath.StartsWith('\\')) {
        return (& $fail "RunnerPath '$RunnerPath' must not be a UNC or device path.")
    }
    if ($RunnerPath -notmatch '^[A-Za-z]:\\') {
        return (& $fail "RunnerPath '$RunnerPath' must be an absolute local drive path (e.g. C:\...).")
    }
    if ($RunnerPath -cne $RunnerPath.TrimEnd(' ', '.')) {
        return (& $fail "RunnerPath '$RunnerPath' must not contain trailing spaces or dots.")
    }
    if ($RunnerPath.Length -gt 3 -and $RunnerPath.Substring(2).Contains('\\')) {
        return (& $fail "RunnerPath '$RunnerPath' must not contain redundant '\\' separators.")
    }
    if ($RunnerPath.Length -gt 2 -and $RunnerPath.Substring(2).Contains(':')) {
        return (& $fail "RunnerPath '$RunnerPath' must not contain extra ':' characters or alternate data stream suffixes.")
    }
    if ($RunnerPath.Contains('/')) {
        return (& $fail "RunnerPath '$RunnerPath' must use canonical backslashes only.")
    }
    if ($RunnerPath.Length -gt 3 -and $RunnerPath.EndsWith('\')) {
        return (& $fail "RunnerPath '$RunnerPath' must not end with a trailing backslash.")
    }

    $rawParts = $RunnerPath.Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($rawParts -contains '..' -or $rawParts -contains '.') {
        return (& $fail "RunnerPath '$RunnerPath' must not contain '.' or '..' traversal segments.")
    }
    foreach ($part in $rawParts) {
        if ($part -cne $part.TrimEnd(' ', '.')) {
            return (& $fail "RunnerPath '$RunnerPath' must not contain path segments with trailing spaces or dots.")
        }
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($RunnerPath).TrimEnd('\')
        $root = [System.IO.Path]::GetPathRoot($fullPath)
        if ($root -notmatch '^[A-Za-z]:\\$') {
            return (& $fail "Unsupported drive root '$root' for RunnerPath '$RunnerPath'.")
        }

        $driveInfo = New-Object System.IO.DriveInfo($root)
        if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network -or $driveInfo.DriveType -eq [System.IO.DriveType]::Unknown) {
            return (& $fail "RunnerPath '$RunnerPath' resides on disallowed drive type '$($driveInfo.DriveType)'.")
        }

        $segments = New-Object 'System.Collections.Generic.List[string]'
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

        if ($segments.Count -lt 2) {
            return (& $fail "RunnerPath '$RunnerPath' cannot be a drive root.")
        }

        $normProgramFiles = New-Object 'System.Collections.Generic.List[string]'
        foreach ($pf in $ProgramFilesDirs) {
            if (-not [string]::IsNullOrWhiteSpace($pf)) {
                $normProgramFiles.Add($pf.TrimEnd('\'))
            }
        }

        [int64]$dangerousMask = (
            [int64][System.Security.AccessControl.FileSystemRights]::WriteData -bor
            [int64][System.Security.AccessControl.FileSystemRights]::AppendData -bor
            [int64][System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
            [int64][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [int64][System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
            [int64][System.Security.AccessControl.FileSystemRights]::Delete -bor
            [int64][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [int64][System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
            [int64]0x02000000 -bor
            [int64]0x10000000 -bor
            [int64]0x40000000
        )

        $aclSections = [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Access

        for ($i = 0; $i -lt $segments.Count; $i++) {
            $seg = $segments[$i]
            $isRoot = ($i -eq 0)
            $isLeaf = ($i -eq ($segments.Count - 1))
            $isImmediateParent = ($i -eq ($segments.Count - 2))

            if ($isLeaf) {
                if (-not [System.IO.File]::Exists($seg)) {
                    return (& $fail "Runner file does not exist: '$seg'.")
                }
            } else {
                if (-not [System.IO.Directory]::Exists($seg)) {
                    return (& $fail "Runner ancestor directory does not exist: '$seg'.")
                }
            }

            $attrs = [System.IO.File]::GetAttributes($seg)
            if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return (& $fail "ReparsePoint detected at path segment '$seg'.")
            }

            $acl = if ($isLeaf) {
                [System.IO.File]::GetAccessControl($seg, $aclSections)
            } else {
                [System.IO.Directory]::GetAccessControl($seg, $aclSections)
            }

            $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if ($TrustedOwnerSids -notcontains $ownerSid) {
                return (& $fail "Untrusted owner SID '$ownerSid' on '$seg'.")
            }

            if ($isImmediateParent -and (-not $acl.AreAccessRulesProtected)) {
                return (& $fail "ACL inheritance must be disabled on immediate parent directory '$seg'.")
            }

            $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            foreach ($rule in $rules) {
                if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                    return (& $fail "Disallowed $($rule.AccessControlType) ACE for SID '$($rule.IdentityReference.Value)' on '$seg'.")
                }

                if ($isRoot -and ($segments.Count -gt 2)) {
                    continue
                }

                $sid = $rule.IdentityReference.Value
                if ($TrustedWriteSids -contains $sid) {
                    continue
                }

                $isIntermediate = (-not $isImmediateParent) -and (-not $isLeaf) -and (-not $isRoot)
                if ($isIntermediate -and $sid -eq 'S-1-3-0') {
                    $isInheritOnly = (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
                    if ($isInheritOnly -and ($normProgramFiles -contains $seg.TrimEnd('\'))) {
                        continue
                    }
                }

                [int64]$rightsVal = [int64]$rule.FileSystemRights
                if (($rightsVal -band $dangerousMask) -ne 0) {
                    return (& $fail "Non-admin write/ACL ACE for SID '$sid' ($($rule.FileSystemRights)) on '$seg'.")
                }
            }

            if ($isLeaf) {
                Initialize-PreflightNative
                if ([AgentElevation.PreflightNative]::HasZoneIdentifier($seg)) {
                    return (& $fail "Runner file '$seg' has blocked Zone.Identifier alternate data stream.")
                }
            }
        }
    } catch {
        return (& $fail "RunnerPath '$RunnerPath' validation error: $($_.Exception.Message)")
    }

    return [pscustomobject]@{
        ok       = $true
        code     = 'OK'
        exitCode = 0
        detail   = 'Runner path, ancestry, and raw-SID ACLs verified.'
    }
}

function Invoke-PreflightCheck {
    [CmdletBinding()]
    param(
        [string]$RunnerPath = 'C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1'
    )

    Initialize-PreflightNative

    $win32 = [AgentElevation.PreflightNative]::ProbeSessionState()
    $sessionRes = Evaluate-PreflightState `
        -SessionId $win32.SessionId `
        -WinSta $win32.WinSta `
        -ThreadDesktop $win32.ThreadDesktop `
        -ConnectOk $win32.ConnectOk `
        -ConnectState $win32.ConnectState `
        -InfoExOk $win32.InfoExOk `
        -InfoExBytes $win32.InfoExBytes `
        -Level $win32.Level `
        -SessionFlags $win32.SessionFlags `
        -InputDesktopOk $win32.InputDesktopOk `
        -InputDesktopName $win32.InputDesktopName `
        -InputDesktopError $win32.InputDesktopError

    if (-not $sessionRes.ok) {
        return $sessionRes
    }

    $aclRes = Test-RunnerPathSecurity -RunnerPath $RunnerPath
    if (-not $aclRes.ok) {
        return $aclRes
    }

    return [pscustomobject]@{
        ok       = $true
        code     = 'OK'
        exitCode = 0
        detail   = 'Interactive WinSta0\Default unlocked and runner ACL verified.'
    }
}

function Initialize-InteractiveBrokerTypes {
    [CmdletBinding()]
    param()

    Initialize-PreflightNative

    if ('AgentElevation.BrokerEngine' -as [type]) {
        return
    }

    $csharp = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace AgentElevation
{
    public enum DialogThemeMode
    {
        Light = 0,
        Dark = 1,
        HighContrast = 2
    }

    public sealed class DialogTheme
    {
        public DialogThemeMode Mode { get; private set; }
        public bool IsDark { get { return Mode == DialogThemeMode.Dark; } }
        public bool IsHighContrast { get { return Mode == DialogThemeMode.HighContrast; } }
        public bool UseDarkChrome { get { return Mode == DialogThemeMode.Dark; } }
        public bool UseFlatButtons { get { return Mode == DialogThemeMode.Dark; } }

        public Color FormBackColor { get; private set; }
        public Color FormForeColor { get; private set; }
        public Color MutedForeColor { get; private set; }
        public Color PreviewBackColor { get; private set; }
        public Color PreviewForeColor { get; private set; }
        public Color PreviewBorderColor { get; private set; }
        public Color ReasonAccentColor { get; private set; }
        public Color ReasonBannerBackColor { get; private set; }
        public Color ReasonCaptionForeColor { get; private set; }
        public Color ReasonTextForeColor { get; private set; }
        public Color TargetSignedForeColor { get; private set; }
        public Color TargetUnsignedForeColor { get; private set; }
        public Color ButtonBackColor { get; private set; }
        public Color ButtonForeColor { get; private set; }
        public Color ButtonBorderColor { get; private set; }
        public Color ButtonHoverBackColor { get; private set; }
        public Color ButtonDownBackColor { get; private set; }
        public Color ButtonDisabledBackColor { get; private set; }
        public Color ButtonDisabledBorderColor { get; private set; }
        public Color ButtonDisabledForeColor { get; private set; }

        private DialogTheme() { }

        public static bool TryParseDwmAccentAbgr(object rawValue, out Color color)
        {
            color = Color.Empty;
            if (rawValue == null) return false;

            uint abgr;
            if (rawValue is int)
            {
                abgr = unchecked((uint)(int)rawValue);
            }
            else if (rawValue is uint)
            {
                abgr = (uint)rawValue;
            }
            else if (rawValue is long)
            {
                abgr = unchecked((uint)(long)rawValue);
            }
            else if (rawValue is ulong)
            {
                abgr = unchecked((uint)(ulong)rawValue);
            }
            else
            {
                return false;
            }

            int r = (int)(abgr & 0xFFu);
            int g = (int)((abgr >> 8) & 0xFFu);
            int b = (int)((abgr >> 16) & 0xFFu);
            if (r == 0 && g == 0 && b == 0)
            {
                return false;
            }
            color = Color.FromArgb(r, g, b);
            return true;
        }

        public static DialogTheme Create(DialogThemeMode mode)
        {
            Color defaultAccent = (mode == DialogThemeMode.HighContrast)
                ? SystemColors.Highlight
                : (mode == DialogThemeMode.Dark ? Color.FromArgb(76, 194, 255) : Color.FromArgb(0, 122, 204));
            return CreateCore(mode, defaultAccent);
        }

        public static DialogTheme Create(DialogThemeMode mode, Color accentColor)
        {
            if (mode == DialogThemeMode.HighContrast)
            {
                return CreateCore(mode, SystemColors.Highlight);
            }
            Color fallback = (mode == DialogThemeMode.Dark) ? Color.FromArgb(76, 194, 255) : Color.FromArgb(0, 122, 204);
            Color effectiveAccent = (accentColor.IsEmpty || (accentColor.R == 0 && accentColor.G == 0 && accentColor.B == 0))
                ? fallback
                : Color.FromArgb(accentColor.R, accentColor.G, accentColor.B);
            return CreateCore(mode, effectiveAccent);
        }

        private static DialogTheme CreateCore(DialogThemeMode mode, Color accentColor)
        {
            DialogTheme t = new DialogTheme();
            t.Mode = mode;

            if (mode == DialogThemeMode.HighContrast)
            {
                t.FormBackColor = SystemColors.Control;
                t.FormForeColor = SystemColors.ControlText;
                t.MutedForeColor = SystemColors.ControlText;
                t.PreviewBackColor = SystemColors.Window;
                t.PreviewForeColor = SystemColors.WindowText;
                t.PreviewBorderColor = SystemColors.ControlDark;
                t.ReasonAccentColor = SystemColors.Highlight;
                t.ReasonBannerBackColor = SystemColors.Control;
                t.ReasonCaptionForeColor = SystemColors.ControlText;
                t.ReasonTextForeColor = SystemColors.ControlText;
                t.TargetSignedForeColor = SystemColors.ControlText;
                t.TargetUnsignedForeColor = SystemColors.ControlText;
                t.ButtonBackColor = SystemColors.Control;
                t.ButtonForeColor = SystemColors.ControlText;
                t.ButtonBorderColor = SystemColors.ControlDark;
                t.ButtonHoverBackColor = SystemColors.Control;
                t.ButtonDownBackColor = SystemColors.Control;
                t.ButtonDisabledBackColor = SystemColors.Control;
                t.ButtonDisabledBorderColor = SystemColors.ControlDark;
                t.ButtonDisabledForeColor = SystemColors.GrayText;
                return t;
            }

            if (mode == DialogThemeMode.Dark)
            {
                t.FormBackColor = Color.FromArgb(32, 32, 32);
                t.FormForeColor = Color.FromArgb(243, 243, 243);
                t.MutedForeColor = Color.FromArgb(176, 176, 176);
                t.PreviewBackColor = Color.FromArgb(26, 26, 26);
                t.PreviewForeColor = Color.FromArgb(243, 243, 243);
                t.PreviewBorderColor = Color.FromArgb(63, 63, 70);
                t.ReasonAccentColor = accentColor;
                t.ReasonBannerBackColor = Color.FromArgb(29, 39, 51);
                t.ReasonCaptionForeColor = Color.FromArgb(96, 205, 255);
                t.ReasonTextForeColor = Color.FromArgb(243, 243, 243);
                t.TargetSignedForeColor = Color.FromArgb(74, 222, 128);
                t.TargetUnsignedForeColor = Color.FromArgb(251, 191, 36);
                t.ButtonBackColor = Color.FromArgb(45, 45, 48);
                t.ButtonForeColor = Color.FromArgb(243, 243, 243);
                t.ButtonBorderColor = Color.FromArgb(72, 72, 77);
                t.ButtonHoverBackColor = Color.FromArgb(62, 62, 66);
                t.ButtonDownBackColor = Color.FromArgb(80, 80, 85);
                t.ButtonDisabledBackColor = Color.FromArgb(36, 36, 39);
                t.ButtonDisabledBorderColor = Color.FromArgb(60, 60, 64);
                t.ButtonDisabledForeColor = Color.FromArgb(148, 148, 156);
                return t;
            }

            t.FormBackColor = SystemColors.Control;
            t.FormForeColor = SystemColors.ControlText;
            t.MutedForeColor = SystemColors.ControlText;
            t.PreviewBackColor = SystemColors.Window;
            t.PreviewForeColor = SystemColors.WindowText;
            t.PreviewBorderColor = SystemColors.ControlDark;
            t.ReasonAccentColor = accentColor;
            t.ReasonBannerBackColor = Color.FromArgb(240, 246, 252);
            t.ReasonCaptionForeColor = Color.FromArgb(0, 95, 168);
            t.ReasonTextForeColor = SystemColors.ControlText;
            t.TargetSignedForeColor = Color.DarkGreen;
            t.TargetUnsignedForeColor = Color.DarkGoldenrod;
            t.ButtonBackColor = SystemColors.Control;
            t.ButtonForeColor = SystemColors.ControlText;
            t.ButtonBorderColor = SystemColors.ControlDark;
            t.ButtonHoverBackColor = SystemColors.Control;
            t.ButtonDownBackColor = SystemColors.Control;
            t.ButtonDisabledBackColor = SystemColors.Control;
            t.ButtonDisabledBorderColor = SystemColors.ControlDark;
            t.ButtonDisabledForeColor = SystemColors.GrayText;
            return t;
        }

        public static DialogTheme FromRegistryValues(bool isHighContrast, object appsUseLightThemeValue, object dwmAccentAbgrValue)
        {
            if (isHighContrast)
            {
                return Create(DialogThemeMode.HighContrast);
            }

            DialogThemeMode mode = DialogThemeMode.Light;
            if ((appsUseLightThemeValue is int && (int)appsUseLightThemeValue == 0) ||
                (appsUseLightThemeValue is uint && (uint)appsUseLightThemeValue == 0u) ||
                (appsUseLightThemeValue is long && (long)appsUseLightThemeValue == 0L))
            {
                mode = DialogThemeMode.Dark;
            }

            Color accent;
            if (TryParseDwmAccentAbgr(dwmAccentAbgrValue, out accent))
            {
                return Create(mode, accent);
            }
            return Create(mode);
        }

        public static DialogTheme ResolveSystem()
        {
            bool highContrast = false;
            try
            {
                highContrast = SystemInformation.HighContrast;
            }
            catch { }

            if (highContrast)
            {
                return Create(DialogThemeMode.HighContrast);
            }

            object appsUseLight = null;
            object dwmAccent = null;
            try
            {
                appsUseLight = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", null);
            }
            catch { }
            try
            {
                dwmAccent = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM", "AccentColor", null);
            }
            catch { }

            return FromRegistryValues(false, appsUseLight, dwmAccent);
        }
    }
    public sealed class NonOwningWaitHandle : WaitHandle
    {
        public NonOwningWaitHandle(IntPtr rawHandle)
        {
            this.SafeWaitHandle = new SafeWaitHandle(rawHandle, false);
        }
    }

    public static class PipeSecurityFactory
    {
        public const string ExpectedSddl = "D:P(D;;0x1f019f;;;NU)(A;;0x100000;;;OW)(A;;0x1f019f;;;SY)(A;;0x12019b;;;BA)";

        public static PipeSecurity CreateHardenedPipeSecurity()
        {
            PipeSecurity ps = new PipeSecurity();
            ps.SetAccessRuleProtection(true, false);

            SecurityIdentifier sidNetwork = new SecurityIdentifier("S-1-5-2");
            SecurityIdentifier sidOwnerRights = new SecurityIdentifier("S-1-3-4");
            SecurityIdentifier sidSystem = new SecurityIdentifier("S-1-5-18");
            SecurityIdentifier sidAdmins = new SecurityIdentifier("S-1-5-32-544");

            ps.AddAccessRule(new PipeAccessRule(sidNetwork, PipeAccessRights.FullControl, AccessControlType.Deny));
            ps.AddAccessRule(new PipeAccessRule(sidOwnerRights, PipeAccessRights.Synchronize, AccessControlType.Allow));
            ps.AddAccessRule(new PipeAccessRule(sidSystem, PipeAccessRights.FullControl, AccessControlType.Allow));
            ps.AddAccessRule(new PipeAccessRule(sidAdmins, PipeAccessRights.ReadWrite, AccessControlType.Allow));

            string sddl = ps.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            if (!string.Equals(sddl, ExpectedSddl, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Hardened PipeSecurity SDDL mismatch: " + sddl);
            }
            return ps;
        }

        public static NamedPipeServerStream CreateHardenedServer(string pipeName)
        {
            PipeSecurity ps = CreateHardenedPipeSecurity();
            return new NamedPipeServerStream(
                pipeName,
                PipeDirection.In,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                65536,
                0,
                ps);
        }
    }

    public sealed class BrokerRequestData
    {
        public string RequestId = string.Empty;
        public string RunnerPath = @"C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1";
        public string ManifestFile = string.Empty;
        public string ManifestSha256 = string.Empty;
        public bool NormalWindow = false;
        public int Click1TimeoutSeconds = 300;
        public string Reason = string.Empty;
        public string WorkDir = string.Empty;
        public string[] Args = new string[0];
        public string ScriptPreview = string.Empty;
        public bool ScriptTruncated = false;
        public bool HasTargetMeta = false;
        public string TargetPath = string.Empty;
        public string TargetSubsystem = string.Empty;
        public string TargetPublisher = string.Empty;
        public bool IsSubagent = false;
        public string AttributionRole = string.Empty;
        public string AttributionAgentLabel = string.Empty;
        public string Workspace = string.Empty;
        public string ConversationId = string.Empty;
        public string StepIndex = string.Empty;
        public string ToolCallId = string.Empty;
    }

    public sealed class BrokerEngine
    {
        private const int DECISION_NONE = 0;
        private const int DECISION_PROCEED = 1;
        private const int DECISION_DENY = 2;
        private const int DECISION_TIMEOUT = 3;
        private const int DECISION_CANCEL = 4;

        private const int SW_HIDE = 0;
        private const int SW_SHOWNORMAL = 1;
        private const int SW_RESTORE = 9;
        private const uint SEE_MASK_NOCLOSEPROCESS = 0x00000040;
        private const uint SEE_MASK_NOASYNC = 0x00000100;
        private const uint SEE_MASK_FLAG_NO_UI = 0x00000400;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const int ERROR_CANCELLED = 1223;
        private const int ASFW_ANY = -1;
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHELLEXECUTEINFOW
        {
            public int cbSize;
            public uint fMask;
            public IntPtr hwnd;
            public string lpVerb;
            public string lpFile;
            public string lpParameters;
            public string lpDirectory;
            public int nShow;
            public IntPtr hInstApp;
            public IntPtr lpIDList;
            public string lpClass;
            public IntPtr hkeyClass;
            public uint dwHotKey;
            public IntPtr hIconOrMonitor;
            public IntPtr hProcess;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessDpiAwarenessContext(IntPtr dpiContext);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool AllowSetForegroundWindow(int dwProcessId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern uint GetDpiForSystem();

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ShellExecuteExW(ref SHELLEXECUTEINFOW lpExecInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(
            IntPtr hProcess,
            out long lpCreationTime,
            out long lpExitTime,
            out long lpKernelTime,
            out long lpUserTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        private static extern int SetWindowTheme(IntPtr hwnd, string pszSubAppName, string pszSubIdList);

        private static void ApplyDarkTitleBar(Form form, DialogTheme theme)
        {
            if (form == null || theme == null || !theme.UseDarkChrome) return;
            form.HandleCreated += (s, e) =>
            {
                try
                {
                    if (form.IsDisposed) return;
                    int useDark = 1;
                    int hr = DwmSetWindowAttribute(form.Handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useDark, sizeof(int));
                    if (hr != 0)
                    {
                        DwmSetWindowAttribute(form.Handle, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, ref useDark, sizeof(int));
                    }
                }
                catch { }
            };
        }

        private static void ApplyDarkControlScrollbars(Control ctrl, DialogTheme theme)
        {
            if (ctrl == null || theme == null || !theme.UseDarkChrome) return;
            ctrl.HandleCreated += (s, e) =>
            {
                try
                {
                    if (!ctrl.IsDisposed)
                    {
                        SetWindowTheme(ctrl.Handle, "DarkMode_Explorer", null);
                    }
                }
                catch { }
            };
        }

        private static void ApplyThemedButton(Button btn, DialogTheme theme)
        {
            if (btn == null || theme == null) return;
            if (theme.UseFlatButtons)
            {
                btn.UseVisualStyleBackColor = false;
                btn.FlatStyle = FlatStyle.Flat;
                btn.BackColor = theme.ButtonBackColor;
                btn.ForeColor = theme.ButtonForeColor;
                btn.FlatAppearance.BorderSize = 1;
                btn.FlatAppearance.BorderColor = theme.ButtonBorderColor;
                btn.FlatAppearance.MouseOverBackColor = theme.ButtonHoverBackColor;
                btn.FlatAppearance.MouseDownBackColor = theme.ButtonDownBackColor;
                btn.Paint += (s, e) =>
                {
                    if (!btn.Enabled)
                    {
                        Rectangle rect = btn.ClientRectangle;
                        using (SolidBrush bgBrush = new SolidBrush(theme.ButtonDisabledBackColor))
                        {
                            e.Graphics.FillRectangle(bgBrush, rect);
                        }
                        if (rect.Width > 1 && rect.Height > 1)
                        {
                            using (Pen borderPen = new Pen(theme.ButtonDisabledBorderColor, 1F))
                            {
                                e.Graphics.DrawRectangle(borderPen, 0, 0, rect.Width - 1, rect.Height - 1);
                            }
                        }
                        TextFormatFlags flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.HidePrefix;
                        TextRenderer.DrawText(e.Graphics, btn.Text, btn.Font, rect, theme.ButtonDisabledForeColor, flags);
                    }
                };
            }
            else
            {
                btn.FlatStyle = FlatStyle.Standard;
                btn.UseVisualStyleBackColor = true;
            }
        }

        private static int _dpiInitialized = 0;

        private readonly Func<string, object[]> _preflightCallback;
        private readonly Func<BrokerRequestData, string, PipeSecurity, IntPtr, int> _customUacLauncher;

        private readonly ConcurrentQueue<Dictionary<string, object>> _workQueue =
            new ConcurrentQueue<Dictionary<string, object>>();
        private readonly AutoResetEvent _workEvent = new AutoResetEvent(false);
        private readonly ManualResetEventSlim _doneEvent = new ManualResetEventSlim(false);
        private readonly ManualResetEventSlim _shutdownOrEofEvent = new ManualResetEventSlim(false);
        private readonly ManualResetEventSlim _proceedSignal = new ManualResetEventSlim(false);
        private readonly ManualResetEventSlim _uacDoneEvent = new ManualResetEventSlim(true);
        private readonly ManualResetEventSlim _reminderClosedEvent = new ManualResetEventSlim(true);
        private readonly object _pipeLock = new object();
        private readonly object _formLock = new object();
        private IntPtr _proceedModalHwnd = IntPtr.Zero;
        private static readonly object _stdoutLock = new object();
        private static Stream _stdoutStream = null;
        private static readonly UTF8Encoding _utf8NoBom = new UTF8Encoding(false);
        private static readonly DateTime UnixEpochUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private NamedPipeServerStream _activePipe = null;
        private Form _click1Form = null;
        private Form _reminderForm = null;
        private Button _proceedButton = null;
        private Button _denyButton = null;
        private Label _statusLabel = null;
        private System.Windows.Forms.Timer _countdownTimer = null;
        private bool _allowClick1Close = false;
        private bool _click1ShownFired = false;

        private BrokerRequestData _activeRequest = null;
        private int _decisionState = DECISION_NONE;
        private int _proceedUiHandled = 0;
        private int _terminalEmitted = 0;
        private int _runnerConnected = 0;
        private int _cancelled = 0;
        private int _killed = 0;
        private int _shuttingDown = 0;
        private int _reminderOpen = 0;

        public BrokerEngine(
            Func<string, object[]> preflightCallback,
            Func<BrokerRequestData, string, PipeSecurity, IntPtr, int> customUacLauncher)
        {
            _preflightCallback = preflightCallback;
            _customUacLauncher = customUacLauncher;
        }

        public static void EnsureDpiAwareness()
        {
            if (Interlocked.CompareExchange(ref _dpiInitialized, 1, 0) == 0)
            {
                try { SetProcessDpiAwarenessContext(new IntPtr(-4)); } catch { }
                try { Application.EnableVisualStyles(); } catch { }
                try { Application.SetCompatibleTextRenderingDefault(false); } catch { }
            }
        }

        public static float GetSystemDpiScale()
        {
            try
            {
                uint dpi = GetDpiForSystem();
                if (dpi >= 96u)
                {
                    return dpi / 96.0F;
                }
            }
            catch { }
            try
            {
                using (Graphics g = Graphics.FromHwnd(IntPtr.Zero))
                {
                    if (g.DpiX >= 96.0F)
                    {
                        return g.DpiX / 96.0F;
                    }
                }
            }
            catch { }
            return 1.0F;
        }

        public static long GetUtcNowMs()
        {
            return (DateTime.UtcNow.Ticks - UnixEpochUtc.Ticks) / TimeSpan.TicksPerMillisecond;
        }

        private static int ScalePx(int px, float dpiScale)
        {
            if (px <= 0) return 0;
            float s = (dpiScale < 1.0F) ? 1.0F : dpiScale;
            return (int)Math.Ceiling(px * s);
        }

        public static long GetCurrentProcessCreationFileTime()
        {
            long c, e, k, u;
            if (!GetProcessTimes(GetCurrentProcess(), out c, out e, out k, out u))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcessTimes failed.");
            }
            return c;
        }

        public static string QuoteArg(string arg)
        {
            if (string.IsNullOrEmpty(arg)) return "\"\"";
            bool needs = false;
            for (int i = 0; i < arg.Length; i++)
            {
                char ch = arg[i];
                if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '"')
                {
                    needs = true;
                    break;
                }
            }
            if (!needs) return arg;
            StringBuilder sb = new StringBuilder();
            sb.Append('"');
            int bs = 0;
            for (int i = 0; i < arg.Length; i++)
            {
                char ch = arg[i];
                if (ch == '\\') { bs++; }
                else if (ch == '"')
                {
                    sb.Append('\\', bs * 2 + 1);
                    sb.Append('"');
                    bs = 0;
                }
                else
                {
                    if (bs > 0) { sb.Append('\\', bs); bs = 0; }
                    sb.Append(ch);
                }
            }
            if (bs > 0) sb.Append('\\', bs * 2);
            sb.Append('"');
            return sb.ToString();
        }

        public static void EmitJson(Dictionary<string, object> payload)
        {
            JavaScriptSerializer ser = new JavaScriptSerializer();
            ser.MaxJsonLength = 16777216;
            string line = ser.Serialize(payload);
            byte[] bytes = _utf8NoBom.GetBytes((line ?? string.Empty) + "\n");
            lock (_stdoutLock)
            {
                if (_stdoutStream == null)
                {
                    _stdoutStream = Console.OpenStandardOutput();
                }
                _stdoutStream.Write(bytes, 0, bytes.Length);
                _stdoutStream.Flush();
            }
        }

        private void EmitClick1Shown(string requestId, long? click1DeadlineAt)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["event"] = "click1_shown";
            if (!string.IsNullOrEmpty(requestId)) d["requestId"] = requestId;
            if (click1DeadlineAt.HasValue && click1DeadlineAt.Value > 0)
            {
                d["click1DeadlineAt"] = click1DeadlineAt.Value;
            }
            EmitJson(d);
        }

        private void EmitSimpleEvent(string ev, string requestId)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["event"] = ev;
            if (!string.IsNullOrEmpty(requestId)) d["requestId"] = requestId;
            EmitJson(d);
        }

        private bool TryClaimTerminal()
        {
            return Interlocked.CompareExchange(ref _terminalEmitted, 1, 0) == 0;
        }

        public void DisposeActivePipe()
        {
            NamedPipeServerStream pipe = null;
            lock (_pipeLock)
            {
                pipe = _activePipe;
                _activePipe = null;
            }
            if (pipe != null)
            {
                try { pipe.Dispose(); } catch { }
            }
        }

        private void CloseClick1FormAsync()
        {
            Form f;
            lock (_formLock) { f = _click1Form; }
            if (f != null && !f.IsDisposed && f.IsHandleCreated)
            {
                try
                {
                    f.BeginInvoke(new Action(() =>
                    {
                        _allowClick1Close = true;
                        if (_countdownTimer != null)
                        {
                            try { _countdownTimer.Stop(); } catch { }
                        }
                        if (!f.IsDisposed)
                        {
                            try { f.Close(); } catch { }
                        }
                    }));
                }
                catch { }
            }
        }

        private void CloseReminderFormAsync()
        {
            Form f;
            lock (_formLock) { f = _reminderForm; }
            if (f != null && !f.IsDisposed && f.IsHandleCreated)
            {
                try
                {
                    f.BeginInvoke(new Action(() =>
                    {
                        if (!f.IsDisposed)
                        {
                            try { f.Close(); } catch { }
                        }
                    }));
                }
                catch { }
            }
        }

        private void TriggerShutdown(bool isEof)
        {
            _shutdownOrEofEvent.Set();
            if (Interlocked.CompareExchange(ref _shuttingDown, 1, 0) != 0)
            {
                _workEvent.Set();
                return;
            }
            DisposeActivePipe();
            CloseClick1FormAsync();
            CloseReminderFormAsync();
            _doneEvent.Set();
            _workEvent.Set();
        }

        public void StartStdinReaderThread(TextReader customReader)
        {
            Thread t = new Thread(() =>
            {
                try
                {
                    TextReader reader = customReader ?? new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
                    JavaScriptSerializer ser = new JavaScriptSerializer();
                    ser.MaxJsonLength = 16777216;

                    while (true)
                    {
                        string line = reader.ReadLine();
                        if (line == null)
                        {
                            TriggerShutdown(true);
                            break;
                        }
                        string trimmed = line.Trim();
                        if (trimmed.Length == 0) continue;

                        Dictionary<string, object> msg = null;
                        try
                        {
                            msg = ser.DeserializeObject(trimmed) as Dictionary<string, object>;
                        }
                        catch
                        {
                            continue;
                        }
                        if (msg == null) continue;

                        string cmd = GetDictString(msg, "cmd");
                        HandleStdinCommand(cmd, msg);
                        if (Volatile.Read(ref _shuttingDown) != 0)
                        {
                            break;
                        }
                    }
                }
                catch
                {
                    TriggerShutdown(true);
                }
            });
            t.IsBackground = true;
            t.Name = "BrokerStdinReader";
            t.Start();
        }

        public void HandleStdinCommand(string cmd, Dictionary<string, object> msg)
        {
            string reqId = GetDictString(msg, "requestId");
            BrokerRequestData active = Volatile.Read(ref _activeRequest);
            switch (cmd)
            {
                case "shutdown":
                    TriggerShutdown(false);
                    break;

                case "start_request":
                {
                    BrokerRequestData parsed = ParseRequestData(msg);
                    Interlocked.CompareExchange(ref _activeRequest, parsed, null);
                    _workQueue.Enqueue(msg);
                    _workEvent.Set();
                    break;
                }

                case "show_reminder":
                    _workQueue.Enqueue(msg);
                    _workEvent.Set();
                    break;

                case "approve":
                    if (active != null && (string.IsNullOrEmpty(reqId) || string.Equals(reqId, active.RequestId, StringComparison.Ordinal)))
                    {
                        if (Interlocked.CompareExchange(ref _decisionState, DECISION_PROCEED, DECISION_NONE) == DECISION_NONE)
                        {
                            CloseWaitFormUpdateOnProceed(true);
                        }
                    }
                    break;

                case "deny":
                    if (active != null && (string.IsNullOrEmpty(reqId) || string.Equals(reqId, active.RequestId, StringComparison.Ordinal)))
                    {
                        if (Interlocked.CompareExchange(ref _decisionState, DECISION_DENY, DECISION_NONE) == DECISION_NONE)
                        {
                            EmitClick1Decision(active.RequestId, "deny");
                            CloseClick1FormAsync();
                        }
                    }
                    break;

                case "cancel":
                    if (active != null && (string.IsNullOrEmpty(reqId) || string.Equals(reqId, active.RequestId, StringComparison.Ordinal)))
                    {
                        Interlocked.Exchange(ref _cancelled, 1);
                        Interlocked.CompareExchange(ref _decisionState, DECISION_CANCEL, DECISION_NONE);
                        DisposeActivePipe();
                        if (TryClaimTerminal())
                        {
                            EmitSimpleEvent("cancelled", active.RequestId);
                        }
                        CloseClick1FormAsync();
                        _doneEvent.Set();
                    }
                    break;

                case "kill":
                    if (active != null && (string.IsNullOrEmpty(reqId) || string.Equals(reqId, active.RequestId, StringComparison.Ordinal)))
                    {
                        Interlocked.Exchange(ref _killed, 1);
                        DisposeActivePipe();
                        if (TryClaimTerminal())
                        {
                            EmitSimpleEvent("killed", active.RequestId);
                        }
                        CloseClick1FormAsync();
                        _doneEvent.Set();
                    }
                    break;
            }
        }

        private void CloseWaitFormUpdateOnProceed(bool fromSidePanel)
        {
            Form f;
            lock (_formLock) { f = _click1Form; }
            if (f != null && !f.IsDisposed && f.IsHandleCreated)
            {
                try
                {
                    f.BeginInvoke(new Action(() =>
                    {
                        if (!f.IsDisposed &&
                            _click1ShownFired &&
                            Volatile.Read(ref _shuttingDown) == 0 &&
                            Volatile.Read(ref _cancelled) == 0 &&
                            Interlocked.CompareExchange(ref _proceedUiHandled, 1, 0) == 0)
                        {
                            OnProceedWonOnUiThread(fromSidePanel);
                        }
                    }));
                }
                catch { }
            }
        }

        private void EmitClick1Decision(string requestId, string decision)
        {
            if (string.Equals(decision, "deny", StringComparison.Ordinal) ||
                string.Equals(decision, "timeout", StringComparison.Ordinal))
            {
                TryClaimTerminal();
            }
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["event"] = "click1_decision";
            d["requestId"] = requestId;
            d["decision"] = decision;
            EmitJson(d);
            if (!string.Equals(decision, "proceed", StringComparison.Ordinal))
            {
                _doneEvent.Set();
            }
        }

        public int RunMainLoop()
        {
            bool hasRequest = false;
            bool requestCompleted = false;
            bool preUacStarted = false;
            bool standaloneReminderStarted = false;
            bool standaloneReminderSkipped = false;
            BrokerRequestData activeReq = null;
            ManualResetEventSlim uiDone = new ManualResetEventSlim(false);

            while (Volatile.Read(ref _shuttingDown) == 0)
            {
                Dictionary<string, object> msg;
                while (Volatile.Read(ref _shuttingDown) == 0 && _workQueue.TryDequeue(out msg))
                {
                    string cmd = GetDictString(msg, "cmd");
                    if (cmd == "start_request" && !hasRequest)
                    {
                        hasRequest = true;
                        activeReq = Volatile.Read(ref _activeRequest) ?? ParseRequestData(msg);
                        Volatile.Write(ref _activeRequest, activeReq);
                        bool completedImmediately;
                        StartRequestInitialPhase(activeReq, uiDone, out completedImmediately);
                        if (completedImmediately)
                        {
                            requestCompleted = true;
                        }
                    }
                    else if (cmd == "show_reminder")
                    {
                        bool startedModal = StartShowReminderPhase(msg);
                        if (!hasRequest)
                        {
                            if (startedModal)
                            {
                                standaloneReminderStarted = true;
                            }
                            else if (Volatile.Read(ref _reminderOpen) == 0)
                            {
                                standaloneReminderSkipped = true;
                            }
                        }
                    }
                }

                if (Volatile.Read(ref _shuttingDown) != 0)
                {
                    break;
                }

                if (hasRequest && !requestCompleted && !preUacStarted && _proceedSignal.IsSet)
                {
                    preUacStarted = true;
                    LaunchPreUacAndBackgroundUac(activeReq);
                }

                if (hasRequest && !requestCompleted && _doneEvent.IsSet)
                {
                    bool isPreConnectCancel = (Volatile.Read(ref _cancelled) != 0 && Volatile.Read(ref _runnerConnected) == 0);
                    if (isPreConnectCancel)
                    {
                        if (!uiDone.IsSet) uiDone.Wait(250);
                        requestCompleted = true;
                    }
                    else if (!preUacStarted)
                    {
                        if (uiDone.IsSet)
                        {
                            requestCompleted = true;
                        }
                    }
                    else
                    {
                        if (_uacDoneEvent.IsSet && uiDone.IsSet)
                        {
                            requestCompleted = true;
                        }
                    }
                }

                if (requestCompleted)
                {
                    break;
                }

                if (!hasRequest)
                {
                    if (standaloneReminderStarted && _reminderClosedEvent.IsSet && Volatile.Read(ref _reminderOpen) == 0)
                    {
                        break;
                    }
                    if (!standaloneReminderStarted && standaloneReminderSkipped && Volatile.Read(ref _reminderOpen) == 0)
                    {
                        break;
                    }
                }

                List<WaitHandle> waits = new List<WaitHandle>(6);
                waits.Add(_workEvent);
                waits.Add(_shutdownOrEofEvent.WaitHandle);
                if (hasRequest && !requestCompleted)
                {
                    if (!preUacStarted && !_proceedSignal.IsSet) waits.Add(_proceedSignal.WaitHandle);
                    if (!uiDone.IsSet) waits.Add(uiDone.WaitHandle);
                    if (!_doneEvent.IsSet) waits.Add(_doneEvent.WaitHandle);
                    if (preUacStarted && !_uacDoneEvent.IsSet) waits.Add(_uacDoneEvent.WaitHandle);
                }
                else if (!hasRequest && standaloneReminderStarted && !_reminderClosedEvent.IsSet)
                {
                    waits.Add(_reminderClosedEvent.WaitHandle);
                }

                WaitHandle.WaitAny(waits.ToArray());
            }

            if (Volatile.Read(ref _shuttingDown) == 0)
            {
                // Brief grace so caller can send shutdown or close stdin without broken-pipe race
                _shutdownOrEofEvent.Wait(200);
            }
            lock (_stdoutLock)
            {
                if (_stdoutStream != null)
                {
                    try { _stdoutStream.Flush(); } catch { }
                }
            }
            return 0;
        }

        private object[] RunPreflight(string runnerPath)
        {
            try
            {
                object[] res = _preflightCallback(runnerPath);
                if (res != null && res.Length >= 4)
                {
                    return res;
                }
                return new object[] { false, "E_RUNNER_INVALID", 1204, "Preflight returned an invalid result." };
            }
            catch (Exception ex)
            {
                return new object[] { false, "E_RUNNER_INVALID", 1204, "Preflight check failed: " + ex.Message };
            }
        }

        private void EmitPreflightEvent(string requestId, object[] res)
        {
            bool ok = Convert.ToBoolean(res[0]);
            string code = Convert.ToString(res[1]) ?? string.Empty;
            int exitCode = Convert.ToInt32(res[2]);
            string detail = Convert.ToString(res[3]) ?? string.Empty;

            Dictionary<string, object> d = new Dictionary<string, object>();
            d["event"] = "preflight_result";
            d["requestId"] = requestId;
            d["ok"] = ok;
            d["code"] = code;
            d["exitCode"] = exitCode;
            d["detail"] = detail;
            EmitJson(d);
        }

        private bool StartShowReminderPhase(Dictionary<string, object> msg)
        {
            string activeSummary = GetDictString(msg, "activeSummary");
            int queueCount = GetDictInt(msg, "queueCount", 1);

            object[] pf = RunPreflight(null);
            bool ok = Convert.ToBoolean(pf[0]);
            string detail = Convert.ToString(pf[3]) ?? string.Empty;
            if (!ok)
            {
                Dictionary<string, object> skip = new Dictionary<string, object>();
                skip["event"] = "reminder_skipped";
                skip["detail"] = detail;
                EmitJson(skip);
                return false;
            }

            if (Interlocked.CompareExchange(ref _reminderOpen, 1, 0) != 0)
            {
                Dictionary<string, object> skip = new Dictionary<string, object>();
                skip["event"] = "reminder_skipped";
                skip["detail"] = "Reminder modal is already open.";
                EmitJson(skip);
                return false;
            }

            _reminderClosedEvent.Reset();
            Thread reminderThread = new Thread(() =>
            {
                Form rf = null;
                try
                {
                    if (Volatile.Read(ref _shuttingDown) != 0)
                    {
                        return;
                    }
                    EnsureDpiAwareness();
                    rf = BuildReminderForm(activeSummary, queueCount);
                    IntPtr createdHwnd = rf.Handle;
                    lock (_formLock)
                    {
                        if (Volatile.Read(ref _shuttingDown) != 0)
                        {
                            rf.Dispose();
                            rf = null;
                            return;
                        }
                        _reminderForm = rf;
                    }
                    // Consume any one-shot STARTUPINFO.wShowWindow (e.g. SW_HIDE from Node windowsHide:true)
                    // before Application.Run(rf) calls ShowWindow(Handle, SW_SHOWNORMAL).
                    ShowWindow(createdHwnd, SW_HIDE);
                    rf.Shown += (s, e) =>
                    {
                        if (Volatile.Read(ref _shuttingDown) != 0)
                        {
                            try { rf.Close(); } catch { }
                            return;
                        }
                        if (!IsWindowVisible(rf.Handle))
                        {
                            ShowWindow(rf.Handle, SW_SHOWNORMAL);
                        }
                        try
                        {
                            SetForegroundWindow(rf.Handle);
                            rf.Activate();
                        }
                        catch { }
                        EmitSimpleEvent("reminder_shown", null);
                    };
                    rf.FormClosed += (s, e) =>
                    {
                        Interlocked.Exchange(ref _reminderOpen, 0);
                        if (Volatile.Read(ref _shuttingDown) == 0)
                        {
                            EmitSimpleEvent("reminder_dismissed", null);
                        }
                    };
                    Application.Run(rf);
                }
                finally
                {
                    Interlocked.Exchange(ref _reminderOpen, 0);
                    lock (_formLock) { _reminderForm = null; }
                    if (rf != null && !rf.IsDisposed)
                    {
                        try { rf.Dispose(); } catch { }
                    }
                    _reminderClosedEvent.Set();
                }
            });
            reminderThread.IsBackground = true;
            reminderThread.SetApartmentState(ApartmentState.STA);
            reminderThread.Start();
            return true;
        }

        private void ProcessShowReminder(Dictionary<string, object> msg)
        {
            bool started = StartShowReminderPhase(msg);
            if (started)
            {
                while (!_reminderClosedEvent.Wait(100))
                {
                    if (Volatile.Read(ref _shuttingDown) != 0)
                    {
                        CloseReminderFormAsync();
                        _reminderClosedEvent.Wait(500);
                        break;
                    }
                }
            }
            if (Volatile.Read(ref _activeRequest) == null)
            {
                _doneEvent.Set();
            }
        }

        private void StartRequestInitialPhase(BrokerRequestData req, ManualResetEventSlim uiDone, out bool completedImmediately)
        {
            completedImmediately = false;
            int preDec = Volatile.Read(ref _decisionState);
            if (Volatile.Read(ref _shuttingDown) != 0 ||
                Volatile.Read(ref _cancelled) != 0 ||
                preDec == DECISION_DENY ||
                preDec == DECISION_CANCEL)
            {
                _doneEvent.Set();
                uiDone.Set();
                completedImmediately = true;
                return;
            }

            object[] pf = RunPreflight(req.RunnerPath);
            if (Volatile.Read(ref _shuttingDown) != 0 || Volatile.Read(ref _cancelled) != 0)
            {
                _doneEvent.Set();
                uiDone.Set();
                completedImmediately = true;
                return;
            }

            EmitPreflightEvent(req.RequestId, pf);
            if (!Convert.ToBoolean(pf[0]))
            {
                TryClaimTerminal();
                _doneEvent.Set();
                uiDone.Set();
                completedImmediately = true;
                return;
            }

            int afterPfDec = Volatile.Read(ref _decisionState);
            if (afterPfDec == DECISION_DENY ||
                afterPfDec == DECISION_CANCEL ||
                Volatile.Read(ref _cancelled) != 0 ||
                Volatile.Read(ref _shuttingDown) != 0)
            {
                _doneEvent.Set();
                uiDone.Set();
                completedImmediately = true;
                return;
            }

            _proceedSignal.Reset();
            _uacDoneEvent.Set();
            _proceedModalHwnd = IntPtr.Zero;
            _proceedUiHandled = 0;
            _click1ShownFired = false;

            Thread uiThread = new Thread(() =>
            {
                Form f = null;
                try
                {
                    int dec0 = Volatile.Read(ref _decisionState);
                    if (Volatile.Read(ref _shuttingDown) != 0 ||
                        Volatile.Read(ref _cancelled) != 0 ||
                        dec0 == DECISION_DENY ||
                        dec0 == DECISION_CANCEL ||
                        dec0 == DECISION_TIMEOUT)
                    {
                        return;
                    }
                    EnsureDpiAwareness();
                    f = BuildClick1Form(req);
                    IntPtr createdHwnd = f.Handle;
                    lock (_formLock)
                    {
                        int dec1 = Volatile.Read(ref _decisionState);
                        if (Volatile.Read(ref _shuttingDown) != 0 ||
                            Volatile.Read(ref _cancelled) != 0 ||
                            dec1 == DECISION_DENY ||
                            dec1 == DECISION_CANCEL ||
                            dec1 == DECISION_TIMEOUT)
                        {
                            _allowClick1Close = true;
                            f.Dispose();
                            f = null;
                            return;
                        }
                        _click1Form = f;
                    }
                    // Consume any one-shot STARTUPINFO.wShowWindow (e.g. SW_HIDE from Node windowsHide:true)
                    // before Application.Run(f) calls ShowWindow(Handle, SW_SHOWNORMAL).
                    ShowWindow(createdHwnd, SW_HIDE);
                    Application.Run(f);
                }
                finally
                {
                    lock (_formLock) { _click1Form = null; }
                    if (f != null && !f.IsDisposed)
                    {
                        try { f.Dispose(); } catch { }
                    }
                    if (!_proceedSignal.IsSet && !_doneEvent.IsSet)
                    {
                        if (Volatile.Read(ref _decisionState) == DECISION_NONE)
                        {
                            if (TryClaimTerminal())
                            {
                                EmitRunnerError(req.RequestId, "RUNNER_ERROR", "Click-1 UI exited unexpectedly.");
                            }
                        }
                        _doneEvent.Set();
                    }
                    uiDone.Set();
                }
            });
            uiThread.IsBackground = true;
            uiThread.SetApartmentState(ApartmentState.STA);
            uiThread.Start();
        }

        private void LaunchPreUacAndBackgroundUac(BrokerRequestData req)
        {
            // Run preflight re-check strictly on the PowerShell main thread (safe Runspace)
            try { AllowSetForegroundWindow(ASFW_ANY); } catch { }

            object[] pf2 = RunPreflight(req.RunnerPath);
            if (Volatile.Read(ref _cancelled) != 0 || Volatile.Read(ref _shuttingDown) != 0)
            {
                CloseClick1FormAsync();
                _doneEvent.Set();
                return;
            }

            EmitPreflightEvent(req.RequestId, pf2);
            if (!Convert.ToBoolean(pf2[0]) || Volatile.Read(ref _cancelled) != 0 || Volatile.Read(ref _shuttingDown) != 0)
            {
                TryClaimTerminal();
                CloseClick1FormAsync();
                _doneEvent.Set();
                return;
            }

            _uacDoneEvent.Reset();
            IntPtr hwndForUac = _proceedModalHwnd;

            if (_customUacLauncher != null)
            {
                string testPipe = "ag-elev-" + Guid.NewGuid().ToString("N");
                EmitUacStarted(req.RequestId, testPipe);
                Thread uacThread = new Thread(() =>
                {
                    System.Management.Automation.Runspaces.Runspace rs = null;
                    try
                    {
                        rs = System.Management.Automation.Runspaces.RunspaceFactory.CreateRunspace();
                        rs.Open();
                        System.Management.Automation.Runspaces.Runspace.DefaultRunspace = rs;
                        _customUacLauncher(req, testPipe, PipeSecurityFactory.CreateHardenedPipeSecurity(), hwndForUac);
                    }
                    catch (Exception ex)
                    {
                        if (Volatile.Read(ref _cancelled) == 0 && Volatile.Read(ref _shuttingDown) == 0)
                        {
                            if (TryClaimTerminal()) EmitRunnerError(req.RequestId, "RUNNER_ERROR", ex.Message);
                        }
                    }
                    finally
                    {
                        if (rs != null) { try { rs.Dispose(); } catch { } }
                        CloseClick1FormAsync();
                        _doneEvent.Set();
                        _uacDoneEvent.Set();
                    }
                });
                uacThread.IsBackground = true;
                uacThread.SetApartmentState(ApartmentState.STA);
                uacThread.Start();
            }
            else
            {
                Thread uacThread = new Thread(() =>
                {
                    try
                    {
                        RunUacAndPipeLifecycle(req, hwndForUac);
                    }
                    catch (Exception ex)
                    {
                        if (Volatile.Read(ref _cancelled) == 0 && Volatile.Read(ref _shuttingDown) == 0)
                        {
                            if (TryClaimTerminal()) EmitRunnerError(req.RequestId, "RUNNER_ERROR", ex.Message);
                        }
                        CloseClick1FormAsync();
                        _doneEvent.Set();
                    }
                    finally
                    {
                        _uacDoneEvent.Set();
                    }
                });
                uacThread.IsBackground = true;
                uacThread.SetApartmentState(ApartmentState.STA);
                uacThread.Start();
            }
        }

        private static void SendWinRtToastBestEffort(string reason)
        {
            try
            {
                Type tXml = Type.GetType("Windows.Data.Xml.Dom.XmlDocument, Windows, ContentType=WindowsRuntime");
                Type tMgr = Type.GetType("Windows.UI.Notifications.ToastNotificationManager, Windows, ContentType=WindowsRuntime");
                Type tNotif = Type.GetType("Windows.UI.Notifications.ToastNotification, Windows, ContentType=WindowsRuntime");
                if (tXml == null || tMgr == null || tNotif == null) return;

                string title = System.Security.SecurityElement.Escape("Elevation Request Approved — Windows UAC Ready");
                string bodyRaw = string.IsNullOrEmpty(reason)
                    ? "Windows UAC approval prompt is ready on your desktop."
                    : "Windows UAC approval prompt is ready (" + reason + ").";
                string body = System.Security.SecurityElement.Escape(bodyRaw);
                string xml = "<toast><visual><binding template='ToastGeneric'><text>" + title + "</text><text>" + body + "</text></binding></visual></toast>";

                object doc = Activator.CreateInstance(tXml);
                System.Reflection.MethodInfo mLoad = tXml.GetMethod("LoadXml", new Type[] { typeof(string) });
                if (mLoad == null) return;
                mLoad.Invoke(doc, new object[] { xml });

                object toast = Activator.CreateInstance(tNotif, new object[] { doc });
                System.Reflection.MethodInfo mCreate = tMgr.GetMethod("CreateToastNotifier", new Type[] { typeof(string) });
                if (mCreate == null) return;
                object notifier = mCreate.Invoke(null, new object[] { "electron.app.Antigravity" });
                if (notifier == null) return;
                System.Reflection.MethodInfo mShow = notifier.GetType().GetMethod("Show", new Type[] { tNotif });
                if (mShow != null) mShow.Invoke(notifier, new object[] { toast });
            }
            catch { }
        }

        private void OnProceedWonOnUiThread(bool fromSidePanel)
        {
            if (_countdownTimer != null)
            {
                try { _countdownTimer.Stop(); } catch { }
            }
            if (_proceedButton != null) _proceedButton.Enabled = false;
            if (_denyButton != null) _denyButton.Enabled = false;
            if (_statusLabel != null) _statusLabel.Text = "Waiting for Windows UAC...";

            Form f;
            lock (_formLock) { f = _click1Form; }
            IntPtr modalHwnd = IntPtr.Zero;
            if (f != null && !f.IsDisposed)
            {
                modalHwnd = f.Handle;
                f.TopMost = false;
                if (fromSidePanel)
                {
                    try
                    {
                        if (IsIconic(modalHwnd)) ShowWindow(modalHwnd, SW_RESTORE);
                        SetForegroundWindow(modalHwnd);
                        f.Activate();
                    }
                    catch { }
                }
            }

            if (fromSidePanel && _activeRequest != null)
            {
                string rsn = _activeRequest.Reason;
                Thread toastThread = new Thread(() =>
                {
                    SendWinRtToastBestEffort(rsn);
                });
                toastThread.IsBackground = true;
                toastThread.Start();
            }

            EmitClick1Decision(_activeRequest.RequestId, "proceed");

            // Signal the main PowerShell thread to run pre-flight re-check and spawn STA UAC/Pipe thread
            _proceedModalHwnd = modalHwnd;
            _proceedSignal.Set();
        }

        private void RunUacAndPipeLifecycle(BrokerRequestData req, IntPtr modalHwnd)
        {
            if (Volatile.Read(ref _cancelled) != 0 || Volatile.Read(ref _shuttingDown) != 0)
            {
                CloseClick1FormAsync();
                _doneEvent.Set();
                return;
            }

            string pipeName = "ag-elev-" + Guid.NewGuid().ToString("N");
            NamedPipeServerStream pipeServer = null;
            IntPtr hProcess = IntPtr.Zero;

            try
            {
                pipeServer = PipeSecurityFactory.CreateHardenedServer(pipeName);
                lock (_pipeLock)
                {
                    if (Volatile.Read(ref _cancelled) != 0 || Volatile.Read(ref _shuttingDown) != 0)
                    {
                        pipeServer.Dispose();
                        pipeServer = null;
                        CloseClick1FormAsync();
                        _doneEvent.Set();
                        return;
                    }
                    _activePipe = pipeServer;
                }

                EmitUacStarted(req.RequestId, pipeName);

                int callerPid = Process.GetCurrentProcess().Id;
                long callerStart = GetCurrentProcessCreationFileTime();
                string psExe = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
                string parameters = string.Format(
                    CultureInfo.InvariantCulture,
                    "-NoProfile -InputFormat None -OutputFormat Text -ExecutionPolicy Bypass -File {0} -PipeName {1} -CallerPid {2} -CallerStart {3} -ManifestFile {4} -ManifestSha256 {5}",
                    QuoteArg(req.RunnerPath),
                    QuoteArg(pipeName),
                    callerPid,
                    callerStart,
                    QuoteArg(req.ManifestFile),
                    QuoteArg(req.ManifestSha256));

                SHELLEXECUTEINFOW sei = new SHELLEXECUTEINFOW();
                sei.cbSize = Marshal.SizeOf(typeof(SHELLEXECUTEINFOW));
                sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
                sei.hwnd = modalHwnd;
                sei.lpVerb = "runas";
                sei.lpFile = psExe;
                sei.lpParameters = parameters;
                sei.lpDirectory = Environment.SystemDirectory;
                sei.nShow = req.NormalWindow ? 1 : 7;

                bool launched = ShellExecuteExW(ref sei);
                hProcess = sei.hProcess;

                if (!launched)
                {
                    int winErr = Marshal.GetLastWin32Error();
                    DisposeActivePipe();
                    if (Volatile.Read(ref _cancelled) == 0 && Volatile.Read(ref _shuttingDown) == 0)
                    {
                        if (winErr == ERROR_CANCELLED)
                        {
                            if (TryClaimTerminal()) EmitSimpleEvent("uac_denied", req.RequestId);
                        }
                        else
                        {
                            if (TryClaimTerminal()) EmitRunnerError(req.RequestId, "RUNNER_ERROR", "ShellExecuteExW failed with Win32 error " + winErr);
                        }
                    }
                    CloseClick1FormAsync();
                    _doneEvent.Set();
                    return;
                }

                // Race WaitForConnectionAsync ONLY against sei.hProcess pre-connect exit (or cancel disposal)
                Task connectTask = pipeServer.WaitForConnectionAsync();
                bool connected = false;
                bool preconnectExited = false;

                if (hProcess != IntPtr.Zero)
                {
                    TaskCompletionSource<bool> procExitedTcs = new TaskCompletionSource<bool>();
                    NonOwningWaitHandle waitHandle = new NonOwningWaitHandle(hProcess);
                    RegisteredWaitHandle reg = null;
                    try
                    {
                        reg = ThreadPool.RegisterWaitForSingleObject(
                            waitHandle,
                            (state, timedOut) => procExitedTcs.TrySetResult(true),
                            null,
                            Timeout.Infinite,
                            true);

                        Task winner = Task.WhenAny(connectTask, procExitedTcs.Task).GetAwaiter().GetResult();
                        if (winner == connectTask)
                        {
                            try
                            {
                                connectTask.GetAwaiter().GetResult();
                                connected = pipeServer.IsConnected;
                            }
                            catch
                            {
                                connected = false;
                            }
                        }
                        else
                        {
                            // Process exited; allow tiny grace in case connect completed concurrently
                            try
                            {
                                if (connectTask.Wait(50))
                                {
                                    connected = pipeServer.IsConnected;
                                }
                                else
                                {
                                    preconnectExited = true;
                                }
                            }
                            catch
                            {
                                connected = false;
                            }
                        }
                    }
                    finally
                    {
                        if (reg != null) try { reg.Unregister(null); } catch { }
                        waitHandle.Dispose();
                    }
                }
                else
                {
                    try
                    {
                        connectTask.GetAwaiter().GetResult();
                        connected = pipeServer.IsConnected;
                    }
                    catch
                    {
                        connected = false;
                    }
                }

                if (!connected)
                {
                    DisposeActivePipe();
                    if (preconnectExited && Volatile.Read(ref _cancelled) == 0 && Volatile.Read(ref _shuttingDown) == 0)
                    {
                        int preCode = 1204;
                        if (hProcess != IntPtr.Zero)
                        {
                            uint rawExit = 0;
                            if (GetExitCodeProcess(hProcess, out rawExit))
                            {
                                preCode = unchecked((int)rawExit);
                            }
                        }
                        if (TryClaimTerminal())
                        {
                            Dictionary<string, object> d = new Dictionary<string, object>();
                            d["event"] = "runner_preconnect_exit";
                            d["requestId"] = req.RequestId;
                            d["exitCode"] = preCode;
                            EmitJson(d);
                        }
                    }
                    CloseClick1FormAsync();
                    _doneEvent.Set();
                    return;
                }

                Interlocked.Exchange(ref _runnerConnected, 1);
                EmitSimpleEvent("runner_connected", req.RequestId);
                CloseClick1FormAsync();

                PumpPipeStreamToEof(pipeServer, req.RequestId, hProcess);
            }
            finally
            {
                DisposeActivePipe();
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
                CloseClick1FormAsync();
                _doneEvent.Set();
            }
        }

        private void EmitUacStarted(string requestId, string pipeName)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["event"] = "uac_started";
            d["requestId"] = requestId;
            d["pipeName"] = pipeName;
            EmitJson(d);
        }

        private void EmitRunnerError(string requestId, string code, string detail)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["event"] = "runner_error";
            d["requestId"] = requestId;
            d["code"] = code;
            d["detail"] = detail;
            EmitJson(d);
        }

        public int PumpPipeStreamToEof(Stream pipeStream, string requestId, IntPtr hProcess)
        {
            bool hasFrameExit = false;
            int frameExitCode = 0;
            bool hasErrorFrame = false;
            string errorCode = string.Empty;
            bool pipeBroken = false;

            byte[] hdr = new byte[5];
            try
            {
                while (true)
                {
                    int hdrRead = ReadExactOrEofAsync(pipeStream, hdr, 0, 5).GetAwaiter().GetResult();
                    if (hdrRead == 0)
                    {
                        break; // Clean EOF
                    }
                    if (hdrRead < 5)
                    {
                        break; // Truncated header on EOF
                    }

                    byte frameType = hdr[0];
                    uint payloadLenU = (uint)hdr[1]
                        | ((uint)hdr[2] << 8)
                        | ((uint)hdr[3] << 16)
                        | ((uint)hdr[4] << 24);

                    if (payloadLenU > 16777216u)
                    {
                        throw new InvalidDataException("Frame payload length exceeds 16 MiB: " + payloadLenU);
                    }

                    int payloadLen = unchecked((int)payloadLenU);
                    byte[] payload = (payloadLen > 0) ? new byte[payloadLen] : new byte[0];
                    if (payloadLen > 0)
                    {
                        int bodyRead = ReadExactOrEofAsync(pipeStream, payload, 0, payloadLen).GetAwaiter().GetResult();
                        if (bodyRead < payloadLen)
                        {
                            break; // Unexpected EOF mid-frame
                        }
                    }

                    switch (frameType)
                    {
                        case 0:
                            // Heartbeat
                            break;
                        case 1:
                            {
                                string txt = Encoding.UTF8.GetString(payload);
                                Dictionary<string, object> d = new Dictionary<string, object>();
                                d["event"] = "stdout";
                                d["requestId"] = requestId;
                                d["text"] = txt;
                                EmitJson(d);
                                break;
                            }
                        case 2:
                            {
                                string txt = Encoding.UTF8.GetString(payload);
                                Dictionary<string, object> d = new Dictionary<string, object>();
                                d["event"] = "stderr";
                                d["requestId"] = requestId;
                                d["text"] = txt;
                                EmitJson(d);
                                break;
                            }
                        case 3:
                            if (payloadLen >= 4)
                            {
                                uint u = (uint)payload[0]
                                    | ((uint)payload[1] << 8)
                                    | ((uint)payload[2] << 16)
                                    | ((uint)payload[3] << 24);
                                frameExitCode = unchecked((int)u);
                                hasFrameExit = true;
                            }
                            break;
                        case 4:
                            {
                                string rawErr = Encoding.UTF8.GetString(payload);
                                string eCode = "RUNNER_ERROR";
                                string eDetail = rawErr;
                                if (rawErr.StartsWith("SHA256_MISMATCH:", StringComparison.Ordinal))
                                {
                                    eCode = "SHA256_MISMATCH";
                                    eDetail = rawErr.Substring("SHA256_MISMATCH:".Length);
                                }
                                else if (rawErr.StartsWith("RUNNER_ERROR:", StringComparison.Ordinal))
                                {
                                    eCode = "RUNNER_ERROR";
                                    eDetail = rawErr.Substring("RUNNER_ERROR:".Length);
                                }
                                hasErrorFrame = true;
                                errorCode = eCode;
                                EmitRunnerError(requestId, eCode, eDetail);
                                break;
                            }
                    }
                }
            }
            catch (IOException)
            {
                pipeBroken = true;
            }
            catch (ObjectDisposedException)
            {
                pipeBroken = true;
            }

            if (Volatile.Read(ref _killed) != 0 || Volatile.Read(ref _cancelled) != 0 || Volatile.Read(ref _shuttingDown) != 0)
            {
                return (Volatile.Read(ref _killed) != 0) ? 1207 : 1201;
            }

            bool hasProcExit = false;
            int procExit = 0;
            if (hProcess != IntPtr.Zero)
            {
                WaitForSingleObject(hProcess, 10000);
                uint rawProcExit = 0;
                if (GetExitCodeProcess(hProcess, out rawProcExit))
                {
                    procExit = unchecked((int)rawProcExit);
                    hasProcExit = true;
                }
            }

            int finalExit;
            if (hasFrameExit)
            {
                finalExit = frameExitCode;
            }
            else if (hasErrorFrame)
            {
                if (string.Equals(errorCode, "SHA256_MISMATCH", StringComparison.Ordinal))
                {
                    finalExit = 1205;
                }
                else if (hasProcExit)
                {
                    finalExit = procExit;
                }
                else
                {
                    finalExit = 1204;
                }
            }
            else if (hasProcExit)
            {
                finalExit = procExit;
            }
            else
            {
                finalExit = pipeBroken ? 1204 : 0;
            }

            if (TryClaimTerminal())
            {
                Dictionary<string, object> ex = new Dictionary<string, object>();
                ex["event"] = "exit";
                ex["requestId"] = requestId;
                ex["exitCode"] = finalExit;
                EmitJson(ex);
            }
            return finalExit;
        }

        private static async Task<int> ReadExactOrEofAsync(Stream s, byte[] buf, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int n = await s.ReadAsync(buf, offset + total, count - total).ConfigureAwait(false);
                if (n <= 0)
                {
                    return total;
                }
                total += n;
            }
            return total;
        }

        public static string FormatSha256Grouped(string sha)
        {
            if (string.IsNullOrEmpty(sha)) return string.Empty;
            StringBuilder sb = new StringBuilder(sha.Length + 16);
            for (int i = 0; i < sha.Length; i++)
            {
                if (i > 0 && (i % 4) == 0) sb.Append(' ');
                sb.Append(sha[i]);
            }
            return sb.ToString();
        }

        public static string BuildAttributionLine(BrokerRequestData req)
        {
            string actor;
            if (req.IsSubagent)
            {
                actor = string.IsNullOrEmpty(req.AttributionRole) ? "Subagent" : "Subagent (" + req.AttributionRole + ")";
            }
            else if (!string.IsNullOrEmpty(req.AttributionAgentLabel))
            {
                actor = req.AttributionAgentLabel;
            }
            else
            {
                actor = "Main Agent";
            }
            List<string> meta = new List<string>();
            if (!string.IsNullOrEmpty(req.ConversationId)) meta.Add("conv " + req.ConversationId);
            if (!string.IsNullOrEmpty(req.StepIndex)) meta.Add("step " + req.StepIndex);
            if (!string.IsNullOrEmpty(req.ToolCallId)) meta.Add("tool " + req.ToolCallId);
            string metaStr = (meta.Count > 0) ? " (" + string.Join(", ", meta.ToArray()) + ")" : string.Empty;
            string wsStr = string.IsNullOrEmpty(req.Workspace) ? string.Empty : " from workspace '" + req.Workspace + "'";
            return actor + wsStr + metaStr + " wants to execute elevated:";
        }

        public Form BuildClick1Form(BrokerRequestData req)
        {
            return BuildClick1FormWithScale(req, GetSystemDpiScale(), null);
        }

        public Form BuildClick1Form(BrokerRequestData req, DialogTheme theme)
        {
            return BuildClick1FormWithScale(req, GetSystemDpiScale(), theme);
        }

        public Form BuildClick1FormWithScale(BrokerRequestData req, float dpiScale)
        {
            return BuildClick1FormWithScale(req, dpiScale, null);
        }

        public Form BuildClick1FormWithScale(BrokerRequestData req, float dpiScale, DialogTheme theme)
        {
            DialogTheme effectiveTheme = theme ?? DialogTheme.ResolveSystem();
            float effectiveScale = (dpiScale < 1.0F) ? 1.0F : dpiScale;
            Func<int, int> S = delegate(int px) { return ScalePx(px, effectiveScale); };

            _allowClick1Close = false;
            _countdownTimer = null;

            Form form = new Form();
            form.SuspendLayout();
            form.Name = "Click1Form";
            form.Text = "Elevation Request — Google Antigravity";
            form.TopMost = true;
            form.AutoScaleMode = AutoScaleMode.None;
            form.StartPosition = FormStartPosition.CenterScreen;
            form.MinimumSize = new Size(S(680), S(560));
            form.MinimizeBox = false;
            form.ShowInTaskbar = true;
            form.Font = new Font("Segoe UI", 9.5F, FontStyle.Regular);
            form.BackColor = effectiveTheme.FormBackColor;
            form.ForeColor = effectiveTheme.FormForeColor;
            ApplyDarkTitleBar(form, effectiveTheme);

            TableLayoutPanel root = new TableLayoutPanel();
            root.SuspendLayout();
            root.Name = "root";
            root.Dock = DockStyle.Fill;
            root.Padding = new Padding(S(14));
            root.ColumnCount = 1;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            root.RowCount = 5;
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 0: topScrollHost (Header + Attribution + ReasonBanner + Meta)
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 1: Preview label
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F)); // 2: Script preview box
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 3: Status + Countdown
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 4: Buttons

            Panel topScrollHost = new Panel();
            topScrollHost.SuspendLayout();
            topScrollHost.Name = "topScrollHost";
            topScrollHost.Dock = DockStyle.Fill;
            topScrollHost.AutoSize = true;
            topScrollHost.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            topScrollHost.Margin = new Padding(0);
            ApplyDarkControlScrollbars(topScrollHost, effectiveTheme);

            TableLayoutPanel topPanel = new TableLayoutPanel();
            topPanel.SuspendLayout();
            topPanel.Name = "topPanel";
            topPanel.Dock = DockStyle.Top;
            topPanel.AutoSize = true;
            topPanel.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            topPanel.Margin = new Padding(0);
            topPanel.ColumnCount = 1;
            topPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            topPanel.RowCount = 4;
            topPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 0: lblHeader
            topPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 1: lblAttr
            topPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 2: reasonBanner
            topPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 3: metaPanel

            Label lblHeader = new Label();
            lblHeader.UseCompatibleTextRendering = false;
            lblHeader.Name = "lblHeader";
            lblHeader.Text = "Elevation Request — Google Antigravity";
            lblHeader.Font = new Font("Segoe UI", 12F, FontStyle.Bold);
            lblHeader.ForeColor = effectiveTheme.FormForeColor;
            lblHeader.AutoSize = true;
            lblHeader.Margin = new Padding(0, 0, 0, S(6));
            topPanel.Controls.Add(lblHeader, 0, 0);

            Label lblAttr = new Label();
            lblAttr.UseCompatibleTextRendering = false;
            lblAttr.Name = "lblAttr";
            lblAttr.Text = BuildAttributionLine(req);
            lblAttr.ForeColor = effectiveTheme.MutedForeColor;
            lblAttr.AutoSize = true;
            lblAttr.MaximumSize = new Size(S(730), 0);
            lblAttr.Margin = new Padding(0, 0, 0, S(8));
            topPanel.Controls.Add(lblAttr, 0, 1);

            TableLayoutPanel reasonBanner = new TableLayoutPanel();
            reasonBanner.SuspendLayout();
            reasonBanner.Name = "reasonBanner";
            reasonBanner.Dock = DockStyle.Top;
            reasonBanner.AutoSize = true;
            reasonBanner.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            reasonBanner.Margin = new Padding(0, 0, 0, S(10));
            reasonBanner.Padding = new Padding(0);
            reasonBanner.CellBorderStyle = TableLayoutPanelCellBorderStyle.None;
            reasonBanner.ColumnCount = 2;
            reasonBanner.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, S(4)));
            reasonBanner.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            reasonBanner.RowCount = 1;
            reasonBanner.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            Panel reasonAccent = new Panel();
            reasonAccent.Name = "reasonAccent";
            reasonAccent.Dock = DockStyle.Fill;
            reasonAccent.BackColor = effectiveTheme.ReasonAccentColor;
            reasonAccent.Margin = new Padding(0);
            reasonBanner.Controls.Add(reasonAccent, 0, 0);

            TableLayoutPanel reasonContent = new TableLayoutPanel();
            reasonContent.SuspendLayout();
            reasonContent.Name = "reasonContent";
            reasonContent.Dock = DockStyle.Fill;
            reasonContent.AutoSize = true;
            reasonContent.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            reasonContent.BackColor = effectiveTheme.ReasonBannerBackColor;
            reasonContent.Padding = new Padding(S(10), S(8), S(10), S(8));
            reasonContent.Margin = new Padding(0);
            reasonContent.ColumnCount = 1;
            reasonContent.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            reasonContent.RowCount = 2;
            reasonContent.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            reasonContent.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            Label lblReasonCaption = new Label();
            lblReasonCaption.UseCompatibleTextRendering = false;
            lblReasonCaption.Name = "lblReasonCaption";
            lblReasonCaption.Text = "REASON FOR ELEVATION";
            lblReasonCaption.Font = new Font("Segoe UI", 8F, FontStyle.Bold);
            lblReasonCaption.ForeColor = effectiveTheme.ReasonCaptionForeColor;
            lblReasonCaption.AutoSize = true;
            lblReasonCaption.Margin = new Padding(0, 0, 0, S(2));
            reasonContent.Controls.Add(lblReasonCaption, 0, 0);

            Label lblReason = new Label();
            lblReason.UseCompatibleTextRendering = false;
            lblReason.Name = "lblReason";
            lblReason.Text = string.IsNullOrEmpty(req.Reason) ? "(none)" : req.Reason;
            lblReason.Font = new Font("Segoe UI", 10.5F, FontStyle.Bold);
            lblReason.ForeColor = effectiveTheme.ReasonTextForeColor;
            lblReason.AutoSize = true;
            lblReason.MaximumSize = new Size(S(700), 0);
            lblReason.Margin = new Padding(0);
            reasonContent.Controls.Add(lblReason, 0, 1);

            reasonBanner.Controls.Add(reasonContent, 1, 0);
            topPanel.Controls.Add(reasonBanner, 0, 2);

            TableLayoutPanel metaPanel = new TableLayoutPanel();
            metaPanel.SuspendLayout();
            metaPanel.Name = "metaPanel";
            metaPanel.Dock = DockStyle.Top;
            metaPanel.AutoSize = true;
            metaPanel.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            metaPanel.Margin = new Padding(0);
            metaPanel.ColumnCount = 2;
            metaPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            metaPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

            List<Label> metaKeyLabels = new List<Label>();
            List<Label> metaValLabels = new List<Label>();
            int rowIdx = 0;

            Label lblWorkDirKey;
            Label lblWorkDirVal = AddMetaRow(metaPanel, rowIdx++, "WorkDir:", string.IsNullOrEmpty(req.WorkDir) ? "(default)" : req.WorkDir, false, effectiveScale, effectiveTheme, out lblWorkDirKey);
            metaKeyLabels.Add(lblWorkDirKey);
            metaValLabels.Add(lblWorkDirVal);

            string argsText = (req.Args != null && req.Args.Length > 0) ? string.Join(" ", req.Args) : "(none)";
            Label lblArgsKey;
            Label lblArgsVal = AddMetaRow(metaPanel, rowIdx++, "Args:", argsText, false, effectiveScale, effectiveTheme, out lblArgsKey);
            metaKeyLabels.Add(lblArgsKey);
            metaValLabels.Add(lblArgsVal);

            if (req.HasTargetMeta)
            {
                string pub = string.IsNullOrEmpty(req.TargetPublisher) ? "Unsigned / Unknown" : req.TargetPublisher;
                string sub = string.IsNullOrEmpty(req.TargetSubsystem) ? "" : " [" + req.TargetSubsystem + "]";
                string badgeText = string.Format("{0}{1} — Publisher: {2}", req.TargetPath, sub, pub);
                Label lblTargetKey;
                Label lblBadge = AddMetaRow(metaPanel, rowIdx++, "Target:", badgeText, true, effectiveScale, effectiveTheme, out lblTargetKey);
                lblBadge.ForeColor = string.IsNullOrEmpty(req.TargetPublisher) ? effectiveTheme.TargetUnsignedForeColor : effectiveTheme.TargetSignedForeColor;
                metaKeyLabels.Add(lblTargetKey);
                metaValLabels.Add(lblBadge);
            }

            Label lblShaKey;
            Label lblSha = AddMetaRow(metaPanel, rowIdx++, "ManifestSha256:", FormatSha256Grouped(req.ManifestSha256), false, effectiveScale, effectiveTheme, out lblShaKey);
            lblSha.Font = new Font("Consolas", 9F, FontStyle.Regular);
            metaKeyLabels.Add(lblShaKey);
            metaValLabels.Add(lblSha);

            int metaKeyColW = 0;
            for (int i = 0; i < metaKeyLabels.Count; i++)
            {
                Label kl = metaKeyLabels[i];
                int kw = kl.PreferredSize.Width + kl.Margin.Horizontal;
                if (kw > metaKeyColW) metaKeyColW = kw;
            }

            topPanel.Controls.Add(metaPanel, 0, 3);
            topScrollHost.Controls.Add(topPanel);
            root.Controls.Add(topScrollHost, 0, 0);

            string previewHdrText = req.ScriptTruncated
                ? "Frozen Script Preview (truncated above 64 KB — inspect the full script in the Elevated Execution Side Panel):"
                : "Frozen Script Preview (verbatim UTF-8):";
            Label lblPreviewHdr = new Label();
            lblPreviewHdr.UseCompatibleTextRendering = false;
            lblPreviewHdr.Name = "lblPreviewHdr";
            lblPreviewHdr.Text = previewHdrText;
            lblPreviewHdr.ForeColor = effectiveTheme.MutedForeColor;
            lblPreviewHdr.AutoSize = true;
            lblPreviewHdr.Margin = new Padding(0, S(8), 0, S(4));
            root.Controls.Add(lblPreviewHdr, 0, 1);

            string normPreview = (req.ScriptPreview ?? string.Empty).Replace("\r\n", "\n").Replace("\n", "\r\n");
            if (normPreview.Length > 65536)
            {
                normPreview = normPreview.Substring(0, 65536) + "\r\n\r\n... [Preview truncated at 64 KB — inspect the full script in the Side Panel] ...";
            }

            Panel previewWrapper = new Panel();
            previewWrapper.SuspendLayout();
            previewWrapper.Name = "previewWrapper";
            previewWrapper.Dock = DockStyle.Fill;
            previewWrapper.Padding = new Padding(1);
            previewWrapper.Margin = new Padding(0);
            previewWrapper.BackColor = effectiveTheme.PreviewBorderColor;
            previewWrapper.MinimumSize = new Size(0, S(140) + previewWrapper.Padding.Vertical);

            TextBox txtPreview = new TextBox();
            txtPreview.Name = "txtPreview";
            txtPreview.BorderStyle = BorderStyle.None;
            txtPreview.Multiline = true;
            txtPreview.ReadOnly = true;
            txtPreview.ScrollBars = ScrollBars.Both;
            txtPreview.WordWrap = false;
            txtPreview.Font = new Font("Consolas", 9.5F, FontStyle.Regular);
            txtPreview.BackColor = effectiveTheme.PreviewBackColor;
            txtPreview.ForeColor = effectiveTheme.PreviewForeColor;
            txtPreview.Dock = DockStyle.Fill;
            txtPreview.Margin = new Padding(0);
            txtPreview.MinimumSize = new Size(0, S(140));
            txtPreview.Text = normPreview;
            txtPreview.SelectionStart = 0;
            txtPreview.SelectionLength = 0;
            ApplyDarkControlScrollbars(txtPreview, effectiveTheme);
            previewWrapper.Controls.Add(txtPreview);
            previewWrapper.ResumeLayout(false);
            root.Controls.Add(previewWrapper, 0, 2);

            TableLayoutPanel statusPanel = new TableLayoutPanel();
            statusPanel.SuspendLayout();
            statusPanel.Name = "statusPanel";
            statusPanel.Dock = DockStyle.Fill;
            statusPanel.AutoSize = true;
            statusPanel.ColumnCount = 2;
            statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            statusPanel.Margin = new Padding(0, S(8), 0, S(8));

            _statusLabel = new Label();
            _statusLabel.UseCompatibleTextRendering = false;
            _statusLabel.Name = "lblStatus";
            _statusLabel.Text = "Review the script and details above before proceeding.";
            _statusLabel.ForeColor = effectiveTheme.MutedForeColor;
            _statusLabel.AutoSize = true;
            _statusLabel.Anchor = AnchorStyles.Left;

            Label lblCountdown = new Label();
            lblCountdown.UseCompatibleTextRendering = false;
            lblCountdown.Name = "lblCountdown";
            lblCountdown.ForeColor = effectiveTheme.FormForeColor;
            lblCountdown.AutoSize = true;
            lblCountdown.Anchor = AnchorStyles.Right;
            lblCountdown.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);

            int timeoutSec = req.Click1TimeoutSeconds;
            int lastRenderedSec = timeoutSec;
            long click1DeadlineMs = 0;
            if (timeoutSec > 0)
            {
                lblCountdown.Text = FormatCountdown(timeoutSec);
            }
            else
            {
                lblCountdown.Text = "No timeout";
            }

            statusPanel.Controls.Add(_statusLabel, 0, 0);
            statusPanel.Controls.Add(lblCountdown, 1, 0);
            root.Controls.Add(statusPanel, 0, 3);

            FlowLayoutPanel btnPanel = new FlowLayoutPanel();
            btnPanel.SuspendLayout();
            btnPanel.Name = "btnPanel";
            btnPanel.Dock = DockStyle.Fill;
            btnPanel.FlowDirection = FlowDirection.RightToLeft;
            btnPanel.AutoSize = true;
            btnPanel.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            btnPanel.Margin = new Padding(0);

            _denyButton = new Button();
            _denyButton.UseCompatibleTextRendering = false;
            _denyButton.Name = "btnDeny";
            _denyButton.Text = "Deny";
            _denyButton.AutoSize = true;
            _denyButton.MinimumSize = new Size(S(110), S(34));
            _denyButton.Padding = new Padding(S(8), S(4), S(8), S(4));
            ApplyThemedButton(_denyButton, effectiveTheme);

            _proceedButton = new Button();
            _proceedButton.UseCompatibleTextRendering = false;
            _proceedButton.Name = "btnProceed";
            _proceedButton.Text = "Proceed → Windows UAC";
            _proceedButton.AutoSize = true;
            _proceedButton.MinimumSize = new Size(S(190), S(34));
            _proceedButton.Padding = new Padding(S(10), S(4), S(10), S(4));
            _proceedButton.Enabled = false; // 300 ms guard against accidental Enter mash
            ApplyThemedButton(_proceedButton, effectiveTheme);

            btnPanel.Controls.Add(_denyButton);
            btnPanel.Controls.Add(_proceedButton);
            root.Controls.Add(btnPanel, 0, 4);

            form.Controls.Add(root);
            form.AcceptButton = null;
            form.CancelButton = _denyButton;

            int lastTopWrapW = -1;
            int lastPreviewWrapW = -1;
            Action<int, int> applyWrapWidths = delegate(int topContentW, int previewContentW)
            {
                int safeTopW = Math.Max(S(240), topContentW);
                if (safeTopW != lastTopWrapW)
                {
                    lastTopWrapW = safeTopW;
                    topPanel.SuspendLayout();
                    reasonContent.SuspendLayout();
                    metaPanel.SuspendLayout();
                    lblHeader.MaximumSize = new Size(safeTopW, 0);
                    lblAttr.MaximumSize = new Size(safeTopW, 0);

                    int reasonWrapW = Math.Max(S(200), safeTopW - S(4) - reasonContent.Padding.Horizontal - S(4));
                    lblReasonCaption.MaximumSize = new Size(reasonWrapW, 0);
                    lblReason.MaximumSize = new Size(reasonWrapW, 0);

                    int metaValW = Math.Max(S(200), safeTopW - metaKeyColW - S(16));
                    for (int i = 0; i < metaValLabels.Count; i++)
                    {
                        metaValLabels[i].MaximumSize = new Size(metaValW, 0);
                    }
                    bool perform = form.IsHandleCreated;
                    metaPanel.ResumeLayout(perform);
                    reasonContent.ResumeLayout(perform);
                    topPanel.ResumeLayout(perform);
                }

                if (previewContentW > 0)
                {
                    int safePrevW = Math.Max(S(240), previewContentW - lblPreviewHdr.Margin.Horizontal);
                    if (safePrevW != lastPreviewWrapW)
                    {
                        lastPreviewWrapW = safePrevW;
                        lblPreviewHdr.MaximumSize = new Size(safePrevW, 0);
                    }
                }
            };

            bool updatingLayout = false;
            Action updateLayout = delegate()
            {
                if (updatingLayout || form.IsDisposed) return;
                if (form.WindowState == FormWindowState.Minimized) return;
                updatingLayout = true;
                try
                {
                    int cw = (form.ClientSize.Width > 0) ? form.ClientSize.Width : S(780);
                    int ch = (form.ClientSize.Height > 0) ? form.ClientSize.Height : S(680);
                    int availW = Math.Max(S(240), cw - root.Padding.Horizontal);

                    applyWrapWidths(availW, availW);

                    int prevHdrH = lblPreviewHdr.GetPreferredSize(new Size(availW, 0)).Height + lblPreviewHdr.Margin.Vertical;
                    int prevMinH = S(140) + previewWrapper.Padding.Vertical + previewWrapper.Margin.Vertical;
                    int statusH = statusPanel.GetPreferredSize(new Size(availW, 0)).Height + statusPanel.Margin.Vertical;
                    int btnH = btnPanel.GetPreferredSize(new Size(availW, 0)).Height + btnPanel.Margin.Vertical;
                    int reservedBottomH = root.Padding.Vertical + prevHdrH + prevMinH + statusH + btnH;
                    int maxTopH = Math.Max(S(120), ch - reservedBottomH);

                    int topPrefH = topPanel.GetPreferredSize(new Size(availW, 0)).Height;
                    if (topPrefH > maxTopH)
                    {
                        int scrollAvailW = Math.Max(S(240), availW - SystemInformation.VerticalScrollBarWidth);
                        applyWrapWidths(scrollAvailW, availW);
                        topScrollHost.AutoScroll = true;
                        topScrollHost.MaximumSize = new Size(0, maxTopH);
                    }
                    else
                    {
                        topScrollHost.AutoScroll = false;
                        topScrollHost.MaximumSize = new Size(0, 0);
                    }
                }
                finally
                {
                    updatingLayout = false;
                }
            };

            int initClientW = S(780);
            int initAvailW = Math.Max(S(240), initClientW - root.Padding.Horizontal);
            applyWrapWidths(initAvailW, initAvailW);
            int initPrevHdrH = lblPreviewHdr.GetPreferredSize(new Size(initAvailW, 0)).Height + lblPreviewHdr.Margin.Vertical;
            int initStatusH = statusPanel.GetPreferredSize(new Size(initAvailW, 0)).Height + statusPanel.Margin.Vertical;
            int initBtnH = btnPanel.GetPreferredSize(new Size(initAvailW, 0)).Height + btnPanel.Margin.Vertical;
            int initNonTopH = root.Padding.Vertical + initPrevHdrH + previewWrapper.Padding.Vertical + previewWrapper.Margin.Vertical + initStatusH + initBtnH;
            int initTopH = topPanel.GetPreferredSize(new Size(initAvailW, 0)).Height;
            int maxClientH = Math.Max(S(560), (int)(Screen.PrimaryScreen.WorkingArea.Height * 0.85));
            int initClientH = Math.Min(maxClientH, Math.Max(S(680), initTopH + initNonTopH + S(200)));
            form.ClientSize = new Size(initClientW, initClientH);

            int initMaxTopH = Math.Max(S(120), initClientH - (initNonTopH + S(140)));
            if (initTopH > initMaxTopH)
            {
                int scrollAvailW = Math.Max(S(240), initAvailW - SystemInformation.VerticalScrollBarWidth);
                applyWrapWidths(scrollAvailW, initAvailW);
                topScrollHost.AutoScroll = true;
                topScrollHost.MaximumSize = new Size(0, initMaxTopH);
            }
            else
            {
                topScrollHost.AutoScroll = false;
                topScrollHost.MaximumSize = new Size(0, 0);
            }

            btnPanel.ResumeLayout(false);
            statusPanel.ResumeLayout(false);
            metaPanel.ResumeLayout(false);
            reasonContent.ResumeLayout(false);
            reasonBanner.ResumeLayout(false);
            topPanel.ResumeLayout(false);
            topScrollHost.ResumeLayout(false);
            root.ResumeLayout(false);
            form.ResumeLayout(false);

            int lastLayoutW = initClientW;
            int lastLayoutH = initClientH;
            form.SizeChanged += (s, e) =>
            {
                if (updatingLayout || form.IsDisposed) return;
                if (form.WindowState == FormWindowState.Minimized) return;
                int cw = form.ClientSize.Width;
                int ch = form.ClientSize.Height;
                if (cw <= 0 || ch <= 0) return;
                if (cw == lastLayoutW && ch == lastLayoutH) return;
                lastLayoutW = cw;
                lastLayoutH = ch;
                root.SuspendLayout();
                topScrollHost.SuspendLayout();
                updateLayout();
                topScrollHost.ResumeLayout(true);
                root.ResumeLayout(true);
            };

            System.Windows.Forms.Timer guardTimer = new System.Windows.Forms.Timer();
            guardTimer.Interval = 300;
            guardTimer.Tick += (s, e) =>
            {
                guardTimer.Stop();
                guardTimer.Dispose();
                if (Volatile.Read(ref _decisionState) == DECISION_NONE && !_proceedButton.IsDisposed)
                {
                    _proceedButton.Enabled = true;
                }
            };

            if (timeoutSec > 0)
            {
                _countdownTimer = new System.Windows.Forms.Timer();
                _countdownTimer.Interval = 200;
                _countdownTimer.Tick += (s, e) =>
                {
                    if (click1DeadlineMs <= 0) return;
                    long remMs = Math.Max(0L, click1DeadlineMs - GetUtcNowMs());
                    int remSec = (remMs > 0L) ? (int)Math.Ceiling(remMs / 1000.0) : 0;
                    if (remMs <= 0L)
                    {
                        _countdownTimer.Stop();
                        if (lastRenderedSec != 0)
                        {
                            lastRenderedSec = 0;
                            lblCountdown.Text = "Auto-cancels in 00:00";
                        }
                        if (Interlocked.CompareExchange(ref _decisionState, DECISION_TIMEOUT, DECISION_NONE) == DECISION_NONE)
                        {
                            EmitClick1Decision(req.RequestId, "timeout");
                            _allowClick1Close = true;
                            form.Close();
                        }
                        return;
                    }
                    if (remSec != lastRenderedSec)
                    {
                        lastRenderedSec = remSec;
                        lblCountdown.Text = FormatCountdown(remSec);
                    }
                };
            }

            _proceedButton.Click += (s, e) =>
            {
                if (Interlocked.CompareExchange(ref _decisionState, DECISION_PROCEED, DECISION_NONE) == DECISION_NONE)
                {
                    if (Interlocked.CompareExchange(ref _proceedUiHandled, 1, 0) == 0)
                    {
                        OnProceedWonOnUiThread(false);
                    }
                }
            };

            _denyButton.Click += (s, e) =>
            {
                if (Interlocked.CompareExchange(ref _decisionState, DECISION_DENY, DECISION_NONE) == DECISION_NONE)
                {
                    EmitClick1Decision(req.RequestId, "deny");
                    _allowClick1Close = true;
                    form.Close();
                }
            };

            form.Shown += (s, e) =>
            {
                int dec = Volatile.Read(ref _decisionState);
                if (Volatile.Read(ref _shuttingDown) != 0 ||
                    Volatile.Read(ref _cancelled) != 0 ||
                    dec == DECISION_DENY ||
                    dec == DECISION_CANCEL ||
                    dec == DECISION_TIMEOUT)
                {
                    _allowClick1Close = true;
                    try { form.Close(); } catch { }
                    return;
                }

                if (!IsWindowVisible(form.Handle))
                {
                    ShowWindow(form.Handle, SW_SHOWNORMAL);
                }
                try
                {
                    SetForegroundWindow(form.Handle);
                    form.Activate();
                }
                catch { }

                _click1ShownFired = true;
                long? deadlineToEmit = null;
                if (timeoutSec > 0)
                {
                    click1DeadlineMs = GetUtcNowMs() + (long)timeoutSec * 1000L;
                    deadlineToEmit = click1DeadlineMs;
                }
                EmitClick1Shown(req.RequestId, deadlineToEmit);

                if (dec == DECISION_PROCEED)
                {
                    if (Interlocked.CompareExchange(ref _proceedUiHandled, 1, 0) == 0)
                    {
                        OnProceedWonOnUiThread(true);
                    }
                    return;
                }

                guardTimer.Start();
                if (_countdownTimer != null) _countdownTimer.Start();
            };

            form.FormClosing += (s, e) =>
            {
                if (_allowClick1Close || Volatile.Read(ref _shuttingDown) != 0 || Volatile.Read(ref _cancelled) != 0)
                {
                    return;
                }
                int current = Volatile.Read(ref _decisionState);
                if (current == DECISION_DENY || current == DECISION_CANCEL || current == DECISION_TIMEOUT)
                {
                    return;
                }
                if (current == DECISION_NONE)
                {
                    if (Interlocked.CompareExchange(ref _decisionState, DECISION_DENY, DECISION_NONE) == DECISION_NONE)
                    {
                        EmitClick1Decision(req.RequestId, "deny");
                    }
                    return;
                }
                if (current == DECISION_PROCEED && Volatile.Read(ref _runnerConnected) == 0)
                {
                    // Keep modal handle alive while ShellExecuteExW / UAC owns it
                    e.Cancel = true;
                }
            };

            Action disposeTimers = delegate()
            {
                try { guardTimer.Stop(); } catch { }
                try { guardTimer.Dispose(); } catch { }
                if (_countdownTimer != null)
                {
                    try { _countdownTimer.Stop(); } catch { }
                    try { _countdownTimer.Dispose(); } catch { }
                    _countdownTimer = null;
                }
            };

            form.FormClosed += (s, e) => { disposeTimers(); };
            form.Disposed += (s, e) => { disposeTimers(); };

            return form;
        }

        private static Label AddMetaRow(TableLayoutPanel panel, int row, string key, string val, bool boldVal, float dpiScale, DialogTheme theme, out Label kLblOut)
        {
            Func<int, int> S = delegate(int px) { return ScalePx(px, dpiScale); };

            Label kLbl = new Label();
            kLbl.UseCompatibleTextRendering = false;
            kLbl.Name = "metaKey_" + row.ToString(CultureInfo.InvariantCulture);
            kLbl.Text = key;
            kLbl.ForeColor = theme.MutedForeColor;
            kLbl.AutoSize = true;
            kLbl.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            kLbl.Margin = new Padding(0, S(2), S(10), S(2));

            Label vLbl = new Label();
            vLbl.UseCompatibleTextRendering = false;
            vLbl.Name = "metaVal_" + row.ToString(CultureInfo.InvariantCulture);
            vLbl.Text = val;
            vLbl.ForeColor = theme.FormForeColor;
            vLbl.AutoSize = true;
            vLbl.MaximumSize = new Size(S(580), 0);
            if (boldVal) vLbl.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
            vLbl.Margin = new Padding(0, S(2), 0, S(2));

            panel.Controls.Add(kLbl, 0, row);
            panel.Controls.Add(vLbl, 1, row);
            kLblOut = kLbl;
            return vLbl;
        }

        private static string FormatCountdown(int sec)
        {
            if (sec < 0) sec = 0;
            int m = sec / 60;
            int s = sec % 60;
            return string.Format(CultureInfo.InvariantCulture, "Auto-cancels in {0:D2}:{1:D2}", m, s);
        }

        public Form BuildReminderForm(string activeSummary, int queueCount)
        {
            return BuildReminderFormWithScale(activeSummary, queueCount, GetSystemDpiScale(), null);
        }

        public Form BuildReminderForm(string activeSummary, int queueCount, DialogTheme theme)
        {
            return BuildReminderFormWithScale(activeSummary, queueCount, GetSystemDpiScale(), theme);
        }

        public Form BuildReminderFormWithScale(string activeSummary, int queueCount, float dpiScale)
        {
            return BuildReminderFormWithScale(activeSummary, queueCount, dpiScale, null);
        }

        public Form BuildReminderFormWithScale(string activeSummary, int queueCount, float dpiScale, DialogTheme theme)
        {
            DialogTheme effectiveTheme = theme ?? DialogTheme.ResolveSystem();
            float effectiveScale = (dpiScale < 1.0F) ? 1.0F : dpiScale;
            Func<int, int> S = delegate(int px) { return ScalePx(px, effectiveScale); };

            Form form = new Form();
            form.SuspendLayout();
            form.Name = "ReminderForm";
            form.Text = "Pending Elevation Queue — Google Antigravity";
            form.TopMost = true;
            form.AutoScaleMode = AutoScaleMode.None;
            form.StartPosition = FormStartPosition.CenterScreen;
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.MaximizeBox = false;
            form.MinimizeBox = false;
            form.Font = new Font("Segoe UI", 9.5F, FontStyle.Regular);
            form.BackColor = effectiveTheme.FormBackColor;
            form.ForeColor = effectiveTheme.FormForeColor;
            ApplyDarkTitleBar(form, effectiveTheme);

            int targetClientW = S(500);
            int wrapW = targetClientW - S(32);

            TableLayoutPanel root = new TableLayoutPanel();
            root.SuspendLayout();
            root.Name = "root";
            root.Dock = DockStyle.Fill;
            root.Padding = new Padding(S(16));
            root.ColumnCount = 1;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            root.RowCount = 2;
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F)); // 0: scrollHost
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));      // 1: btnPanel (pinned outside scrollHost)

            // Host scrollable TableLayoutPanel inside a plain Panel to avoid the .NET 4.8
            // TableLayoutPanel AutoScroll last-row height explosion bug when clamped.
            Panel scrollHost = new Panel();
            scrollHost.SuspendLayout();
            scrollHost.Name = "scrollHost";
            scrollHost.Dock = DockStyle.Fill;
            scrollHost.Margin = new Padding(0);
            scrollHost.Padding = new Padding(0);
            scrollHost.AutoScroll = false;
            ApplyDarkControlScrollbars(scrollHost, effectiveTheme);

            TableLayoutPanel contentTable = new TableLayoutPanel();
            contentTable.SuspendLayout();
            contentTable.Name = "contentTable";
            contentTable.Dock = DockStyle.Top;
            contentTable.AutoSize = true;
            contentTable.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            contentTable.Margin = new Padding(0);
            contentTable.Padding = new Padding(0);
            contentTable.ColumnCount = 1;
            contentTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            contentTable.RowCount = 3;
            contentTable.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 0: lblTitle
            contentTable.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 1: lblActive
            contentTable.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 2: lblHint

            Label lblTitle = new Label();
            lblTitle.UseCompatibleTextRendering = false;
            lblTitle.Name = "lblTitle";
            lblTitle.Text = string.Format(CultureInfo.InvariantCulture, "Elevation Queue Reminder ({0} waiting)", queueCount);
            lblTitle.Font = new Font("Segoe UI", 11F, FontStyle.Bold);
            lblTitle.ForeColor = effectiveTheme.FormForeColor;
            lblTitle.AutoSize = true;
            lblTitle.MaximumSize = new Size(wrapW, 0);
            lblTitle.Margin = new Padding(0, 0, 0, S(8));
            contentTable.Controls.Add(lblTitle, 0, 0);

            Label lblActive = new Label();
            lblActive.UseCompatibleTextRendering = false;
            lblActive.Name = "lblActive";
            lblActive.Text = "Active elevated task: " + (string.IsNullOrEmpty(activeSummary) ? "(running)" : activeSummary);
            lblActive.ForeColor = effectiveTheme.FormForeColor;
            lblActive.AutoSize = true;
            lblActive.MaximumSize = new Size(wrapW, 0);
            lblActive.Margin = new Padding(0, 0, 0, S(8));
            contentTable.Controls.Add(lblActive, 0, 1);

            Label lblHint = new Label();
            lblHint.UseCompatibleTextRendering = false;
            lblHint.Name = "lblHint";
            lblHint.Text = "Queued requests will present Click-1 approval strictly one-by-one when the active task finishes. Open the Elevated Execution Side Panel to inspect or manage the queue. Closes automatically when the active task finishes or the queue clears.";
            lblHint.ForeColor = effectiveTheme.MutedForeColor;
            lblHint.AutoSize = true;
            lblHint.MaximumSize = new Size(wrapW, 0);
            lblHint.Margin = new Padding(0, 0, 0, S(4));
            contentTable.Controls.Add(lblHint, 0, 2);

            scrollHost.Controls.Add(contentTable);
            root.Controls.Add(scrollHost, 0, 0);

            FlowLayoutPanel btnPanel = new FlowLayoutPanel();
            btnPanel.SuspendLayout();
            btnPanel.Name = "btnPanel";
            btnPanel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnPanel.FlowDirection = FlowDirection.RightToLeft;
            btnPanel.AutoSize = true;
            btnPanel.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            btnPanel.Margin = new Padding(0, S(8), 0, 0);

            Button btnDismiss = new Button();
            btnDismiss.UseCompatibleTextRendering = false;
            btnDismiss.Name = "btnDismiss";
            btnDismiss.Text = "Dismiss";
            btnDismiss.AutoSize = true;
            btnDismiss.MinimumSize = new Size(S(100), S(32));
            btnDismiss.Padding = new Padding(S(8), S(4), S(8), S(4));
            ApplyThemedButton(btnDismiss, effectiveTheme);
            btnDismiss.Click += (s, e) => form.Close();

            btnPanel.Controls.Add(btnDismiss);
            root.Controls.Add(btnPanel, 0, 1);

            form.Controls.Add(root);
            form.AcceptButton = btnDismiss;
            form.CancelButton = btnDismiss;

            btnPanel.ResumeLayout(false);
            contentTable.ResumeLayout(false);
            scrollHost.ResumeLayout(false);
            root.ResumeLayout(false);

            Size prefContent = contentTable.GetPreferredSize(new Size(wrapW, 0));
            Size prefBtn = btnPanel.GetPreferredSize(new Size(wrapW, 0));
            int prefW = Math.Max(prefContent.Width, prefBtn.Width) + root.Padding.Horizontal;
            int prefH = root.Padding.Vertical + prefContent.Height + btnPanel.Margin.Vertical + prefBtn.Height;
            int maxClientH = Math.Max(S(240), (int)(Screen.PrimaryScreen.WorkingArea.Height * 0.75));
            int clientW = Math.Max(targetClientW, prefW);
            bool clamped = (prefH + S(4)) > maxClientH;
            if (clamped)
            {
                scrollHost.AutoScroll = true;
                clientW += SystemInformation.VerticalScrollBarWidth;
            }
            int clientH = Math.Min(maxClientH, Math.Max(S(190), prefH + S(4)));
            form.ClientSize = new Size(clientW, clientH);
            form.MinimumSize = form.Size;
            form.ResumeLayout(false);
            return form;
        }

        public static BrokerRequestData ParseRequestData(Dictionary<string, object> msg)
        {
            BrokerRequestData r = new BrokerRequestData();
            r.RequestId = GetDictString(msg, "requestId");
            string rp = GetDictString(msg, "runnerPath");
            if (!string.IsNullOrEmpty(rp)) r.RunnerPath = rp;
            r.ManifestFile = GetDictString(msg, "manifestFile");
            r.ManifestSha256 = GetDictString(msg, "manifestSha256");
            r.NormalWindow = GetDictBool(msg, "normalWindow", false);
            r.Click1TimeoutSeconds = GetDictInt(msg, "click1TimeoutSeconds", 300);
            r.Reason = GetDictString(msg, "reason");
            r.WorkDir = GetDictString(msg, "workDir");
            r.ScriptPreview = GetDictString(msg, "scriptPreview");
            r.ScriptTruncated = GetDictBool(msg, "scriptTruncated", false);

            object argsObj;
            if (msg.TryGetValue("args", out argsObj) && argsObj != null)
            {
                System.Collections.IEnumerable seq = argsObj as System.Collections.IEnumerable;
                if (seq != null && !(argsObj is string))
                {
                    List<string> list = new List<string>();
                    foreach (object item in seq)
                    {
                        list.Add(item == null ? string.Empty : Convert.ToString(item));
                    }
                    r.Args = list.ToArray();
                }
            }

            object tmObj;
            if (msg.TryGetValue("targetMeta", out tmObj) && tmObj is Dictionary<string, object>)
            {
                Dictionary<string, object> tm = (Dictionary<string, object>)tmObj;
                r.HasTargetMeta = true;
                r.TargetPath = GetDictString(tm, "canonicalPath");
                if (string.IsNullOrEmpty(r.TargetPath)) r.TargetPath = GetDictString(tm, "originalPath");
                r.TargetSubsystem = GetDictString(tm, "subsystem");
                r.TargetPublisher = GetDictString(tm, "publisher");
            }

            object attrObj;
            if (msg.TryGetValue("attribution", out attrObj) && attrObj is Dictionary<string, object>)
            {
                Dictionary<string, object> attr = (Dictionary<string, object>)attrObj;
                r.IsSubagent = GetDictBool(attr, "isSubagent", false);
                r.AttributionRole = GetDictString(attr, "role");
                r.AttributionAgentLabel = GetDictString(attr, "agentLabel");
                r.Workspace = GetDictString(attr, "workspace");
                r.ConversationId = GetDictString(attr, "conversationId");
                r.StepIndex = GetDictString(attr, "stepIndex");
                r.ToolCallId = GetDictString(attr, "toolCallId");
            }

            return r;
        }

        private static string GetDictString(Dictionary<string, object> d, string key)
        {
            if (d == null) return string.Empty;
            object v;
            if (!d.TryGetValue(key, out v) || v == null) return string.Empty;
            return Convert.ToString(v, CultureInfo.InvariantCulture) ?? string.Empty;
        }

        private static int GetDictInt(Dictionary<string, object> d, string key, int fallback)
        {
            if (d == null) return fallback;
            object v;
            if (!d.TryGetValue(key, out v) || v == null) return fallback;
            try { return Convert.ToInt32(v, CultureInfo.InvariantCulture); } catch { return fallback; }
        }

        private static bool GetDictBool(Dictionary<string, object> d, string key, bool fallback)
        {
            if (d == null) return fallback;
            object v;
            if (!d.TryGetValue(key, out v) || v == null) return fallback;
            try { return Convert.ToBoolean(v, CultureInfo.InvariantCulture); } catch { return fallback; }
        }
    }
}
'@

    Add-Type -TypeDefinition $csharp -Language CSharp -ReferencedAssemblies @(
        'System.Windows.Forms',
        'System.Drawing',
        'System.Core',
        'System.Web.Extensions',
        ([System.Management.Automation.Runspaces.Runspace].Assembly.Location)
    )
}

function New-HardenedPipeSecurity {
    [CmdletBinding()]
    [OutputType([System.IO.Pipes.PipeSecurity])]
    param()

    Initialize-InteractiveBrokerTypes
    return [AgentElevation.PipeSecurityFactory]::CreateHardenedPipeSecurity()
}

function Send-AntigravityToastNotification {
    [CmdletBinding()]
    param(
        [string]$RequestId = '',
        [string]$Reason = '',
        [string]$Message = 'Windows UAC approval prompt is ready on your desktop.'
    )

    try {
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime]

        $escTitle = [System.Security.SecurityElement]::Escape('Elevation Request Approved — Windows UAC Ready')
        $bodyText = if ([string]::IsNullOrWhiteSpace($Reason)) { $Message } else { "$Message ($Reason)" }
        $escBody = [System.Security.SecurityElement]::Escape($bodyText)

        $xmlStr = "<toast><visual><binding template='ToastGeneric'><text>$escTitle</text><text>$escBody</text></binding></visual></toast>"
        $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $doc.LoadXml($xmlStr)

        $toast = New-Object Windows.UI.Notifications.ToastNotification($doc)
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('electron.app.Antigravity')
        $notifier.Show($toast)
    } catch {
        # Best-effort toast fallback; ignore errors in non-interactive or policy-restricted sessions
    }
}

function New-BrokerEngine {
    [CmdletBinding()]
    param(
        [scriptblock]$PreflightOverride,
        [scriptblock]$UacLauncherOverride
    )

    Initialize-InteractiveBrokerTypes

    $pfScript = if ($null -ne $PreflightOverride) {
        {
            param([string]$rp)
            $target = if ([string]::IsNullOrWhiteSpace($rp)) { 'C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1' } else { $rp }
            $r = & $PreflightOverride $target
            return [object[]]@([bool]$r.ok, [string]$r.code, [int]$r.exitCode, [string]$r.detail)
        }.GetNewClosure()
    } else {
        {
            param([string]$rp)
            $target = if ([string]::IsNullOrWhiteSpace($rp)) { 'C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1' } else { $rp }
            $r = Invoke-PreflightCheck -RunnerPath $target
            return [object[]]@([bool]$r.ok, [string]$r.code, [int]$r.exitCode, [string]$r.detail)
        }
    }
    $pfFunc = [System.Func[string, object[]]]$pfScript

    $uacFunc = $null
    if ($null -ne $UacLauncherOverride) {
        $uacScript = {
            param($reqData, $pipeName, $pipeSec, $hwnd)
            return [int](& $UacLauncherOverride $reqData $pipeName $pipeSec $hwnd)
        }.GetNewClosure()
        $uacFunc = [System.Func[AgentElevation.BrokerRequestData, string, System.IO.Pipes.PipeSecurity, IntPtr, int]]$uacScript
    }

    return New-Object AgentElevation.BrokerEngine($pfFunc, $uacFunc)
}

function Invoke-BrokerHelperMain {
    [CmdletBinding()]
    param(
        [switch]$PreflightOnly,
        [string]$RunnerPath = 'C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1'
    )

    if ($PreflightOnly) {
        try {
            Initialize-PreflightNative
            $res = Invoke-PreflightCheck -RunnerPath $RunnerPath
            $json = [AgentElevation.PreflightNative]::FormatPreflightJson([bool]$res.ok, [string]$res.code, [int]$res.exitCode, [string]$res.detail)
            [AgentElevation.PreflightNative]::WriteStdoutUtf8Line($json)
        } catch {
            try {
                Initialize-PreflightNative
                $json = [AgentElevation.PreflightNative]::FormatPreflightJson($false, 'E_RUNNER_INVALID', 1204, $_.Exception.Message)
                [AgentElevation.PreflightNative]::WriteStdoutUtf8Line($json)
            } catch {
                $utf8 = New-Object System.Text.UTF8Encoding($false)
                $fallback = '{"ok":false,"code":"E_RUNNER_INVALID","exitCode":1204,"detail":"Preflight initialization failed."}' + "`n"
                $bytes = $utf8.GetBytes($fallback)
                $stdout = [Console]::OpenStandardOutput()
                $stdout.Write($bytes, 0, $bytes.Length)
                $stdout.Flush()
            }
        }
        exit 0
    }

    Initialize-InteractiveBrokerTypes
    $engine = New-BrokerEngine
    $engine.StartStdinReaderThread($null)
    $exitCode = $engine.RunMainLoop()
    exit $exitCode
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-BrokerHelperMain -PreflightOnly:$PreflightOnly -RunnerPath $RunnerPath
}
