<#
.SYNOPSIS
Area 4: Per-Line & 150-250 ms Idle-Flush zh-CN Decoder (CP936 / UTF-8 / UTF-16LE), 64 KB Cap BVA, Trailing-Byte Holdback, Live Native Binaries, and Repo AST Extraction.
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

$decoderCs = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace AeTestDecoder {
    public sealed class LineDecoder {
        public const int MaxLineBytes = 65536;

        private readonly string _mode;
        private readonly Action<string> _onEmit;
        private readonly List<byte> _buf = new List<byte>(4096);
        private bool _inUtf16Line = false;
        private bool _utf16BomStream = false;

        private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private static readonly Encoding LenientUtf8 = new UTF8Encoding(false, false);
        private static readonly Encoding Cp936Lenient = Encoding.GetEncoding(936);
        private static readonly Encoding Cp936Strict = Encoding.GetEncoding(936, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);

        public LineDecoder(string encodingMode, Action<string> onEmit) {
            _mode = string.IsNullOrEmpty(encodingMode) ? "auto" : encodingMode.ToLowerInvariant();
            _onEmit = onEmit;
        }

        public void Feed(byte[] buffer, int offset, int count) {
            if (buffer == null || count <= 0) return;
            for (int i = 0; i < count; i++) {
                byte b = buffer[offset + i];
                _buf.Add(b);

                if (_mode == "utf16") {
                    _inUtf16Line = true;
                } else if (_mode == "auto") {
                    if (_buf.Count >= 2 && _buf[0] == 0xFF && _buf[1] == 0xFE) {
                        _utf16BomStream = true;
                        _inUtf16Line = true;
                    } else if (_utf16BomStream) {
                        _inUtf16Line = true;
                    } else if (!_inUtf16Line) {
                        if (_buf.Count >= 2 && _buf[0] != 0x00 && _buf[1] == 0x00) {
                            _inUtf16Line = true;
                        } else if (_buf.Count >= 4 && (_buf.Count % 2 == 0) && b == 0x00) {
                            int oddNuls = 0;
                            int evenNuls = 0;
                            for (int k = 0; k < _buf.Count; k++) {
                                if (_buf[k] == 0x00) {
                                    if ((k % 2) == 1) oddNuls++; else evenNuls++;
                                }
                            }
                            if (oddNuls > 0 && oddNuls > evenNuls) {
                                _inUtf16Line = true;
                            }
                        }
                    }
                }

                if (_inUtf16Line) {
                    int n = _buf.Count;
                    if (n >= 2 && (n % 2 == 0) && _buf[n - 2] == 0x0A && _buf[n - 1] == 0x00) {
                        EmitRange(0, n, true);
                        _buf.Clear();
                        _inUtf16Line = false;
                        continue;
                    }
                } else {
                    if (b == 0x0A) {
                        EmitRange(0, _buf.Count, false);
                        _buf.Clear();
                        continue;
                    }
                }

                if (_buf.Count >= MaxLineBytes) {
                    FlushPartial(true);
                }
            }
        }

        private static bool BufferHasZeroByte(List<byte> buf) {
            for (int i = 0; i < buf.Count; i++) {
                if (buf[i] == 0x00) return true;
            }
            return false;
        }

        public void FlushIdle() {
            if (_buf.Count == 0) return;
            FlushPartial(true);
        }

        public void FlushEof() {
            if (_buf.Count == 0) return;
            FlushPartial(false);
        }

        private void FlushPartial(bool holdBackIncomplete) {
            int n = _buf.Count;
            if (n == 0) return;

            bool isUtf16 = _inUtf16Line || _utf16BomStream || _mode == "utf16";
            if (isUtf16 && _utf16BomStream && _mode == "auto" && !BufferHasZeroByte(_buf) && !(n >= 2 && _buf[0] == 0xFF && _buf[1] == 0xFE)) {
                _utf16BomStream = false;
                _inUtf16Line = false;
                isUtf16 = false;
            }
            int hold = holdBackIncomplete ? CountTrailingIncomplete(n, isUtf16) : 0;
            int emitLen = n - hold;
            if (emitLen <= 0) return;

            EmitRange(0, emitLen, isUtf16);
            if (hold > 0) {
                byte[] rem = new byte[hold];
                for (int i = 0; i < hold; i++) rem[i] = _buf[emitLen + i];
                _buf.Clear();
                _buf.AddRange(rem);
            } else {
                _buf.Clear();
                _inUtf16Line = false;
            }
        }

        private int CountTrailingIncomplete(int n, bool isUtf16) {
            if (n <= 0) return 0;
            if (isUtf16) {
                int hold = 0;
                int evenLen = n;
                if ((n % 2) != 0) {
                    hold = 1;
                    evenLen = n - 1;
                }
                if (evenLen >= 2) {
                    ushort lastUnit = (ushort)(_buf[evenLen - 2] | (_buf[evenLen - 1] << 8));
                    if (lastUnit >= 0xD800 && lastUnit <= 0xDBFF) {
                        hold += 2;
                    }
                }
                return hold;
            }

            if (_mode == "oem") {
                return CountTrailingCp936(n);
            }

            // Crucial invariant: if the entire buffer is already complete valid strict UTF-8, hold back 0
            if (IsValidStrictUtf8(n)) {
                return 0;
            }

            int utf8Trail = CountTrailingUtf8Candidate(n);
            if (utf8Trail > 0 && IsValidStrictUtf8(n - utf8Trail)) {
                return utf8Trail;
            }

            if (_mode == "utf8") {
                return 0;
            }

            return CountTrailingCp936(n);
        }

        private bool IsValidStrictUtf8(int len) {
            if (len == 0) return true;
            try {
                byte[] tmp = new byte[len];
                for (int i = 0; i < len; i++) tmp[i] = _buf[i];
                StrictUtf8.GetString(tmp, 0, len);
                return true;
            } catch {
                return false;
            }
        }

        private int CountTrailingUtf8Candidate(int n) {
            int maxCheck = Math.Min(3, n);
            for (int trail = 1; trail <= maxCheck; trail++) {
                int idx = n - trail;
                byte lead = _buf[idx];
                int expectedLen = 0;
                if (lead >= 0xC2 && lead <= 0xDF) expectedLen = 2;
                else if (lead >= 0xE0 && lead <= 0xEF) expectedLen = 3;
                else if (lead >= 0xF0 && lead <= 0xF4) expectedLen = 4;
                if (expectedLen > trail) {
                    bool ok = true;
                    for (int k = 1; k < trail; k++) {
                        byte cb = _buf[idx + k];
                        if (cb < 0x80 || cb > 0xBF) { ok = false; break; }
                        if (k == 1) {
                            if (lead == 0xE0 && cb < 0xA0) { ok = false; break; }
                            if (lead == 0xED && cb > 0x9F) { ok = false; break; }
                            if (lead == 0xF0 && cb < 0x90) { ok = false; break; }
                            if (lead == 0xF4 && cb > 0x8F) { ok = false; break; }
                        }
                    }
                    if (ok) return trail;
                }
            }
            return 0;
        }

        private int CountTrailingCp936(int n) {
            int i = 0;
            while (i < n) {
                byte b = _buf[i];
                if (b >= 0x81 && b <= 0xFE) {
                    if (i + 1 >= n) return 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            return 0;
        }

        private void EmitRange(int start, int len, bool isUtf16) {
            if (len <= 0 || _onEmit == null) return;
            byte[] data = new byte[len];
            for (int i = 0; i < len; i++) data[i] = _buf[start + i];
            string decoded = DecodeSlice(data, isUtf16);
            if (!string.IsNullOrEmpty(decoded)) {
                _onEmit(decoded);
            }
        }

        private string DecodeSlice(byte[] data, bool isUtf16) {
            int offset = 0;
            int len = data.Length;

            if (isUtf16 || _mode == "utf16") {
                if (len >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
                    offset = 2;
                }
                return Encoding.Unicode.GetString(data, offset, len - offset);
            }

            if (len >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
                offset = 3;
            }
            int effLen = len - offset;

            if (_mode == "oem") {
                return Cp936Lenient.GetString(data, offset, effLen);
            }
            if (_mode == "utf8") {
                return LenientUtf8.GetString(data, offset, effLen);
            }

            // auto mode: strict UTF-8 with 2-byte CJK false-positive fallback to CP936
            try {
                string u8 = StrictUtf8.GetString(data, offset, effLen);
                if (AllNonAsciiAre2ByteUtf8(u8)) {
                    try {
                        string cp = Cp936Strict.GetString(data, offset, effLen);
                        if (AllNonAsciiAreCjkIdeographs(cp)) {
                            return cp;
                        }
                    } catch { }
                }
                return u8;
            } catch {
                return Cp936Lenient.GetString(data, offset, effLen);
            }
        }

        private static bool AllNonAsciiAre2ByteUtf8(string s) {
            bool hasNonAscii = false;
            for (int i = 0; i < s.Length; i++) {
                int ch = s[i];
                if (ch <= 0x7F) continue;
                hasNonAscii = true;
                if (ch > 0x07FF) return false;
            }
            return hasNonAscii;
        }

        private static bool AllNonAsciiAreCjkIdeographs(string s) {
            bool hasNonAscii = false;
            for (int i = 0; i < s.Length; i++) {
                int ch = s[i];
                if (ch <= 0x7F) continue;
                hasNonAscii = true;
                bool isCjk = (ch >= 0x4E00 && ch <= 0x9FFF) ||
                             (ch >= 0x3400 && ch <= 0x4DBF) ||
                             (ch >= 0xF900 && ch <= 0xFAFF);
                if (!isCjk) return false;
            }
            return hasNonAscii;
        }
    }

    public sealed class TimedEmit {
        public string Text;
        public long Ms;
    }

    public sealed class TimedStreamPump : IDisposable {
        private readonly LineDecoder _decoder;
        private readonly object _streamLock = new object();
        private readonly Timer _idleTimer;
        private readonly int _idleMs;
        private readonly List<TimedEmit> _emits = new List<TimedEmit>();
        private long _lastWriteTicks;
        private bool _disposed = false;

        public TimedStreamPump(string encodingMode, int idleMs) {
            _idleMs = idleMs;
            Stopwatch sw = Stopwatch.StartNew();
            _decoder = new LineDecoder(encodingMode, s => {
                _emits.Add(new TimedEmit { Text = s, Ms = sw.ElapsedMilliseconds });
            });
            _lastWriteTicks = Stopwatch.GetTimestamp();
            _idleTimer = new Timer(OnTimer, null, Timeout.Infinite, Timeout.Infinite);
        }

        public TimedEmit[] GetEmits() {
            lock (_streamLock) {
                return _emits.ToArray();
            }
        }

        public static void ScheduleDelayedWrite(StreamWriter sw, int delayMs, string text) {
            Thread t = new Thread(() => {
                try {
                    Thread.Sleep(delayMs);
                    sw.Write(text);
                    sw.Flush();
                    sw.Close();
                } catch { }
            });
            t.IsBackground = true;
            t.Start();
        }

        public void PumpStream(Stream stream) {
            byte[] buf = new byte[4096];
            while (true) {
                int read = stream.Read(buf, 0, buf.Length);
                if (read <= 0) break;
                lock (_streamLock) {
                    if (_disposed) break;
                    _decoder.Feed(buf, 0, read);
                    _lastWriteTicks = Stopwatch.GetTimestamp();
                    _idleTimer.Change(_idleMs, Timeout.Infinite);
                }
            }
            lock (_streamLock) {
                _idleTimer.Change(Timeout.Infinite, Timeout.Infinite);
                _decoder.FlushEof();
            }
        }

        private void OnTimer(object state) {
            lock (_streamLock) {
                if (_disposed) return;
                double elapsedMs = ((double)(Stopwatch.GetTimestamp() - _lastWriteTicks) * 1000.0) / Stopwatch.Frequency;
                if (elapsedMs + 5.0 < _idleMs) {
                    int remaining = Math.Max(10, _idleMs - (int)elapsedMs);
                    _idleTimer.Change(remaining, Timeout.Infinite);
                    return;
                }
                _decoder.FlushIdle();
            }
        }

        public void Dispose() {
            lock (_streamLock) {
                if (_disposed) return;
                _disposed = true;
                _idleTimer.Dispose();
            }
        }
    }
}
'@
Add-Type -TypeDefinition $decoderCs -Language CSharp

function Invoke-DecoderSequence {
    param(
        [string]$Mode = 'auto',
        [array]$Chunks,
        [switch]$IdleAfterEach,
        [string]$DecoderTypeName = 'AeTestDecoder.LineDecoder'
    )
    $emits = New-Object 'System.Collections.Generic.List[string]'
    $cb = [System.Action[string]]{ param($s) $emits.Add($s) | Out-Null }
    $dec = New-Object $DecoderTypeName($Mode, $cb)
    foreach ($c in $Chunks) {
        [byte[]]$b = $c
        $dec.Feed($b, 0, $b.Length)
        if ($IdleAfterEach) {
            $dec.FlushIdle()
        }
    }
    $dec.FlushEof()
    return ,$emits.ToArray()
}

function Run-AllDecoderVectors {
    param(
        [string]$DecoderTypeName,
        [string]$Prefix = 'A4'
    )
    $cp936 = [System.Text.Encoding]::GetEncoding(936)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $utf16le = [System.Text.Encoding]::Unicode

    # --- TIER 1 ---
    Invoke-TestCase -Id "$Prefix-T1-01" -Area '4' -Tier 1 -Name 'ASCII \r\n and bare \n line splitting preserves exact line endings' -Body {
        $bytes = $utf8.GetBytes("line1`r`nline2`nline3")
        $emits = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$bytes) -DecoderTypeName $DecoderTypeName
        if ($emits.Count -ne 3 -or $emits[0] -cne "line1`r`n" -or $emits[1] -cne "line2`n" -or $emits[2] -cne 'line3') {
            throw "Unexpected emits: $($emits | ConvertTo-Json -Compress)"
        }
        return 'Preserved CRLF, bare LF, and EOF tail'
    }

    Invoke-TestCase -Id "$Prefix-T1-02" -Area '4' -Tier 1 -Name 'icacls-style CP936 summary line decodes cleanly in auto and oem' -Body {
        $txt = "已成功处理 1 个文件; 处理 0 个文件时失败`r`n"
        $bytes = $cp936.GetBytes($txt)
        $e1 = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$bytes) -DecoderTypeName $DecoderTypeName
        $e2 = Invoke-DecoderSequence -Mode 'oem' -Chunks @(,$bytes) -DecoderTypeName $DecoderTypeName
        if ($e1[0] -cne $txt -or $e2[0] -cne $txt) { throw "CP936 decode mismatch" }
        return 'Decoded icacls-style CP936 in both auto and oem'
    }

    Invoke-TestCase -Id "$Prefix-T1-03" -Area '4' -Tier 1 -Name 'netsh-style UTF-8 lines decode cleanly in auto and utf8' -Body {
        $l1 = "域配置文件 设置: `r`n"
        $l2 = "确定。`r`n"
        $bytes = $utf8.GetBytes($l1 + $l2)
        $e1 = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$bytes) -DecoderTypeName $DecoderTypeName
        $e2 = Invoke-DecoderSequence -Mode 'utf8' -Chunks @(,$bytes) -DecoderTypeName $DecoderTypeName
        if ($e1[0] -cne $l1 -or $e1[1] -cne $l2 -or $e2[0] -cne $l1) { throw "UTF-8 decode mismatch" }
        return 'Decoded netsh-style UTF-8 in both auto and utf8'
    }

    Invoke-TestCase -Id "$Prefix-T1-04" -Area '4' -Tier 1 -Name 'UTF-16LE with FF FE BOM (incl. U+4E0A and multi-line CJK) does not split on 0x0A byte' -Body {
        # FF FE + U+4E0A ('上' = 0A 4E) + '\n' (0A 00) + 'ok' (6F 00 6B 00) + '\n' (0A 00)
        $raw = [byte[]](0xFF, 0xFE, 0x0A, 0x4E, 0x0A, 0x00, 0x6F, 0x00, 0x6B, 0x00, 0x0A, 0x00)
        $emits = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$raw) -DecoderTypeName $DecoderTypeName
        if ($emits.Count -ne 2 -or $emits[0] -cne ([char]0x4E0A + "`n") -or $emits[1] -cne "ok`n") {
            throw "UTF-16LE U+4E0A framing failed: $($emits | ConvertTo-Json -Compress)"
        }
        # Multi-line CJK: FF FE + '上\n下\n' (0A 4E 0A 00 0B 4E 0A 00)
        $raw2 = [byte[]](0xFF, 0xFE, 0x0A, 0x4E, 0x0A, 0x00, 0x0B, 0x4E, 0x0A, 0x00)
        $emits2 = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$raw2) -DecoderTypeName $DecoderTypeName
        if ($emits2.Count -ne 2 -or $emits2[0] -cne ([char]0x4E0A + "`n") -or $emits2[1] -cne ([char]0x4E0B + "`n")) {
            throw "UTF-16LE multi-line CJK framing failed: $($emits2 | ConvertTo-Json -Compress)"
        }
        return 'U+4E0A (0A 4E) and multi-line CJK framed at 2-byte 0A 00 boundaries without splitting'
    }

    Invoke-TestCase -Id "$Prefix-T1-05" -Area '4' -Tier 1 -Name 'BOM-less UTF-16LE (cmd /u & bare-LF multi-line) detected via odd-NUL dominance' -Body {
        $txt = "Hello 状态`r`n"
        $raw = $utf16le.GetBytes($txt)
        $emits = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$raw) -DecoderTypeName $DecoderTypeName
        if ($emits.Count -ne 1 -or $emits[0] -cne $txt) {
            throw "BOM-less UTF-16LE failed: $($emits | ConvertTo-Json -Compress)"
        }
        # BOM-less UTF-16LE bare \n: "A\nB\n" (41 00 0A 00 42 00 0A 00)
        $rawBare = $utf16le.GetBytes("A`nB`n")
        $emitsBare = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$rawBare) -DecoderTypeName $DecoderTypeName
        if ($emitsBare.Count -ne 2 -or $emitsBare[0] -cne "A`n" -or $emitsBare[1] -cne "B`n") {
            throw "BOM-less UTF-16LE bare-LF failed: $($emitsBare | ConvertTo-Json -Compress)"
        }
        return 'BOM-less UTF-16LE (CRLF and multi-line bare LF) decoded cleanly'
    }

    Invoke-TestCase -Id "$Prefix-T1-06" -Area '4' -Tier 1 -Name 'Explicit -Encoding utf8/oem/utf16 overrides behave deterministically' -Body {
        # CP936 "状态" bytes (D7 B4 CC AC) forced as utf8 yields U+05F4 U+032C instead of auto-fallback
        $cpBytes = $cp936.GetBytes("状态`n")
        $eUtf8 = Invoke-DecoderSequence -Mode 'utf8' -Chunks @(,$cpBytes) -DecoderTypeName $DecoderTypeName
        $expectedForceU8 = ([char]0x05F4) + ([char]0x032C) + "`n"
        if ($eUtf8[0] -cne $expectedForceU8) {
            throw "Explicit utf8 override failed: got $($eUtf8[0])"
        }
        $eOem = Invoke-DecoderSequence -Mode 'oem' -Chunks @(,$cpBytes) -DecoderTypeName $DecoderTypeName
        if ($eOem[0] -cne "状态`n") { throw 'Explicit oem override failed' }
        $u16Bytes = $utf16le.GetBytes("状态`n")
        $eU16 = Invoke-DecoderSequence -Mode 'utf16' -Chunks @(,$u16Bytes) -DecoderTypeName $DecoderTypeName
        if ($eU16[0] -cne "状态`n") { throw 'Explicit utf16 override failed' }
        return 'Verified explicit utf8, oem, and utf16 overrides'
    }

    # --- TIER 2 ---
    Invoke-TestCase -Id "$Prefix-T2-01" -Area '4' -Tier 2 -Name '2-byte UTF-8 false-positive "状态/系统/目录/未知/小" in CP936 falls back to Chinese' -Body {
        $target = "状态/系统/目录/未知/小`r`n"
        $cpBytes = $cp936.GetBytes($target)
        # Verify test vector itself is indeed valid strict UTF-8 (proving non-triviality)
        $strictU8 = New-Object System.Text.UTF8Encoding($false, $true)
        $null = $strictU8.GetString($cpBytes)

        $emits = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$cpBytes) -DecoderTypeName $DecoderTypeName
        if ($emits.Count -ne 1 -or $emits[0] -cne $target) {
            throw "False-positive fallback failed: got [$($emits -join '|')]"
        }
        return '100% 2-byte UTF-8 false positive decoded accurately as CP936 Chinese'
    }

    Invoke-TestCase -Id "$Prefix-T2-02" -Area '4' -Tier 2 -Name 'Mixed 3-byte CJK + 2-byte Latin ("状态 — é" and "状态 é") stays UTF-8' -Body {
        $v1 = "状态 — é`n"
        $v2 = "状态 é`n"
        $b1 = $utf8.GetBytes($v1)
        $b2 = $utf8.GetBytes($v2)
        $e1 = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$b1) -DecoderTypeName $DecoderTypeName
        $e2 = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$b2) -DecoderTypeName $DecoderTypeName
        if ($e1[0] -cne $v1 -or $e2[0] -cne $v2) {
            throw "Corrupted UTF-8 Latin/CJK line: e1=[$($e1[0])] e2=[$($e2[0])]"
        }
        return 'Preserved UTF-8 é and — alongside 3-byte CJK'
    }

    Invoke-TestCase -Id "$Prefix-T2-03" -Area '4' -Tier 2 -Name 'Non-sticky mixed-encoding stream (CP936 -> UTF-8 -> UTF-16LE BOM -> CP936 false-pos)' -Body {
        $c1 = $cp936.GetBytes("已成功`r`n")
        $c2 = $utf8.GetBytes("状态 关闭。`n")
        $c3 = [byte[]](0xFF, 0xFE, 0x0A, 0x4E, 0x0A, 0x00) # "上\n" in UTF-16LE
        $c4 = $cp936.GetBytes("状态`n") # 2-byte false positive
        $combined = New-Object byte[] ($c1.Length + $c2.Length + $c3.Length + $c4.Length)
        $pos = 0
        foreach ($arr in @($c1, $c2, $c3, $c4)) {
            [System.Buffer]::BlockCopy($arr, 0, $combined, $pos, $arr.Length)
            $pos += $arr.Length
        }
        $emits = Invoke-DecoderSequence -Mode 'auto' -Chunks @(,$combined) -DecoderTypeName $DecoderTypeName
        if ($emits.Count -ne 4 -or
            $emits[0] -cne "已成功`r`n" -or
            $emits[1] -cne "状态 关闭。`n" -or
            $emits[2] -cne ([char]0x4E0A + "`n") -or
            $emits[3] -cne "状态`n") {
            throw "Mixed stream mismatch: $($emits | ConvertTo-Json -Compress)"
        }
        return 'Decoded 4-encoding mixed single stream cleanly without stickiness'
    }

    Invoke-TestCase -Id "$Prefix-T2-04" -Area '4' -Tier 2 -Name '64 KB (65536) cap BVA: 65535 buffered, 65536 splits mid-UTF-8 & mid-CP936 losslessly, 65537' -Body {
        $emits65535 = New-Object 'System.Collections.Generic.List[string]'
        $dec1 = New-Object $DecoderTypeName('auto', ([System.Action[string]]{ param($s) $emits65535.Add($s) | Out-Null }))
        $b65535 = [byte[]](0x61) * 65535
        $dec1.Feed($b65535, 0, $b65535.Length)
        if ($emits65535.Count -ne 0) { throw "65535 bytes should remain buffered, got $($emits65535.Count) emits" }
        $dec1.Feed([byte[]](0x61, 0x62), 0, 2) # 65537 total
        $dec1.FlushEof()
        if ($emits65535.Count -ne 2 -or $emits65535[0].Length -ne 65536 -or $emits65535[1] -cne 'b') {
            throw "65537 ASCII split mismatch: count=$($emits65535.Count) len0=$($emits65535[0].Length)"
        }

        # 65534 'a' + E7 8A (split 3-byte UTF-8 '状' at 65536) + B6 at 65537
        $part1 = New-Object byte[] 65536
        for ($i = 0; $i -lt 65534; $i++) { $part1[$i] = 0x61 }
        $part1[65534] = 0xE7; $part1[65535] = 0x8A
        $eU8 = Invoke-DecoderSequence -Mode 'auto' -Chunks @($part1, [byte[]](0xB6)) -DecoderTypeName $DecoderTypeName
        if ($eU8.Count -ne 2 -or $eU8[0].Length -ne 65534 -or $eU8[1] -cne '状') {
            throw "64KB mid-UTF-8 split failed: count=$($eU8.Count) tail=$($eU8[1])"
        }

        # 65535 'a' + D7 (split 2-byte CP936 '状' at 65536) + B4 at 65537
        $part2 = New-Object byte[] 65536
        for ($i = 0; $i -lt 65535; $i++) { $part2[$i] = 0x61 }
        $part2[65535] = 0xD7
        $eCp = Invoke-DecoderSequence -Mode 'auto' -Chunks @($part2, [byte[]](0xB4)) -DecoderTypeName $DecoderTypeName
        if ($eCp.Count -ne 2 -or $eCp[0].Length -ne 65535 -or $eCp[1] -cne '状') {
            throw "64KB mid-CP936 split failed: count=$($eCp.Count) tail=$($eCp[1])"
        }
        return '65535/65536/65537 and 64KB mid-UTF8/mid-CP936 splits passed losslessly'
    }

    Invoke-TestCase -Id "$Prefix-T2-05" -Area '4' -Tier 2 -Name 'Idle holdback (1+2/2+1/3+1 UTF-8, CP936 lead, double idle no-op, IsValidStrictUtf8 invariant)' -Body {
        # 1+2 UTF-8 split ('Hi ' + E7 | 8A B6)
        $e1 = Invoke-DecoderSequence -Mode 'auto' -IdleAfterEach -Chunks @([byte[]](0x48, 0x69, 0x20, 0xE7), [byte[]](0x8A, 0xB6)) -DecoderTypeName $DecoderTypeName
        if ($e1.Count -ne 2 -or $e1[0] -cne 'Hi ' -or $e1[1] -cne '状') { throw "1+2 UTF-8 split failed: $($e1 -join '|')" }

        # 2+1 UTF-8 split ('Hi ' + E7 8A | B6)
        $e2 = Invoke-DecoderSequence -Mode 'auto' -IdleAfterEach -Chunks @([byte[]](0x48, 0x69, 0x20, 0xE7, 0x8A), [byte[]](0xB6)) -DecoderTypeName $DecoderTypeName
        if ($e2.Count -ne 2 -or $e2[0] -cne 'Hi ' -or $e2[1] -cne '状') { throw "2+1 UTF-8 split failed: $($e2 -join '|')" }

        # 3+1 4-byte UTF-8 split ('Hi ' + F0 9F 98 | 80 -> U+1F600)
        $e3 = Invoke-DecoderSequence -Mode 'auto' -IdleAfterEach -Chunks @([byte[]](0x48, 0x69, 0x20, 0xF0, 0x9F, 0x98), [byte[]](0x80)) -DecoderTypeName $DecoderTypeName
        $emoji = [System.Char]::ConvertFromUtf32(0x1F600)
        if ($e3.Count -ne 2 -or $e3[0] -cne 'Hi ' -or $e3[1] -cne $emoji) { throw "3+1 4B UTF-8 split failed: $($e3 -join '|')" }

        # CP936 split (D6 D0 B9 | FA -> '中', '国')
        $e4 = Invoke-DecoderSequence -Mode 'auto' -IdleAfterEach -Chunks @([byte[]](0xD6, 0xD0, 0xB9), [byte[]](0xFA)) -DecoderTypeName $DecoderTypeName
        if ($e4.Count -ne 2 -or $e4[0] -cne '中' -or $e4[1] -cne '国') { throw "CP936 split failed: $($e4 -join '|')" }

        # Double idle on lone lead byte [E7] must emit 0 lines until remaining bytes arrive
        $emitsDbl = New-Object 'System.Collections.Generic.List[string]'
        $dec = New-Object $DecoderTypeName('auto', ([System.Action[string]]{ param($s) $emitsDbl.Add($s) | Out-Null }))
        $dec.Feed([byte[]](0xE7), 0, 1)
        $dec.FlushIdle()
        $dec.FlushIdle()
        if ($emitsDbl.Count -ne 0) { throw "Double FlushIdle on lone lead byte emitted $($emitsDbl.Count) times" }
        $dec.Feed([byte[]](0x8A, 0xB6), 0, 2)
        $dec.FlushIdle()
        if ($emitsDbl.Count -ne 1 -or $emitsDbl[0] -cne '状') { throw "Failed to complete held-back UTF-8 char" }

        return 'All split UTF-8/CP936 holdback and double-idle invariants passed'
    }

    Invoke-TestCase -Id "$Prefix-T2-06" -Area '4' -Tier 2 -Name 'FlushEof emits dangling byte without hanging and strips UTF-8 EF BB BF BOM' -Body {
        $eBom = Invoke-DecoderSequence -Mode 'auto' -Chunks @([byte[]](0xEF, 0xBB, 0xBF, 0xE7, 0x8A, 0xB6, 0x0A)) -DecoderTypeName $DecoderTypeName
        if ($eBom.Count -ne 1 -or $eBom[0] -cne "状`n") { throw "Failed to strip UTF-8 BOM: $($eBom[0])" }

        $eEof = Invoke-DecoderSequence -Mode 'auto' -Chunks @([byte[]](0x41, 0xE7)) -DecoderTypeName $DecoderTypeName
        if ($eEof.Count -ne 1 -or $eEof[0].Length -lt 2) { throw "FlushEof dropped dangling byte" }
        return 'UTF-8 BOM stripped cleanly and FlushEof drained dangling byte'
    }
}

# Run self-test vectors against embedded reference LineDecoder
Run-AllDecoderVectors -DecoderTypeName 'AeTestDecoder.LineDecoder' -Prefix 'A4'

# Tier 2 #7: Live timed StreamPump (200 ms) on real Windows native binaries
Invoke-TestCase -Id 'A4-T2-07' -Area '4' -Tier 2 -Name 'Live timed 200ms StreamPump on icacls.exe, netsh.exe, cmd /u, and delayed-stdin choice.exe' -Body {
    $runBinary = {
        param([string]$File, [string]$ArgStr, [int]$DelayStdinMs = -1, [string]$StdinText = '')
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $File
        $psi.Arguments = $ArgStr
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardInput = ($DelayStdinMs -ge 0)
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)

        $pump = New-Object AeTestDecoder.TimedStreamPump('auto', 200)
        try {
            if ($DelayStdinMs -ge 0) {
                [AeTestDecoder.TimedStreamPump]::ScheduleDelayedWrite($p.StandardInput, $DelayStdinMs, $StdinText)
            }
            $pump.PumpStream($p.StandardOutput.BaseStream)
            $null = $p.WaitForExit(10000)
            if (-not $p.HasExited) { $p.Kill(); throw "$File hung" }
            $emitsOut = $pump.GetEmits()
        }
        finally {
            $pump.Dispose()
        }
        return ,$emitsOut
    }

    # 1. icacls.exe (CP936 + bare \n + \r\n)
    $icaclsOut = (& $runBinary 'icacls.exe' "`"$env:TEMP`"")
    $icaclsFull = ($icaclsOut | ForEach-Object { $_.Text }) -join ''
    if ($icaclsFull -notmatch '已成功处理') { throw "icacls CP936 mojibake: $icaclsFull" }

    # 2. netsh.exe (UTF-8)
    $netshOut = (& $runBinary 'netsh.exe' 'advfirewall show allprofiles state')
    $netshFull = ($netshOut | ForEach-Object { $_.Text }) -join ''
    if ($netshFull -notmatch '状态' -or $netshFull -notmatch '确定') { throw "netsh UTF-8 mojibake: $netshFull" }

    # 3. cmd /u (BOM-less UTF-16LE)
    $cmdUOut = (& $runBinary 'cmd.exe' '/u /c echo Hello 状态')
    $cmdUFull = ($cmdUOut | ForEach-Object { $_.Text }) -join ''
    if ($cmdUFull -notmatch 'Hello 状态') { throw "cmd /u UTF-16LE failed: $cmdUFull" }

    # 4. choice.exe /C YN /M "状态" with 500 ms delayed stdin -> prompt must flush at 150-380 ms BEFORE stdin!
    $choiceOut = (& $runBinary 'choice.exe' '/C YN /M "状态"' 500 "Y`r`n")
    $promptEv = $choiceOut | Where-Object { $_.Text -match '状态 \[Y,N\]\?' } | Select-Object -First 1
    if (-not $promptEv) { throw "choice.exe prompt missing: $(($choiceOut | ForEach-Object { $_.Text }) -join '|')" }
    if ($promptEv.Ms -ge 480) { throw "choice.exe prompt did not idle-flush before 500ms stdin (flushed at $($promptEv.Ms) ms)" }

    return "icacls/netsh/cmd-u clean; choice.exe prompt idle-flushed at $($promptEv.Ms) ms (<500ms stdin)"
}

# --- REPO INTEGRATION (-RepoRoot\runner\Invoke-ElevatedRunner.ps1) ---
if ($RepoRoot) {
    Invoke-TestCase -Id 'A4-REPO-01' -Area '4' -Tier 1 -Name 'Repo Invoke-ElevatedRunner.ps1 AST C# LineDecoder compilation & stream-pump wiring' -Body {
        $runnerPath = Join-Path $RepoRoot 'runner\Invoke-ElevatedRunner.ps1'
        if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
            throw "Missing runner: $runnerPath"
        }
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($runnerPath, [ref]$tokens, [ref]$errs)
        if ($null -ne $errs -and $errs.Count -gt 0) {
            throw "Runner PS 5.1 parse error: $($errs[0].Message)"
        }

        $rawSrc = [System.IO.File]::ReadAllText($runnerPath, (New-Object System.Text.UTF8Encoding($false, $true)))
        if ($rawSrc -match 'SetConsoleOutputCP') {
            throw 'Runner must NOT call SetConsoleOutputCP'
        }
        foreach ($reqToken in @('FlushEof', 'unchecked((int)')) {
            if ($rawSrc -notmatch [regex]::Escape($reqToken)) {
                throw "Runner missing required pump/output token: $reqToken"
            }
        }
        if ($rawSrc -notmatch 'FlushIdle|FlushIfIdle') {
            throw 'Runner missing required idle-flush token: FlushIdle|FlushIfIdle'
        }
        if ($rawSrc -notmatch '\[Console\]::Write|Console\.Write') {
            throw 'Runner missing required console tee token: [Console]::Write|Console.Write'
        }

        # Extract C# Add-Type string literals (inline OR variable-assigned) and test compilation + LineDecoder in an isolated child PS5.1 process
        $varStrings = @{}
        $assignAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
        foreach ($aa in $assignAsts) {
            if ($aa.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $vName = $aa.Left.VariablePath.UserPath
                $rhsExpr = $null
                if ($aa.Right -is [System.Management.Automation.Language.CommandExpressionAst]) {
                    $rhsExpr = $aa.Right.Expression
                }
                if ($rhsExpr -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                    ($rhsExpr -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $rhsExpr.NestedExpressions.Count -eq 0)) {
                    if ($rhsExpr.Value.Length -gt 200) {
                        $varStrings[$vName] = $rhsExpr.Value
                    }
                }
            }
        }

        $cmdAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        $csBlocks = New-Object 'System.Collections.Generic.List[string]'
        foreach ($ca in $cmdAsts) {
            if ($ca.GetCommandName() -eq 'Add-Type') {
                foreach ($el in $ca.CommandElements) {
                    if (($el -is [System.Management.Automation.Language.StringConstantExpressionAst] -or ($el -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $el.NestedExpressions.Count -eq 0)) -and $el.Value.Length -gt 200) {
                        if (-not $csBlocks.Contains($el.Value)) { $csBlocks.Add($el.Value) | Out-Null }
                    }
                    elseif ($el -is [System.Management.Automation.Language.VariableExpressionAst]) {
                        $vn = $el.VariablePath.UserPath
                        if ($varStrings.ContainsKey($vn) -and -not $csBlocks.Contains($varStrings[$vn])) {
                            $csBlocks.Add($varStrings[$vn]) | Out-Null
                        }
                    }
                }
            }
        }
        if ($csBlocks.Count -eq 0) {
            throw 'No C# Add-Type blocks extracted from Invoke-ElevatedRunner.ps1'
        }

        $tempProbeDir = Join-Path $env:TEMP ("ae-repo-dec-" + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tempProbeDir -Force | Out-Null
        try {
            $probeScript = Join-Path $tempProbeDir 'probe_runner_decoder.ps1'
            $joinedCs = ($csBlocks | ForEach-Object {
                $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($_))
                "`$cs = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$b64')); Add-Type -TypeDefinition `$cs -Language CSharp -ReferencedAssemblies @('System.Core')"
            }) -join "`r`n"

            $verifyBody = @"
$joinedCs
`$t = 'AgentElevation.LineDecoder' -as [type]
if (-not `$t) {
    `$t = [AppDomain]::CurrentDomain.GetAssemblies() |
        ForEach-Object { try { `$_.GetTypes() } catch { @() } } |
        Where-Object {
            `$_.Name -eq 'LineDecoder' -and
            `$_.GetMethod('Feed') -and
            (`$_.GetMethod('FlushIdle') -or `$_.GetMethod('FlushIfIdle')) -and
            `$_.GetMethod('FlushEof')
        } | Select-Object -First 1
}
if (-not `$t) { throw 'LineDecoder type not found in Invoke-ElevatedRunner.ps1 Add-Type blocks' }
`$feedParamCount = `$t.GetMethod('Feed').GetParameters().Count
`$hasFlushIfIdle = (`$null -ne `$t.GetMethod('FlushIfIdle'))
`$cp936 = [System.Text.Encoding]::GetEncoding(936)
`$utf8 = New-Object System.Text.UTF8Encoding(`$false)
`$utf16le = [System.Text.Encoding]::Unicode
function RunVec([string]`$mode, [byte[][]]`$chunks, [bool]`$idle) {
    `$list = New-Object 'System.Collections.Generic.List[string]'
    `$cb = [System.Action[string]]{ param(`$s) `$list.Add(`$s) | Out-Null }
    `$dec = [Activator]::CreateInstance(`$t, @(`$mode, `$cb))
    [long]`$nowMs = 0
    foreach (`$c in `$chunks) {
        `$nowMs += 10
        if (`$feedParamCount -eq 4) {
            `$dec.Feed(`$c, 0, `$c.Length, `$nowMs)
        } else {
            `$dec.Feed(`$c, 0, `$c.Length)
        }
        if (`$idle) {
            `$nowMs += 250
            if (`$hasFlushIfIdle) {
                `$dec.FlushIfIdle(`$nowMs, 200)
            } else {
                `$dec.FlushIdle()
            }
        }
    }
    `$dec.FlushEof()
    return ,`$list.ToArray()
}
`$v1 = RunVec 'auto' @(,(`$cp936.GetBytes("状态/系统/目录/未知/小`r`n"))) `$false
if (`$v1[0] -cne "状态/系统/目录/未知/小`r`n") { throw "Repo LineDecoder failed CP936 false-pos: `$(`$v1[0])" }
`$v2 = RunVec 'auto' @(,(`$utf8.GetBytes("状态 — é`n"))) `$false
if (`$v2[0] -cne "状态 — é`n") { throw "Repo LineDecoder failed mixed UTF-8: `$(`$v2[0])" }
`$v3 = RunVec 'auto' @(,([byte[]](0xFF,0xFE,0x0A,0x4E,0x0A,0x00))) `$false
if (`$v3[0] -cne ([char]0x4E0A + "`n")) { throw "Repo LineDecoder failed UTF-16LE U+4E0A" }
`$v3b = RunVec 'auto' @(,([byte[]](0xFF,0xFE,0x0A,0x4E,0x0A,0x00,0x0B,0x4E,0x0A,0x00))) `$false
if (`$v3b.Count -ne 2 -or `$v3b[0] -cne ([char]0x4E0A + "`n") -or `$v3b[1] -cne ([char]0x4E0B + "`n")) { throw "Repo LineDecoder failed UTF-16LE multi-line CJK" }
`$v3c = RunVec 'auto' @(,(`$utf16le.GetBytes("A`nB`n"))) `$false
if (`$v3c.Count -ne 2 -or `$v3c[0] -cne "A`n" -or `$v3c[1] -cne "B`n") { throw "Repo LineDecoder failed BOM-less UTF-16LE bare-LF" }
`$v4 = RunVec 'auto' @(([byte[]](0x48,0x69,0x20,0xE7)), ([byte[]](0x8A,0xB6))) `$true
if (`$v4.Count -ne 2 -or `$v4[0] -cne 'Hi ' -or `$v4[1] -cne '状') { throw "Repo LineDecoder failed 1+2 idle holdback" }
`$p64 = New-Object byte[] 65536
for (`$i=0; `$i -lt 65534; `$i++) { `$p64[`$i] = 0x61 }
`$p64[65534] = 0xE7; `$p64[65535] = 0x8A
`$v5 = RunVec 'auto' @(`$p64, ([byte[]](0xB6))) `$false
if (`$v5.Count -ne 2 -or `$v5[0].Length -ne 65534 -or `$v5[1] -cne '状') { throw "Repo LineDecoder failed 64KB UTF-8 split" }
Write-Output 'REPO_DECODER_OK'
"@
            [System.IO.File]::WriteAllText($probeScript, $verifyBody, (New-Object System.Text.UTF8Encoding($true)))
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'powershell.exe'
            $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$probeScript`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $p = [System.Diagnostics.Process]::Start($psi)
            $so = $p.StandardOutput.ReadToEnd()
            $se = $p.StandardError.ReadToEnd()
            $null = $p.WaitForExit(15000)
            if ($p.ExitCode -ne 0 -or $so -notmatch 'REPO_DECODER_OK') {
                throw "Repo LineDecoder probe failed (exit=$($p.ExitCode)): out=$so err=$se"
            }
            return "Compiled Invoke-ElevatedRunner.ps1 C# blocks and passed all live AgentElevation.LineDecoder vectors"
        }
        finally {
            Remove-Item -LiteralPath $tempProbeDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

$total = $results.Count
$passedCount = @($results | Where-Object { $_.passed }).Count
$failedCount = $total - $passedCount

if ($JsonReport) {
    $reportObj = [pscustomobject]@{
        module  = 'Test-Decoder.ps1'
        summary = [pscustomobject]@{ total = $total; passed = $passedCount; failed = $failedCount }
        results = $results
    }
    $utf8NoBomOut = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($JsonReport, ($reportObj | ConvertTo-Json -Depth 6), $utf8NoBomOut)
}

Write-Host ("Area 4 Summary: {0}/{1} passed ({2} failed)" -f $passedCount, $total, $failedCount)
if ($failedCount -gt 0) { exit 1 }
exit 0
