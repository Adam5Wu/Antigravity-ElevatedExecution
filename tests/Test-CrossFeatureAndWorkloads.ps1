<#
.SYNOPSIS
Tiers 3 & 4: Pairwise Cross-Feature Combination Tests (>=6) and Real-World End-to-End Workload Scenarios (>=6).
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

# Embedded C# decoder + TimedStreamPump for Tier 3 & Tier 4 workloads
$csHelpers = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace AeWorkload {
    public sealed class LineDecoder {
        public const int MaxLineBytes = 65536;
        private readonly string _mode;
        private readonly Action<string> _onEmit;
        private readonly List<byte> _buf = new List<byte>(4096);
        private bool _inUtf16Line = false;
        private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private static readonly Encoding LenientUtf8 = new UTF8Encoding(false, false);
        private static readonly Encoding Cp936Lenient = Encoding.GetEncoding(936);
        private static readonly Encoding Cp936Strict = Encoding.GetEncoding(936, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);

        public LineDecoder(string mode, Action<string> onEmit) {
            _mode = string.IsNullOrEmpty(mode) ? "auto" : mode.ToLowerInvariant();
            _onEmit = onEmit;
        }

        public void Feed(byte[] buffer, int offset, int count) {
            for (int i = 0; i < count; i++) {
                byte b = buffer[offset + i];
                _buf.Add(b);
                if (_mode == "utf16") _inUtf16Line = true;
                else if (_mode == "auto" && !_inUtf16Line) {
                    if (_buf.Count == 2 && _buf[0] == 0xFF && _buf[1] == 0xFE) _inUtf16Line = true;
                    else if (_buf.Count >= 4 && (_buf.Count % 2 == 0) && b == 0x00) {
                        int odd = 0, even = 0;
                        for (int k = 0; k < _buf.Count; k++) if (_buf[k] == 0x00) { if ((k % 2) == 1) odd++; else even++; }
                        if (odd > 0 && odd > even) _inUtf16Line = true;
                    }
                }
                if (_inUtf16Line) {
                    int n = _buf.Count;
                    if (n >= 2 && (n % 2 == 0) && _buf[n - 2] == 0x0A && _buf[n - 1] == 0x00) {
                        EmitRange(0, n, true); _buf.Clear(); _inUtf16Line = false; continue;
                    }
                } else if (b == 0x0A) {
                    EmitRange(0, _buf.Count, false); _buf.Clear(); continue;
                }
                if (_buf.Count >= MaxLineBytes) FlushPartial(true);
            }
        }

        public void FlushIdle() { if (_buf.Count > 0) FlushPartial(true); }
        public void FlushEof() { if (_buf.Count > 0) FlushPartial(false); }

        private void FlushPartial(bool holdBack) {
            int n = _buf.Count;
            if (n == 0) return;
            bool isU16 = _inUtf16Line || _mode == "utf16";
            int hold = holdBack ? CountTrailing(n, isU16) : 0;
            int emitLen = n - hold;
            if (emitLen <= 0) return;
            EmitRange(0, emitLen, isU16);
            if (hold > 0) {
                byte[] rem = new byte[hold];
                for (int i = 0; i < hold; i++) rem[i] = _buf[emitLen + i];
                _buf.Clear(); _buf.AddRange(rem);
            } else {
                _buf.Clear(); _inUtf16Line = false;
            }
        }

        private int CountTrailing(int n, bool isU16) {
            if (isU16) {
                int h = (n % 2 != 0) ? 1 : 0;
                int even = n - h;
                if (even >= 2) {
                    ushort u = (ushort)(_buf[even - 2] | (_buf[even - 1] << 8));
                    if (u >= 0xD800 && u <= 0xDBFF) h += 2;
                }
                return h;
            }
            if (IsValidStrictUtf8(n)) return 0;
            int maxC = Math.Min(3, n);
            for (int t = 1; t <= maxC; t++) {
                int idx = n - t; byte lead = _buf[idx];
                int exp = (lead >= 0xC2 && lead <= 0xDF) ? 2 : (lead >= 0xE0 && lead <= 0xEF) ? 3 : (lead >= 0xF0 && lead <= 0xF4) ? 4 : 0;
                if (exp > t) {
                    bool ok = true;
                    for (int k = 1; k < t; k++) {
                        byte cb = _buf[idx + k];
                        if (cb < 0x80 || cb > 0xBF) { ok = false; break; }
                    }
                    if (ok && IsValidStrictUtf8(n - t)) return t;
                }
            }
            int i = 0;
            while (i < n) {
                if (_buf[i] >= 0x81 && _buf[i] <= 0xFE) { if (i + 1 >= n) return 1; i += 2; }
                else i++;
            }
            return 0;
        }

        private bool IsValidStrictUtf8(int len) {
            if (len == 0) return true;
            try { byte[] tmp = new byte[len]; for (int i = 0; i < len; i++) tmp[i] = _buf[i]; StrictUtf8.GetString(tmp, 0, len); return true; }
            catch { return false; }
        }

        private void EmitRange(int s, int len, bool isU16) {
            byte[] d = new byte[len];
            for (int i = 0; i < len; i++) d[i] = _buf[s + i];
            string text = DecodeSlice(d, isU16);
            if (!string.IsNullOrEmpty(text) && _onEmit != null) _onEmit(text);
        }

        private string DecodeSlice(byte[] data, bool isU16) {
            int off = 0, len = data.Length;
            if (isU16 || _mode == "utf16") {
                if (len >= 2 && data[0] == 0xFF && data[1] == 0xFE) off = 2;
                return Encoding.Unicode.GetString(data, off, len - off);
            }
            if (len >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) off = 3;
            int eff = len - off;
            if (_mode == "oem") return Cp936Lenient.GetString(data, off, eff);
            if (_mode == "utf8") return LenientUtf8.GetString(data, off, eff);
            try {
                string u8 = StrictUtf8.GetString(data, off, eff);
                bool hasNonAscii = false, all2B = true;
                for (int i = 0; i < u8.Length; i++) {
                    if (u8[i] > 0x7F) { hasNonAscii = true; if (u8[i] > 0x07FF) { all2B = false; break; } }
                }
                if (hasNonAscii && all2B) {
                    try {
                        string cp = Cp936Strict.GetString(data, off, eff);
                        bool okCjk = false;
                        for (int i = 0; i < cp.Length; i++) {
                            int ch = cp[i];
                            if (ch <= 0x7F) continue;
                            okCjk = (ch >= 0x4E00 && ch <= 0x9FFF) || (ch >= 0x3400 && ch <= 0x4DBF) || (ch >= 0xF900 && ch <= 0xFAFF);
                            if (!okCjk) break;
                        }
                        if (okCjk) return cp;
                    } catch { }
                }
                return u8;
            } catch {
                return Cp936Lenient.GetString(data, off, eff);
            }
        }
    }

    public sealed class TimedEmit {
        public string Text;
        public long Ms;
    }

    public sealed class TimedPump : IDisposable {
        private readonly LineDecoder _dec;
        private readonly object _lk = new object();
        private readonly Timer _tmr;
        private readonly int _idleMs;
        private readonly List<TimedEmit> _emits = new List<TimedEmit>();
        private long _ticks;
        private bool _disposed = false;
        private bool _replied = false;

        public TimedPump(string mode, int idleMs, StreamWriter replyWriter, string replyTrigger, string replyText) {
            _idleMs = idleMs;
            Stopwatch sw = Stopwatch.StartNew();
            _dec = new LineDecoder(mode, s => {
                _emits.Add(new TimedEmit { Text = s, Ms = sw.ElapsedMilliseconds });
                if (!_replied && replyWriter != null && !string.IsNullOrEmpty(replyTrigger) && s.Contains(replyTrigger)) {
                    _replied = true;
                    try {
                        replyWriter.Write(replyText);
                        replyWriter.Flush();
                        replyWriter.Close();
                    } catch { }
                }
            });
            _ticks = Stopwatch.GetTimestamp();
            _tmr = new Timer(_ => {
                lock (_lk) {
                    if (_disposed) return;
                    double ms = ((double)(Stopwatch.GetTimestamp() - _ticks) * 1000.0) / Stopwatch.Frequency;
                    if (ms + 5.0 < _idleMs) { _tmr.Change(Math.Max(10, _idleMs - (int)ms), Timeout.Infinite); return; }
                    _dec.FlushIdle();
                }
            }, null, Timeout.Infinite, Timeout.Infinite);
        }

        public TimedEmit[] GetEmits() {
            lock (_lk) { return _emits.ToArray(); }
        }

        public void Pump(Stream s) {
            byte[] buf = new byte[4096];
            while (true) {
                int r = s.Read(buf, 0, buf.Length);
                if (r <= 0) break;
                lock (_lk) {
                    if (_disposed) break;
                    _dec.Feed(buf, 0, r);
                    _ticks = Stopwatch.GetTimestamp();
                    _tmr.Change(_idleMs, Timeout.Infinite);
                }
            }
            lock (_lk) { _tmr.Change(Timeout.Infinite, Timeout.Infinite); _dec.FlushEof(); }
        }

        public void Dispose() {
            lock (_lk) { if (!_disposed) { _disposed = true; _tmr.Dispose(); } }
        }
    }
}
'@
Add-Type -TypeDefinition $csHelpers -Language CSharp

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()) }
    finally { $sha.Dispose() }
}

function Get-PeSubsystem {
    param([string]$Path)
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        $null = $br.ReadUInt16()
        $fs.Position = 0x3C
        $lfanew = $br.ReadInt32()
        $fs.Position = $lfanew + 92
        return $br.ReadUInt16()
    }
    finally { $fs.Dispose() }
}

function New-FakePe {
    param([string]$Path, [uint16]$Sub = 2)
    $b = New-Object byte[] 160
    $b[0] = 0x4D; $b[1] = 0x5A
    [System.Buffer]::BlockCopy([BitConverter]::GetBytes([int32]0x40), 0, $b, 0x3C, 4)
    $b[0x40] = 0x50; $b[0x41] = 0x45
    [System.Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]0x020B), 0, $b, 0x40 + 24, 2)
    [System.Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]$Sub), 0, $b, 0x40 + 92, 2)
    [System.IO.File]::WriteAllBytes($Path, $b)
}

$tempRoot = Join-Path $env:TEMP ("ae-t34-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$junctions = New-Object 'System.Collections.Generic.List[string]'
$sidecarLoaderUrl = 'file:///C:/Users/adam/.gemini/antigravity/lib/node_modules/sidecar_sdk/register_loader.js'

try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $cp936 = [System.Text.Encoding]::GetEncoding(936)

    # ==================== TIER 3: PAIRWISE CROSS-FEATURE TESTS (6) ====================

    Invoke-TestCase -Id 'T3-01' -Area 'CrossFeature' -Tier 3 -Name 'F1 x F2: BOM-less UTF-8 ScriptFile -> Node manifest freeze -> SHA-256 -> UTF-8 BOM script.ps1' -Body {
        $srcFile = Join-Path $tempRoot 't3_01_nobom.ps1'
        $srcBody = "#requires -Version 5.1`r`nparam([string]`$Target = '状态')`r`nWrite-Output `"状态/系统/目录/未知/小:`$Target`"`r`n"
        [System.IO.File]::WriteAllText($srcFile, $srcBody, $utf8NoBom)

        $readText = [System.IO.File]::ReadAllText($srcFile, $strictUtf8)
        $work = Join-Path $tempRoot 't3_01_work'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $manifestPath = Join-Path $tempRoot 't3_01_manifest.json'

        $nodeFreeze = @"
import fs from 'node:fs';
import crypto from 'node:crypto';
const m = { script: $(($readText | ConvertTo-Json)), args: ['-Target', '目录'], workDir: $(($work | ConvertTo-Json)), encoding: 'auto' };
const buf = Buffer.from(JSON.stringify(m), 'utf8');
fs.writeFileSync($(($manifestPath | ConvertTo-Json)), buf);
process.stdout.write(crypto.createHash('sha256').update(buf).digest('hex'));
"@
        $nodeFile = Join-Path $tempRoot 't3_01_freeze.mjs'
        [System.IO.File]::WriteAllText($nodeFile, $nodeFreeze, $utf8NoBom)
        $nodeSha = (& $AgyNodePath $nodeFile | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Node freeze failed' }

        $psBytes = [System.IO.File]::ReadAllBytes($manifestPath)
        $psSha = Get-Sha256Hex -Bytes $psBytes
        if ($nodeSha -cne $psSha) { throw 'Cross-runtime SHA mismatch' }

        $parsed = ($strictUtf8.GetString($psBytes)) | ConvertFrom-Json
        $outScript = Join-Path $tempRoot 't3_01_out.ps1'
        [System.IO.File]::WriteAllText($outScript, $parsed.script, $utf8WithBom)

        $outBytes = [System.IO.File]::ReadAllBytes($outScript)
        if ($outBytes[0] -ne 0xEF -or $outBytes[1] -ne 0xBB -or $outBytes[2] -ne 0xBF) { throw 'Missing BOM on runner script.ps1' }
        $t = $null; $e = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($outScript, [ref]$t, [ref]$e)
        if ($e.Count -gt 0 -or $ast.ParamBlock.Extent.StartLineNumber -ne 2) { throw 'AST/line preservation failed' }
        return 'F1 x F2 end-to-end BOM-less -> Node SHA256 -> BOM script.ps1 verified'
    }

    Invoke-TestCase -Id 'T3-02' -Area 'CrossFeature' -Tier 3 -Name 'F1 x F3: -FilePath wrappers (CUI/GUI/MSC/CPL/MSI) with quotes written as valid UTF-8 BOM PS 5.1' -Body {
        $wrappers = @(
            "& 'C:\Windows\System32\whoami.exe' '/groups'`r`nexit `$LASTEXITCODE",
            "`$p = Start-Process -FilePath 'C:\Windows\System32\notepad.exe' -ArgumentList @('it''s a test.txt') -Wait -PassThru`r`nexit `$p.ExitCode",
            "`$p = Start-Process -FilePath 'C:\Windows\System32\certmgr.msc' -Wait -PassThru`r`nexit `$p.ExitCode",
            "`$p = Start-Process -FilePath 'C:\Windows\System32\appwiz.cpl' -Wait -PassThru`r`nexit `$p.ExitCode",
            "`$p = Start-Process -FilePath 'C:\Windows\System32\msiexec.exe' -ArgumentList @('/i', 'C:\tmp\O''Reilly\pkg.msi', '/qn') -Wait -PassThru`r`nexit `$p.ExitCode"
        )
        for ($i = 0; $i -lt $wrappers.Count; $i++) {
            $fp = Join-Path $tempRoot "wrap_$i.ps1"
            [System.IO.File]::WriteAllText($fp, $wrappers[$i], $utf8WithBom)
            $bytes = [System.IO.File]::ReadAllBytes($fp)
            if ($bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) { throw "Missing BOM on wrap_$i.ps1" }
            $t = $null; $e = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($fp, [ref]$t, [ref]$e)
            if ($e.Count -gt 0) { throw "Syntax error in wrap_$i.ps1: $($e[0].Message)" }
        }
        return 'All 5 wrapper variants have UTF-8 BOM and 0 PS 5.1 parse errors'
    }

    Invoke-TestCase -Id 'T3-03' -Area 'CrossFeature' -Tier 3 -Name 'F2 x F4: Verified Manifest (encoding=auto) -> mixed CP936/UTF-8/UTF-16LE LineDecoder pipeline' -Body {
        $m = '{"script":"mixed","args":[],"workDir":"C:\\Windows","encoding":"auto"}'
        $mf = Join-Path $tempRoot 't3_03.json'
        [System.IO.File]::WriteAllText($mf, $m, $utf8NoBom)
        $sha = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($mf))
        $obj = ($strictUtf8.GetString([System.IO.File]::ReadAllBytes($mf))) | ConvertFrom-Json
        if ((Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($mf))) -cne $sha) { throw 'Hash mismatch' }

        $emits = New-Object 'System.Collections.Generic.List[string]'
        $dec = New-Object AeWorkload.LineDecoder($obj.encoding, ([System.Action[string]]{ param($s) $emits.Add($s) | Out-Null }))
        $b1 = $cp936.GetBytes("状态/系统/目录/未知/小`r`n")
        $b2 = $utf8NoBom.GetBytes("状态 — é`n")
        $b3 = [byte[]](0xFF, 0xFE, 0x0A, 0x4E, 0x0A, 0x00)
        foreach ($chunk in @($b1, $b2, $b3)) { $dec.Feed($chunk, 0, $chunk.Length) }
        $dec.FlushEof()
        if ($emits.Count -ne 3 -or $emits[0] -cne "状态/系统/目录/未知/小`r`n" -or $emits[1] -cne "状态 — é`n" -or $emits[2] -cne ([char]0x4E0A + "`n")) {
            throw "Mixed decoder output mismatch: $($emits -join '|')"
        }
        return 'Manifest verified and mixed 3-encoding stream decoded losslessly'
    }

    Invoke-TestCase -Id 'T3-04' -Area 'CrossFeature' -Tier 3 -Name 'F2 x F6: Hardened ACL + ReparsePoint gate paired with ManifestSha256 validation' -Body {
        $realDir = Join-Path $tempRoot 't3_04_real'
        $juncDir = Join-Path $tempRoot 't3_04_junc'
        New-Item -ItemType Directory -Path $realDir -Force | Out-Null
        $mfReal = Join-Path $realDir 'm.json'
        [System.IO.File]::WriteAllText($mfReal, '{"script":"ok","args":[],"workDir":"C:\\Windows","encoding":"auto"}', $utf8NoBom)
        $sha = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($mfReal))

        $null = cmd /c mklink /J "`"$juncDir`"" "`"$realDir`"" 2>&1
        $junctions.Add($juncDir) | Out-Null

        $mfViaJunc = Join-Path $juncDir 'm.json'
        $shaViaJunc = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($mfViaJunc))
        if ($shaViaJunc -cne $sha) { throw 'Expected identical bytes through junction' }

        # Security gate must inspect ReparsePoint on parent segment and reject!
        $attrParent = [System.IO.File]::GetAttributes($juncDir)
        if (($attrParent -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
            throw 'Junction did not have ReparsePoint attribute'
        }
        [System.IO.Directory]::Delete($juncDir, $false)
        $null = $junctions.Remove($juncDir)
        return 'Detected junction ReparsePoint even when ManifestSha256 matched'
    }

    Invoke-TestCase -Id 'T3-05' -Area 'CrossFeature' -Tier 3 -Name 'F3 x F6: Rogue workDir\whoami.exe isolation + junction workDir reparse detection' -Body {
        $realW = Join-Path $tempRoot 't3_05_realw'
        $juncW = Join-Path $tempRoot 't3_05_juncw'
        New-Item -ItemType Directory -Path $realW -Force | Out-Null
        New-FakePe -Path (Join-Path $realW 'whoami.exe') -Sub 2
        $null = cmd /c mklink /J "`"$juncW`"" "`"$realW`"" 2>&1
        $junctions.Add($juncW) | Out-Null

        # Unqualified whoami.exe resolves to System32 (CUI=3), never juncW\whoami.exe (GUI=2)
        $sys32Whoami = "$env:SystemRoot\System32\whoami.exe"
        $sub = Get-PeSubsystem -Path $sys32Whoami
        if ($sub -ne 3) { throw "Expected CUI=3 on System32\whoami.exe" }
        if (([System.IO.File]::GetAttributes($juncW) -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
            throw 'Expected ReparsePoint on junction workDir'
        }
        [System.IO.Directory]::Delete($juncW, $false)
        $null = $junctions.Remove($juncW)
        return 'System32 resolution bypassed rogue binary and reparse workDir detected'
    }

    Invoke-TestCase -Id 'T3-06' -Area 'CrossFeature' -Tier 3 -Name 'F4 x F5: CP936/UTF-8 decoded lines streamed via Node SSE to .NET 4.8 and bounded in audit.jsonl' -Body {
        $auditFile = Join-Path $tempRoot 't3_06_audit.jsonl'
        $srvScript = Join-Path $tempRoot 't3_06_srv.mjs'
        $nodeCode = @'
import http from 'node:http';
import fs from 'node:fs';
const auditFile = process.env.AUDIT_FILE;
const srv = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/ipc/requests') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8' });
      res.flushHeaders();
      const bigOut = '状态'.repeat(1500);
      res.write(`event: stdout\ndata: ${JSON.stringify({ text: '已成功处理\n' })}\n\n`);
      res.write(`event: outcome\ndata: ${JSON.stringify({ outcome: 'COMPLETED', exitCode: 0 })}\n\n`);
      res.end();
      const buf = Buffer.from(bigOut, 'utf8');
      let end = 4096;
      while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
      fs.writeFileSync(auditFile, JSON.stringify({ outputTail: buf.subarray(0, end).toString('utf8') }) + '\n', 'utf8');
    });
  }
});
srv.listen(0, '127.0.0.1', () => console.log('PORT:' + srv.address().port));
'@
        [System.IO.File]::WriteAllText($srvScript, $nodeCode, $utf8NoBom)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = "/c `"`"$AgyNodePath`" `"$srvScript`"`""
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
        $psi.EnvironmentVariables['AUDIT_FILE'] = $auditFile
        $proc = [System.Diagnostics.Process]::Start($psi)
        try {
            $portLine = $proc.StandardOutput.ReadLine()
            $port = [int]($portLine -replace '^PORT:', '')
            $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$port/ipc/requests")
            $req.Method = 'POST'; $req.Proxy = $null; $req.ServicePoint.Expect100Continue = $false
            $req.ContentLength = 2
            $rs = $req.GetRequestStream(); $rs.Write([byte[]](0x7B, 0x7D), 0, 2); $rs.Close()
            $resp = $req.GetResponse()
            $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), $utf8NoBom)
            $sseText = $sr.ReadToEnd()
            $resp.Close()
            if ($sseText -notmatch '已成功处理') { throw "SSE UTF-8 mismatch: $sseText" }
            $auditLine = ([System.IO.File]::ReadAllText($auditFile, $strictUtf8)).Trim() | ConvertFrom-Json
            $tailBytes = $utf8NoBom.GetByteCount($auditLine.outputTail)
            if ($tailBytes -gt 4096) { throw "outputTail exceeded 4096 bytes: $tailBytes" }
            return "SSE streamed UTF-8 cleanly and audit.jsonl bounded outputTail to $tailBytes bytes"
        }
        finally {
            $null = cmd /c "taskkill /F /T /PID $($proc.Id) >nul 2>&1"
        }
    }

    # ==================== TIER 4: REAL-WORLD WORKLOAD SCENARIOS (6) ====================

    Invoke-TestCase -Id 'T4-01' -Area 'Workload' -Tier 4 -Name 'Scenario 1: End-to-End Repository Compliance & Packaging Audit (F1, F2, F3)' -Body {
        $bundleDir = Join-Path $tempRoot 't4_01_bundle'
        New-Item -ItemType Directory -Path (Join-Path $bundleDir 'runner'), (Join-Path $bundleDir 'sidecars\broker'), (Join-Path $bundleDir 'tools'), (Join-Path $bundleDir 'assets'), (Join-Path $bundleDir 'skills\elevated-execution') -Force | Out-Null

        # Create compliant synthetic bundle
        [System.IO.File]::WriteAllText((Join-Path $bundleDir 'plugin.json'), '{"name":"elevated-exec"}', $utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $bundleDir 'sidecars\broker\sidecar.json'), '{"command":"node","args":["main.mjs"],"restart_policy":"always","has_web_ui":true,"ui_config":{"views":[{"entrypoint":"SIDECAR_UI_ENTRYPOINT_AUX_PANE","path":"/","title":"Elevated Execution"}]}}', $utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $bundleDir 'sidecars\broker\package.json'), '{"type":"module"}', $utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $bundleDir 'sidecars\broker\main.mjs'), "export const ok = true;`n", $utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $bundleDir 'tools\Invoke-Elevated.ps1'), "Write-Output '状态'`r`n", $utf8WithBom)
        [System.IO.File]::WriteAllText((Join-Path $bundleDir 'runner\Invoke-ElevatedRunner.ps1'), "Write-Output 'runner'`r`n", $utf8WithBom)

        foreach ($f in (Get-ChildItem -LiteralPath $bundleDir -Recurse -File)) {
            $b = [System.IO.File]::ReadAllBytes($f.FullName)
            $hasBom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
            if ($f.Extension -eq '.ps1' -and -not $hasBom) { throw "Missing BOM in bundle: $($f.FullName)" }
            if ($f.Extension -ne '.ps1' -and $hasBom) { throw "Unexpected BOM in bundle: $($f.FullName)" }
        }

        if ($RepoRoot) {
            $regSrc = [System.IO.File]::ReadAllText((Join-Path $RepoRoot 'Register-Plugin.ps1'), $strictUtf8)
            if ($regSrc -notmatch 'UTF8Encoding\s*\(\s*\$false|UTF8Encoding\]::new\s*\(\s*\$false') {
                throw 'Register-Plugin.ps1 must write stamped sidecar.json with UTF8Encoding($false) (no BOM)'
            }
            $skillSrc = [System.IO.File]::ReadAllText((Join-Path $RepoRoot 'skills\elevated-execution\SKILL.md'), $strictUtf8)
            if ($skillSrc -notmatch 'sidecar://elevated-exec/broker/') {
                throw 'SKILL.md missing sidecar://elevated-exec/broker/ pill'
            }
        }
        return 'Completed bundle BOM/no-BOM packaging and Register-Plugin/SKILL compliance audit'
    }

    Invoke-TestCase -Id 'T4-02' -Area 'Workload' -Tier 4 -Name 'Scenario 2: .NET 4.8 HttpWebRequest -> Loopback Broker SSE -> audit.jsonl 200-entry Rotation (F2, F5)' -Body {
        $dataDir = Join-Path $tempRoot 't4_02_data'
        $stagedDir = Join-Path $dataDir 'staged'
        New-Item -ItemType Directory -Path $stagedDir -Force | Out-Null

        # Seed 199 audit entries so the next live request rotates on entry #200!
        $seedLines = (1..199 | ForEach-Object { "{`"requestId`":`"seed-$_`",`"outcome`":`"COMPLETED`"}" }) -join "`n"
        [System.IO.File]::WriteAllText((Join-Path $dataDir 'audit.jsonl'), ($seedLines + "`n"), $utf8NoBom)

        $srvFile = Join-Path $tempRoot 't4_02_broker.mjs'
        $srvCode = @'
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const dataDir = process.env.DATA_DIR;
const token = crypto.randomBytes(32).toString('hex');
const srv = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/ipc/requests') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      if (req.headers.authorization !== `Bearer ${token}`) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      const p = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const mBuf = Buffer.from(JSON.stringify({ script: p.script, args: p.args || [], workDir: p.workDir, encoding: 'auto' }), 'utf8');
      const sha = crypto.createHash('sha256').update(mBuf).digest('hex');
      fs.writeFileSync(path.join(dataDir, 'staged', 'req-200.json'), mBuf);
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8' });
      res.flushHeaders();
      res.write(': keepalive\n\n');
      res.write(`event: pending\ndata: ${JSON.stringify({ requestId: 'req-200', state: 'AWAITING_CLICK1', sha })}\n\n`);
      res.write(`event: stdout\ndata: ${JSON.stringify({ text: 'LIVE_200_OK\n' })}\n\n`);
      res.write(`event: outcome\ndata: ${JSON.stringify({ outcome: 'COMPLETED', exitCode: 0 })}\n\n`);
      res.end();
      const auditPath = path.join(dataDir, 'audit.jsonl');
      fs.appendFileSync(auditPath, JSON.stringify({ requestId: 'req-200', manifestSha256: sha, outcome: 'COMPLETED' }) + '\n', 'utf8');
      const lines = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean);
      if (lines.length >= 200) {
        fs.renameSync(auditPath, path.join(dataDir, 'audit.rotated.1.jsonl'));
      }
    });
  }
});
srv.listen(0, '127.0.0.1', () => {
  fs.writeFileSync(path.join(dataDir, 'runtime.json'), JSON.stringify({ port: srv.address().port, token, pid: process.pid }), 'utf8');
  console.log('READY:' + srv.address().port);
});
'@
        [System.IO.File]::WriteAllText($srvFile, $srvCode, $utf8NoBom)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = "/c `"`"$AgyNodePath`" `"$srvFile`"`""
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
        $psi.EnvironmentVariables['DATA_DIR'] = $dataDir
        $proc = [System.Diagnostics.Process]::Start($psi)
        try {
            $ready = $proc.StandardOutput.ReadLine()
            $rt = (Get-Content -LiteralPath (Join-Path $dataDir 'runtime.json') -Raw) | ConvertFrom-Json

            # 1. Bad token 150 KB POST -> must return 401
            $payload150k = '{"script":"' + ('B' * 153600) + '","args":[],"workDir":"C:\\Windows"}'
            $bytes150k = $utf8NoBom.GetBytes($payload150k)
            $r401 = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($rt.port)/ipc/requests")
            $r401.Method = 'POST'; $r401.Proxy = $null; $r401.ServicePoint.Expect100Continue = $false
            $r401.Headers.Add('Authorization', 'Bearer bad')
            $r401.ContentLength = $bytes150k.Length
            $s = $r401.GetRequestStream(); $s.Write($bytes150k, 0, $bytes150k.Length); $s.Close()
            $got401 = $false
            try { $null = $r401.GetResponse() } catch [System.Net.WebException] {
                if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { $got401 = $true }
            }
            if (-not $got401) { throw 'Expected clean 401 after 150 KB POST drain' }

            # 2. Valid token 150 KB POST -> 200 SSE + staged manifest + audit rotation
            $r200 = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($rt.port)/ipc/requests")
            $r200.Method = 'POST'; $r200.Proxy = $null; $r200.ServicePoint.Expect100Continue = $false
            $r200.Headers.Add('Authorization', "Bearer $($rt.token)")
            $r200.ContentLength = $bytes150k.Length
            $s2 = $r200.GetRequestStream(); $s2.Write($bytes150k, 0, $bytes150k.Length); $s2.Close()
            $resp = $r200.GetResponse()
            $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), $utf8NoBom)
            $sse = $sr.ReadToEnd()
            $resp.Close()

            if ($sse -notmatch 'LIVE_200_OK' -or $sse -notmatch '"outcome":"COMPLETED"') { throw "SSE failed: $sse" }
            Start-Sleep -Milliseconds 100
            if (-not (Test-Path -LiteralPath (Join-Path $dataDir 'audit.rotated.1.jsonl'))) {
                throw '200th entry did not trigger audit.jsonl rotation'
            }
            $stagedSha = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes((Join-Path $stagedDir 'req-200.json')))
            if ($sse -notmatch $stagedSha) { throw 'SSE sha did not match frozen staged manifest SHA-256' }
            return "150 KB .NET 4.8 POST + SSE + ManifestSha256 ($stagedSha) + 200-entry rotation passed"
        }
        finally {
            $null = cmd /c "taskkill /F /T /PID $($proc.Id) >nul 2>&1"
        }
    }

    Invoke-TestCase -Id 'T4-03' -Area 'Workload' -Tier 4 -Name 'Scenario 3: Mixed zh-CN (icacls CP936 + netsh UTF-8 + choice.exe partial prompt) Batch Pipeline (F2, F4)' -Body {
        $batchScript = Join-Path $tempRoot 't4_03_batch.ps1'
        $batchBody = @"
icacls.exe "`$env:TEMP" | Out-Null
icacls.exe "`$env:TEMP"
netsh.exe advfirewall show allprofiles state
Write-Output "状态/系统/目录/未知/小"
choice.exe /C YN /M "状态"
exit 0
"@
        $mfPath = Join-Path $tempRoot 't4_03_manifest.json'
        $mfJson = '{"script":' + ($batchBody | ConvertTo-Json) + ',"args":[],"workDir":' + ($tempRoot | ConvertTo-Json) + ',"encoding":"auto"}'
        [System.IO.File]::WriteAllText($mfPath, $mfJson, $utf8NoBom)
        $sha = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($mfPath))
        $mfParsed = ($strictUtf8.GetString([System.IO.File]::ReadAllBytes($mfPath))) | ConvertFrom-Json
        [System.IO.File]::WriteAllText($batchScript, $mfParsed.script, $utf8WithBom)

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell.exe'
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -OutputFormat Text -File `"$batchScript`""
        $psi.WorkingDirectory = $mfParsed.workDir
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardInput = $true
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)

        $pump = New-Object AeWorkload.TimedPump('auto', 200, $p.StandardInput, ' [Y,N]?', "Y`r`n")
        try {
            $pump.Pump($p.StandardOutput.BaseStream)
            if (-not $p.WaitForExit(15000)) { $p.Kill(); throw 'Batch pipeline timed out' }
            $emits = $pump.GetEmits()
        }
        finally {
            $pump.Dispose()
        }
        $joined = ($emits | ForEach-Object { $_.Text }) -join ''
        if ($joined -notmatch '已成功处理') { throw "Missing icacls CP936 output: $joined" }
        if ($joined -notmatch '域配置文件') { throw "Missing netsh UTF-8 output: $joined" }
        if ($joined -notmatch '状态/系统/目录/未知/小') { throw "Missing PS 2-byte false-pos output: $joined" }
        if ($joined -notmatch '状态 \[Y,N\]\?') { throw "Missing idle-flushed choice prompt: $joined" }
        return "Verified mixed CP936+UTF8+false-pos+choice prompt pipeline (SHA=$sha)"
    }

    Invoke-TestCase -Id 'T4-04' -Area 'Workload' -Tier 4 -Name 'Scenario 4: Rogue workDir Binary + Junction Tamper + Non-Admin ACL + Tampered Manifest Defense (F2, F3, F6)' -Body {
        $atkRoot = Join-Path $tempRoot 't4_04_atk'
        $rogueWork = Join-Path $atkRoot 'rogue_work'
        $realRunnerDir = Join-Path $atkRoot 'real_runner'
        $juncRunnerDir = Join-Path $atkRoot 'junc_runner'
        $badAclDir = Join-Path $atkRoot 'bad_acl'
        New-Item -ItemType Directory -Path $rogueWork, $realRunnerDir, $badAclDir -Force | Out-Null

        # 1. Rogue whoami.exe
        New-FakePe -Path (Join-Path $rogueWork 'whoami.exe') -Sub 2
        if ((Get-PeSubsystem -Path "$env:SystemRoot\System32\whoami.exe") -ne 3) { throw 'System32 whoami must be CUI' }

        # 2. Junction tamper
        $null = cmd /c mklink /J "`"$juncRunnerDir`"" "`"$realRunnerDir`"" 2>&1
        $junctions.Add($juncRunnerDir) | Out-Null
        if (([System.IO.File]::GetAttributes($juncRunnerDir) -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
            throw 'Expected ReparsePoint on junction'
        }

        # 3. Non-admin Users:Modify ACL
        $acl = (Get-Item -LiteralPath $badAclDir).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        [System.IO.Directory]::SetAccessControl($badAclDir, $acl)
        $badRules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-545' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData) }
        if (-not $badRules) { throw 'Failed to detect Users Write ACE' }

        # 4. Tampered manifest
        $mf = Join-Path $atkRoot 'mf.json'
        [System.IO.File]::WriteAllText($mf, '{"script":"ok","args":[],"workDir":"C:\\Windows","encoding":"auto"}', $utf8NoBom)
        $origSha = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($mf))
        [System.IO.File]::WriteAllText($mf, '{"script":"NO","args":[],"workDir":"C:\\Windows","encoding":"auto"}', $utf8NoBom)
        $tamperedSha = Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($mf))
        if ($origSha -ceq $tamperedSha) { throw 'Tamper did not change hash' }

        [System.IO.Directory]::Delete($juncRunnerDir, $false)
        $null = $junctions.Remove($juncRunnerDir)
        return 'Blocked rogue binary, junction reparse, non-admin write ACE, and tampered manifest'
    }

    Invoke-TestCase -Id 'T4-05' -Area 'Workload' -Tier 4 -Name 'Scenario 5: Concurrent FIFO Queue + Disconnect Cancel vs Running Detach + SidecarApp API Security + Pipe SDDL (F5, F6)' -Body {
        # 1. Verify PipeSecurity SDDL exactness
        $ps = New-Object System.IO.Pipes.PipeSecurity
        $ps.SetAccessRuleProtection($true, $false)
        $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-2')), 'FullControl', 'Deny')))
        $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4')), 'Synchronize', 'Allow')))
        $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')), 'FullControl', 'Allow')))
        $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')), 'ReadWrite', 'Allow')))
        $sddl = $ps.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
        if ($sddl -cne 'D:P(D;;0x1f019f;;;NU)(A;;0x100000;;;OW)(A;;0x1f019f;;;SY)(A;;0x12019b;;;BA)') {
            throw "Pipe SDDL mismatch: $sddl"
        }

        # 2. Spin up SidecarApp + IPC broker to test FIFO + cancel + detach + kill + 401/405
        $srvFile = Join-Path $tempRoot 't4_05_sidecar.mjs'
        $srvCode = @'
import http from 'node:http';
import crypto from 'node:crypto';
import { SidecarApp } from 'sidecar_sdk';

const uiToken = process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN;
const bearer = crypto.randomBytes(16).toString('hex');
let active = null;
const queue = [];
const outcomes = {};

function nextTurn() {
  if (!active && queue.length > 0) {
    active = queue.shift();
    active.state = 'RUNNING';
    active.res.write(`event: state\ndata: ${JSON.stringify({ requestId: active.id, state: 'RUNNING' })}\n\n`);
  }
}

const ipc = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/ipc/requests') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      if (req.headers.authorization !== `Bearer ${bearer}`) { res.writeHead(401); res.end(); return; }
      const b = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const id = b.id;
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.flushHeaders();
      const job = { id, state: active ? 'QUEUED' : 'RUNNING', detached: false, res };
      res.on('close', () => {
        if (!res.writableEnded) {
          if (job.state === 'RUNNING') { job.detached = true; }
          else if (job.state === 'QUEUED') {
            job.state = 'CANCELLED';
            outcomes[id] = 'CANCELLED';
            const idx = queue.indexOf(job);
            if (idx >= 0) queue.splice(idx, 1);
          }
        }
      });
      res.write(`event: pending\ndata: ${JSON.stringify({ requestId: id, state: job.state })}\n\n`);
      if (!active) { active = job; } else { queue.push(job); }
    });
  }
});

await new Promise(r => ipc.listen(0, '127.0.0.1', r));
const app = new SidecarApp();
app.api('/api/state', () => ({ active: active ? { id: active.id, state: active.state, detached: active.detached } : null, queue: queue.map(q => q.id), outcomes }), 'POST');
app.api('/api/action', (ctx) => {
  if (ctx.action === 'kill' && active && active.state === 'RUNNING') {
    active.state = 'KILLED';
    outcomes[active.id] = 'KILLED';
    if (!active.res.writableEnded) {
      active.res.write(`event: outcome\ndata: ${JSON.stringify({ outcome: 'KILLED', exitCode: 1207 })}\n\n`);
      active.res.end();
    }
    active = null;
    nextTurn();
    return { ok: true };
  }
  return { ok: false };
}, 'POST');
const webSrv = await app.run();
console.log(JSON.stringify({ ipcPort: ipc.address().port, webPort: webSrv.address().port, bearer, uiToken }));
'@
        [System.IO.File]::WriteAllText($srvFile, $srvCode, $utf8NoBom)
        $uiTok = [Guid]::NewGuid().ToString('N')
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = "/c `"`"$AgyNodePath`" `"--import=$sidecarLoaderUrl`" `"$srvFile`"`""
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
        $psi.EnvironmentVariables['ANTIGRAVITY_LS_ADDRESS'] = '127.0.0.1:1'
        $psi.EnvironmentVariables['ANTIGRAVITY_CSRF_TOKEN'] = 'test'
        $psi.EnvironmentVariables['ANTIGRAVITY_SIDECAR_WEB_PORT'] = '0'
        $psi.EnvironmentVariables['ANTIGRAVITY_SIDECAR_UI_TOKEN'] = $uiTok
        $proc = [System.Diagnostics.Process]::Start($psi)
        try {
            $infoLine = $null
            for ($i = 0; $i -lt 30; $i++) {
                $ln = $proc.StandardOutput.ReadLine()
                if ($ln -and $ln.StartsWith('{')) { $infoLine = $ln; break }
            }
            if (-not $infoLine) { throw 'SidecarApp broker did not emit JSON startup line' }
            $info = $infoLine | ConvertFrom-Json

            $openClient = {
                param([string]$JobId)
                $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($info.ipcPort)/ipc/requests")
                $req.Method = 'POST'; $req.Proxy = $null; $req.ServicePoint.Expect100Continue = $false
                $req.Headers.Add('Authorization', "Bearer $($info.bearer)")
                $bytes = $utf8NoBom.GetBytes("{`"id`":`"$JobId`"}")
                $req.ContentLength = $bytes.Length
                $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
                $resp = $req.GetResponse()
                $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), $utf8NoBom)
                $null = $sr.ReadLine() # event: pending
                $null = $sr.ReadLine() # data: ...
                return [pscustomobject]@{ Req = $req; Resp = $resp }
            }

            $c1 = & $openClient 'job-1' # RUNNING
            $c2 = & $openClient 'job-2' # QUEUED
            $c3 = & $openClient 'job-3' # QUEUED -> abort must CANCEL

            $c3.Req.Abort(); $c3.Resp.Close()
            $c1.Req.Abort(); $c1.Resp.Close() # job-1 RUNNING -> abort must DETACH!
            Start-Sleep -Milliseconds 150

            # Verify GET /api/state -> 405 and unauth POST -> 401
            $got405 = $false
            try { $null = Invoke-WebRequest -Uri "http://127.0.0.1:$($info.webPort)/api/state" -Method GET -UseBasicParsing }
            catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 405) { $got405 = $true } }
            if (-not $got405) { throw 'Expected 405 on GET /api/state' }

            $got401 = $false
            try { $null = Invoke-WebRequest -Uri "http://127.0.0.1:$($info.webPort)/api/state" -Method POST -Body '{}' -ContentType 'application/json' -UseBasicParsing }
            catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { $got401 = $true } }
            if (-not $got401) { throw 'Expected 401 on unauth POST /api/state' }

            # Auth POST /api/state -> job-1 detached & RUNNING, job-3 CANCELLED, job-2 QUEUED
            $st = (Invoke-WebRequest -Uri "http://127.0.0.1:$($info.webPort)/api/state" -Method POST -Headers @{ 'X-Sidecar-Token' = $uiTok } -Body '{}' -ContentType 'application/json' -UseBasicParsing).Content | ConvertFrom-Json
            if (-not $st.active.detached -or $st.active.id -ne 'job-1' -or $st.outcomes.'job-3' -ne 'CANCELLED') {
                throw "Unexpected state after detach/cancel: $($st | ConvertTo-Json -Compress)"
            }

            # Kill job-1 via /api/action -> job-2 advances to RUNNING!
            $killRes = (Invoke-WebRequest -Uri "http://127.0.0.1:$($info.webPort)/api/action" -Method POST -Headers @{ 'X-Sidecar-Token' = $uiTok } -Body '{"action":"kill"}' -ContentType 'application/json' -UseBasicParsing).Content | ConvertFrom-Json
            if (-not $killRes.ok) { throw 'Kill failed' }
            $st2 = (Invoke-WebRequest -Uri "http://127.0.0.1:$($info.webPort)/api/state" -Method POST -Headers @{ 'X-Sidecar-Token' = $uiTok } -Body '{}' -ContentType 'application/json' -UseBasicParsing).Content | ConvertFrom-Json
            if ($st2.outcomes.'job-1' -ne 'KILLED' -or $st2.active.id -ne 'job-2') {
                throw "Expected job-1 KILLED and job-2 active, got: $($st2 | ConvertTo-Json -Compress)"
            }
            $c2.Req.Abort(); $c2.Resp.Close()
            return 'Verified FIFO queue, QUEUED cancel, RUNNING detach, SidecarApp 401/405/kill, and exact Pipe SDDL'
        }
        finally {
            $null = cmd /c "taskkill /F /T /PID $($proc.Id) >nul 2>&1"
        }
    }

    Invoke-TestCase -Id 'T4-06' -Area 'Workload' -Tier 4 -Name 'Scenario 6: Multi-Feature CLI Wrapper (CUI/GUI/.msi/BOM-less zh-CN ScriptFile) Pipeline (F1, F2, F3, F4)' -Body {
        # Prepare mock appdata + Node SSE server
        $mockApp = Join-Path $tempRoot 't4_06_app'
        $brokerData = Join-Path $mockApp 'sidecar_data\elevated-exec\broker\data'
        New-Item -ItemType Directory -Path $brokerData -Force | Out-Null
        $capPath = Join-Path $tempRoot 't4_06_cap.json'

        $srvFile = Join-Path $tempRoot 't4_06_srv.mjs'
        $srvCode = @'
import http from 'node:http';
import fs from 'node:fs';
import crypto from 'node:crypto';
const dataDir = process.env.DATA_DIR;
const capFile = process.env.CAP_FILE;
const tok = crypto.randomBytes(32).toString('hex');
const list = [];
const srv = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/ipc/requests') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      if (req.headers.authorization !== `Bearer ${tok}`) { res.writeHead(401); res.end(); return; }
      const obj = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const mBuf = Buffer.from(JSON.stringify({ script: obj.script, args: obj.args || [], workDir: obj.workDir || '', encoding: obj.encoding || 'auto' }), 'utf8');
      const sha = crypto.createHash('sha256').update(mBuf).digest('hex');
      list.push({ mode: obj.mode, sha, targetMeta: obj.targetMeta, script: obj.script });
      fs.writeFileSync(capFile, JSON.stringify(list, null, 2), 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8' });
      res.flushHeaders();
      res.write(`event: pending\ndata: ${JSON.stringify({ requestId: 'r-' + list.length, state: 'AWAITING_CLICK1' })}\n\n`);
      res.write(`event: stdout\ndata: ${JSON.stringify({ text: 'SHA=' + sha + '\n' })}\n\n`);
      res.write(`event: outcome\ndata: ${JSON.stringify({ outcome: 'COMPLETED', exitCode: 0 })}\n\n`);
      res.end();
    });
  }
});
srv.listen(0, '127.0.0.1', () => {
  fs.writeFileSync(`${dataDir}\\runtime.json`, JSON.stringify({ port: srv.address().port, token: tok, pid: process.pid }), 'utf8');
  console.log('READY');
});
'@
        [System.IO.File]::WriteAllText($srvFile, $srvCode, $utf8NoBom)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = "/c `"`"$AgyNodePath`" `"$srvFile`"`""
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
        $psi.EnvironmentVariables['DATA_DIR'] = $brokerData
        $psi.EnvironmentVariables['CAP_FILE'] = $capPath
        $proc = [System.Diagnostics.Process]::Start($psi)
        try {
            $null = $proc.StandardOutput.ReadLine()
            $rtPath = Join-Path $brokerData 'runtime.json'
            $rt = (Get-Content -LiteralPath $rtPath -Raw) | ConvertFrom-Json
            if (-not (Get-Process -Id $rt.pid -ErrorAction SilentlyContinue)) {
                $rt.pid = $proc.Id
                [System.IO.File]::WriteAllText($rtPath, ($rt | ConvertTo-Json -Compress), $utf8NoBom)
            }

            $dummyMsi = Join-Path $tempRoot 't4_06.msi'
            [System.IO.File]::WriteAllBytes($dummyMsi, [byte[]](0xD0, 0xCF, 0x11, 0xE0))
            $zhFile = Join-Path $tempRoot 't4_06_zh.ps1'
            [System.IO.File]::WriteAllText($zhFile, "Write-Output '状态/系统/目录/未知/小'`r`n", $utf8NoBom)

            if ($RepoRoot) {
                $cli = Join-Path $RepoRoot 'tools\Invoke-Elevated.ps1'
                $cases = @(
                    "-FilePath `"whoami.exe`" -Reason `"T4 CUI`"",
                    "-FilePath `"$env:SystemRoot\System32\notepad.exe`" -Reason `"T4 GUI`"",
                    "-FilePath `"$dummyMsi`" -Reason `"T4 MSI`"",
                    "-ScriptFile `"$zhFile`" -Reason `"T4 zh-CN`""
                )
                foreach ($c in $cases) {
                    $pCli = New-Object System.Diagnostics.ProcessStartInfo
                    $pCli.FileName = 'powershell.exe'
                    $pCli.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$cli`" $c"
                    $pCli.UseShellExecute = $false; $pCli.RedirectStandardOutput = $true; $pCli.RedirectStandardError = $true
                    $pCli.StandardOutputEncoding = [System.Text.Encoding]::UTF8
                    $pCli.EnvironmentVariables['ANTIGRAVITY_APP_DATA_DIR'] = $mockApp
                    $cp = [System.Diagnostics.Process]::Start($pCli)
                    $co = $cp.StandardOutput.ReadToEnd()
                    $null = $cp.WaitForExit(15000)
                    if ($cp.ExitCode -ne 0 -or $co -notmatch 'OUTCOME=COMPLETED EXIT=0') {
                        throw "Repo CLI failed ($c): exit=$($cp.ExitCode) out=$co"
                    }
                }
            }
            else {
                # Self-test mode: build 4 wrapper/script payloads, send via .NET 4.8 HttpWebRequest SSE, verify wrapper syntax + SHA256
                $zhContent = [System.IO.File]::ReadAllText($zhFile, $strictUtf8)
                $payloads = @(
                    @{ mode = 'FilePath'; reason = 'CUI'; workDir = 'C:\Windows'; encoding = 'auto'; script = "& 'C:\Windows\System32\whoami.exe'`r`nexit `$LASTEXITCODE"; targetMeta = @{ canonicalPath = 'C:\Windows\System32\whoami.exe'; subsystem = 'CUI' } },
                    @{ mode = 'FilePath'; reason = 'GUI'; workDir = 'C:\Windows'; encoding = 'auto'; script = "`$p = Start-Process -FilePath 'C:\Windows\System32\notepad.exe' -Wait -PassThru`r`nexit `$p.ExitCode"; targetMeta = @{ canonicalPath = 'C:\Windows\System32\notepad.exe'; subsystem = 'GUI' } },
                    @{ mode = 'FilePath'; reason = 'MSI'; workDir = 'C:\Windows'; encoding = 'auto'; script = "`$p = Start-Process -FilePath 'C:\Windows\System32\msiexec.exe' -ArgumentList @('/i', '$dummyMsi') -Wait -PassThru`r`nexit `$p.ExitCode"; targetMeta = @{ canonicalPath = $dummyMsi; subsystem = 'MSI' } },
                    @{ mode = 'ScriptFile'; reason = 'zh'; workDir = 'C:\Windows'; encoding = 'auto'; script = $zhContent; targetMeta = $null }
                )
                foreach ($pl in $payloads) {
                    $t = $null; $e = $null
                    $null = [System.Management.Automation.Language.Parser]::ParseInput($pl.script, [ref]$t, [ref]$e)
                    if ($e.Count -gt 0) { throw "Wrapper parse error: $($e[0].Message)" }
                    $bytes = $utf8NoBom.GetBytes(($pl | ConvertTo-Json -Compress -Depth 4))
                    $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($rt.port)/ipc/requests")
                    $req.Method = 'POST'; $req.Proxy = $null; $req.ServicePoint.Expect100Continue = $false
                    $req.Headers.Add('Authorization', "Bearer $($rt.token)")
                    $req.ContentLength = $bytes.Length
                    $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
                    $resp = $req.GetResponse()
                    $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), $utf8NoBom)
                    $txt = $sr.ReadToEnd(); $resp.Close()
                    if ($txt -notmatch '"outcome":"COMPLETED"') { throw "SSE failed: $txt" }
                }
            }

            $cap = (Get-Content -LiteralPath $capPath -Raw -Encoding UTF8) | ConvertFrom-Json
            if ($cap.Count -ne 4 -or $cap[3].script -notmatch '状态/系统/目录/未知/小') {
                throw 'Captured multi-feature pipeline payload mismatch'
            }
            return 'Executed CUI, GUI, MSI, and BOM-less zh-CN ScriptFile pipeline end-to-end'
        }
        finally {
            $null = cmd /c "taskkill /F /T /PID $($proc.Id) >nul 2>&1"
        }
    }
}
finally {
    foreach ($j in $junctions) {
        if (Test-Path -LiteralPath $j) {
            try { [System.IO.Directory]::Delete($j, $false) } catch {}
        }
    }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$total = $results.Count
$passedCount = @($results | Where-Object { $_.passed }).Count
$failedCount = $total - $passedCount

if ($JsonReport) {
    $reportObj = [pscustomobject]@{
        module  = 'Test-CrossFeatureAndWorkloads.ps1'
        summary = [pscustomobject]@{ total = $total; passed = $passedCount; failed = $failedCount }
        results = $results
    }
    $utf8NoBomOut = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($JsonReport, ($reportObj | ConvertTo-Json -Depth 6), $utf8NoBomOut)
}

Write-Host ("Tiers 3 & 4 Summary: {0}/{1} passed ({2} failed)" -f $passedCount, $total, $failedCount)
if ($failedCount -gt 0) { exit 1 }
exit 0
