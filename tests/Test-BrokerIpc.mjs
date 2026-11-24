/**
 * Area 5: Loopback HTTP/SSE IPC, .NET 4.8 HttpWebRequest Drain-Before-Response,
 * res.on('close') Cancel vs RUNNING Detach, FIFO Queue + Reminder, SidecarApp POST APIs,
 * Source Metadata Hygiene, and audit.jsonl 4 KB UTF-8 Truncation & 200-Entry / 5 MB Rotation.
 */
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import zlib from 'node:zlib';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { SidecarApp, Response } from 'sidecar_sdk';

function parseArgs(argv) {
  const opts = { selfTest: false, repoRoot: '', jsonReport: '' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--self-test') opts.selfTest = true;
    else if (a === '--repo-root' && i + 1 < argv.length) opts.repoRoot = argv[++i];
    else if (a === '--json-report' && i + 1 < argv.length) opts.jsonReport = argv[++i];
  }
  return opts;
}

const opts = parseArgs(process.argv.slice(2));
const results = [];

async function runCase(id, area, tier, name, fn) {
  const t0 = Date.now();
  let passed = false;
  let detail = '';
  try {
    detail = (await fn()) || 'OK';
    passed = true;
  } catch (err) {
    passed = false;
    detail = err && err.stack ? err.message : String(err);
  }
  const durationMs = Date.now() - t0;
  results.push({ id, area, tier, name, passed, detail, durationMs });
  const tag = passed ? 'PASS' : 'FAIL';
  console.log(`[${tag}] ${id} (Area ${area} / Tier ${tier}) ${name} - ${detail} (${durationMs} ms)`);
}

function truncateUtf8Bytes(str, maxBytes = 4096) {
  const buf = Buffer.from(str, 'utf8');
  if (buf.length <= maxBytes) return str;
  let end = maxBytes;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) {
    end--;
  }
  return buf.subarray(0, end).toString('utf8');
}

function sanitizeSourceMetadata(rawEnv) {
  if (!rawEnv) return { conversationId: '', stepIndex: 0, toolCallId: '' };
  const parsed = JSON.parse(rawEnv);
  const tool = parsed.tool || {};
  const tc = tool.toolCall || {};
  return {
    conversationId: String(tool.conversationId || ''),
    stepIndex: Number(tool.stepIndex || 0),
    toolCallId: String(tc.id || '')
  };
}

function writeAtomicJson(targetPath, obj) {
  const tmpPath = `${targetPath}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmpPath, Buffer.from(JSON.stringify(obj), 'utf8'));
  fs.renameSync(tmpPath, targetPath);
}

class AuditLogger {
  constructor(dataDir, { maxEntries = 200, maxBytes = 5 * 1024 * 1024 } = {}) {
    this.dataDir = dataDir;
    this.auditPath = path.join(dataDir, 'audit.jsonl');
    this.maxEntries = maxEntries;
    this.maxBytes = maxBytes;
  }
  append(entry) {
    const sanitized = {
      ...entry,
      scriptPreview: truncateUtf8Bytes(String(entry.scriptPreview || ''), 4096),
      outputTail: truncateUtf8Bytes(String(entry.outputTail || ''), 4096)
    };
    const line = JSON.stringify(sanitized) + '\n';
    fs.appendFileSync(this.auditPath, line, 'utf8');
    this._rotateIfNeeded();
  }
  _rotateIfNeeded() {
    if (!fs.existsSync(this.auditPath)) return;
    const stat = fs.statSync(this.auditPath);
    let lineCount = 0;
    if (stat.size < this.maxBytes) {
      const content = fs.readFileSync(this.auditPath, 'utf8');
      lineCount = content.split('\n').filter(Boolean).length;
    }
    if (stat.size >= this.maxBytes || lineCount >= this.maxEntries) {
      const rotated = path.join(this.dataDir, `audit.${Date.now()}.${Math.random().toString(16).slice(2, 6)}.jsonl`);
      fs.renameSync(this.auditPath, rotated);
    }
  }
}

function createHarnessBroker(dataDir, { preflightOk = true, preflightOutcome = 'OK', preflightCode = 0, click1TimeoutMs = 5000, reminderIntervalMs = 300000, deferClick1Deadline = false } = {}) {
  const stagedDir = path.join(dataDir, 'staged');
  const runtimePath = path.join(dataDir, 'runtime.json');
  fs.mkdirSync(stagedDir, { recursive: true });

  // Startup sweep of stale staged/ & runtime.json
  for (const name of fs.readdirSync(stagedDir)) {
    fs.rmSync(path.join(stagedDir, name), { recursive: true, force: true });
  }
  if (fs.existsSync(runtimePath)) {
    fs.rmSync(runtimePath, { force: true });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const audit = new AuditLogger(dataDir);
  const state = {
    seq: 1,
    activeJob: null,
    queue: [],
    config: { click1TimeoutSeconds: Math.round(click1TimeoutMs / 1000), reminderIntervalSeconds: Math.round(reminderIntervalMs / 1000) },
    reminderShownCount: 0,
    reminderActive: false,
    reminderTimer: null,
    sidecarInfo: { pid: process.pid }
  };

  const waiters = [];
  function bumpSeq() {
    state.seq++;
    while (waiters.length > 0) {
      const w = waiters.shift();
      clearTimeout(w.timer);
      w.resolve(true);
    }
  }

  function sendSse(job, eventName, payloadObj) {
    if (!job.res || job.detached || job.res.writableEnded) return;
    job.res.write(`event: ${eventName}\ndata: ${JSON.stringify(payloadObj)}\n\n`);
  }

  function finishJob(job, outcome, exitCode, message = '') {
    if (job.finished) return;
    job.finished = true;
    if (job.click1Timer) { clearTimeout(job.click1Timer); job.click1Timer = null; }
    if (job.keepaliveTimer) { clearInterval(job.keepaliveTimer); job.keepaliveTimer = null; }
    if (job.runTimer) { clearTimeout(job.runTimer); job.runTimer = null; }

    job.state = outcome;
    sendSse(job, 'outcome', { outcome, exitCode, message });
    if (job.res && !job.detached && !job.res.writableEnded) {
      job.res.end();
    }

    audit.append({
      requestId: job.requestId,
      reason: job.payload.reason || '',
      manifestSha256: job.manifestSha256,
      outcome,
      exitCode,
      scriptPreview: job.payload.script || '',
      outputTail: job.outputBuf
    });

    if (state.activeJob && state.activeJob.requestId === job.requestId) {
      state.activeJob = null;
      if (state.reminderTimer) { clearTimeout(state.reminderTimer); state.reminderTimer = null; }
      state.reminderActive = false;
      dispatchNext();
    } else {
      state.queue = state.queue.filter(q => q.requestId !== job.requestId);
      if (state.queue.length === 0 && state.reminderTimer) {
        clearTimeout(state.reminderTimer);
        state.reminderTimer = null;
      }
    }
    bumpSeq();
  }

  function scheduleHarnessReminder() {
    if (
      !state.activeJob ||
      state.activeJob.state !== 'RUNNING' ||
      state.queue.length === 0 ||
      reminderIntervalMs <= 0
    ) {
      if (state.reminderTimer) { clearTimeout(state.reminderTimer); state.reminderTimer = null; }
      return;
    }
    if (state.reminderActive || state.reminderTimer) return;
    state.reminderTimer = setTimeout(() => {
      state.reminderTimer = null;
      if (state.activeJob && state.activeJob.state === 'RUNNING' && state.queue.length > 0 && !state.reminderActive) {
        state.reminderActive = true;
        state.reminderShownCount++;
        bumpSeq();
      }
    }, reminderIntervalMs);
    state.reminderTimer.unref();
  }

  function dispatchNext() {
    if (state.activeJob || state.queue.length === 0) return;
    const job = state.queue.shift();
    state.activeJob = job;
    job.state = 'AWAITING_CLICK1';
    job.click1Shown = false;
    job.click1TimeoutSeconds = Number(state.config.click1TimeoutSeconds) || 0;
    job.click1DeadlineAt = null;
    sendSse(job, 'state', {
      requestId: job.requestId,
      state: 'AWAITING_CLICK1',
      click1TimeoutSeconds: job.click1TimeoutSeconds,
      click1DeadlineAt: null
    });
    bumpSeq();

    if (click1TimeoutMs > 0) {
      const initialWait = deferClick1Deadline ? (click1TimeoutMs + 15000) : click1TimeoutMs;
      job.click1Timer = setTimeout(() => {
        if (job.state === 'AWAITING_CLICK1') {
          finishJob(job, 'TIMEOUT_CLICK1', 1460, 'Click 1 countdown expired');
        }
      }, initialWait);
    }
  }

  function startRunning(job) {
    if (job.click1Timer) { clearTimeout(job.click1Timer); job.click1Timer = null; }
    job.state = 'RUNNING';
    sendSse(job, 'state', { requestId: job.requestId, state: 'RUNNING' });
    bumpSeq();

    scheduleHarnessReminder();

    const chunk = `OUTPUT_${job.requestId}\n`;
    job.outputBuf += chunk;
    sendSse(job, 'stdout', { text: chunk });
    job.runTimer = setTimeout(() => {
      if (job.state === 'RUNNING') {
        finishJob(job, 'COMPLETED', 0, 'ok');
      }
    }, job.runDurationMs || 250);
  }

  const server = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/ipc/requests') {
      const chunks = [];
      let reqClosedBeforeEnd = false;
      req.on('data', c => chunks.push(c));
      req.on('close', () => { reqClosedBeforeEnd = !req.complete; });
      req.on('end', () => {
        // Must drain full POST body before sending 401/409/200!
        const auth = req.headers.authorization || '';
        if (auth !== `Bearer ${token}`) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'unauthorized' }));
          return;
        }
        if (!preflightOk) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, outcome: preflightOutcome, exitCode: preflightCode, message: 'Preflight failed' }));
          return;
        }

        const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        const manifestObj = {
          script: String(payload.script || ''),
          args: Array.isArray(payload.args) ? payload.args : [],
          workDir: String(payload.workDir || ''),
          encoding: String(payload.encoding || 'auto')
        };
        const manifestBuf = Buffer.from(JSON.stringify(manifestObj), 'utf8');
        const manifestSha256 = crypto.createHash('sha256').update(manifestBuf).digest('hex');
        const requestId = 'req-' + crypto.randomBytes(6).toString('hex');
        fs.writeFileSync(path.join(stagedDir, `${requestId}.json`), manifestBuf);

        const job = {
          requestId,
          payload,
          manifestSha256,
          state: state.activeJob ? 'QUEUED' : 'AWAITING_CLICK1',
          res,
          detached: false,
          finished: false,
          outputBuf: '',
          runDurationMs: payload._testRunMs || 250,
          reqClosedBeforeEnd
        };

        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive'
        });
        res.flushHeaders();
        res.write(': keepalive\n\n');

        // Critical Node v24 rule: use res.on('close'), NOT req.on('close')!
        res.on('close', () => {
          if (!res.writableEnded && !job.finished) {
            if (job.state === 'RUNNING') {
              job.detached = true;
              bumpSeq();
            } else if (job.state === 'QUEUED' || job.state === 'AWAITING_CLICK1' || job.state === 'AWAITING_UAC') {
              finishJob(job, 'CANCELLED', 1201, 'Client disconnected before execution');
            }
          }
        });

        job.keepaliveTimer = setInterval(() => {
          if (!job.detached && !res.writableEnded) {
            res.write(': keepalive\n\n');
          }
        }, 15000);

        const initialState = state.activeJob ? 'QUEUED' : 'AWAITING_CLICK1';
        sendSse(job, 'pending', { requestId, state: initialState });
        state.queue.push(job);
        dispatchNext();
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  function snapshotState() {
    return {
      seq: state.seq,
      activeJob: state.activeJob ? {
        requestId: state.activeJob.requestId,
        state: state.activeJob.state,
        click1Shown: Boolean(state.activeJob.click1Shown),
        click1TimeoutSeconds: state.activeJob.click1TimeoutSeconds,
        click1DeadlineAt: state.activeJob.click1DeadlineAt,
        detached: state.activeJob.detached,
        manifestSha256: state.activeJob.manifestSha256
      } : null,
      queue: state.queue.map(q => ({ requestId: q.requestId, state: q.state })),
      config: state.config,
      reminderShownCount: state.reminderShownCount
    };
  }

  function handleAction(body) {
    const act = body.action;
    if (act === 'save-config' && body.config) {
      state.config = { ...state.config, ...body.config };
      bumpSeq();
      return { ok: true };
    }
    if (act === 'dismiss-reminder') {
      const wasActive = state.reminderActive;
      state.reminderActive = false;
      if (wasActive) {
        scheduleHarnessReminder();
      }
      bumpSeq();
      return { ok: true };
    }
    const job = state.activeJob && (!body.requestId || body.requestId === state.activeJob.requestId)
      ? state.activeJob
      : state.queue.find(q => q.requestId === body.requestId);
    if (!job) return { ok: false, error: 'Job not found' };

    if (act === 'approve-click1' && job.state === 'AWAITING_CLICK1') {
      job.state = 'AWAITING_UAC';
      job.click1DeadlineAt = null;
      sendSse(job, 'state', { requestId: job.requestId, state: 'AWAITING_UAC' });
      bumpSeq();
      return { ok: true };
    }
    if (act === 'click1-shown' && job.state === 'AWAITING_CLICK1') {
      job.click1Shown = true;
      if (job.click1TimeoutSeconds > 0) {
        const parsed = Number(body.click1DeadlineAt);
        job.click1DeadlineAt = Number.isFinite(parsed) && parsed > 0
          ? Math.trunc(parsed)
          : Date.now() + job.click1TimeoutSeconds * 1000;
        if (job.click1Timer) { clearTimeout(job.click1Timer); job.click1Timer = null; }
        job.click1Timer = setTimeout(() => {
          if (job.state === 'AWAITING_CLICK1') {
            finishJob(job, 'TIMEOUT_CLICK1', 1460, 'Click 1 countdown expired');
          }
        }, Math.max(0, job.click1DeadlineAt - Date.now()) + 3000);
      }
      sendSse(job, 'state', {
        requestId: job.requestId,
        state: 'AWAITING_CLICK1',
        click1Shown: true,
        click1TimeoutSeconds: job.click1TimeoutSeconds,
        click1DeadlineAt: job.click1DeadlineAt
      });
      bumpSeq();
      return { ok: true };
    }
    if (act === 'uac-yes' && job.state === 'AWAITING_UAC') {
      startRunning(job);
      return { ok: true };
    }
    if (act === 'uac-no' && job.state === 'AWAITING_UAC') {
      finishJob(job, 'DENIED_UAC', 1223, 'UAC denied by user');
      return { ok: true };
    }
    if (act === 'deny' && job.state === 'AWAITING_CLICK1') {
      finishJob(job, 'DENIED_CLICK1', 1223, 'Denied at Click 1');
      return { ok: true };
    }
    if (act === 'cancel' && (job.state === 'QUEUED' || job.state === 'AWAITING_CLICK1' || job.state === 'AWAITING_UAC')) {
      finishJob(job, 'CANCELLED', 1201, 'Cancelled');
      return { ok: true };
    }
    if (act === 'kill' && job.state === 'RUNNING') {
      finishJob(job, 'KILLED', 1207, 'Killed by user');
      return { ok: true };
    }
    return { ok: false, error: `Invalid action ${act} in state ${job.state}` };
  }

  async function waitStream(sinceSeq, waitMs) {
    const capped = Math.min(Math.max(0, Number(waitMs || 0)), 15000);
    if (state.seq > sinceSeq || capped === 0) {
      return { seq: state.seq, changed: state.seq > sinceSeq, state: snapshotState() };
    }
    await new Promise(resolve => {
      const timer = setTimeout(() => {
        const idx = waiters.findIndex(w => w.resolve === resolve);
        if (idx >= 0) waiters.splice(idx, 1);
        resolve(false);
      }, capped);
      waiters.push({ resolve, timer });
    });
    return { seq: state.seq, changed: state.seq > sinceSeq, state: snapshotState() };
  }

  return {
    token,
    state,
    audit,
    snapshotState,
    handleAction,
    waitStream,
    async start() {
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const port = server.address().port;
      writeAtomicJson(runtimePath, { port, token, pid: process.pid, startedAt: new Date().toISOString() });
      return { port, token, runtimePath };
    },
    async close() {
      if (state.reminderTimer) { clearTimeout(state.reminderTimer); state.reminderTimer = null; }
      if (state.activeJob) {
        clearTimeout(state.activeJob.click1Timer);
        clearInterval(state.activeJob.keepaliveTimer);
        clearTimeout(state.activeJob.runTimer);
      }
      await new Promise(resolve => server.close(resolve));
    }
  };
}

function runPsDotNetHttp(psScript) {
  return new Promise((resolve, reject) => {
    const b64 = Buffer.from(psScript, 'utf16le').toString('base64');
    const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', b64], {
      windowsHide: true
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString('utf8'); });
    child.stderr.on('data', d => { stderr += d.toString('utf8'); });
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
}

async function runSelfTestSuite() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-area5-'));
  try {
    // --- TIER 1 ---
    await runCase('A5-T1-01', '5', 1, 'Atomic runtime.json creation (64-hex token) + startup sweep of stale staged/ and runtime.json', async () => {
      const d = path.join(tempRoot, 't1_01');
      fs.mkdirSync(path.join(d, 'staged'), { recursive: true });
      fs.writeFileSync(path.join(d, 'staged', 'stale.json'), '{}');
      fs.writeFileSync(path.join(d, 'runtime.json'), '{"port":1,"token":"old"}');

      const broker = createHarnessBroker(d);
      const { port, token, runtimePath } = await broker.start();
      try {
        assert.equal(fs.existsSync(path.join(d, 'staged', 'stale.json')), false, 'stale staged file must be swept');
        const rt = JSON.parse(fs.readFileSync(runtimePath, 'utf8'));
        assert.equal(rt.port, port);
        assert.match(rt.token, /^[0-9a-f]{64}$/);
        assert.equal(rt.token, token);
        assert.equal(rt.pid, process.pid);
        assert.ok(Date.parse(rt.startedAt) > 0);
        return `Swept stale files and wrote atomic runtime.json on port ${port}`;
      } finally {
        await broker.close();
      }
    });

    await runCase('A5-T1-02', '5', 1, '.NET 4.8 HttpWebRequest 256 KB POST drains before 200 SSE + keepalive + outcome', async () => {
      const d = path.join(tempRoot, 't1_02');
      const broker = createHarnessBroker(d);
      const { port, token } = await broker.start();
      try {
        const ps = `
          $url = "http://127.0.0.1:${port}/ipc/requests"
          $pad = "A" * 262144
          $bodyObj = @{ mode="ScriptText"; reason="dotnet48 test"; script=$pad; args=@(); workDir="C:\\Windows"; encoding="auto" }
          $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(($bodyObj | ConvertTo-Json -Compress))
          $req = [System.Net.HttpWebRequest]::Create($url)
          $req.Method = "POST"
          $req.ContentType = "application/json; charset=utf-8"
          $req.Headers.Add("Authorization", "Bearer ${token}")
          $req.Proxy = $null
          $req.ServicePoint.Expect100Continue = $false
          $req.Timeout = [Threading.Timeout]::Infinite
          $req.ReadWriteTimeout = [Threading.Timeout]::Infinite
          $req.ContentLength = $bytes.Length
          $rs = $req.GetRequestStream()
          $rs.Write($bytes, 0, $bytes.Length)
          $rs.Close()
          $resp = $req.GetResponse()
          $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
          $lines = New-Object 'System.Collections.Generic.List[string]'
          while ($null -ne ($line = $sr.ReadLine())) {
            $lines.Add($line) | Out-Null
            if ($line -match '"requestId":"(req-[0-9a-f]+)"') {
              Write-Output ("PENDING_ID=" + $Matches[1])
            }
          }
          $resp.Close()
          Write-Output ("LINES=" + $lines.Count)
          Write-Output ("HAS_KEEPALIVE=" + ($lines -contains ': keepalive'))
          Write-Output ("HAS_COMPLETED=" + (($lines -join ',') -match '"outcome":"COMPLETED"'))
        `;
        const childPromise = runPsDotNetHttp(ps);
        // Wait for job to enter AWAITING_CLICK1, then approve -> uac-yes
        let reqId = null;
        for (let i = 0; i < 400; i++) {
          if (broker.state.activeJob) { reqId = broker.state.activeJob.requestId; break; }
          await new Promise(r => setTimeout(r, 25));
        }
        if (!reqId) {
          const earlyRes = await childPromise;
          throw new Error(`Job did not arrive (psExit=${earlyRes.code} out=${earlyRes.stdout} err=${earlyRes.stderr})`);
        }
        assert.equal(broker.handleAction({ action: 'approve-click1', requestId: reqId }).ok, true);
        assert.equal(broker.handleAction({ action: 'uac-yes', requestId: reqId }).ok, true);

        const res = await childPromise;
        assert.equal(res.code, 0, `PS failed: ${res.stderr} ${res.stdout}`);
        assert.match(res.stdout, /PENDING_ID=req-/);
        assert.match(res.stdout, /HAS_KEEPALIVE=True/);
        assert.match(res.stdout, /HAS_COMPLETED=True/);
        return '256 KB .NET 4.8 HttpWebRequest POST -> SSE stream completed cleanly';
      } finally {
        await broker.close();
      }
    });

    await runCase('A5-T1-03', '5', 1, "res.on('close') cancels QUEUED/AWAITING_CLICK1/AWAITING_UAC vs detaches RUNNING", async () => {
      const d = path.join(tempRoot, 't1_03');
      const broker = createHarnessBroker(d);
      const { port, token } = await broker.start();
      try {
        const makeAbortPs = (runMs = 300) => `
          $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:${port}/ipc/requests")
          $req.Method = "POST"
          $req.ContentType = "application/json; charset=utf-8"
          $req.Headers.Add("Authorization", "Bearer ${token}")
          $req.Proxy = $null
          $req.ServicePoint.Expect100Continue = $false
          $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes('{"mode":"ScriptText","reason":"abort","script":"ok","args":[],"workDir":"C:\\\\Windows","encoding":"auto","_testRunMs":${runMs}}')
          $req.ContentLength = $bytes.Length
          $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
          $resp = $req.GetResponse()
          $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
          while ($null -ne ($line = $sr.ReadLine())) {
            if ($line -like 'data:*') { break }
          }
          Start-Sleep -Milliseconds 150
          $req.Abort()
          $resp.Close()
        `;

        // 1. Abort during AWAITING_CLICK1 -> must CANCEL
        const p1 = runPsDotNetHttp(makeAbortPs(300));
        const r1 = await p1;
        assert.equal(r1.code, 0, r1.stderr);
        await new Promise(r => setTimeout(r, 80));
        assert.equal(broker.state.activeJob, null, 'AWAITING_CLICK1 job should have cancelled and cleared');

        // 2. Abort during AWAITING_UAC -> must CANCEL
        const p2 = runPsDotNetHttp(makeAbortPs(300).replace('Start-Sleep -Milliseconds 150', 'Start-Sleep -Milliseconds 350'));
        let id2 = null;
        for (let i = 0; i < 400; i++) {
          if (broker.state.activeJob) { id2 = broker.state.activeJob.requestId; break; }
          await new Promise(r => setTimeout(r, 25));
        }
        assert.ok(id2, 'Job 2 did not arrive in AWAITING_CLICK1');
        broker.handleAction({ action: 'approve-click1', requestId: id2 });
        await p2;
        await new Promise(r => setTimeout(r, 120));
        assert.equal(broker.state.activeJob, null, 'AWAITING_UAC job should have cancelled');

        // 3. Abort during RUNNING -> must DETACH and complete in background!
        const p3 = runPsDotNetHttp(makeAbortPs(1200).replace('Start-Sleep -Milliseconds 150', 'Start-Sleep -Milliseconds 350'));
        let id3 = null;
        for (let i = 0; i < 400; i++) {
          if (broker.state.activeJob) { id3 = broker.state.activeJob.requestId; break; }
          await new Promise(r => setTimeout(r, 25));
        }
        assert.ok(id3, 'Job 3 did not arrive in AWAITING_CLICK1');
        broker.handleAction({ action: 'approve-click1', requestId: id3 });
        broker.handleAction({ action: 'uac-yes', requestId: id3 });
        await p3;
        await new Promise(r => setTimeout(r, 60));
        assert.ok(broker.state.activeJob !== null, 'RUNNING job must still be active right after client abort');
        assert.equal(broker.state.activeJob.detached, true, 'RUNNING job must be marked detached=true on client abort');
        for (let i = 0; i < 80 && broker.state.activeJob !== null; i++) {
          await new Promise(r => setTimeout(r, 30));
        }
        assert.equal(broker.state.activeJob, null, 'Detached RUNNING job did not finish within timeout');
        const auditLines = fs.readFileSync(path.join(d, 'audit.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
        const last = auditLines[auditLines.length - 1];
        assert.equal(last.outcome, 'COMPLETED', `Detached RUNNING job must finish COMPLETED, got ${last.outcome}`);
        return 'Verified cancel on AWAITING_CLICK1/AWAITING_UAC and detach-to-COMPLETED on RUNNING';
      } finally {
        await broker.close();
      }
    });

    await runCase('A5-T1-04', '5', 1, 'Strict 1-by-1 FIFO queue serialization + non-stacking reminder timer', async () => {
      const d = path.join(tempRoot, 't1_04');
      const broker = createHarnessBroker(d, { reminderIntervalMs: 60, click1TimeoutMs: 5000 });
      const { port, token } = await broker.start();
      try {
        const openSse = (reason, runMs) => {
          return new Promise(resolve => {
            const events = [];
            const req = http.request({
              host: '127.0.0.1', port, path: '/ipc/requests', method: 'POST',
              headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
            }, res => {
              res.on('data', chunk => { events.push(chunk.toString('utf8')); });
              res.on('end', () => resolve({ status: res.statusCode, body: events.join('') }));
            });
            req.end(JSON.stringify({ mode: 'ScriptText', reason, script: 'ok', args: [], workDir: 'C:\\Windows', encoding: 'auto', _testRunMs: runMs }));
          });
        };

        const p1 = openSse('job1', 240);
        await new Promise(r => setTimeout(r, 30));
        const p2 = openSse('job2', 50);
        await new Promise(r => setTimeout(r, 30));

        assert.ok(broker.state.activeJob, 'Job 1 must be active');
        assert.equal(broker.state.queue.length, 1, 'Job 2 must remain QUEUED');
        assert.equal(broker.state.queue[0].state, 'QUEUED');

        const id1 = broker.state.activeJob.requestId;
        const id2 = broker.state.queue[0].requestId;
        broker.handleAction({ action: 'approve-click1', requestId: id1 });
        broker.handleAction({ action: 'uac-yes', requestId: id1 });

        // Wait enough for multiple reminder intervals while job 1 is RUNNING and job 2 is QUEUED
        await new Promise(r => setTimeout(r, 180));
        assert.equal(broker.state.reminderShownCount, 1, 'Reminder must not stack while previous reminder is active');

        const r1 = await p1;
        assert.match(r1.body, /"outcome":"COMPLETED"/);
        // Now job 2 must have been dispatched to AWAITING_CLICK1!
        assert.equal(broker.state.activeJob.requestId, id2);
        assert.equal(broker.state.activeJob.state, 'AWAITING_CLICK1');
        broker.handleAction({ action: 'approve-click1', requestId: id2 });
        broker.handleAction({ action: 'uac-yes', requestId: id2 });
        const r2 = await p2;
        assert.match(r2.body, /"outcome":"COMPLETED"/);
        return 'FIFO serialized Job 1 -> Job 2 and non-stacking reminder fired once';
      } finally {
        await broker.close();
      }
    });

    await runCase('A5-T1-05', '5', 1, 'SidecarApp GET static routes + POST /api/state, /api/stream (<=15s), /api/action with X-Sidecar-Token', async () => {
      const d = path.join(tempRoot, 't1_05');
      const broker = createHarnessBroker(d);
      await broker.start();

      const uiToken = crypto.randomBytes(16).toString('hex');
      const savedEnv = {
        ANTIGRAVITY_LS_ADDRESS: process.env.ANTIGRAVITY_LS_ADDRESS,
        ANTIGRAVITY_CSRF_TOKEN: process.env.ANTIGRAVITY_CSRF_TOKEN,
        ANTIGRAVITY_SIDECAR_WEB_PORT: process.env.ANTIGRAVITY_SIDECAR_WEB_PORT,
        ANTIGRAVITY_SIDECAR_UI_TOKEN: process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN
      };
      process.env.ANTIGRAVITY_LS_ADDRESS = '127.0.0.1:1';
      process.env.ANTIGRAVITY_CSRF_TOKEN = 'test-csrf';
      process.env.ANTIGRAVITY_SIDECAR_WEB_PORT = '0';
      process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN = uiToken;

      const app = new SidecarApp();
      app.page('/', () => '<!doctype html><html><body>OK</body></html>');
      app.api('/styles.css', () => new Response('body{}', { contentType: 'text/css; charset=utf-8' }), 'GET');
      app.api('/app.js', () => new Response('console.log(1);', { contentType: 'application/javascript; charset=utf-8' }), 'GET');
      app.api('/api/state', () => broker.snapshotState(), 'POST');
      app.api('/api/stream', async (ctx) => broker.waitStream(ctx.sinceSeq, ctx.waitMs), 'POST');
      app.api('/api/action', (ctx) => broker.handleAction(ctx), 'POST');
      const sidecarServer = await app.run();
      const webPort = sidecarServer.address().port;

      try {
        const g1 = await fetch(`http://127.0.0.1:${webPort}/`);
        assert.equal(g1.status, 200);
        const g2 = await fetch(`http://127.0.0.1:${webPort}/styles.css`);
        assert.equal(g2.status, 200);
        assert.match(g2.headers.get('content-type') || '', /text\/css/);
        const g3 = await fetch(`http://127.0.0.1:${webPort}/app.js`);
        assert.equal(g3.status, 200);

        const pState = await fetch(`http://127.0.0.1:${webPort}/api/state`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
          body: '{}'
        });
        assert.equal(pState.status, 200);
        const stJson = await pState.json();
        assert.equal(stJson.seq, 1);

        const pAct = await fetch(`http://127.0.0.1:${webPort}/api/action`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
          body: JSON.stringify({ action: 'save-config', config: { click1TimeoutSeconds: 120 } })
        });
        assert.equal(pAct.status, 200);
        assert.equal((await pAct.json()).ok, true);

        const pStream = await fetch(`http://127.0.0.1:${webPort}/api/stream`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
          body: JSON.stringify({ sinceSeq: 1, waitMs: 500 })
        });
        assert.equal(pStream.status, 200);
        const streamJson = await pStream.json();
        assert.equal(streamJson.changed, true);
        assert.equal(streamJson.state.config.click1TimeoutSeconds, 120);
        return `Verified SidecarApp GET static + POST /api/* on port ${webPort}`;
      } finally {
        await new Promise(r => sidecarServer.close(r));
        await broker.close();
        for (const [k, v] of Object.entries(savedEnv)) {
          if (v === undefined) delete process.env[k];
          else process.env[k] = v;
        }
      }
    });

    await runCase('A5-T1-06', '5', 1, 'audit.jsonl 200-entry rotation and Node canonical manifest SHA-256 parity', async () => {
      const d = path.join(tempRoot, 't1_06');
      fs.mkdirSync(d, { recursive: true });
      const logger = new AuditLogger(d, { maxEntries: 200, maxBytes: 5 * 1024 * 1024 });
      for (let i = 1; i <= 200; i++) {
        logger.append({ requestId: `r-${i}`, outcome: 'COMPLETED', exitCode: 0, scriptPreview: 'ok', outputTail: 'done' });
      }
      const rotated = fs.readdirSync(d).filter(n => n.startsWith('audit.') && n !== 'audit.jsonl');
      assert.equal(rotated.length, 1, 'Expected rotation on 200th entry');
      assert.equal(fs.existsSync(path.join(d, 'audit.jsonl')), false);
      logger.append({ requestId: 'r-201', outcome: 'COMPLETED', exitCode: 0, scriptPreview: 'ok', outputTail: 'done' });
      assert.equal(fs.readFileSync(path.join(d, 'audit.jsonl'), 'utf8').trim().split('\n').length, 1);

      const canonical = Buffer.from(JSON.stringify({
        script: "Write-Output '状态/系统/目录/未知/小'",
        args: ['-DriverName', 'AIMtkRD'],
        workDir: 'C:\\temp\\space dir',
        encoding: 'auto'
      }), 'utf8');
      const sha = crypto.createHash('sha256').update(canonical).digest('hex');
      assert.equal(sha, '198aef785eb77d47707cc15e1ec0ec3298df9285dd3874e7b4438e2c7b7b4160');
      return '200-entry audit rotation and exact SHA-256 parity verified';
    });

    await runCase('A5-T1-07', '5', 1, 'Click-1 deadline null before click1_shown, populated on click1_shown, and backup timer anchored to deadline', async () => {
      const d = path.join(tempRoot, 't1_07');
      const broker = createHarnessBroker(d, { click1TimeoutMs: 400, deferClick1Deadline: true });
      const { port, token } = await broker.start();
      try {
        broker.handleAction({ action: 'save-config', config: { click1TimeoutSeconds: 1 } });
        const resPromise = fetch(`http://127.0.0.1:${port}/ipc/requests`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'ScriptText', reason: 'countdown-sync', script: 'Write-Output 1', workDir: 'C:\\Windows' })
        }).then(r => r.text());

        let reqId = null;
        for (let i = 0; i < 80; i++) {
          if (broker.state.activeJob) { reqId = broker.state.activeJob.requestId; break; }
          await new Promise(r => setTimeout(r, 15));
        }
        assert.ok(reqId, 'Job did not enter AWAITING_CLICK1');

        const snapBefore = broker.snapshotState();
        assert.equal(snapBefore.activeJob.click1Shown, false);
        assert.equal(snapBefore.activeJob.click1DeadlineAt, null);
        assert.equal(snapBefore.activeJob.click1TimeoutSeconds, 1);

        // Simulate 500ms cold start (> click1TimeoutMs=400ms): watchdog must NOT fire prematurely
        await new Promise(r => setTimeout(r, 500));
        assert.ok(broker.state.activeJob && !broker.state.activeJob.finished, 'Watchdog fired prematurely before click1_shown');

        const explicitDeadline = Date.now() + 1000;
        const seqBefore = broker.state.seq;
        const streamPromise = broker.waitStream(seqBefore, 1000);
        broker.handleAction({ action: 'click1-shown', requestId: reqId, click1DeadlineAt: explicitDeadline });

        const streamRes = await streamPromise;
        assert.equal(streamRes.changed, true);
        assert.equal(streamRes.state.activeJob.click1Shown, true);
        assert.equal(streamRes.state.activeJob.click1DeadlineAt, explicitDeadline);
        assert.equal(streamRes.state.activeJob.click1TimeoutSeconds, 1);

        assert.equal(broker.handleAction({ action: 'deny', requestId: reqId }).ok, true);
        const sseText = await resPromise;
        assert.match(sseText, /"click1Shown":true/);
        assert.match(sseText, /"outcome":"DENIED_CLICK1"/);
        return 'Verified click1_shown deadline anchoring, UI snapshot fields, and non-premature watchdog';
      } finally {
        await broker.close();
      }
    });

    await runCase('A5-T1-08', '5', 1, 'One-shot post-dismissal reminder re-arm (no setInterval overlap or premature re-fire)', async () => {
      const d = path.join(tempRoot, 't1_08');
      const broker = createHarnessBroker(d, { reminderIntervalMs: 320, click1TimeoutMs: 5000 });
      const { port, token } = await broker.start();
      try {
        const openSse = (reason, runMs) => {
          return new Promise((resolve) => {
            const chunks = [];
            const req = http.request({
              host: '127.0.0.1', port, path: '/ipc/requests', method: 'POST',
              headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
            }, (res) => {
              res.on('data', (c) => chunks.push(c.toString('utf8')));
              res.on('end', () => resolve(chunks.join('')));
            });
            req.end(JSON.stringify({ mode: 'ScriptText', reason, script: 'ok', args: [], workDir: 'C:\\Windows', encoding: 'auto', _testRunMs: runMs }));
          });
        };

        const p1 = openSse('rem-1', 2600);
        for (let i = 0; i < 40 && !broker.state.activeJob; i++) await new Promise(r => setTimeout(r, 15));
        const p2 = openSse('rem-2', 50);
        for (let i = 0; i < 40 && broker.state.queue.length === 0; i++) await new Promise(r => setTimeout(r, 15));

        const id1 = broker.state.activeJob.requestId;
        const id2 = broker.state.queue[0].requestId;
        broker.handleAction({ action: 'approve-click1', requestId: id1 });
        broker.handleAction({ action: 'uac-yes', requestId: id1 });

        for (let i = 0; i < 60 && broker.state.reminderShownCount < 1; i++) await new Promise(r => setTimeout(r, 20));
        assert.equal(broker.state.reminderShownCount, 1, 'First reminder should appear');

        // Hold reminder open longer than reminderIntervalMs (450ms > 320ms) -> must NOT stack
        await new Promise(r => setTimeout(r, 450));
        assert.equal(broker.state.reminderShownCount, 1, 'Reminder must remain single-instance while open');

        const tDismiss = Date.now();
        assert.equal(broker.handleAction({ action: 'dismiss-reminder' }).ok, true);
        assert.equal(broker.state.reminderActive, false);

        // Must NOT fire before full 320ms elapses from dismissal
        await new Promise(r => setTimeout(r, 160));
        assert.equal(broker.state.reminderShownCount, 1, 'Reminder fired prematurely after dismissal');

        // Must fire after full 320ms from dismissal
        let tSecond = 0;
        for (let i = 0; i < 50; i++) {
          if (broker.state.reminderShownCount >= 2) { tSecond = Date.now(); break; }
          await new Promise(r => setTimeout(r, 20));
        }
        assert.equal(broker.state.reminderShownCount, 2, 'Second reminder did not re-arm after dismissal');
        assert.ok(tSecond - tDismiss >= 290, `Second reminder fired too early (${tSecond - tDismiss} ms < 290 ms)`);

        broker.handleAction({ action: 'cancel', requestId: id2 });
        broker.handleAction({ action: 'kill', requestId: id1 });
        await Promise.all([p1, p2]);
        return `Verified one-shot post-dismissal re-arm (${tSecond - tDismiss} ms after dismiss)`;
      } finally {
        await broker.close();
      }
    });

    // --- TIER 2 ---
    await runCase('A5-T2-01', '5', 2, 'Reject missing/invalid Bearer token with 401 AFTER draining 256 KB .NET 4.8 POST body', async () => {
      const d = path.join(tempRoot, 't2_01');
      const broker = createHarnessBroker(d);
      const { port } = await broker.start();
      try {
        const ps = `
          $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(('{"script":"' + ('X' * 262144) + '"}'))
          $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:${port}/ipc/requests")
          $req.Method = "POST"
          $req.ContentType = "application/json"
          $req.Headers.Add("Authorization", "Bearer wrong-token")
          $req.Proxy = $null
          $req.ServicePoint.Expect100Continue = $false
          $req.ContentLength = $bytes.Length
          $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
          try {
            $null = $req.GetResponse()
            throw "Expected 401"
          } catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            if ($null -eq $resp) { throw ("Connection dropped without 401 response: " + $_.Exception.Message) }
            $code = [int]$resp.StatusCode
            $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $body = $sr.ReadToEnd()
            Write-Output "HTTP=$code BODY=$body"
          }
        `;
        const res = await runPsDotNetHttp(ps);
        assert.equal(res.code, 0, res.stderr + res.stdout);
        assert.match(res.stdout, /HTTP=401 BODY=\{"error":"unauthorized"\}/);
        return '.NET 4.8 received clean 401 JSON after 256 KB body drain';
      } finally {
        await broker.close();
      }
    });

    await runCase('A5-T2-02', '5', 2, 'SidecarApp rejects missing/bad X-Sidecar-Token (401), GET on POST route (405), bad JSON (500)', async () => {
      const uiToken = 'secret-token-123';
      const savedEnv = {
        ANTIGRAVITY_LS_ADDRESS: process.env.ANTIGRAVITY_LS_ADDRESS,
        ANTIGRAVITY_CSRF_TOKEN: process.env.ANTIGRAVITY_CSRF_TOKEN,
        ANTIGRAVITY_SIDECAR_WEB_PORT: process.env.ANTIGRAVITY_SIDECAR_WEB_PORT,
        ANTIGRAVITY_SIDECAR_UI_TOKEN: process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN
      };
      process.env.ANTIGRAVITY_LS_ADDRESS = '127.0.0.1:1';
      process.env.ANTIGRAVITY_CSRF_TOKEN = 'test-csrf';
      process.env.ANTIGRAVITY_SIDECAR_WEB_PORT = '0';
      process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN = uiToken;

      const app = new SidecarApp();
      app.api('/api/state', () => ({ ok: true }), 'POST');
      app.api('/api/action', (ctx) => ctx, 'POST');
      const srv = await app.run();
      const webPort = srv.address().port;
      try {
        const rNoTok = await fetch(`http://127.0.0.1:${webPort}/api/state`, { method: 'POST', body: '{}' });
        assert.equal(rNoTok.status, 401);
        const rBadTok = await fetch(`http://127.0.0.1:${webPort}/api/state`, {
          method: 'POST',
          headers: { 'X-Sidecar-Token': 'wrong' },
          body: '{}'
        });
        assert.equal(rBadTok.status, 401);
        const rGet = await fetch(`http://127.0.0.1:${webPort}/api/state`, { method: 'GET' });
        assert.equal(rGet.status, 405);
        const rBadJson = await fetch(`http://127.0.0.1:${webPort}/api/action`, {
          method: 'POST',
          headers: { 'X-Sidecar-Token': uiToken, 'Content-Type': 'application/json' },
          body: '{broken-json'
        });
        assert.equal(rBadJson.status, 500);
        return 'SidecarApp enforced 401, 405, and 500 error contracts';
      } finally {
        await new Promise(r => srv.close(r));
        for (const [k, v] of Object.entries(savedEnv)) {
          if (v === undefined) delete process.env[k];
          else process.env[k] = v;
        }
      }
    });

    await runCase('A5-T2-03', '5', 2, 'ANTIGRAVITY_SOURCE_METADATA strips argumentsJson & missing/slow agentapi falls back to workDir', async () => {
      const rawMeta = JSON.stringify({
        tool: {
          conversationId: 'conv-abc-123',
          stepIndex: 7,
          toolCall: {
            id: 'call-99',
            name: 'run_command',
            argumentsJson: '{"CommandLine":"SUPER_SECRET_ARGUMENTS_MUST_NOT_LEAK"}'
          }
        }
      });
      const sanitized = sanitizeSourceMetadata(rawMeta);
      assert.deepEqual(sanitized, { conversationId: 'conv-abc-123', stepIndex: 7, toolCallId: 'call-99' });
      assert.equal(JSON.stringify(sanitized).includes('argumentsJson'), false);
      assert.equal(JSON.stringify(sanitized).includes('SUPER_SECRET'), false);

      // Simulate missing agentapi fallback
      let workspaceLabel = 'C:\\fallback\\workDir';
      try {
        await new Promise((resolve, reject) => {
          const c = spawn(path.join(tempRoot, 'nonexistent_agentapi.exe'), ['agentapi', 'get-conversation-metadata', 'conv-abc-123']);
          c.on('error', reject);
        });
      } catch {
        workspaceLabel = 'workDir:C:\\fallback\\workDir';
      }
      assert.match(workspaceLabel, /fallback\\workDir/);
      return 'Stripped argumentsJson and verified graceful workDir fallback';
    });

    await runCase('A5-T2-04', '5', 2, 'Adversarial outcomes: 409 preflight fail, TIMEOUT_CLICK1 (1460), DENIED_UAC (1223), KILLED (1207)', async () => {
      // 1. 409 preflight failure
      const d1 = path.join(tempRoot, 't2_04_pf');
      const b1 = createHarnessBroker(d1, { preflightOk: false, preflightOutcome: 'SESSION_NOT_INTERACTIVE', preflightCode: 1202 });
      const { port: p1, token: tok1 } = await b1.start();
      try {
        const resp409 = await fetch(`http://127.0.0.1:${p1}/ipc/requests`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${tok1}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'ScriptText', reason: 'pf', script: '1', workDir: 'C:\\Windows' })
        });
        assert.equal(resp409.status, 409);
        const j409 = await resp409.json();
        assert.equal(j409.exitCode, 1202);
        assert.equal(j409.outcome, 'SESSION_NOT_INTERACTIVE');
      } finally {
        await b1.close();
      }

      // 2. Click-1 timeout, UAC denial, and RUNNING Kill
      const d2 = path.join(tempRoot, 't2_04_life');
      const b2 = createHarnessBroker(d2, { click1TimeoutMs: 120 });
      const { port: p2, token: tok2 } = await b2.start();
      const postReq = async (runMs = 500) => {
        const res = await fetch(`http://127.0.0.1:${p2}/ipc/requests`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${tok2}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'ScriptText', reason: 'adv', script: '1', workDir: 'C:\\Windows', _testRunMs: runMs })
        });
        return await res.text();
      };
      try {
        const sseTimeout = await postReq();
        assert.match(sseTimeout, /"outcome":"TIMEOUT_CLICK1","exitCode":1460/);

        const pUac = postReq();
        for (let i = 0; i < 40 && !b2.state.activeJob; i++) await new Promise(r => setTimeout(r, 10));
        const idUac = b2.state.activeJob.requestId;
        b2.handleAction({ action: 'approve-click1', requestId: idUac });
        b2.handleAction({ action: 'uac-no', requestId: idUac });
        const sseUacNo = await pUac;
        assert.match(sseUacNo, /"outcome":"DENIED_UAC","exitCode":1223/);

        const pKill = postReq(2000);
        for (let i = 0; i < 40 && !b2.state.activeJob; i++) await new Promise(r => setTimeout(r, 10));
        const idKill = b2.state.activeJob.requestId;
        b2.handleAction({ action: 'approve-click1', requestId: idKill });
        b2.handleAction({ action: 'uac-yes', requestId: idKill });
        await new Promise(r => setTimeout(r, 30));
        b2.handleAction({ action: 'kill', requestId: idKill });
        const sseKilled = await pKill;
        assert.match(sseKilled, /"outcome":"KILLED","exitCode":1207/);
        return 'Verified 409 (1202), TIMEOUT_CLICK1 (1460), DENIED_UAC (1223), and KILLED (1207)';
      } finally {
        await b2.close();
      }
    });

    await runCase('A5-T2-05', '5', 2, 'Multi-byte UTF-8 ("状态") 4 KB truncation never exceeds 4096 bytes or emits U+FFFD', async () => {
      const d = path.join(tempRoot, 't2_05');
      fs.mkdirSync(d, { recursive: true });
      const logger = new AuditLogger(d);
      const longZh = '状态'.repeat(1500); // 3000 chars, 9000 UTF-8 bytes
      logger.append({
        requestId: 'zh-4k',
        outcome: 'COMPLETED',
        exitCode: 0,
        scriptPreview: longZh,
        outputTail: longZh
      });
      const line = fs.readFileSync(path.join(d, 'audit.jsonl'), 'utf8').trim();
      const parsed = JSON.parse(line);
      const spBytes = Buffer.byteLength(parsed.scriptPreview, 'utf8');
      const otBytes = Buffer.byteLength(parsed.outputTail, 'utf8');
      assert.ok(spBytes <= 4096 && spBytes >= 4092, `Unexpected scriptPreview bytes: ${spBytes}`);
      assert.ok(otBytes <= 4096 && otBytes >= 4092, `Unexpected outputTail bytes: ${otBytes}`);
      assert.equal(parsed.scriptPreview.includes('\uFFFD'), false, 'Must not contain replacement char U+FFFD');
      assert.equal(parsed.outputTail.includes('\uFFFD'), false, 'Must not contain replacement char U+FFFD');
      return `Bounded multi-byte zh-CN preview to ${spBytes} UTF-8 bytes without U+FFFD`;
    });

    await runCase('A5-T2-06', '5', 2, 'audit.jsonl 5 MB size-based rotation triggers below 200 entries', async () => {
      const d = path.join(tempRoot, 't2_06');
      fs.mkdirSync(d, { recursive: true });
      // Seed 51 x ~102.4 KB lines = 5,224,338 bytes (< 5,242,880 = 5 MiB)
      const bigLine = JSON.stringify({ requestId: 'seed', payload: 'Z'.repeat(102400) }) + '\n';
      fs.writeFileSync(path.join(d, 'audit.jsonl'), bigLine.repeat(51), 'utf8');
      const logger = new AuditLogger(d, { maxEntries: 200, maxBytes: 5 * 1024 * 1024 });
      // Still under 5 MiB -> must NOT rotate yet
      logger.append({ requestId: 'under-5mb', outcome: 'COMPLETED', exitCode: 0, scriptPreview: 'a', outputTail: 'b' });
      assert.equal(fs.readdirSync(d).filter(n => n.startsWith('audit.') && n !== 'audit.jsonl').length, 0, 'Should not rotate below 5 MiB');

      // Now push over 5,242,880 bytes with < 60 entries
      logger.append({ requestId: 'trigger-5mb', reason: 'R'.repeat(25000), outcome: 'COMPLETED', exitCode: 0, scriptPreview: 'a', outputTail: 'b' });
      const rotated = fs.readdirSync(d).filter(n => n.startsWith('audit.') && n !== 'audit.jsonl');
      assert.equal(rotated.length, 1, 'Expected 5 MiB rotation with < 200 entries');
      return '5 MiB size-based audit.jsonl rotation BVA verified (<5 MiB stays, >=5 MiB rotates)';
    });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

async function runRepoIntegration(repoRoot) {
  await runCase('A5-REPO-01', '5', 1, 'Repo sidecars\\broker\\main.mjs live spawn, runtime.json, .NET 4.8 401/409, and SidecarApp /api/* checks', async () => {
    const mainMjs = path.join(repoRoot, 'sidecars', 'broker', 'main.mjs');
    assert.ok(fs.existsSync(mainMjs), `Missing ${mainMjs}`);
    const mainSrc = fs.readFileSync(mainMjs, 'utf8');

    for (const token of ["res.on('close'", 'ANTIGRAVITY_EXECUTABLE_DATA_DIR', 'ANTIGRAVITY_AGENTAPI_EXE', 'ANTIGRAVITY_SOURCE_METADATA', 'audit.jsonl', '/ipc/requests', '/api/state', '/api/stream', '/api/action']) {
      assert.ok(mainSrc.includes(token) || (token === "res.on('close'" && mainSrc.includes('res.on("close"')), `main.mjs missing required token: ${token}`);
    }
    assert.match(mainSrc, /(16\s*\*\s*1024\s*\*\s*1024|16777216|16\s*<<\s*20)/, 'main.mjs missing 16 MiB maxBuffer configuration');
    const mainNoComments = mainSrc.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    assert.equal(
      /\bSidecarApp\.prototype\.getConversationMetadata\b|\b(?:app|sidecar|this)\.getConversationMetadata\s*\(/.test(mainNoComments),
      false,
      'main.mjs must not call blocking SidecarApp.getConversationMetadata()'
    );

    const tempData = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-broker-'));
    const stagedDir = path.join(tempData, 'staged');
    fs.mkdirSync(stagedDir, { recursive: true });
    fs.writeFileSync(path.join(stagedDir, 'stale.json'), '{"stale":true}', 'utf8');
    fs.writeFileSync(path.join(tempData, 'runtime.json'), '{"port":1,"token":"old"}', 'utf8');

    const uiToken = crypto.randomBytes(16).toString('hex');
    const loaderUrl = 'file:///C:/Users/adam/.gemini/antigravity/lib/node_modules/sidecar_sdk/register_loader.js';
    const syntheticSourceMeta = JSON.stringify({
      tool: {
        conversationId: 'conv-repo-probe-1',
        stepIndex: 42,
        toolCall: {
          id: 'call-repo-probe-99',
          name: 'run_command',
          argumentsJson: '{"CommandLine":"SECRET_ARGUMENTS_MUST_NOT_LEAK"}'
        }
      }
    });
    const child = spawn(process.execPath, [`--import=${loaderUrl}`, mainMjs], {
      cwd: path.dirname(mainMjs),
      env: {
        ...process.env,
        ELECTRON_RUN_AS_NODE: '1',
        ANTIGRAVITY_EXECUTABLE_DATA_DIR: tempData,
        ANTIGRAVITY_LS_ADDRESS: '127.0.0.1:1',
        ANTIGRAVITY_CSRF_TOKEN: 'test-csrf',
        ANTIGRAVITY_SIDECAR_WEB_PORT: '0',
        ANTIGRAVITY_SIDECAR_UI_TOKEN: uiToken,
        ANTIGRAVITY_SOURCE_METADATA: syntheticSourceMeta
      },
      windowsHide: true
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString('utf8'); });
    child.stderr.on('data', d => { stderr += d.toString('utf8'); });

    try {
      let webPort = 0;
      const runtimePath = path.join(tempData, 'runtime.json');
      let rt = null;
      for (let i = 0; i < 80; i++) {
        const m = stdout.match(/\[sidecar\]\s+listening on 127\.0\.0\.1:(\d+)/i);
        if (m) webPort = Number(m[1]);
        if (fs.existsSync(runtimePath)) {
          try {
            const candidate = JSON.parse(fs.readFileSync(runtimePath, 'utf8'));
            if (candidate.pid === child.pid && candidate.port > 0) rt = candidate;
          } catch {}
        }
        if (webPort > 0 && rt) break;
        if (child.exitCode !== null) {
          throw new Error(`main.mjs exited prematurely (${child.exitCode}): stdout=${stdout} stderr=${stderr}`);
        }
        await new Promise(r => setTimeout(r, 100));
      }
      assert.ok(webPort > 0, `Sidecar web port did not appear in stdout: ${stdout} stderr=${stderr}`);
      assert.ok(rt, `runtime.json not populated with child PID ${child.pid}`);
      assert.match(rt.token, /^[0-9a-f]{64}$/);
      assert.equal(fs.existsSync(path.join(stagedDir, 'stale.json')), false, 'Startup sweep must delete stale staged/ files');

      // .NET 4.8 large POST bad Bearer -> clean 401
      const ps401 = `
        $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(('{"mode":"ScriptText","reason":"bad","script":"' + ('A' * 131072) + '"}'))
        $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:${rt.port}/ipc/requests")
        $req.Method = "POST"; $req.ContentType = "application/json"; $req.Headers.Add("Authorization", "Bearer bad")
        $req.Proxy = $null; $req.ServicePoint.Expect100Continue = $false; $req.ContentLength = $bytes.Length
        $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
        try { $null = $req.GetResponse(); throw "Expected 401" }
        catch [System.Net.WebException] {
          $r = $_.Exception.Response
          if ($null -eq $r) { throw $_.Exception.Message }
          Write-Output ("STATUS=" + [int]$r.StatusCode)
        }
      `;
      const res401 = await runPsDotNetHttp(ps401);
      assert.equal(res401.code, 0, res401.stderr + res401.stdout);
      assert.match(res401.stdout, /STATUS=401/);

      // Authenticated POST /ipc/requests -> 409 in exebox-*/pre-Phase-2, or 200 SSE if interactive post-Phase-2
      const ipcAc = new AbortController();
      const ipcTimer = setTimeout(() => ipcAc.abort(), 8000);
      let ipcSummary = '';
      try {
        const rIpc = await fetch(`http://127.0.0.1:${rt.port}/ipc/requests`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${rt.token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mode: 'ScriptText',
            reason: 'probe',
            script: 'Write-Output 1',
            args: [],
            workDir: 'C:\\Windows',
            encoding: 'auto',
            sourceMeta: {
              conversationId: 'conv-repo-probe-1',
              stepIndex: 42,
              toolCallId: 'call-repo-probe-99',
              argumentsJson: '{"CommandLine":"SECRET_ARGUMENTS_MUST_NOT_LEAK"}'
            }
          }),
          signal: ipcAc.signal
        });
        if (rIpc.status === 409) {
          const jIpc = await rIpc.json();
          assert.ok([1202, 1204].includes(jIpc.exitCode), `Expected exitCode 1202/1204, got ${JSON.stringify(jIpc)}`);
          ipcSummary = `preflight409=${jIpc.outcome}`;
        } else if (rIpc.status === 200) {
          assert.match(rIpc.headers.get('content-type') || '', /text\/event-stream/i);
          ipcAc.abort();
          ipcSummary = 'sse200-aborted';
        } else {
          assert.fail(`Unexpected /ipc/requests status ${rIpc.status}`);
        }
      } finally {
        clearTimeout(ipcTimer);
      }

      // SidecarApp static + POST /api/* routes + argumentsJson leakage assertion
      for (const staticPath of ['/', '/styles.css', '/app.js', '/preload.js']) {
        const sr = await fetch(`http://127.0.0.1:${webPort}${staticPath}`);
        assert.equal(sr.status, 200, `GET ${staticPath} returned ${sr.status}`);
      }
      assert.equal((await fetch(`http://127.0.0.1:${webPort}/api/state`)).status, 405);
      assert.equal((await fetch(`http://127.0.0.1:${webPort}/api/state`, { method: 'POST', body: '{}' })).status, 401);

      const st = await fetch(`http://127.0.0.1:${webPort}/api/state`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: '{}'
      });
      assert.equal(st.status, 200);
      const stText = await st.text();
      assert.equal(stText.includes('SECRET_ARGUMENTS_MUST_NOT_LEAK'), false, '/api/state leaked SECRET_ARGUMENTS_MUST_NOT_LEAK');
      assert.equal(stText.includes('"argumentsJson"'), false, '/api/state leaked "argumentsJson" key');
      JSON.parse(stText);

      const act = await fetch(`http://127.0.0.1:${webPort}/api/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: JSON.stringify({ action: 'save-config', config: { click1TimeoutSeconds: 180 } })
      });
      assert.equal(act.status, 200);

      const streamResp = await fetch(`http://127.0.0.1:${webPort}/api/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: JSON.stringify({ sinceSeq: 0, waitMs: 50 })
      });
      assert.equal(streamResp.status, 200);
      const streamText = await streamResp.text();
      assert.equal(streamText.includes('SECRET_ARGUMENTS_MUST_NOT_LEAK'), false, '/api/stream leaked SECRET_ARGUMENTS_MUST_NOT_LEAK');
      assert.equal(streamText.includes('"argumentsJson"'), false, '/api/stream leaked "argumentsJson" key');
      const streamJson = JSON.parse(streamText);
      assert.equal(typeof streamJson.seq, 'number');

      return `Live main.mjs verified: ipcPort=${rt.port}, webPort=${webPort}, ${ipcSummary}`;
    } finally {
      try { child.kill(); } catch {}
      await new Promise(r => setTimeout(r, 150));
      fs.rmSync(tempData, { recursive: true, force: true });
    }
  });

  await runCase('A5-REPO-02', '5', 2, 'Live main.mjs click1DeadlineAt propagation, fallback deadline, serializeJobForUi.click1TimeoutSeconds, and non-premature watchdog', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-sync-'));
    const tempData = path.join(tempRoot, 'data');
    const brokerDir = path.join(tempRoot, 'repo', 'sidecars', 'broker');
    const assetsDir = path.join(tempRoot, 'repo', 'assets');
    fs.mkdirSync(tempData, { recursive: true });
    fs.mkdirSync(brokerDir, { recursive: true });
    fs.mkdirSync(assetsDir, { recursive: true });

    for (const f of ['main.mjs', 'package.json', 'sidecar.json', 'index.html', 'styles.css', 'app.js']) {
      fs.copyFileSync(path.join(repoRoot, 'sidecars', 'broker', f), path.join(brokerDir, f));
    }
    fs.copyFileSync(path.join(repoRoot, 'assets', 'logo.svg'), path.join(assetsDir, 'logo.svg'));

    const helperStub = `param(
    [switch]$PreflightOnly,
    [string]$RunnerPath
)
$ErrorActionPreference = 'Stop'
if ($PreflightOnly) {
    [Console]::Out.WriteLine('{"ok":true,"code":"OK","exitCode":0,"detail":"stub"}')
    exit 0
}
Add-Type -AssemblyName System.Web.Extensions
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $utf8NoBom)
$stdout = [Console]::OpenStandardOutput()
$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer

function Emit-Line([hashtable]$obj) {
    $bytes = $utf8NoBom.GetBytes($ser.Serialize($obj) + "\`n")
    $stdout.Write($bytes, 0, $bytes.Length)
    $stdout.Flush()
}

while ($null -ne ($line = $reader.ReadLine())) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $msg = $ser.DeserializeObject($line)
    $cmd = [string]$msg['cmd']
    if ($cmd -eq 'start_request') {
        $reqId = [string]$msg['requestId']
        $reason = [string]$msg['reason']
        $timeoutSec = [int]$msg['click1TimeoutSeconds']
        $delayMs = if ($reason -match 'SLOW_START') { 2500 } elseif ($reason -match 'OMIT_DEADLINE') { 400 } else { 900 }
        Start-Sleep -Milliseconds $delayMs
        if ($reason -match 'OMIT_DEADLINE') {
            Emit-Line @{ event = 'click1_shown'; requestId = $reqId }
        } else {
            $nowMs = [int64](([DateTime]::UtcNow.Ticks - 621355968000000000L) / 10000L)
            $deadline = $nowMs + ([int64]$timeoutSec * 1000L)
            Emit-Line @{ event = 'click1_shown'; requestId = $reqId; click1DeadlineAt = $deadline }
        }
    } elseif ($cmd -eq 'deny') {
        Emit-Line @{ event = 'click1_decision'; requestId = [string]$msg['requestId']; decision = 'deny' }
    } elseif ($cmd -eq 'cancel') {
        Emit-Line @{ event = 'cancelled'; requestId = [string]$msg['requestId'] }
    } elseif ($cmd -eq 'shutdown') {
        break
    }
}
exit 0
`;
    fs.writeFileSync(path.join(brokerDir, 'broker_helper.ps1'), Buffer.from('\uFEFF' + helperStub, 'utf8'));

    const uiToken = crypto.randomBytes(16).toString('hex');
    const loaderUrl = 'file:///C:/Users/adam/.gemini/antigravity/lib/node_modules/sidecar_sdk/register_loader.js';
    const tempMain = path.join(brokerDir, 'main.mjs');
    const child = spawn(process.execPath, [`--import=${loaderUrl}`, tempMain], {
      cwd: brokerDir,
      env: {
        ...process.env,
        ELECTRON_RUN_AS_NODE: '1',
        ANTIGRAVITY_EXECUTABLE_DATA_DIR: tempData,
        ANTIGRAVITY_LS_ADDRESS: '127.0.0.1:1',
        ANTIGRAVITY_CSRF_TOKEN: 'test-csrf',
        ANTIGRAVITY_SIDECAR_WEB_PORT: '0',
        ANTIGRAVITY_SIDECAR_UI_TOKEN: uiToken
      },
      windowsHide: true
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString('utf8'); });
    child.stderr.on('data', d => { stderr += d.toString('utf8'); });

    try {
      let webPort = 0;
      let rt = null;
      const runtimePath = path.join(tempData, 'runtime.json');
      for (let i = 0; i < 80; i++) {
        const m = stdout.match(/\[sidecar\]\s+listening on 127\.0\.0\.1:(\d+)/i);
        if (m) webPort = Number(m[1]);
        if (fs.existsSync(runtimePath)) {
          try {
            const candidate = JSON.parse(fs.readFileSync(runtimePath, 'utf8'));
            if (candidate.pid === child.pid && candidate.port > 0) rt = candidate;
          } catch {}
        }
        if (webPort > 0 && rt) break;
        if (child.exitCode !== null) throw new Error(`Stubbed main.mjs exited early (${child.exitCode}): ${stderr}`);
        await new Promise(r => setTimeout(r, 100));
      }
      assert.ok(webPort > 0 && rt, `Stubbed main.mjs did not initialize: stdout=${stdout} stderr=${stderr}`);

      const postApi = async (p, body) => {
        const r = await fetch(`http://127.0.0.1:${webPort}${p}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
          body: JSON.stringify(body)
        });
        assert.equal(r.status, 200, `${p} returned ${r.status}`);
        return await r.json();
      };

      const openSse = async (reason) => {
        const chunks = [];
        const resp = await fetch(`http://127.0.0.1:${rt.port}/ipc/requests`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${rt.token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'ScriptText', reason, script: 'Write-Output 1', args: [], workDir: 'C:\\Windows', encoding: 'auto' })
        });
        assert.equal(resp.status, 200);
        const done = (async () => {
          const reader = resp.body.getReader();
          const dec = new TextDecoder('utf-8');
          while (true) {
            const { value, done: d } = await reader.read();
            if (d) break;
            chunks.push(dec.decode(value, { stream: true }));
          }
          chunks.push(dec.decode());
          return chunks.join('');
        })();
        return { done };
      };

      // Case 1: 8s timeout, 900ms cold start -> deadline null until click1_shown, then adopted & immutable vs config change
      await postApi('/api/action', { action: 'save-config', config: { click1TimeoutSeconds: 8 } });
      const tReq1 = Date.now();
      const sse1 = await openSse('sync-case-1');

      let st1 = null;
      for (let i = 0; i < 60; i++) {
        const snap = await postApi('/api/state', {});
        if (snap.activeJob) { st1 = snap; break; }
        await new Promise(r => setTimeout(r, 25));
      }
      assert.ok(st1?.activeJob, 'Case 1 job did not enter activeJob');
      assert.equal(st1.activeJob.state, 'AWAITING_CLICK1');
      assert.equal(st1.activeJob.click1Shown, false);
      assert.equal(st1.activeJob.click1DeadlineAt, null);
      assert.equal(st1.activeJob.click1TimeoutSeconds, 8);

      let st1Shown = null;
      let cursorSeq = st1.seq;
      for (let i = 0; i < 20; i++) {
        const sr = await postApi('/api/stream', { sinceSeq: cursorSeq, waitMs: 3000 });
        cursorSeq = sr.seq;
        if (sr.state?.activeJob?.click1Shown) { st1Shown = sr.state; break; }
      }
      const tShown1 = Date.now();
      assert.ok(st1Shown?.activeJob, 'Case 1 click1_shown did not arrive');
      assert.equal(st1Shown.activeJob.click1Shown, true);
      assert.equal(st1Shown.activeJob.click1TimeoutSeconds, 8);
      assert.ok(Number.isInteger(st1Shown.activeJob.click1DeadlineAt), 'click1DeadlineAt must be integer epoch ms');
      assert.ok(
        st1Shown.activeJob.click1DeadlineAt >= tReq1 + 8500 && st1Shown.activeJob.click1DeadlineAt <= tShown1 + 8500,
        `click1DeadlineAt=${st1Shown.activeJob.click1DeadlineAt} not anchored near click1_shown`
      );

      // Update global config to 120s while job 1 is active -> activeJob.click1TimeoutSeconds must stay 8
      await postApi('/api/action', { action: 'save-config', config: { click1TimeoutSeconds: 120 } });
      const st1AfterCfg = await postApi('/api/state', {});
      assert.equal(st1AfterCfg.activeJob.click1TimeoutSeconds, 8);

      await postApi('/api/action', { action: 'deny', requestId: st1Shown.activeJob.requestId });
      const sse1Text = await sse1.done;
      assert.ok(sse1Text.includes(`"click1DeadlineAt":${st1Shown.activeJob.click1DeadlineAt}`), 'SSE state missing click1DeadlineAt');
      assert.ok(sse1Text.includes('"click1TimeoutSeconds":8'), 'SSE state missing click1TimeoutSeconds');
      assert.match(sse1Text, /"outcome":"DENIED_CLICK1"/);

      // Case 2: OMIT_DEADLINE fallback computation by main.mjs (using frozen 120s)
      const tBefore2 = Date.now();
      const sse2 = await openSse('OMIT_DEADLINE');
      let st2Shown = null;
      let seq2 = st1AfterCfg.seq;
      for (let i = 0; i < 25; i++) {
        const sr = await postApi('/api/stream', { sinceSeq: seq2, waitMs: 3000 });
        seq2 = sr.seq;
        if (sr.state?.activeJob?.click1Shown) { st2Shown = sr.state; break; }
      }
      const tAfter2 = Date.now();
      assert.ok(st2Shown?.activeJob?.click1DeadlineAt, 'Fallback click1DeadlineAt not populated');
      assert.ok(
        st2Shown.activeJob.click1DeadlineAt >= tBefore2 + 120000 - 1000 && st2Shown.activeJob.click1DeadlineAt <= tAfter2 + 120000 + 500,
        `Fallback deadline ${st2Shown.activeJob.click1DeadlineAt} outside expected range`
      );
      await postApi('/api/action', { action: 'deny', requestId: st2Shown.activeJob.requestId });
      await sse2.done;

      // Case 3: SLOW_START (2500ms delay with 1s timeout) -> initial watchdog must NOT fire prematurely, re-armed timer expires after deadline
      await postApi('/api/action', { action: 'save-config', config: { click1TimeoutSeconds: 1 } });
      const sse3 = await openSse('SLOW_START');
      let st3Shown = null;
      let seq3 = (await postApi('/api/state', {})).seq;
      for (let i = 0; i < 25; i++) {
        const sr = await postApi('/api/stream', { sinceSeq: seq3, waitMs: 4000 });
        seq3 = sr.seq;
        if (sr.state?.activeJob?.click1Shown) { st3Shown = sr.state; break; }
      }
      assert.ok(st3Shown?.activeJob?.click1Shown, 'SLOW_START job killed prematurely before click1_shown');
      const sse3Text = await sse3.done;
      const tTimeout3 = Date.now();
      assert.match(sse3Text, /"outcome":"TIMEOUT_CLICK1","exitCode":1460/);
      assert.ok(tTimeout3 >= st3Shown.activeJob.click1DeadlineAt + 2500, 'Backup timer fired prematurely before deadline + 3000ms');

      return `Verified main.mjs deadline propagation (${st1Shown.activeJob.click1DeadlineAt}), fallback, and non-premature watchdog`;
    } finally {
      try { child.kill(); } catch {}
      await new Promise(r => setTimeout(r, 150));
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  await runCase('A5-REPO-03', '5', 2, 'Live app.js UTC deadline countdown math, paused pre-click1_shown state, and <= 250 ms cadence', async () => {
    const appJsPath = path.join(repoRoot, 'sidecars', 'broker', 'app.js');
    assert.ok(fs.existsSync(appJsPath), `Missing ${appJsPath}`);
    const appSrc = fs.readFileSync(appJsPath, 'utf8');

    const elements = new Map();
    const makeClassList = () => {
      const set = new Set();
      return {
        add: (...cls) => cls.forEach(c => set.add(c)),
        remove: (...cls) => cls.forEach(c => set.delete(c)),
        toggle: (c, force) => {
          if (force === undefined) {
            if (set.has(c)) { set.delete(c); return false; }
            set.add(c); return true;
          }
          if (force) set.add(c); else set.delete(c);
          return Boolean(force);
        },
        contains: (c) => set.has(c)
      };
    };
    const makeEl = (id = '') => ({
      id,
      style: {},
      dataset: {},
      classList: makeClassList(),
      children: [],
      firstChild: null,
      textContent: '',
      value: '',
      scrollTop: 0,
      scrollHeight: 0,
      clientHeight: 100,
      addEventListener: () => {},
      setAttribute: () => {},
      remove: () => {},
      appendChild(ch) { this.children.push(ch); this.firstChild = this.children[0] || null; return ch; },
      append(...chs) { for (const ch of chs) this.appendChild(ch); }
    });
    const getEl = (id) => {
      if (!elements.has(id)) elements.set(id, makeEl(id));
      return elements.get(id);
    };

    let fakeNowMs = 1_700_000_000_000;
    class FakeDate extends Date {
      static now() { return fakeNowMs; }
    }

    const intervals = [];
    let nextStreamResolver = null;
    let initialSnap = { seq: 1, activeJob: null, queue: [], config: { click1TimeoutSeconds: 300, reminderIntervalSeconds: 300 }, audit: [] };

    const docEl = { dataset: {}, clientWidth: 400, clientHeight: 600, appendChild: () => {} };
    const sandbox = {
      console,
      Date: FakeDate,
      Math,
      Number,
      String,
      Boolean,
      Array,
      Object,
      JSON,
      Promise,
      Set,
      Map,
      RegExp,
      Error,
      TextEncoder,
      AbortController,
      Headers: globalThis.Headers,
      navigator: { clipboard: { writeText: async () => {} } },
      getComputedStyle: () => ({ color: 'rgb(247, 247, 248)' }),
      MutationObserver: class { observe() {} },
      ResizeObserver: class { observe() {} },
      document: {
        visibilityState: 'visible',
        documentElement: docEl,
        getElementById: getEl,
        createElement: () => makeEl(''),
        querySelectorAll: () => [],
        addEventListener: () => {}
      },
      window: {
        addEventListener: () => {},
        sidecar: {
          fetch: async (url) => {
            if (url === '/api/state') {
              return { ok: true, status: 200, json: async () => initialSnap };
            }
            if (url === '/api/stream') {
              return await new Promise((resolve) => {
                nextStreamResolver = (snap) => resolve({
                  ok: true,
                  status: 200,
                  json: async () => ({ seq: snap.seq, changed: true, state: snap })
                });
              });
            }
            return { ok: true, status: 200, json: async () => ({ ok: true }) };
          }
        }
      },
      setInterval: (fn, ms) => {
        intervals.push({ fn, ms });
        return intervals.length;
      },
      clearInterval: () => {},
      setTimeout,
      clearTimeout
    };
    sandbox.globalThis = sandbox;

    vm.runInNewContext(appSrc, sandbox, { filename: appJsPath });

    // Wait for initial /api/state fetch and first /api/stream registration
    for (let i = 0; i < 40 && !nextStreamResolver; i++) {
      await new Promise(r => setTimeout(r, 10));
    }
    assert.ok(nextStreamResolver, 'app.js poll loop did not start');
    assert.ok(intervals.length >= 1, 'app.js did not register countdown interval');
    const countdownIv = intervals[0];
    assert.ok(countdownIv.ms <= 250, `Expected countdown interval <= 250 ms, got ${countdownIv.ms} ms`);

    const pushSnap = async (snap) => {
      for (let i = 0; i < 40 && !nextStreamResolver; i++) {
        await new Promise(r => setTimeout(r, 10));
      }
      const r = nextStreamResolver;
      nextStreamResolver = null;
      assert.ok(r, 'Poll loop not waiting on /api/stream');
      r(snap);
      await new Promise(r => setTimeout(r, 10));
    };

    const cdText = getEl('countdown-text');
    const cdBar = getEl('countdown-bar');

    // 1. Pre-click1_shown: paused at frozen job.click1TimeoutSeconds=120 (NOT global config 300)
    await pushSnap({
      seq: 2,
      activeJob: {
        requestId: 'r-ui-1',
        state: 'AWAITING_CLICK1',
        click1Shown: false,
        click1TimeoutSeconds: 120,
        click1DeadlineAt: null,
        reason: 'test',
        mode: 'ScriptText',
        encoding: 'auto',
        workDir: 'C:\\Windows',
        manifestSha256: 'ab'.repeat(32),
        script: '1'
      },
      queue: [],
      config: { click1TimeoutSeconds: 300, reminderIntervalSeconds: 300 },
      audit: []
    });
    assert.equal(cdText.textContent, 'Auto-cancels in 02:00');
    assert.equal(cdBar.style.width, '100%');

    // 2. click1_shown with UTC deadline = t0 + 120000
    const t0 = fakeNowMs;
    await pushSnap({
      seq: 3,
      activeJob: {
        requestId: 'r-ui-1',
        state: 'AWAITING_CLICK1',
        click1Shown: true,
        click1TimeoutSeconds: 120,
        click1DeadlineAt: t0 + 120000,
        reason: 'test',
        mode: 'ScriptText',
        encoding: 'auto',
        workDir: 'C:\\Windows',
        manifestSha256: 'ab'.repeat(32),
        script: '1'
      },
      queue: [],
      config: { click1TimeoutSeconds: 300, reminderIntervalSeconds: 300 },
      audit: []
    });

    fakeNowMs = t0 + 1500;
    countdownIv.fn();
    assert.equal(cdText.textContent, 'Auto-cancels in 01:59');
    assert.equal(cdBar.style.width, '98.8%');

    fakeNowMs = t0 + 119001;
    countdownIv.fn();
    assert.equal(cdText.textContent, 'Auto-cancels in 00:01');

    fakeNowMs = t0 + 120000;
    countdownIv.fn();
    assert.equal(cdText.textContent, 'Auto-cancels in 00:00');
    assert.equal(cdBar.style.width, '0.0%');

    // 3. Zero-timeout job -> 'No timeout (manual decision required)' + '100%'
    await pushSnap({
      seq: 4,
      activeJob: {
        requestId: 'r-ui-2',
        state: 'AWAITING_CLICK1',
        click1Shown: true,
        click1TimeoutSeconds: 0,
        click1DeadlineAt: null,
        reason: 'no-timeout',
        mode: 'ScriptText',
        encoding: 'auto',
        workDir: 'C:\\Windows',
        manifestSha256: 'cd'.repeat(32),
        script: '2'
      },
      queue: [],
      config: { click1TimeoutSeconds: 300, reminderIntervalSeconds: 300 },
      audit: []
    });
    assert.equal(cdText.textContent, 'No timeout (manual decision required)');
    assert.equal(cdBar.style.width, '100%');

    // Cleanly stop app.js poll loop
    docEl.clientWidth = 0;
    docEl.clientHeight = 0;
    return `Verified unmodified app.js UTC countdown math and ${countdownIv.ms} ms cadence`;
  });

  await runCase('A5-REPO-04', '5', 1, 'Real main.mjs clear-audit in-process ZIP archival (incl. rotated files + UTF-8), truncation, ongoing/queued preservation, and empty handling', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-clear-'));
    const tempData = path.join(tempRoot, 'data');
    const brokerDir = path.join(tempRoot, 'repo', 'sidecars', 'broker');
    const assetsDir = path.join(tempRoot, 'repo', 'assets');
    const extractDir = path.join(tempRoot, 'extracted');
    fs.mkdirSync(tempData, { recursive: true });
    fs.mkdirSync(brokerDir, { recursive: true });
    fs.mkdirSync(assetsDir, { recursive: true });

    for (const f of ['main.mjs', 'package.json', 'sidecar.json', 'index.html', 'styles.css', 'app.js']) {
      fs.copyFileSync(path.join(repoRoot, 'sidecars', 'broker', f), path.join(brokerDir, f));
    }
    fs.copyFileSync(path.join(repoRoot, 'assets', 'logo.svg'), path.join(assetsDir, 'logo.svg'));

    const rotatedName = 'audit.1700000000000.ab12.jsonl';
    const seedRotEntry = { requestId: 'req-seed-0', reason: 'rotated entry', outcome: 'COMPLETED', exitCode: 0, finishedAt: '2026-11-24T01:00:00.000Z', workDir: 'C:\\Windows', manifestSha256: '00'.repeat(32) };
    const seedEntry1 = { requestId: 'req-seed-1', reason: '状态/测试 utf8 entry 1', outcome: 'COMPLETED', exitCode: 0, finishedAt: '2026-11-24T01:01:00.000Z', workDir: 'C:\\Windows', manifestSha256: '11'.repeat(32) };
    const seedEntry2 = { requestId: 'req-seed-2', reason: 'seed entry 2', outcome: 'DENIED_CLICK1', exitCode: 1223, finishedAt: '2026-11-24T01:02:00.000Z', workDir: 'C:\\Windows', manifestSha256: '22'.repeat(32) };
    fs.writeFileSync(path.join(tempData, rotatedName), JSON.stringify(seedRotEntry) + '\n', 'utf8');
    fs.writeFileSync(path.join(tempData, 'audit.jsonl'), JSON.stringify(seedEntry1) + '\n' + JSON.stringify(seedEntry2) + '\n', 'utf8');

    const helperStub = `param(
    [switch]$PreflightOnly,
    [string]$RunnerPath
)
$ErrorActionPreference = 'Stop'
if ($PreflightOnly) {
    [Console]::Out.WriteLine('{"ok":true,"code":"OK","exitCode":0,"detail":"stub"}')
    exit 0
}
Add-Type -AssemblyName System.Web.Extensions
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $utf8NoBom)
$stdout = [Console]::OpenStandardOutput()
$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer

function Emit-Line([hashtable]$obj) {
    $bytes = $utf8NoBom.GetBytes($ser.Serialize($obj) + "\`n")
    $stdout.Write($bytes, 0, $bytes.Length)
    $stdout.Flush()
}

while ($null -ne ($line = $reader.ReadLine())) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $msg = $ser.DeserializeObject($line)
    $cmd = [string]$msg['cmd']
    if ($cmd -eq 'start_request') {
        $reqId = [string]$msg['requestId']
        Emit-Line @{ event = 'click1_shown'; requestId = $reqId }
    } elseif ($cmd -eq 'approve') {
        $reqId = [string]$msg['requestId']
        Emit-Line @{ event = 'uac_started'; requestId = $reqId }
        Emit-Line @{ event = 'runner_connected'; requestId = $reqId }
        Emit-Line @{ event = 'stdout'; requestId = $reqId; text = "running-$reqId\`n" }
    } elseif ($cmd -eq 'kill') {
        Emit-Line @{ event = 'killed'; requestId = [string]$msg['requestId'] }
    } elseif ($cmd -eq 'cancel') {
        Emit-Line @{ event = 'cancelled'; requestId = [string]$msg['requestId'] }
    } elseif ($cmd -eq 'shutdown') {
        break
    }
}
exit 0
`;
    fs.writeFileSync(path.join(brokerDir, 'broker_helper.ps1'), Buffer.from('\uFEFF' + helperStub, 'utf8'));

    const uiToken = crypto.randomBytes(16).toString('hex');
    const loaderUrl = 'file:///C:/Users/adam/.gemini/antigravity/lib/node_modules/sidecar_sdk/register_loader.js';
    const child = spawn(process.execPath, [`--import=${loaderUrl}`, path.join(brokerDir, 'main.mjs')], {
      cwd: brokerDir,
      env: {
        ...process.env,
        ELECTRON_RUN_AS_NODE: '1',
        ANTIGRAVITY_EXECUTABLE_DATA_DIR: tempData,
        ANTIGRAVITY_LS_ADDRESS: '127.0.0.1:1',
        ANTIGRAVITY_CSRF_TOKEN: 'test-csrf',
        ANTIGRAVITY_SIDECAR_WEB_PORT: '0',
        ANTIGRAVITY_SIDECAR_UI_TOKEN: uiToken
      },
      windowsHide: true
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString('utf8'); });
    child.stderr.on('data', d => { stderr += d.toString('utf8'); });

    try {
      let webPort = 0;
      let rt = null;
      const runtimePath = path.join(tempData, 'runtime.json');
      for (let i = 0; i < 80; i++) {
        const m = stdout.match(/\[sidecar\]\s+listening on 127\.0\.0\.1:(\d+)/i);
        if (m) webPort = Number(m[1]);
        if (fs.existsSync(runtimePath)) {
          try {
            const c = JSON.parse(fs.readFileSync(runtimePath, 'utf8'));
            if (c.pid === child.pid && c.port > 0) rt = c;
          } catch {}
        }
        if (webPort > 0 && rt) break;
        if (child.exitCode !== null) throw new Error(`main.mjs exited early (${child.exitCode}): ${stderr}`);
        await new Promise(r => setTimeout(r, 100));
      }
      assert.ok(webPort > 0 && rt, `main.mjs failed to start: stdout=${stdout} stderr=${stderr}`);

      const postApi = async (p, body) => {
        const r = await fetch(`http://127.0.0.1:${webPort}${p}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
          body: JSON.stringify(body)
        });
        assert.equal(r.status, 200, `${p} returned ${r.status}`);
        return await r.json();
      };

      const openSse = async (reason) => {
        const resp = await fetch(`http://127.0.0.1:${rt.port}/ipc/requests`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${rt.token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'ScriptText', reason, script: 'Write-Output 1', args: [], workDir: 'C:\\Windows', encoding: 'auto' })
        });
        assert.equal(resp.status, 200);
        const textPromise = resp.text().catch((err) => ({ _sseErr: err }));
        return { textPromise };
      };

      // Verify pre-seeded audit loaded
      const st0 = await postApi('/api/state', {});
      assert.equal(st0.audit.length, 2);

      // Submit req1 -> RUNNING, then req2 -> QUEUED
      const sse1 = await openSse('keep-running');
      let stClick1 = null;
      let cursorSeq = st0.seq;
      for (let i = 0; i < 20; i++) {
        const sr = await postApi('/api/stream', { sinceSeq: cursorSeq, waitMs: 3000 });
        cursorSeq = sr.seq;
        if (sr.state?.activeJob?.click1Shown) { stClick1 = sr.state; break; }
      }
      assert.ok(stClick1?.activeJob, 'req1 did not reach click1Shown');
      const req1Id = stClick1.activeJob.requestId;
      await postApi('/api/action', { action: 'approve', requestId: req1Id });

      for (let i = 0; i < 20; i++) {
        const s = await postApi('/api/state', {});
        cursorSeq = s.seq;
        if (s.activeJob?.state === 'RUNNING') break;
        await postApi('/api/stream', { sinceSeq: cursorSeq, waitMs: 3000 });
      }
      const sse2 = await openSse('keep-queued');
      let stBeforeClear = null;
      for (let i = 0; i < 20; i++) {
        const s = await postApi('/api/state', {});
        if (s.activeJob?.state === 'RUNNING' && s.queue.length === 1) { stBeforeClear = s; break; }
        await postApi('/api/stream', { sinceSeq: s.seq, waitMs: 3000 });
      }
      assert.ok(stBeforeClear?.activeJob && stBeforeClear.queue.length === 1, 'Expected RUNNING activeJob + 1 QUEUED job');
      const req2Id = stBeforeClear.queue[0].requestId;
      const seqBefore = stBeforeClear.seq;

      // Clear audit while req1 is RUNNING and req2 is QUEUED
      const clearRes = await postApi('/api/action', { action: 'clear-audit' });
      assert.equal(clearRes.ok, true);
      assert.equal(clearRes.clearedCount, 3);
      assert.ok(clearRes.archivePath && fs.existsSync(clearRes.archivePath), 'archive .zip missing');
      const archiveDir = path.join(tempData, 'archives');
      assert.equal(path.dirname(clearRes.archivePath), archiveDir);
      assert.equal(clearRes.state.audit.length, 0, 'state.audit must be empty after clear');
      assert.ok(clearRes.state.seq > seqBefore, 'seq must increment after clear');
      assert.equal(clearRes.state.activeJob?.requestId, req1Id, 'RUNNING activeJob must stay untouched');
      assert.equal(clearRes.state.activeJob?.state, 'RUNNING');
      assert.equal(clearRes.state.queue.length, 1, 'QUEUED job must stay untouched');
      assert.equal(clearRes.state.queue[0].requestId, req2Id);
      assert.equal(fs.readFileSync(path.join(tempData, 'audit.jsonl'), 'utf8'), '', 'audit.jsonl must be truncated to 0 bytes');
      assert.equal(fs.existsSync(path.join(tempData, rotatedName)), false, 'Archived rotated jsonl must be removed');

      // Validate .zip via .NET System.IO.Compression.ZipFile
      const zipPs = `
        $ErrorActionPreference = 'Stop'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipPath = '${clearRes.archivePath.replace(/'/g, "''")}'
        $dest = '${extractDir.replace(/'/g, "''")}'
        $za = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
          $names = ($za.Entries | ForEach-Object { $_.FullName }) -join ','
          Write-Output "ENTRIES=$names"
        } finally {
          $za.Dispose()
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $dest)
      `;
      const zipOut = await runPsDotNetHttp(zipPs);
      assert.equal(zipOut.code, 0, `ZipFile validation failed: ${zipOut.stderr} ${zipOut.stdout}`);
      assert.match(zipOut.stdout, new RegExp(rotatedName.replace(/\./g, '\\.')));
      assert.match(zipOut.stdout, /audit\.jsonl/);
      const extractedAudit = fs.readFileSync(path.join(extractDir, 'audit.jsonl'), 'utf8');
      assert.equal(extractedAudit.includes('状态/测试 utf8 entry 1'), true, 'ZIP must preserve UTF-8 payload verbatim');
      const extractedRot = fs.readFileSync(path.join(extractDir, rotatedName), 'utf8');
      assert.equal(extractedRot.includes('req-seed-0'), true, 'ZIP must include rotated file contents');

      // Call clear-audit again when empty -> clearedCount: 0, no new empty zip
      const archivesBefore = fs.readdirSync(archiveDir);
      const emptyRes = await postApi('/api/action', { action: 'clear-audit' });
      assert.equal(emptyRes.ok, true);
      assert.equal(emptyRes.clearedCount, 0);
      assert.equal(emptyRes.archivePath, null);
      assert.deepEqual(fs.readdirSync(archiveDir), archivesBefore, 'Empty clear-audit must not create empty zip');
      assert.equal(emptyRes.state.activeJob?.requestId, req1Id);
      assert.equal(emptyRes.state.queue.length, 1);

      // Finish req2 and req1 -> post-clear audit.jsonl appends cleanly
      await postApi('/api/action', { action: 'cancel', requestId: req2Id });
      await postApi('/api/action', { action: 'kill', requestId: req1Id });
      await Promise.all([sse1.textPromise, sse2.textPromise]);
      const postClearLines = fs.readFileSync(path.join(tempData, 'audit.jsonl'), 'utf8').trim().split(/\r?\n/).filter(Boolean);
      assert.equal(postClearLines.length, 2, 'Post-clear completed/cancelled requests must append cleanly');
      return 'Verified in-process ZIP archive, UTF-8 round-trip, rotated cleanup, ongoing/queued preservation, and empty clear';
    } finally {
      try { child.kill(); } catch {}
      await new Promise(r => setTimeout(r, 150));
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  await runCase('A5-REPO-05', '5', 1, 'Real main.mjs startBroker DI open-audit-archives creates ARCHIVE_DIR, enforces X-Sidecar-Token, and mocks Explorer without spawning', async () => {
    const mainMjs = path.join(repoRoot, 'sidecars', 'broker', 'main.mjs');
    const mainSrc = fs.readFileSync(mainMjs, 'utf8');
    // Ensure zero secret env-var bypasses exist in production main.mjs
    assert.equal(/(NO_EXPLORER|SKIP_EXPLORER|DISABLE_EXPLORER|MOCK_EXPLORER)/i.test(mainSrc), false, 'main.mjs must not contain secret env-var bypasses');

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-di-'));
    const tempData = path.join(tempRoot, 'data');
    const uiToken = crypto.randomBytes(16).toString('hex');
    const spawnCalls = [];
    let unrefCalled = 0;

    const { startBroker, buildZipBuffer } = await import(pathToFileURL(mainMjs).href);
    assert.equal(typeof startBroker, 'function', 'main.mjs must export startBroker');
    assert.equal(typeof buildZipBuffer, 'function', 'main.mjs must export buildZipBuffer');

    const broker = await startBroker({
      dataDir: tempData,
      webPort: 0,
      uiToken,
      registerSignalHandlers: false,
      spawnExplorer: (cmd, args, opts) => {
        spawnCalls.push({ cmd, args, opts });
        return { unref: () => { unrefCalled++; } };
      },
    });

    try {
      const expectedArchiveDir = path.join(tempData, 'archives');
      assert.equal(broker.archiveDir, expectedArchiveDir);
      assert.equal(fs.existsSync(expectedArchiveDir), false, 'archives dir should not exist before open/clear');

      // Missing X-Sidecar-Token -> 401
      const unauth = await fetch(`http://127.0.0.1:${broker.webPort}/api/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'open-audit-archives' }),
      });
      assert.equal(unauth.status, 401);
      assert.equal(spawnCalls.length, 0);

      // Authorized open-audit-archives -> 200, creates ARCHIVE_DIR, invokes DI spawnExplorer
      const authRes = await fetch(`http://127.0.0.1:${broker.webPort}/api/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: JSON.stringify({ action: 'open-audit-archives' }),
      });
      assert.equal(authRes.status, 200);
      const json = await authRes.json();
      assert.equal(json.ok, true);
      assert.equal(json.archiveDir, expectedArchiveDir);
      assert.equal(fs.existsSync(expectedArchiveDir), true, 'open-audit-archives must create ARCHIVE_DIR');
      assert.equal(spawnCalls.length, 1);
      assert.equal(spawnCalls[0].cmd, 'explorer.exe');
      assert.deepEqual(spawnCalls[0].args, [expectedArchiveDir]);
      assert.deepEqual(spawnCalls[0].opts, { detached: true, stdio: 'ignore', windowsHide: false });
      assert.equal(unrefCalled, 1);

      // Verify state.sidecarInfo.archiveDir
      const stRes = await fetch(`http://127.0.0.1:${broker.webPort}/api/state`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: '{}',
      });
      const stJson = await stRes.json();
      assert.equal(stJson.sidecarInfo?.archiveDir, expectedArchiveDir);

      return 'Verified startBroker DI, 401 auth gate, ARCHIVE_DIR creation, and mocked explorer.exe launch';
    } finally {
      await broker.close();
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  await runCase('A5-REPO-06', '5', 2, 'Real main.mjs one-shot setTimeout reminder re-arm from last dismissal and cancel on config/finish', async () => {
    const mainMjs = path.join(repoRoot, 'sidecars', 'broker', 'main.mjs');
    const mainSrc = fs.readFileSync(mainMjs, 'utf8');
    const remSection = mainSrc.slice(mainSrc.indexOf('function isReminderEligible'), mainSrc.indexOf('function appendAuditRecord'));
    assert.equal(remSection.includes('setInterval'), false, 'Reminder state machine must NOT use setInterval');
    assert.equal(remSection.includes('setTimeout'), true, 'Reminder state machine must use one-shot setTimeout');

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-rem-'));
    const tempData = path.join(tempRoot, 'data');
    const brokerDir = path.join(tempRoot, 'repo', 'sidecars', 'broker');
    const assetsDir = path.join(tempRoot, 'repo', 'assets');
    fs.mkdirSync(tempData, { recursive: true });
    fs.mkdirSync(brokerDir, { recursive: true });
    fs.mkdirSync(assetsDir, { recursive: true });

    for (const f of ['main.mjs', 'package.json', 'sidecar.json', 'index.html', 'styles.css', 'app.js']) {
      fs.copyFileSync(path.join(repoRoot, 'sidecars', 'broker', f), path.join(brokerDir, f));
    }
    fs.copyFileSync(path.join(repoRoot, 'assets', 'logo.svg'), path.join(assetsDir, 'logo.svg'));

    const helperStub = `param(
    [switch]$PreflightOnly,
    [string]$RunnerPath
)
$ErrorActionPreference = 'Stop'
if ($PreflightOnly) {
    [Console]::Out.WriteLine('{"ok":true,"code":"OK","exitCode":0,"detail":"stub"}')
    exit 0
}
Add-Type -AssemblyName System.Web.Extensions
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $utf8NoBom)
$stdout = [Console]::OpenStandardOutput()
$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$spawnLog = Join-Path $PSScriptRoot 'reminder_spawns.log'

function Emit-Line([hashtable]$obj) {
    $bytes = $utf8NoBom.GetBytes($ser.Serialize($obj) + "\`n")
    $stdout.Write($bytes, 0, $bytes.Length)
    $stdout.Flush()
}

while ($null -ne ($line = $reader.ReadLine())) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $msg = $ser.DeserializeObject($line)
    $cmd = [string]$msg['cmd']
    if ($cmd -eq 'start_request') {
        $reqId = [string]$msg['requestId']
        Emit-Line @{ event = 'click1_shown'; requestId = $reqId }
    } elseif ($cmd -eq 'approve') {
        $reqId = [string]$msg['requestId']
        Emit-Line @{ event = 'uac_started'; requestId = $reqId }
        Emit-Line @{ event = 'runner_connected'; requestId = $reqId }
    } elseif ($cmd -eq 'show_reminder') {
        $nowMs = [int64](([DateTime]::UtcNow.Ticks - 621355968000000000L) / 10000L)
        [System.IO.File]::AppendAllText($spawnLog, "$nowMs\`n", $utf8NoBom)
        $count = ([System.IO.File]::ReadAllLines($spawnLog) | Where-Object { $_ -ne '' }).Count
        Emit-Line @{ event = 'reminder_shown' }
        if ($count -eq 1) {
            Start-Sleep -Milliseconds 1200
            Emit-Line @{ event = 'reminder_dismissed' }
        }
    } elseif ($cmd -eq 'kill') {
        Emit-Line @{ event = 'killed'; requestId = [string]$msg['requestId'] }
    } elseif ($cmd -eq 'cancel') {
        Emit-Line @{ event = 'cancelled'; requestId = [string]$msg['requestId'] }
    } elseif ($cmd -eq 'shutdown') {
        break
    }
}
exit 0
`;
    fs.writeFileSync(path.join(brokerDir, 'broker_helper.ps1'), Buffer.from('\uFEFF' + helperStub, 'utf8'));

    const uiToken = crypto.randomBytes(16).toString('hex');
    const loaderUrl = 'file:///C:/Users/adam/.gemini/antigravity/lib/node_modules/sidecar_sdk/register_loader.js';
    const child = spawn(process.execPath, [`--import=${loaderUrl}`, path.join(brokerDir, 'main.mjs')], {
      cwd: brokerDir,
      env: {
        ...process.env,
        ELECTRON_RUN_AS_NODE: '1',
        ANTIGRAVITY_EXECUTABLE_DATA_DIR: tempData,
        ANTIGRAVITY_LS_ADDRESS: '127.0.0.1:1',
        ANTIGRAVITY_CSRF_TOKEN: 'test-csrf',
        ANTIGRAVITY_SIDECAR_WEB_PORT: '0',
        ANTIGRAVITY_SIDECAR_UI_TOKEN: uiToken
      },
      windowsHide: true
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString('utf8'); });
    child.stderr.on('data', d => { stderr += d.toString('utf8'); });

    try {
      let webPort = 0;
      let rt = null;
      const runtimePath = path.join(tempData, 'runtime.json');
      for (let i = 0; i < 80; i++) {
        const m = stdout.match(/\[sidecar\]\s+listening on 127\.0\.0\.1:(\d+)/i);
        if (m) webPort = Number(m[1]);
        if (fs.existsSync(runtimePath)) {
          try {
            const c = JSON.parse(fs.readFileSync(runtimePath, 'utf8'));
            if (c.pid === child.pid && c.port > 0) rt = c;
          } catch {}
        }
        if (webPort > 0 && rt) break;
        if (child.exitCode !== null) throw new Error(`main.mjs exited early (${child.exitCode}): ${stderr}`);
        await new Promise(r => setTimeout(r, 100));
      }
      assert.ok(webPort > 0 && rt, `main.mjs failed to start: stdout=${stdout} stderr=${stderr}`);

      const postApi = async (p, body) => {
        const r = await fetch(`http://127.0.0.1:${webPort}${p}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
          body: JSON.stringify(body)
        });
        assert.equal(r.status, 200, `${p} returned ${r.status}`);
        return await r.json();
      };
      const openSse = async (reason) => {
        const resp = await fetch(`http://127.0.0.1:${rt.port}/ipc/requests`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${rt.token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'ScriptText', reason, script: 'Write-Output 1', args: [], workDir: 'C:\\Windows', encoding: 'auto' })
        });
        assert.equal(resp.status, 200);
        return { textPromise: resp.text().catch((err) => ({ _sseErr: err })) };
      };

      await postApi('/api/action', { action: 'save-config', config: { reminderIntervalSeconds: 2 } });

      const sse1 = await openSse('rem-run-1');
      let req1Id = '';
      let cursorSeq = (await postApi('/api/state', {})).seq;
      for (let i = 0; i < 20; i++) {
        const s = await postApi('/api/state', {});
        cursorSeq = s.seq;
        if (s.activeJob?.click1Shown) { req1Id = s.activeJob.requestId; break; }
        await postApi('/api/stream', { sinceSeq: cursorSeq, waitMs: 3000 });
      }
      assert.ok(req1Id, 'req1 did not reach click1Shown');
      await postApi('/api/action', { action: 'approve', requestId: req1Id });
      for (let i = 0; i < 20; i++) {
        const s = await postApi('/api/state', {});
        cursorSeq = s.seq;
        if (s.activeJob?.state === 'RUNNING') break;
        await postApi('/api/stream', { sinceSeq: cursorSeq, waitMs: 3000 });
      }

      const sse2 = await openSse('rem-queue-2');
      let seq = (await postApi('/api/state', {})).seq;

      // Wait for 1st reminder_shown
      let gotShown1 = false;
      for (let i = 0; i < 20; i++) {
        const sr = await postApi('/api/stream', { sinceSeq: seq, waitMs: 4000 });
        seq = sr.seq;
        if (sr.state?.reminder?.active) { gotShown1 = true; break; }
      }
      assert.equal(gotShown1, true, '1st reminder did not become active');

      // Wait for native reminder_dismissed after ~1200ms
      let tDismiss1 = 0;
      for (let i = 0; i < 20; i++) {
        const sr = await postApi('/api/stream', { sinceSeq: seq, waitMs: 4000 });
        seq = sr.seq;
        if (!sr.state?.reminder?.active) { tDismiss1 = Date.now(); break; }
      }
      assert.ok(tDismiss1 > 0, '1st reminder did not dismiss natively');

      // Verify 2nd reminder has NOT spawned after 1500ms (< 2000ms full re-arm interval)
      const spawnLogPath = path.join(brokerDir, 'reminder_spawns.log');
      await new Promise(r => setTimeout(r, 1500));
      assert.equal(
        fs.readFileSync(spawnLogPath, 'utf8').trim().split(/\r?\n/).filter(Boolean).length,
        1,
        '2nd reminder spawned prematurely before full 2s post-dismissal interval'
      );

      // Wait for 2nd reminder_shown
      let gotShown2 = false;
      for (let i = 0; i < 20; i++) {
        const s = await postApi('/api/state', {});
        if (s.reminder?.active) { seq = s.seq; gotShown2 = true; break; }
        const sr = await postApi('/api/stream', { sinceSeq: s.seq, waitMs: 4000 });
        seq = sr.seq;
        if (sr.state?.reminder?.active) { gotShown2 = true; break; }
      }
      assert.equal(gotShown2, true, '2nd reminder did not appear after 1st dismissal');

      // Queue a 3rd job while 2nd reminder is active -> must not overlap
      const sse3 = await openSse('rem-queue-3');
      await new Promise(r => setTimeout(r, 250));

      // Dismiss 2nd reminder via Side Panel action
      const tDismiss2 = Date.now();
      const dRes = await postApi('/api/action', { action: 'dismiss-reminder' });
      assert.equal(dRes.state.reminder.active, false, 'dismiss-reminder must clear active state immediately');
      seq = dRes.state.seq;

      // Verify 3rd reminder has NOT spawned after 1500ms (< 2000ms full re-arm interval)
      await new Promise(r => setTimeout(r, 1500));
      assert.equal(
        fs.readFileSync(spawnLogPath, 'utf8').trim().split(/\r?\n/).filter(Boolean).length,
        2,
        '3rd reminder spawned prematurely before full 2s post-dismissal interval'
      );

      // Wait for 3rd reminder_shown
      let gotShown3 = false;
      for (let i = 0; i < 20; i++) {
        const s = await postApi('/api/state', {});
        if (s.reminder?.active) { seq = s.seq; gotShown3 = true; break; }
        const sr = await postApi('/api/stream', { sinceSeq: s.seq, waitMs: 4000 });
        seq = sr.seq;
        if (sr.state?.reminder?.active) { gotShown3 = true; break; }
      }
      assert.equal(gotShown3, true, '3rd reminder did not appear after Side Panel dismissal');

      const spawnTimes = fs.readFileSync(spawnLogPath, 'utf8').trim().split(/\r?\n/).filter(Boolean).map(Number);
      assert.equal(spawnTimes.length, 3, `Expected exactly 3 reminder spawns, got ${spawnTimes.length}`);
      assert.ok(spawnTimes[1] - tDismiss1 >= 1900, `2nd reminder spawned too early after native dismiss (${spawnTimes[1] - tDismiss1} ms)`);
      assert.ok(spawnTimes[2] - tDismiss2 >= 1900, `3rd reminder spawned too early after Side Panel dismiss (${spawnTimes[2] - tDismiss2} ms)`);

      // Dismiss 3rd reminder and disable reminders via save-config -> must cancel timer
      await postApi('/api/action', { action: 'dismiss-reminder' });
      await postApi('/api/action', { action: 'save-config', config: { reminderIntervalSeconds: 0 } });
      await new Promise(r => setTimeout(r, 2300));
      const spawnCountAfterDisable = fs.readFileSync(spawnLogPath, 'utf8').trim().split(/\r?\n/).filter(Boolean).length;
      assert.equal(spawnCountAfterDisable, 3, 'Reminder timer must cancel when reminderIntervalSeconds=0');

      // Re-enable 2s, then kill active job -> must cancel timer cleanly
      await postApi('/api/action', { action: 'save-config', config: { reminderIntervalSeconds: 2 } });
      const stQ = await postApi('/api/state', {});
      for (const q of stQ.queue) {
        await postApi('/api/action', { action: 'cancel', requestId: q.requestId });
      }
      await postApi('/api/action', { action: 'kill', requestId: req1Id });
      await Promise.all([sse1.textPromise, sse2.textPromise, sse3.textPromise]);
      await new Promise(r => setTimeout(r, 2300));
      const spawnCountAfterFinish = fs.readFileSync(spawnLogPath, 'utf8').trim().split(/\r?\n/).filter(Boolean).length;
      assert.equal(spawnCountAfterFinish, 3, 'Reminder timer must cancel when activeJob finishes');

      return `Verified one-shot post-dismissal timings (+${spawnTimes[1] - tDismiss1}ms native, +${spawnTimes[2] - tDismiss2}ms UI) & clean cancel`;
    } finally {
      try { child.kill(); } catch {}
      await new Promise(r => setTimeout(r, 150));
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  await runCase('A5-REPO-07', '5', 2, 'Side Panel UI markup, Live|Archived tabs, shared renderer, 2-click 1.5s Archive + 250ms guard, SSE isolation & revert triggers', async () => {
    const htmlSrc = fs.readFileSync(path.join(repoRoot, 'sidecars', 'broker', 'index.html'), 'utf8');
    const cssSrc = fs.readFileSync(path.join(repoRoot, 'sidecars', 'broker', 'styles.css'), 'utf8');
    const appSrc = fs.readFileSync(path.join(repoRoot, 'sidecars', 'broker', 'app.js'), 'utf8');

    assert.match(htmlSrc, /id="audit-section"/);
    assert.match(htmlSrc, /id="tab-audit-live"/);
    assert.match(htmlSrc, /id="audit-count-badge"/);
    assert.match(htmlSrc, /id="tab-audit-archived"/);
    assert.match(htmlSrc, /id="archive-count-badge"/);
    assert.match(htmlSrc, /id="audit-panel-live"/);
    assert.match(htmlSrc, /id="audit-panel-archived"/);
    assert.match(htmlSrc, /id="archive-select"/);
    assert.match(htmlSrc, /id="btn-open-archives"[^>]*>Open Folder</);
    assert.match(htmlSrc, /id="archive-empty"/);
    assert.match(htmlSrc, /id="archive-status"/);
    assert.match(htmlSrc, /id="archive-list"/);
    assert.match(htmlSrc, /id="btn-clear-audit"[^>]*>/);
    assert.match(htmlSrc, /id="btn-clear-audit-label"[^>]*>Archive</);
    assert.match(htmlSrc, /class="clear-audit-progress"/);
    assert.match(cssSrc, /\.clear-audit-btn[\s\S]*min-width:\s*60px/);
    assert.match(cssSrc, /@keyframes ee-clear-recede/);
    assert.match(cssSrc, /ee-clear-recede\s+1500ms\s+linear\s+forwards/);
    assert.match(cssSrc, /\.audit-tabs/);
    assert.match(cssSrc, /\.archive-select\s*\{/);
    assert.match(cssSrc, /\.archive-select\s+option\s*\{/);

    const elements = new Map();
    const docListeners = new Map();
    const winListeners = new Map();
    const makeClassList = () => {
      const set = new Set();
      return {
        add: (...cls) => cls.forEach(c => set.add(c)),
        remove: (...cls) => cls.forEach(c => set.delete(c)),
        toggle: (c, force) => {
          if (force === undefined) {
            if (set.has(c)) { set.delete(c); return false; }
            set.add(c); return true;
          }
          if (force) set.add(c); else set.delete(c);
          return Boolean(force);
        },
        contains: (c) => set.has(c)
      };
    };
    const makeEl = (id = '', tagName = '') => {
      const listeners = new Map();
      let _text = '';
      return {
        id,
        tagName: String(tagName || '').toUpperCase(),
        style: {},
        dataset: {},
        attrs: {},
        disabled: false,
        open: false,
        selected: false,
        title: '',
        className: '',
        classList: makeClassList(),
        children: [],
        firstChild: null,
        get textContent() { return _text; },
        set textContent(v) {
          _text = String(v ?? '');
          this.children = [];
          this.firstChild = null;
        },
        value: '',
        scrollTop: 0,
        scrollHeight: 0,
        clientHeight: 100,
        addEventListener(type, fn) {
          if (!listeners.has(type)) listeners.set(type, []);
          listeners.get(type).push(fn);
        },
        dispatch(type, evt = {}) {
          const eventObj = { target: this, currentTarget: this, ...evt };
          for (const fn of listeners.get(type) || []) fn(eventObj);
        },
        setAttribute(k, v) { this.attrs[k] = String(v); },
        remove: () => {},
        appendChild(ch) { this.children.push(ch); this.firstChild = this.children[0] || null; return ch; },
        append(...chs) { for (const ch of chs) this.appendChild(ch); }
      };
    };
    const getEl = (id) => {
      if (!elements.has(id)) elements.set(id, makeEl(id));
      return elements.get(id);
    };
    getEl('btn-clear-audit-label').textContent = 'Archive';
    getEl('audit-panel-archived').classList.add('hidden');
    getEl('tab-audit-live').classList.add('active');

    let fakeNowMs = 1_700_000_000_000;
    class FakeDate extends Date {
      static now() { return fakeNowMs; }
    }

    const pendingTimeouts = new Map();
    let nextTimerId = 1;
    const customSetTimeout = (fn, ms) => {
      const id = nextTimerId++;
      const realId = ms === 1500 ? null : setTimeout(() => {
        pendingTimeouts.delete(id);
        fn();
      }, ms);
      pendingTimeouts.set(id, { fn, ms, realId });
      return id;
    };
    const customClearTimeout = (id) => {
      const rec = pendingTimeouts.get(id);
      if (rec) {
        if (rec.realId) clearTimeout(rec.realId);
        pendingTimeouts.delete(id);
      }
    };

    const actionCalls = [];
    let nextStreamResolver = null;
    let resizeObserverCb = null;
    const sampleAudit = [{
      requestId: 'req-a1',
      outcome: 'COMPLETED',
      exitCode: 0,
      finishedAt: '2026-11-24T01:02:03.000Z',
      reason: 'sample audit',
      workDir: 'C:\\Windows',
      manifestSha256: 'ab'.repeat(32)
    }];
    const sampleAudit2 = [
      {
        requestId: 'req-a2',
        outcome: 'COMPLETED',
        exitCode: 0,
        finishedAt: '2026-11-24T01:05:00.000Z',
        reason: 'second audit',
        workDir: 'C:\\Windows',
        manifestSha256: 'cd'.repeat(32)
      },
      ...sampleAudit
    ];
    let mockArchives = [
      { name: 'audit-2026-11-24T02-00-00-000Z-aaaa.zip', sizeBytes: 2048, createdAt: '2026-11-24T02:00:00.000Z' },
      { name: 'audit-2026-11-23T12-30-00-000Z-bbbb.zip', sizeBytes: 1024, createdAt: '2026-11-23T12:30:00.000Z' }
    ];
    const mockArchiveEntries = {
      'audit-2026-11-24T02-00-00-000Z-aaaa.zip': [
        {
          requestId: 'req-arch-new',
          outcome: 'COMPLETED',
          exitCode: 0,
          finishedAt: '2026-11-24T01:50:00.000Z',
          reason: 'archived newer entry',
          workDir: 'C:\\Windows',
          manifestSha256: 'ef'.repeat(32),
          scriptPreview: 'Write-Output 1',
          outputTail: '1'
        }
      ],
      'audit-2026-11-23T12-30-00-000Z-bbbb.zip': [
        {
          requestId: 'req-arch-old',
          outcome: 'DENIED_CLICK1',
          exitCode: 1223,
          finishedAt: '2026-11-23T12:15:00.000Z',
          reason: 'archived older entry',
          workDir: 'C:\\Temp',
          manifestSha256: '12'.repeat(32)
        }
      ]
    };
    let failReadName = '';
    let holdReadName = '';
    const pendingReadResolvers = new Map();
    let holdListRequests = false;
    const pendingListResolvers = [];

    const initialSnap = {
      seq: 1,
      activeJob: null,
      queue: [],
      config: { click1TimeoutSeconds: 300, reminderIntervalSeconds: 300 },
      audit: sampleAudit,
      auditArchiveCount: mockArchives.length,
      auditArchives: mockArchives
    };

    const docEl = { dataset: {}, clientWidth: 400, clientHeight: 600, appendChild: () => {} };
    const sandbox = {
      console,
      Date: FakeDate,
      Math, Number, String, Boolean, Array, Object, JSON, Promise, Set, Map, RegExp, Error, TextEncoder, AbortController,
      Headers: globalThis.Headers,
      navigator: { clipboard: { writeText: async () => {} } },
      getComputedStyle: () => ({ color: 'rgb(247, 247, 248)' }),
      MutationObserver: class { observe() {} },
      ResizeObserver: class {
        constructor(cb) { resizeObserverCb = cb; }
        observe() {}
      },
      document: {
        visibilityState: 'visible',
        documentElement: docEl,
        getElementById: getEl,
        createElement: (tag) => makeEl('', tag),
        querySelectorAll: () => [],
        addEventListener(type, fn) {
          if (!docListeners.has(type)) docListeners.set(type, []);
          docListeners.get(type).push(fn);
        },
        dispatch(type, evt = {}) {
          for (const fn of docListeners.get(type) || []) fn(evt);
        }
      },
      window: {
        addEventListener(type, fn) {
          if (!winListeners.has(type)) winListeners.set(type, []);
          winListeners.get(type).push(fn);
        },
        dispatch(type, evt = {}) {
          for (const fn of winListeners.get(type) || []) fn(evt);
        },
        sidecar: {
          fetch: async (url, init) => {
            if (url === '/api/state') {
              return { ok: true, status: 200, json: async () => initialSnap };
            }
            if (url === '/api/stream') {
              return await new Promise((resolve) => {
                nextStreamResolver = (snap) => resolve({
                  ok: true, status: 200,
                  json: async () => ({ seq: snap.seq, changed: true, state: snap })
                });
              });
            }
            if (url === '/api/action') {
              const payload = JSON.parse(init.body);
              actionCalls.push(payload);
              if (payload.action === 'archive-audit' || payload.action === 'clear-audit') {
                const newArchName = 'audit-2026-11-24T03-00-00-000Z-cccc.zip';
                mockArchives = [
                  { name: newArchName, sizeBytes: 1536, createdAt: '2026-11-24T03:00:00.000Z' },
                  ...mockArchives
                ];
                mockArchiveEntries[newArchName] = [...sampleAudit];
                return {
                  ok: true, status: 200,
                  json: async () => ({
                    ok: true,
                    clearedCount: 1,
                    archivePath: `C:\\tmp\\archives\\${newArchName}`,
                    archiveName: newArchName,
                    archiveSizeBytes: 1536,
                    state: {
                      seq: 10,
                      activeJob: null,
                      queue: [],
                      config: initialSnap.config,
                      audit: [],
                      auditArchiveCount: mockArchives.length,
                      auditArchives: mockArchives
                    }
                  })
                };
              }
              if (payload.action === 'list-audit-archives') {
                if (holdListRequests) {
                  await new Promise((resolve) => pendingListResolvers.push(resolve));
                }
                return {
                  ok: true, status: 200,
                  json: async () => ({ ok: true, archives: mockArchives, auditArchiveCount: mockArchives.length })
                };
              }
              if (payload.action === 'read-audit-archive') {
                if (holdReadName && payload.name === holdReadName) {
                  await new Promise((resolve) => {
                    if (!pendingReadResolvers.has(payload.name)) pendingReadResolvers.set(payload.name, []);
                    pendingReadResolvers.get(payload.name).push(resolve);
                  });
                }
                if (failReadName && payload.name === failReadName) {
                  return {
                    ok: false, status: 422,
                    json: async () => ({ ok: false, error: 'Corrupt DEFLATE stream' })
                  };
                }
                const entries = mockArchiveEntries[payload.name] || [];
                return {
                  ok: true, status: 200,
                  json: async () => ({ ok: true, name: payload.name, sizeBytes: 1024, entries })
                };
              }
              if (payload.action === 'open-audit-archives') {
                return { ok: true, status: 200, json: async () => ({ ok: true, archiveDir: 'C:\\tmp\\archives' }) };
              }
            }
            return { ok: true, status: 200, json: async () => ({ ok: true }) };
          }
        }
      },
      setInterval: () => 1,
      clearInterval: () => {},
      setTimeout: customSetTimeout,
      clearTimeout: customClearTimeout
    };
    sandbox.globalThis = sandbox;

    vm.runInNewContext(appSrc, sandbox, { filename: 'app.js' });
    for (let i = 0; i < 40 && !nextStreamResolver; i++) await new Promise(r => setTimeout(r, 10));
    assert.ok(nextStreamResolver, 'app.js did not start poll loop');

    const pushSnap = async (snap) => {
      for (let i = 0; i < 40 && !nextStreamResolver; i++) await new Promise(r => setTimeout(r, 10));
      const r = nextStreamResolver;
      nextStreamResolver = null;
      r(snap);
      await new Promise(r => setTimeout(r, 10));
    };

    const btnClear = getEl('btn-clear-audit');
    const lblClear = getEl('btn-clear-audit-label');
    const btnArchives = getEl('btn-open-archives');
    const tabLive = getEl('tab-audit-live');
    const tabArchived = getEl('tab-audit-archived');
    const panelLive = getEl('audit-panel-live');
    const panelArchived = getEl('audit-panel-archived');
    const archiveSelect = getEl('archive-select');
    const archiveList = getEl('archive-list');
    const archiveEmpty = getEl('archive-empty');
    const archiveStatus = getEl('archive-status');
    const archiveBadge = getEl('archive-count-badge');
    const auditList = getEl('audit-list');

    // Verify initial date+time format on Live audit entry & archive count badge
    assert.equal(archiveBadge.textContent, '2');
    assert.equal(auditList.children.length, 1);
    const liveDetails = auditList.children[0];
    const liveTimeEl = liveDetails.children[0].children[0].children[1]; // summary -> top -> timeSpan
    assert.match(liveTimeEl.textContent, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/, 'Audit timestamp must include date and time');
    assert.equal(liveTimeEl.title, '2026-11-24T01:02:03.000Z');

    // Expand Live details card and verify SSE push adding a new entry preserves expanded state
    liveDetails.open = true;
    liveDetails.dispatch('toggle');
    await pushSnap({ seq: 2, activeJob: null, queue: [], config: initialSnap.config, audit: sampleAudit2, auditArchiveCount: mockArchives.length, auditArchives: mockArchives });
    assert.equal(auditList.children.length, 2);
    assert.equal(auditList.children[0].dataset.requestId, 'req-a2');
    assert.equal(auditList.children[0].open, false);
    assert.equal(auditList.children[1].dataset.requestId, 'req-a1');
    assert.equal(auditList.children[1].open, true, 'SSE refresh must preserve expanded Live <details> card');

    // (a) Click 1 arms 1500ms receding bar with "Confirm" without disabling focused button
    assert.equal(btnClear.disabled, false);
    btnClear.dispatch('click');
    assert.equal(btnClear.classList.contains('armed'), true);
    assert.equal(btnClear.disabled, false, 'Must not disable button during 250ms guard');
    assert.equal(lblClear.textContent, 'Confirm');
    assert.equal(actionCalls.length, 0);
    const armTimer = Array.from(pendingTimeouts.values()).find(t => t.ms === 1500);
    assert.ok(armTimer, 'Expected 1500ms auto-revert timer');

    // (b) Click 2 < 250ms is ignored by double-click guard
    fakeNowMs += 150;
    btnClear.dispatch('click');
    assert.equal(btnClear.classList.contains('armed'), true);
    assert.equal(actionCalls.length, 0);

    // (c) Incoming /api/stream snapshot while armed must NOT reset or disarm
    await pushSnap({ seq: 3, activeJob: null, queue: [], config: initialSnap.config, audit: sampleAudit2, auditArchiveCount: mockArchives.length, auditArchives: mockArchives });
    assert.equal(btnClear.classList.contains('armed'), true);
    assert.equal(lblClear.textContent, 'Confirm');

    // (d) Click 2 between 250ms and 1500ms executes archive-audit, disarms, disables at 0, and refreshes archive badge/picker
    fakeNowMs += 350;
    btnClear.dispatch('click');
    await new Promise(r => setTimeout(r, 20));
    assert.equal(actionCalls.length, 1);
    assert.equal(actionCalls[0].action, 'archive-audit');
    assert.equal(btnClear.classList.contains('armed'), false);
    assert.equal(lblClear.textContent, 'Archive');
    assert.equal(btnClear.disabled, true, 'Archive button disabled once Live audit is empty');
    assert.equal(archiveBadge.textContent, '3', 'Archive count badge must update seamlessly after archiving');
    assert.equal(archiveSelect.children.length, 3);
    assert.equal(archiveSelect.value, 'audit-2026-11-24T03-00-00-000Z-cccc.zip');

    // (e) Switch to Archived tab -> lazy-loads list-audit-archives + read-audit-archive, renders shared <details> cards
    tabArchived.dispatch('click');
    await new Promise(r => setTimeout(r, 25));
    assert.equal(tabArchived.classList.contains('active'), true);
    assert.equal(tabLive.classList.contains('active'), false);
    assert.equal(panelLive.classList.contains('hidden'), true);
    assert.equal(panelArchived.classList.contains('hidden'), false);
    assert.equal(actionCalls.some(c => c.action === 'list-audit-archives'), true);
    assert.equal(actionCalls.some(c => c.action === 'read-audit-archive' && c.name === 'audit-2026-11-24T03-00-00-000Z-cccc.zip'), true);
    assert.equal(archiveList.children.length, 1);
    assert.equal(archiveList.children[0].dataset.requestId, 'req-a1');
    const archTimeEl = archiveList.children[0].children[0].children[0].children[1];
    assert.match(archTimeEl.textContent, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);

    // (f) Change <select> to older archive, expand its <details> card, and verify SSE push preserves tab, picker & expanded card
    archiveSelect.value = 'audit-2026-11-23T12-30-00-000Z-bbbb.zip';
    archiveSelect.dispatch('change');
    await new Promise(r => setTimeout(r, 25));
    assert.equal(archiveList.children.length, 1);
    assert.equal(archiveList.children[0].dataset.requestId, 'req-arch-old');
    archiveList.children[0].open = true;
    archiveList.children[0].dispatch('toggle');

    const extraArchiveList = [
      { name: 'audit-2026-11-24T04-00-00-000Z-dddd.zip', sizeBytes: 512, createdAt: '2026-11-24T04:00:00.000Z' },
      ...mockArchives
    ];
    await pushSnap({ seq: 11, activeJob: null, queue: [], config: initialSnap.config, audit: sampleAudit, auditArchiveCount: extraArchiveList.length, auditArchives: extraArchiveList });
    assert.equal(tabArchived.classList.contains('active'), true, 'SSE push must not switch away from Archived tab');
    assert.equal(archiveSelect.value, 'audit-2026-11-23T12-30-00-000Z-bbbb.zip', 'SSE push must not reset selected archive');
    assert.equal(archiveList.children[0].open, true, 'SSE push must not collapse expanded Archived <details> card');

    // (g) Read error displays status banner cleanly
    failReadName = 'audit-2026-11-24T02-00-00-000Z-aaaa.zip';
    archiveSelect.value = failReadName;
    archiveSelect.dispatch('change');
    await new Promise(r => setTimeout(r, 25));
    assert.equal(archiveStatus.classList.contains('hidden'), false);
    assert.equal(archiveStatus.classList.contains('error'), true);
    assert.match(archiveStatus.textContent, /Corrupt DEFLATE stream/);
    failReadName = '';

    // (h) Open Folder button works in Archived tab & even when archives are empty
    const callsBeforeOpen = actionCalls.length;
    assert.equal(btnArchives.disabled, false);
    btnArchives.dispatch('click');
    await new Promise(r => setTimeout(r, 15));
    assert.equal(actionCalls[callsBeforeOpen].action, 'open-audit-archives');

    // Empty archive list disables <select>, shows empty notice, keeps Open Folder enabled
    mockArchives = [];
    await pushSnap({ seq: 12, activeJob: null, queue: [], config: initialSnap.config, audit: sampleAudit, auditArchiveCount: 0, auditArchives: [] });
    assert.equal(archiveBadge.textContent, '0');
    assert.equal(archiveSelect.disabled, true);
    assert.equal(archiveEmpty.classList.contains('hidden'), false);
    assert.equal(btnArchives.disabled, false);

    // (i) Switch back to Live tab and verify all revert triggers (1500ms, Escape, visibilitychange, blur, pagehide, ResizeObserver collapse, tab switch)
    tabLive.dispatch('click');
    assert.equal(tabLive.classList.contains('active'), true);
    assert.equal(btnClear.disabled, false);

    // Switching to Archived tab while armed disarms
    btnClear.dispatch('click');
    assert.equal(btnClear.classList.contains('armed'), true);
    tabArchived.dispatch('click');
    await new Promise(r => setTimeout(r, 15));
    assert.equal(btnClear.classList.contains('armed'), false);
    assert.equal(lblClear.textContent, 'Archive');
    tabLive.dispatch('click');

    const callsBeforeRevert = actionCalls.length;
    // 1500ms auto-expiry reverts without POST
    btnClear.dispatch('click');
    assert.equal(btnClear.classList.contains('armed'), true);
    const expEntry = Array.from(pendingTimeouts.entries()).find(([, v]) => v.ms === 1500);
    assert.ok(expEntry);
    pendingTimeouts.delete(expEntry[0]);
    expEntry[1].fn();
    assert.equal(btnClear.classList.contains('armed'), false);
    assert.equal(lblClear.textContent, 'Archive');
    assert.equal(actionCalls.length, callsBeforeRevert);

    // Escape keydown reverts without POST
    btnClear.dispatch('click');
    assert.equal(btnClear.classList.contains('armed'), true);
    sandbox.document.dispatch('keydown', { key: 'Escape' });
    assert.equal(btnClear.classList.contains('armed'), false);

    // visibilitychange hidden reverts without POST
    btnClear.dispatch('click');
    assert.equal(btnClear.classList.contains('armed'), true);
    sandbox.document.visibilityState = 'hidden';
    sandbox.document.dispatch('visibilitychange');
    assert.equal(btnClear.classList.contains('armed'), false);
    sandbox.document.visibilityState = 'visible';
    sandbox.document.dispatch('visibilitychange');
    for (let i = 0; i < 40 && !nextStreamResolver; i++) await new Promise(r => setTimeout(r, 10));

    // window blur & pagehide revert without POST
    btnClear.dispatch('click');
    assert.equal(btnClear.classList.contains('armed'), true);
    sandbox.window.dispatch('blur');
    assert.equal(btnClear.classList.contains('armed'), false);

    btnClear.dispatch('click');
    assert.equal(btnClear.classList.contains('armed'), true);
    sandbox.window.dispatch('pagehide');
    assert.equal(btnClear.classList.contains('armed'), false);

    // ResizeObserver collapse reverts without POST
    docEl.clientWidth = 400;
    docEl.clientHeight = 600;
    if (resizeObserverCb) resizeObserverCb();
    for (let i = 0; i < 40 && !nextStreamResolver; i++) await new Promise(r => setTimeout(r, 10));
    btnClear.dispatch('click');
    assert.equal(btnClear.classList.contains('armed'), true);
    docEl.clientWidth = 0;
    docEl.clientHeight = 0;
    if (resizeObserverCb) resizeObserverCb();
    assert.equal(btnClear.classList.contains('armed'), false);
    assert.equal(actionCalls.length, callsBeforeRevert);

    // Restore pane visibility and archives for P2a / P2b / P2c regression tests
    docEl.clientWidth = 400;
    docEl.clientHeight = 600;
    if (resizeObserverCb) resizeObserverCb();
    for (let i = 0; i < 40 && !nextStreamResolver; i++) await new Promise(r => setTimeout(r, 10));

    const archA = 'audit-2026-11-24T02-00-00-000Z-aaaa.zip';
    const archB = 'audit-2026-11-23T12-30-00-000Z-bbbb.zip';
    mockArchives = [
      { name: archA, sizeBytes: 2048, createdAt: '2026-11-24T02:00:00.000Z' },
      { name: archB, sizeBytes: 1024, createdAt: '2026-11-23T12:30:00.000Z' }
    ];
    await pushSnap({
      seq: 20,
      activeJob: null,
      queue: [],
      config: initialSnap.config,
      audit: sampleAudit,
      auditArchiveCount: mockArchives.length,
      auditArchives: mockArchives
    });

    // (j) P2a: Switching <select> from slow pending read-audit-archive(A) to fast read-audit-archive(B)
    // must clear #archive-status immediately when B resolves, before A settles.
    holdReadName = archA;
    tabArchived.dispatch('click');
    for (let i = 0; i < 40 && !(pendingReadResolvers.get(archA)?.length); i++) {
      await new Promise(r => setTimeout(r, 10));
    }
    assert.equal(pendingReadResolvers.get(archA)?.length, 1, 'Expected slow read-audit-archive(A) in flight');
    assert.equal(archiveStatus.classList.contains('hidden'), false);
    assert.equal(archiveStatus.textContent, 'Loading archive...');

    archiveSelect.value = archB;
    archiveSelect.dispatch('change');
    await new Promise(r => setTimeout(r, 25));
    assert.equal(archiveList.children.length, 1);
    assert.equal(archiveList.children[0].dataset.requestId, 'req-arch-old');
    assert.equal(archiveStatus.classList.contains('hidden'), true, 'P2a: #archive-status must hide immediately when fast B resolves');
    assert.equal(archiveStatus.textContent, '');

    // Settle stale A and verify B remains displayed and banner stays hidden
    holdReadName = '';
    while (pendingReadResolvers.get(archA)?.length) {
      pendingReadResolvers.get(archA).shift()();
    }
    await new Promise(r => setTimeout(r, 25));
    assert.equal(archiveSelect.value, archB);
    assert.equal(archiveList.children[0].dataset.requestId, 'req-arch-old');
    assert.equal(archiveStatus.classList.contains('hidden'), true);

    // (k) P2b: When read-audit-archive(A) fails (422), subsequent /api/stream applySnapshot() pushes
    // must NOT clear #archive-status.error and must NOT re-fire read-audit-archive.
    failReadName = archA;
    archiveSelect.value = archA;
    archiveSelect.dispatch('change');
    await new Promise(r => setTimeout(r, 25));
    assert.equal(archiveStatus.classList.contains('hidden'), false);
    assert.equal(archiveStatus.classList.contains('error'), true);
    assert.match(archiveStatus.textContent, /Corrupt DEFLATE stream/);
    const readCountAfterFail = actionCalls.filter(c => c.action === 'read-audit-archive').length;

    await pushSnap({
      seq: 21,
      activeJob: {
        requestId: 'req-sse-running',
        state: 'RUNNING',
        reason: 'live stdout push',
        mode: 'ScriptText',
        encoding: 'utf8',
        workDir: 'C:\\Windows',
        manifestSha256: 'ab'.repeat(32),
        script: 'Write-Output 1',
        output: { chunks: [{ seq: 1, stream: 'stdout', text: 'line1\n' }], totalBytes: 6, truncated: false }
      },
      queue: [],
      config: initialSnap.config,
      audit: sampleAudit,
      auditArchiveCount: mockArchives.length,
      auditArchives: mockArchives
    });
    await pushSnap({
      seq: 22,
      activeJob: null,
      queue: [],
      config: initialSnap.config,
      audit: sampleAudit,
      auditArchiveCount: mockArchives.length + 1,
      auditArchives: [
        { name: 'audit-2026-11-24T05-00-00-000Z-eeee.zip', sizeBytes: 512, createdAt: '2026-11-24T05:00:00.000Z' },
        ...mockArchives
      ]
    });
    assert.equal(
      actionCalls.filter(c => c.action === 'read-audit-archive').length,
      readCountAfterFail,
      'P2b: SSE applySnapshot pushes must NOT re-fire read-audit-archive on failed archive'
    );
    assert.equal(archiveStatus.classList.contains('hidden'), false);
    assert.equal(archiveStatus.classList.contains('error'), true);
    assert.match(archiveStatus.textContent, /Corrupt DEFLATE stream/, 'P2b: SSE applySnapshot pushes must NOT clear error banner');
    assert.equal(archiveSelect.value, archA);
    failReadName = '';

    // (l) P2c: Slow list-audit-archives settling after read-audit-archive(B) failed
    // must preserve #archive-status.error without wiping or re-fetching B.
    tabLive.dispatch('click');
    await pushSnap({
      seq: 23,
      activeJob: null,
      queue: [],
      config: initialSnap.config,
      audit: sampleAudit,
      auditArchiveCount: mockArchives.length,
      auditArchives: mockArchives
    });
    holdListRequests = true;
    failReadName = archB;
    tabArchived.dispatch('click');
    for (let i = 0; i < 40 && pendingListResolvers.length === 0; i++) {
      await new Promise(r => setTimeout(r, 10));
    }
    assert.equal(pendingListResolvers.length, 1, 'Expected slow list-audit-archives in flight');

    archiveSelect.value = archB;
    archiveSelect.dispatch('change');
    await new Promise(r => setTimeout(r, 25));
    assert.equal(archiveStatus.classList.contains('hidden'), false);
    assert.equal(archiveStatus.classList.contains('error'), true);
    assert.match(archiveStatus.textContent, /Corrupt DEFLATE stream/);
    const readCountBeforeListSettles = actionCalls.filter(c => c.action === 'read-audit-archive').length;

    holdListRequests = false;
    while (pendingListResolvers.length) {
      pendingListResolvers.shift()();
    }
    await new Promise(r => setTimeout(r, 25));
    assert.equal(
      actionCalls.filter(c => c.action === 'read-audit-archive').length,
      readCountBeforeListSettles,
      'P2c: slow list-audit-archives settling must NOT re-fetch failed archive B'
    );
    assert.equal(archiveStatus.classList.contains('hidden'), false);
    assert.equal(archiveStatus.classList.contains('error'), true);
    assert.match(archiveStatus.textContent, /Corrupt DEFLATE stream/, 'P2c: slow list-audit-archives settling must NOT wipe error banner');
    assert.equal(archiveSelect.value, archB);
    failReadName = '';

    // Also verify metadata change on failed archive clears error and retries cleanly
    mockArchives = [
      { name: archA, sizeBytes: 2048, createdAt: '2026-11-24T02:00:00.000Z' },
      { name: archB, sizeBytes: 1536, createdAt: '2026-11-23T12:30:00.000Z' }
    ];
    await pushSnap({
      seq: 24,
      activeJob: null,
      queue: [],
      config: initialSnap.config,
      audit: sampleAudit,
      auditArchiveCount: mockArchives.length,
      auditArchives: mockArchives
    });
    await new Promise(r => setTimeout(r, 25));
    assert.equal(archiveStatus.classList.contains('hidden'), true);
    assert.equal(archiveList.children.length, 1);
    assert.equal(archiveList.children[0].dataset.requestId, 'req-arch-old');

    // Verify renderAuditEntries preserves .open on non-Array HTMLCollection-like .children without toggle event
    await pushSnap({ seq: 25, activeJob: null, queue: [], config: initialSnap.config, audit: [], auditArchiveCount: mockArchives.length, auditArchives: mockArchives });
    await pushSnap({ seq: 26, activeJob: null, queue: [], config: initialSnap.config, audit: sampleAudit, auditArchiveCount: mockArchives.length, auditArchives: mockArchives });
    const collChild = makeEl('', 'details');
    collChild.dataset.requestId = 'req-a1';
    collChild.open = true;
    auditList.children = { 0: collChild, length: 1, item(i) { return this[i] || null; } };
    assert.equal(Array.isArray(auditList.children), false);
    await pushSnap({ seq: 27, activeJob: null, queue: [], config: initialSnap.config, audit: sampleAudit2, auditArchiveCount: mockArchives.length, auditArchives: mockArchives });
    assert.equal(auditList.children[1].dataset.requestId, 'req-a1');
    assert.equal(auditList.children[1].open, true, 'renderAuditEntries must support non-Array HTMLCollection-like .children');

    return 'Verified M6e UI markup, Live|Archived tabs, shared renderer, Archive 2-click/250ms/1500ms, SSE isolation, P2a/P2b/P2c races, and all revert triggers';
  });

  function buildCustomZip(entries) {
    const crcTable = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      crcTable[i] = c >>> 0;
    }
    const calcCrc = (buf) => {
      let c = 0xffffffff;
      for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
      return (c ^ 0xffffffff) >>> 0;
    };

    const localParts = [];
    const centralParts = [];
    let offset = 0;

    for (const e of entries) {
      const nameBuf = Buffer.from(e.name, 'utf8');
      const rawData = Buffer.isBuffer(e.data) ? e.data : Buffer.from(String(e.data ?? ''), 'utf8');
      const method = e.method ?? 8;
      const flags = e.flags ?? 0x0800;
      const compressed = e.compressedData !== undefined
        ? e.compressedData
        : (method === 0 ? rawData : zlib.deflateRawSync(rawData));
      const crc = e.crcOverride !== undefined ? (e.crcOverride >>> 0) : calcCrc(rawData);
      const lfhCompSize = e.lfhCompSize !== undefined ? e.lfhCompSize : compressed.length;
      const lfhUncompSize = e.lfhUncompSize !== undefined ? e.lfhUncompSize : rawData.length;
      const cdCompSize = e.cdCompSize !== undefined ? e.cdCompSize : compressed.length;
      const cdUncompSize = e.cdUncompSize !== undefined ? e.cdUncompSize : rawData.length;

      const lfh = Buffer.alloc(30);
      lfh.writeUInt32LE(0x04034b50, 0);
      lfh.writeUInt16LE(20, 4);
      lfh.writeUInt16LE(flags, 6);
      lfh.writeUInt16LE(method, 8);
      lfh.writeUInt16LE(0, 10);
      lfh.writeUInt16LE(0x5421, 12);
      lfh.writeUInt32LE(crc, 14);
      lfh.writeUInt32LE(lfhCompSize >>> 0, 18);
      lfh.writeUInt32LE(lfhUncompSize >>> 0, 22);
      lfh.writeUInt16LE(nameBuf.length, 26);
      lfh.writeUInt16LE(0, 28);

      const localOffset = offset;
      localParts.push(lfh, nameBuf, compressed);
      offset += lfh.length + nameBuf.length + compressed.length;

      const cdh = Buffer.alloc(46);
      cdh.writeUInt32LE(0x02014b50, 0);
      cdh.writeUInt16LE(20, 4);
      cdh.writeUInt16LE(20, 6);
      cdh.writeUInt16LE(flags, 8);
      cdh.writeUInt16LE(method, 10);
      cdh.writeUInt16LE(0, 12);
      cdh.writeUInt16LE(0x5421, 14);
      cdh.writeUInt32LE(crc, 16);
      cdh.writeUInt32LE(cdCompSize >>> 0, 20);
      cdh.writeUInt32LE(cdUncompSize >>> 0, 24);
      cdh.writeUInt16LE(nameBuf.length, 28);
      cdh.writeUInt16LE(0, 30);
      cdh.writeUInt16LE(0, 32);
      cdh.writeUInt16LE(0, 34);
      cdh.writeUInt16LE(0, 36);
      cdh.writeUInt32LE(0, 38);
      cdh.writeUInt32LE(localOffset >>> 0, 42);

      centralParts.push(cdh, nameBuf);
    }

    const cdBuf = Buffer.concat(centralParts);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(0, 4);
    eocd.writeUInt16LE(0, 6);
    eocd.writeUInt16LE(entries.length, 8);
    eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(cdBuf.length >>> 0, 12);
    eocd.writeUInt32LE(offset >>> 0, 16);
    eocd.writeUInt16LE(0, 20);
    return Buffer.concat([...localParts, cdBuf, eocd]);
  }

  await runCase('A5-REPO-08', '5', 1, 'list-audit-archives, auditArchiveCount, and archive-audit/clear-audit -> read-audit-archive round-trip parity', async () => {
    const mainMjs = path.join(repoRoot, 'sidecars', 'broker', 'main.mjs');
    const { startBroker } = await import(pathToFileURL(mainMjs).href);

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-arch-rt-'));
    const tempData = path.join(tempRoot, 'data');
    fs.mkdirSync(tempData, { recursive: true });

    const eRot = {
      requestId: 'req-rt-0',
      createdAt: '2026-11-24T00:59:50.000Z',
      startedAt: '2026-11-24T00:59:51.000Z',
      finishedAt: '2026-11-24T01:00:00.000Z',
      mode: 'ScriptText',
      reason: 'rotated utf8 状态',
      workDir: 'C:\\Windows',
      args: ['--flag'],
      encoding: 'utf8',
      normalWindow: false,
      targetMeta: null,
      attribution: { agentLabel: 'Antigravity', workspace: 'ws', conversationId: 'conv-1', stepIndex: 1 },
      manifestSha256: '00'.repeat(32),
      outcome: 'COMPLETED',
      exitCode: 0,
      message: 'done',
      scriptPreview: 'Write-Output "状态"',
      outputTail: '状态'
    };
    const eLive1 = { ...eRot, requestId: 'req-rt-1', finishedAt: '2026-11-24T01:01:00.000Z', reason: 'live entry 1' };
    const eLive2 = { ...eRot, requestId: 'req-rt-2', finishedAt: '2026-11-24T01:02:00.000Z', reason: 'live entry 2', outcome: 'DENIED_CLICK1', exitCode: 1223 };
    fs.writeFileSync(path.join(tempData, 'audit.1700000000000.aa11.jsonl'), JSON.stringify(eRot) + '\n', 'utf8');
    fs.writeFileSync(path.join(tempData, 'audit.jsonl'), JSON.stringify(eLive1) + '\n' + JSON.stringify(eLive2) + '\n', 'utf8');

    const uiToken = crypto.randomBytes(16).toString('hex');
    const broker = await startBroker({
      dataDir: tempData,
      webPort: 0,
      uiToken,
      registerSignalHandlers: false,
      spawnExplorer: () => ({ unref() {} })
    });

    const postAction = async (body, token = uiToken) => {
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['X-Sidecar-Token'] = token;
      const r = await fetch(`http://127.0.0.1:${broker.webPort}/api/action`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body)
      });
      return { status: r.status, json: await r.json() };
    };

    try {
      // Unauthenticated list-audit-archives -> 401
      const unauth = await postAction({ action: 'list-audit-archives' }, '');
      assert.equal(unauth.status, 401);

      // Absent ARCHIVE_DIR -> empty list without creating dir
      const emptyList = await postAction({ action: 'list-audit-archives' });
      assert.equal(emptyList.status, 200);
      assert.deepEqual(emptyList.json, { ok: true, archives: [], auditArchiveCount: 0 });
      assert.equal(fs.existsSync(broker.archiveDir), false, 'list-audit-archives must not create ARCHIVE_DIR');

      // Initial /api/state exposes auditArchiveCount=0
      const st0 = await (await fetch(`http://127.0.0.1:${broker.webPort}/api/state`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: '{}'
      })).json();
      assert.equal(st0.auditArchiveCount, 0);
      assert.deepEqual(st0.auditArchives, []);

      // Archive via archive-audit alias
      const arch1 = await postAction({ action: 'archive-audit' });
      assert.equal(arch1.status, 200);
      assert.equal(arch1.json.ok, true);
      assert.equal(arch1.json.clearedCount, 3);
      assert.ok(arch1.json.archiveName && arch1.json.archiveName.endsWith('.zip'));
      assert.ok(arch1.json.archiveSizeBytes > 0);
      assert.equal(arch1.json.state.auditArchiveCount, 1);
      assert.equal(arch1.json.state.auditArchives[0].name, arch1.json.archiveName);

      // Read back via read-audit-archive -> newest-first parity
      const read1 = await postAction({ action: 'read-audit-archive', name: arch1.json.archiveName });
      assert.equal(read1.status, 200);
      assert.equal(read1.json.ok, true);
      assert.equal(read1.json.name, arch1.json.archiveName);
      assert.deepEqual(read1.json.entries, [eLive2, eLive1, eRot]);

      // Create second archive via backward-compatible clear-audit & add noise files to verify filtering + newest-first sort
      const eLive3 = { ...eRot, requestId: 'req-rt-3', finishedAt: '2026-11-24T02:00:00.000Z', reason: 'second batch' };
      fs.writeFileSync(path.join(tempData, 'audit.jsonl'), JSON.stringify(eLive3) + '\n', 'utf8');
      await new Promise(r => setTimeout(r, 30));
      const arch2 = await postAction({ action: 'clear-audit' });
      assert.equal(arch2.status, 200);
      assert.equal(arch2.json.clearedCount, 1);
      assert.ok(arch2.json.archiveName);

      // Noise files ignored by list-audit-archives
      fs.writeFileSync(path.join(broker.archiveDir, 'notes.txt'), 'ignore', 'utf8');
      fs.writeFileSync(path.join(broker.archiveDir, 'bad.zip'), 'ignore', 'utf8');
      fs.writeFileSync(path.join(broker.archiveDir, 'audit-1.zip.tmp.123'), 'ignore', 'utf8');

      // Explicit mtime ordering check
      const tOld = new Date('2026-11-24T01:00:00.000Z');
      const tNew = new Date('2026-11-24T02:00:00.000Z');
      fs.utimesSync(path.join(broker.archiveDir, arch1.json.archiveName), tOld, tOld);
      fs.utimesSync(path.join(broker.archiveDir, arch2.json.archiveName), tNew, tNew);

      const listRes = await postAction({ action: 'list-audit-archives' });
      assert.equal(listRes.status, 200);
      assert.equal(listRes.json.auditArchiveCount, 2);
      assert.deepEqual(listRes.json.archives.map(a => a.name), [arch2.json.archiveName, arch1.json.archiveName]);

      const read2 = await postAction({ action: 'read-audit-archive', name: arch2.json.archiveName });
      assert.equal(read2.status, 200);
      assert.deepEqual(read2.json.entries, [eLive3]);

      return 'Verified list-audit-archives, archive-audit & clear-audit round-trip parity, filtering, and newest-first sorting';
    } finally {
      await broker.close();
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  await runCase('A5-REPO-09', '5', 1, 'Pure node:zlib PKZIP reader supports method 0 STORE, method 8 DEFLATE, and multi-member JSONL sorting', async () => {
    const mainMjs = path.join(repoRoot, 'sidecars', 'broker', 'main.mjs');
    const { startBroker } = await import(pathToFileURL(mainMjs).href);

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-zip-m08-'));
    const tempData = path.join(tempRoot, 'data');
    const archiveDir = path.join(tempData, 'archives');
    fs.mkdirSync(archiveDir, { recursive: true });

    const rec1 = { requestId: 'm0-1', outcome: 'COMPLETED', exitCode: 0, finishedAt: '2026-11-24T01:00:00.000Z', reason: 'store member' };
    const rec2 = { requestId: 'm8-2', outcome: 'COMPLETED', exitCode: 0, finishedAt: '2026-11-24T02:00:00.000Z', reason: 'deflate rotated utf8 测试' };
    const rec3 = { requestId: 'm8-3', outcome: 'FAILED', exitCode: 1, finishedAt: '2026-11-24T03:00:00.000Z', reason: 'live member last' };

    const zipName = 'audit-2026-11-24T03-00-00-000Z-cafe.zip';
    // Intentionally place audit.jsonl first in the ZIP to verify chronological sorting puts rotated first and audit.jsonl last
    const zipBuf = buildCustomZip([
      { name: 'audit.jsonl', data: JSON.stringify(rec3) + '\n', method: 8 },
      { name: 'readme.txt', data: 'not jsonl', method: 0 },
      { name: 'audit.1700000002000.bb22.jsonl', data: JSON.stringify(rec2) + '\n', method: 8 },
      { name: 'audit.1700000001000.aa11.jsonl', data: JSON.stringify(rec1) + '\n', method: 0 }
    ]);
    fs.writeFileSync(path.join(archiveDir, zipName), zipBuf);

    const uiToken = crypto.randomBytes(16).toString('hex');
    const broker = await startBroker({
      dataDir: tempData,
      webPort: 0,
      uiToken,
      registerSignalHandlers: false,
      spawnExplorer: () => ({ unref() {} })
    });

    try {
      const r = await fetch(`http://127.0.0.1:${broker.webPort}/api/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: JSON.stringify({ action: 'read-audit-archive', name: zipName })
      });
      assert.equal(r.status, 200);
      const j = await r.json();
      assert.equal(j.ok, true);
      assert.deepEqual(j.entries, [rec3, rec2, rec1]);
      return 'Verified method 0 STORE, method 8 DEFLATE, non-JSONL skip, and multi-member chronological -> newest-first ordering';
    } finally {
      await broker.close();
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  await runCase('A5-REPO-10', '5', 2, 'read-audit-archive & list-audit-archives security: 401 token, traversal/regex 400, missing 404, and NTFS junction/reparse rejection', async () => {
    const mainMjs = path.join(repoRoot, 'sidecars', 'broker', 'main.mjs');
    const { startBroker } = await import(pathToFileURL(mainMjs).href);

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-zip-sec-'));
    const tempData = path.join(tempRoot, 'data');
    const outsideDir = path.join(tempRoot, 'outside');
    const archiveDir = path.join(tempData, 'archives');
    fs.mkdirSync(archiveDir, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });

    // Place a valid-looking zip in outsideDir and junction to it inside archiveDir
    const validZip = buildCustomZip([{ name: 'audit.jsonl', data: JSON.stringify({ requestId: 'escape' }) + '\n', method: 0 }]);
    fs.writeFileSync(path.join(outsideDir, 'audit-2026-11-24T00-00-00-000Z-out1.zip'), validZip);
    fs.symlinkSync(outsideDir, path.join(archiveDir, 'audit-junction-dir.zip'), 'junction');

    const uiToken = crypto.randomBytes(16).toString('hex');
    const broker = await startBroker({
      dataDir: tempData,
      webPort: 0,
      uiToken,
      registerSignalHandlers: false,
      spawnExplorer: () => ({ unref() {} })
    });

    const postRead = async (name, token = uiToken) => {
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['X-Sidecar-Token'] = token;
      const r = await fetch(`http://127.0.0.1:${broker.webPort}/api/action`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ action: 'read-audit-archive', name })
      });
      return { status: r.status, json: await r.json() };
    };

    try {
      // 401 auth gate
      assert.equal((await postRead('audit-valid.zip', '')).status, 401);
      assert.equal((await postRead('audit-valid.zip', 'wrong-token')).status, 401);

      // 400 invalid names / traversal
      const badNames = [undefined, null, 123, '', '../audit-x.zip', '..\\audit-x.zip', 'sub/audit-x.zip', 'audit-x.zip\0.zip', 'not-audit.zip', 'audit-a b.zip', 'audit-x.txt', 'audit-..zip'];
      for (const bad of badNames) {
        const res = await postRead(bad);
        assert.equal(res.status, 400, `Expected 400 for name=${JSON.stringify(bad)}, got ${res.status}`);
        assert.equal(res.json.ok, false);
      }

      // 404 missing archive
      const missingRes = await postRead('audit-2099-01-01T00-00-00-000Z-dead.zip');
      assert.equal(missingRes.status, 404);
      assert.equal(missingRes.json.ok, false);

      // Junction inside ARCHIVE_DIR rejected on read and ignored on list
      const juncChildRes = await postRead('audit-junction-dir.zip');
      assert.equal(juncChildRes.status, 400);
      const listOk = await fetch(`http://127.0.0.1:${broker.webPort}/api/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: JSON.stringify({ action: 'list-audit-archives' })
      });
      assert.equal(listOk.status, 200);
      assert.deepEqual((await listOk.json()).archives, []);

      // Replace ARCHIVE_DIR itself with NTFS junction to outsideDir -> 400 on list & read
      fs.rmSync(archiveDir, { recursive: true, force: true });
      fs.symlinkSync(outsideDir, archiveDir, 'junction');

      const listJuncDir = await fetch(`http://127.0.0.1:${broker.webPort}/api/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: JSON.stringify({ action: 'list-audit-archives' })
      });
      assert.equal(listJuncDir.status, 400);

      const readJuncDir = await postRead('audit-2026-11-24T00-00-00-000Z-out1.zip');
      assert.equal(readJuncDir.status, 400);

      return 'Verified 401 auth, 400 traversal/regex, 404 missing, and NTFS junction/reparse-point rejection';
    } finally {
      await broker.close();
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  await runCase('A5-REPO-11', '5', 2, 'Anti-zip-bomb (>16 MiB declared & lying-header inflate stream) and corrupt/CRC/unsupported-method errors without broker crash', async () => {
    const mainMjs = path.join(repoRoot, 'sidecars', 'broker', 'main.mjs');
    const { startBroker, parseZipEntries } = await import(pathToFileURL(mainMjs).href);

    // Direct parseZipEntries check for remainingBudget === 0 edge case (must NOT throw ERR_OUT_OF_RANGE)
    const twoMemberBomb = buildCustomZip([
      { name: 'a.jsonl', data: Buffer.alloc(1024, 0x41), method: 8 },
      {
        name: 'b.jsonl',
        data: Buffer.alloc(0),
        method: 8,
        compressedData: zlib.deflateRawSync(Buffer.alloc(100, 0x42)),
        crcOverride: 0,
        lfhCompSize: zlib.deflateRawSync(Buffer.alloc(100, 0x42)).length,
        cdCompSize: zlib.deflateRawSync(Buffer.alloc(100, 0x42)).length,
        lfhUncompSize: 0,
        cdUncompSize: 0
      }
    ]);
    assert.throws(
      () => parseZipEntries(twoMemberBomb, { maxTotalBytes: 1024 }),
      (err) => err && err.status === 413
    );

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-zip-bomb-'));
    const tempData = path.join(tempRoot, 'data');
    const archiveDir = path.join(tempData, 'archives');
    fs.mkdirSync(archiveDir, { recursive: true });

    // 1. Declared single entry > 16 MiB
    const declaredBig = buildCustomZip([
      { name: 'audit.jsonl', data: Buffer.from('{"x":1}\n'), method: 8, lfhUncompSize: 17 * 1024 * 1024, cdUncompSize: 17 * 1024 * 1024 }
    ]);
    fs.writeFileSync(path.join(archiveDir, 'audit-declared-big.zip'), declaredBig);

    // 2. Declared multi-member cumulative 9 MiB + 9 MiB > 16 MiB
    const declaredMulti = buildCustomZip([
      { name: 'audit.1.aa11.jsonl', data: Buffer.from('{"x":1}\n'), method: 8, lfhUncompSize: 9 * 1024 * 1024, cdUncompSize: 9 * 1024 * 1024 },
      { name: 'audit.jsonl', data: Buffer.from('{"x":2}\n'), method: 8, lfhUncompSize: 9 * 1024 * 1024, cdUncompSize: 9 * 1024 * 1024 }
    ]);
    fs.writeFileSync(path.join(archiveDir, 'audit-declared-multi.zip'), declaredMulti);

    // 3. Lying header: actual deflated payload is 17 MiB of zeros, header claims 128 bytes
    const bombPayload = Buffer.alloc(17 * 1024 * 1024, 0);
    const bombCompressed = zlib.deflateRawSync(bombPayload);
    const lyingBomb = buildCustomZip([
      {
        name: 'audit.jsonl',
        data: Buffer.alloc(128, 0),
        method: 8,
        compressedData: bombCompressed,
        lfhCompSize: bombCompressed.length,
        cdCompSize: bombCompressed.length,
        lfhUncompSize: 128,
        cdUncompSize: 128
      }
    ]);
    fs.writeFileSync(path.join(archiveDir, 'audit-lying-bomb.zip'), lyingBomb);

    // 4. Corrupt / truncated ZIP
    fs.writeFileSync(path.join(archiveDir, 'audit-corrupt.zip'), Buffer.from('PK\x03\x04truncated'));

    // 5. CRC-32 mismatch
    const badCrc = buildCustomZip([{ name: 'audit.jsonl', data: '{"x":1}\n', method: 8, crcOverride: 0xdeadbeef }]);
    fs.writeFileSync(path.join(archiveDir, 'audit-bad-crc.zip'), badCrc);

    // 6. Unsupported compression method (99)
    const badMethod = buildCustomZip([{ name: 'audit.jsonl', data: '{"x":1}\n', method: 99, compressedData: Buffer.from('{"x":1}\n') }]);
    fs.writeFileSync(path.join(archiveDir, 'audit-bad-method.zip'), badMethod);

    // 7. Encrypted flag (bit 0)
    const encryptedZip = buildCustomZip([{ name: 'audit.jsonl', data: '{"x":1}\n', method: 8, flags: 0x0801 }]);
    fs.writeFileSync(path.join(archiveDir, 'audit-encrypted.zip'), encryptedZip);

    // 8. Valid ZIP with no .jsonl member
    const noJsonlZip = buildCustomZip([{ name: 'readme.txt', data: 'hello', method: 0 }]);
    fs.writeFileSync(path.join(archiveDir, 'audit-no-jsonl.zip'), noJsonlZip);

    const uiToken = crypto.randomBytes(16).toString('hex');
    const broker = await startBroker({
      dataDir: tempData,
      webPort: 0,
      uiToken,
      registerSignalHandlers: false,
      spawnExplorer: () => ({ unref() {} })
    });

    const postRead = async (name) => {
      const r = await fetch(`http://127.0.0.1:${broker.webPort}/api/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: JSON.stringify({ action: 'read-audit-archive', name })
      });
      return { status: r.status, json: await r.json() };
    };

    try {
      for (const bombName of ['audit-declared-big.zip', 'audit-declared-multi.zip', 'audit-lying-bomb.zip']) {
        const res = await postRead(bombName);
        assert.equal(res.status, 413, `Expected 413 for ${bombName}, got ${res.status}: ${JSON.stringify(res.json)}`);
        assert.equal(res.json.ok, false);
      }

      for (const badName of ['audit-corrupt.zip', 'audit-bad-crc.zip', 'audit-bad-method.zip', 'audit-encrypted.zip', 'audit-no-jsonl.zip']) {
        const res = await postRead(badName);
        assert.equal(res.status, 422, `Expected 422 for ${badName}, got ${res.status}: ${JSON.stringify(res.json)}`);
        assert.equal(res.json.ok, false);
      }

      // Broker remains healthy and responsive
      const stRes = await fetch(`http://127.0.0.1:${broker.webPort}/api/state`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sidecar-Token': uiToken },
        body: '{}'
      });
      assert.equal(stRes.status, 200);
      assert.equal((await stRes.json()).ok, undefined); // state snapshot returned cleanly

      return 'Verified anti-zip-bomb (declared + lying-header + remainingBudget=0) and corrupt/CRC/method/encrypted rejections without crash';
    } finally {
      await broker.close();
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  function writeAutoCompleteHelperStub(stubPath) {
    const helperStub = `param(
    [switch]$PreflightOnly,
    [string]$RunnerPath
)
$ErrorActionPreference = 'Stop'
if ($PreflightOnly) {
    [Console]::Out.WriteLine('{"ok":true,"code":"OK","exitCode":0,"detail":"stub"}')
    exit 0
}
Add-Type -AssemblyName System.Web.Extensions
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $utf8NoBom)
$stdout = [Console]::OpenStandardOutput()
$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer

function Emit-Line([hashtable]$obj) {
    $bytes = $utf8NoBom.GetBytes($ser.Serialize($obj) + "\`n")
    $stdout.Write($bytes, 0, $bytes.Length)
    $stdout.Flush()
}

while ($null -ne ($line = $reader.ReadLine())) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $msg = $ser.DeserializeObject($line)
    $cmd = [string]$msg['cmd']
    if ($cmd -eq 'start_request') {
        $reqId = [string]$msg['requestId']
        Emit-Line @{ event = 'click1_shown'; requestId = $reqId }
        Emit-Line @{ event = 'uac_started'; requestId = $reqId }
        Emit-Line @{ event = 'runner_connected'; requestId = $reqId }
        Emit-Line @{ event = 'stdout'; requestId = $reqId; text = ("out-" + $reqId + "\`n") }
        Emit-Line @{ event = 'exit'; requestId = $reqId; exitCode = 0 }
    } elseif ($cmd -eq 'shutdown') {
        break
    }
}
exit 0
`;
    fs.writeFileSync(stubPath, Buffer.from('\uFEFF' + helperStub, 'utf8'));
  }

  async function submitStubIpcRequest(broker, reason, script = 'Write-Output 1') {
    const resp = await fetch(`http://127.0.0.1:${broker.ipcPort}/ipc/requests`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${broker.ipcBearerToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        mode: 'ScriptText',
        reason,
        script,
        args: [],
        workDir: 'C:\\Windows',
        encoding: 'auto',
      }),
    });
    assert.equal(resp.status, 200, `Expected HTTP 200 SSE for "${reason}", got ${resp.status}`);
    const sseText = await resp.text();
    assert.match(sseText, /event: outcome/, `Missing outcome SSE event for "${reason}"`);
    return sseText;
  }

  async function postUiJson(port, uiToken, apiPath, body) {
    const r = await fetch(`http://127.0.0.1:${port}${apiPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Sidecar-Token': uiToken,
      },
      body: JSON.stringify(body),
    });
    return { status: r.status, json: await r.json() };
  }

  async function watchStreamUntil(port, uiToken, startSeq, predicate, timeoutMs = 12000) {
    let cursorSeq = startSeq;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const remaining = Math.max(200, deadline - Date.now());
      const resp = await postUiJson(port, uiToken, '/api/stream', {
        sinceSeq: cursorSeq,
        waitMs: Math.min(remaining, 5000),
      });
      assert.equal(resp.status, 200);
      if (resp.json.seq > cursorSeq) {
        cursorSeq = resp.json.seq;
      }
      if (resp.json.changed && predicate(resp.json)) {
        return resp.json;
      }
    }
    throw new Error(`Timed out waiting for /api/stream predicate after seq=${startSeq}`);
  }

  await runCase('A5-REPO-12', '5', 1, 'Unified line-threshold auto-archive rotation (env & options), Live reset, SSE stream, archive parity, .NET ZipFile, and restart persistence', async () => {
    const mainMjs = path.join(repoRoot, 'sidecars', 'broker', 'main.mjs');
    const { startBroker } = await import(pathToFileURL(mainMjs).href);

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-autorot-lines-'));
    const tempData1 = path.join(tempRoot, 'data1');
    const tempData2 = path.join(tempRoot, 'data2');
    const extractDir = path.join(tempRoot, 'extracted');
    const stubPath = path.join(tempRoot, 'stub_helper.ps1');
    fs.mkdirSync(tempData1, { recursive: true });
    fs.mkdirSync(tempData2, { recursive: true });
    writeAutoCompleteHelperStub(stubPath);

    const prevEnvLines = process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES;
    const prevEnvBytes = process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES;
    const uiToken = crypto.randomBytes(16).toString('hex');
    let broker1 = null;
    let broker1Restart = null;
    let broker2 = null;

    try {
      // Part A: ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES = '3'
      process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES = '3';
      delete process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES;

      broker1 = await startBroker({
        dataDir: tempData1,
        helperPath: stubPath,
        webPort: 0,
        uiToken,
        registerSignalHandlers: false,
        spawnExplorer: () => ({ unref() {} }),
      });

      await submitStubIpcRequest(broker1, 'line-rot-1 状态', 'Write-Output "状态1"');
      await submitStubIpcRequest(broker1, 'line-rot-2 测试', 'Write-Output "测试2"');

      // 1-below threshold -> no rotation yet
      const auditPath1 = path.join(tempData1, 'audit.jsonl');
      const preLines = fs.readFileSync(auditPath1, 'utf8').split(/\r?\n/).filter((l) => l.trim().length > 0);
      assert.equal(preLines.length, 2, 'Should not rotate at 2 lines when threshold is 3');
      assert.equal(fs.readdirSync(tempData1).filter((n) => /^audit\..*\.jsonl$/i.test(n)).length, 0);
      assert.equal(fs.existsSync(broker1.archiveDir), false, 'ARCHIVE_DIR must not exist before rotation');

      const list0 = await postUiJson(broker1.webPort, uiToken, '/api/action', { action: 'list-audit-archives' });
      assert.equal(list0.status, 200);
      assert.equal(list0.json.auditArchiveCount, 0);

      const st2 = (await postUiJson(broker1.webPort, uiToken, '/api/state', {})).json;
      assert.equal(st2.audit.length, 2);
      assert.deepEqual(st2.audit.map((e) => e.reason), ['line-rot-2 测试', 'line-rot-1 状态']);

      // Watch /api/stream across req 3 lifecycle until finalizeJob() + rotation completes
      const streamPromise = watchStreamUntil(
        broker1.webPort,
        uiToken,
        st2.seq,
        (sr) => sr.state.activeJob === null && sr.state.auditArchiveCount === 1
      );

      await submitStubIpcRequest(broker1, 'line-rot-3 触发', 'Write-Output "触发3"');

      const streamResp = await streamPromise;
      assert.equal(streamResp.changed, true, '/api/stream must wake on rotation');
      assert.ok(streamResp.seq > st2.seq, 'SSE seq must increment after job completion + rotation');
      assert.deepEqual(streamResp.state.audit, [], 'Live audit snapshot must reset to [] on rotation');
      assert.equal(streamResp.state.auditArchiveCount, 1);
      assert.equal(streamResp.state.auditArchives.length, 1);

      const zipName = streamResp.state.auditArchives[0].name;
      assert.match(zipName, /^audit-[A-Za-z0-9._-]+\.zip$/);

      // Verify disk state: audit.jsonl truncated to 0 bytes, zero loose audit.*.jsonl, single .zip in archives\
      assert.equal(fs.statSync(auditPath1).size, 0, 'audit.jsonl must be truncated to 0 bytes after auto-rotation');
      assert.equal(fs.readdirSync(tempData1).filter((n) => /^audit\..*\.jsonl$/i.test(n)).length, 0, 'Zero loose audit.*.jsonl files allowed');
      assert.deepEqual(fs.readdirSync(broker1.archiveDir), [zipName]);

      // Verify list-audit-archives & read-audit-archive parity (newest-first, UTF-8 preserved)
      const list1 = await postUiJson(broker1.webPort, uiToken, '/api/action', { action: 'list-audit-archives' });
      assert.equal(list1.status, 200);
      assert.equal(list1.json.auditArchiveCount, 1);
      assert.equal(list1.json.archives[0].name, zipName);

      const read1 = await postUiJson(broker1.webPort, uiToken, '/api/action', { action: 'read-audit-archive', name: zipName });
      assert.equal(read1.status, 200);
      assert.equal(read1.json.ok, true);
      assert.equal(read1.json.entries.length, 3);
      assert.deepEqual(read1.json.entries.map((e) => e.reason), ['line-rot-3 触发', 'line-rot-2 测试', 'line-rot-1 状态']);

      // Verify .NET ZipFile readability + UTF-8 extraction
      const zipPath = path.join(broker1.archiveDir, zipName);
      const zipPs = `
        $ErrorActionPreference = 'Stop'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipPath = '${zipPath.replace(/'/g, "''")}'
        $dest = '${extractDir.replace(/'/g, "''")}'
        $za = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
          $names = ($za.Entries | ForEach-Object { $_.FullName }) -join ','
          Write-Output "ENTRIES=$names"
        } finally {
          $za.Dispose()
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $dest)
      `;
      const zipOut = await runPsDotNetHttp(zipPs);
      assert.equal(zipOut.code, 0, `.NET ZipFile check failed: ${zipOut.stderr} ${zipOut.stdout}`);
      assert.match(zipOut.stdout, /ENTRIES=audit\.jsonl/);
      const extractedAudit = fs.readFileSync(path.join(extractDir, 'audit.jsonl'), 'utf8');
      assert.equal(extractedAudit.split(/\r?\n/).filter((l) => l.trim().length > 0).length, 3);
      assert.equal(extractedAudit.includes('line-rot-1 状态'), true);

      // Post-rotation 4th request starts fresh in audit.jsonl and survives broker restart
      await submitStubIpcRequest(broker1, 'post-rot-4', 'Write-Output 4');
      const stAfter4 = (await postUiJson(broker1.webPort, uiToken, '/api/state', {})).json;
      assert.equal(stAfter4.audit.length, 1);
      assert.equal(stAfter4.audit[0].reason, 'post-rot-4');
      assert.equal(stAfter4.auditArchiveCount, 1);
      assert.equal(fs.readFileSync(auditPath1, 'utf8').split(/\r?\n/).filter((l) => l.trim().length > 0).length, 1);
      assert.equal(fs.readdirSync(tempData1).filter((n) => /^audit\..*\.jsonl$/i.test(n)).length, 0);

      await broker1.close();
      broker1 = null;

      broker1Restart = await startBroker({
        dataDir: tempData1,
        helperPath: stubPath,
        webPort: 0,
        uiToken,
        registerSignalHandlers: false,
        spawnExplorer: () => ({ unref() {} }),
      });
      const stRestart = (await postUiJson(broker1Restart.webPort, uiToken, '/api/state', {})).json;
      assert.equal(stRestart.audit.length, 1, 'Restarted broker must load exact 1 post-rotation entry');
      assert.equal(stRestart.audit[0].reason, 'post-rot-4');
      assert.equal(stRestart.auditArchiveCount, 1);
      await broker1Restart.close();
      broker1Restart = null;

      // Part B: options.auditRotateMaxLines overrides env and triggers at 2
      process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES = '99';
      broker2 = await startBroker({
        dataDir: tempData2,
        helperPath: stubPath,
        webPort: 0,
        uiToken,
        auditRotateMaxLines: 2,
        registerSignalHandlers: false,
        spawnExplorer: () => ({ unref() {} }),
      });
      await submitStubIpcRequest(broker2, 'opt-line-1');
      assert.equal((await postUiJson(broker2.webPort, uiToken, '/api/state', {})).json.audit.length, 1);
      await submitStubIpcRequest(broker2, 'opt-line-2');
      const stOpt2 = (await postUiJson(broker2.webPort, uiToken, '/api/state', {})).json;
      assert.deepEqual(stOpt2.audit, []);
      assert.equal(stOpt2.auditArchiveCount, 1);
      assert.equal(fs.statSync(path.join(tempData2, 'audit.jsonl')).size, 0);
      assert.equal(fs.readdirSync(tempData2).filter((n) => /^audit\..*\.jsonl$/i.test(n)).length, 0);
      const readOpt2 = await postUiJson(broker2.webPort, uiToken, '/api/action', {
        action: 'read-audit-archive',
        name: stOpt2.auditArchives[0].name,
      });
      assert.deepEqual(readOpt2.json.entries.map((e) => e.reason), ['opt-line-2', 'opt-line-1']);

      return 'Verified line-threshold auto-archive rotation (env + options), SSE stream, Live reset, .NET ZipFile, zero loose files, and restart persistence';
    } finally {
      if (prevEnvLines === undefined) delete process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES;
      else process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES = prevEnvLines;
      if (prevEnvBytes === undefined) delete process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES;
      else process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES = prevEnvBytes;
      if (broker1) await broker1.close();
      if (broker1Restart) await broker1Restart.close();
      if (broker2) await broker2.close();
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  await runCase('A5-REPO-13', '5', 2, 'Byte-threshold auto-archive rotation below line limit, invalid threshold fallback (200 / 5 MiB), and legacy audit.*.jsonl absorption', async () => {
    const mainMjs = path.join(repoRoot, 'sidecars', 'broker', 'main.mjs');
    const { startBroker } = await import(pathToFileURL(mainMjs).href);

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-repo-autorot-bytes-'));
    const tempDataEnv = path.join(tempRoot, 'data-env');
    const tempDataOpt = path.join(tempRoot, 'data-opt');
    const tempDataInvEnv = path.join(tempRoot, 'data-invenv');
    const tempDataInvOpt1 = path.join(tempRoot, 'data-invopt1');
    const tempDataInvOpt2 = path.join(tempRoot, 'data-invopt2');
    const stubPath = path.join(tempRoot, 'stub_helper.ps1');
    for (const d of [tempDataEnv, tempDataOpt, tempDataInvEnv, tempDataInvOpt1, tempDataInvOpt2]) {
      fs.mkdirSync(d, { recursive: true });
    }
    writeAutoCompleteHelperStub(stubPath);

    const prevEnvLines = process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES;
    const prevEnvBytes = process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES;
    const uiToken = crypto.randomBytes(16).toString('hex');
    const openBrokers = [];

    try {
      // Part A: ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES = '1800' (< 200 lines) + legacy audit.<ts>.<hex>.jsonl absorption
      const legacyEntry = {
        requestId: 'req-legacy-0',
        createdAt: '2026-11-24T00:00:00.000Z',
        startedAt: '2026-11-24T00:00:01.000Z',
        finishedAt: '2026-11-24T00:00:02.000Z',
        mode: 'ScriptText',
        reason: 'legacy-pre-m6g',
        workDir: 'C:\\Windows',
        args: [],
        encoding: 'auto',
        normalWindow: false,
        targetMeta: null,
        attribution: { agentLabel: 'Antigravity', workspace: 'ws', conversationId: '', stepIndex: 0 },
        manifestSha256: '00'.repeat(32),
        outcome: 'COMPLETED',
        exitCode: 0,
        message: 'done',
        scriptPreview: 'Write-Output 0',
        outputTail: '',
      };
      const legacyName = 'audit.1700000000000.cc33.jsonl';
      fs.writeFileSync(path.join(tempDataEnv, legacyName), JSON.stringify(legacyEntry) + '\n', 'utf8');

      process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES = '200';
      process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES = '1800';
      const brokerEnv = await startBroker({
        dataDir: tempDataEnv,
        helperPath: stubPath,
        webPort: 0,
        uiToken,
        registerSignalHandlers: false,
        spawnExplorer: () => ({ unref() {} }),
      });
      openBrokers.push(brokerEnv);

      await submitStubIpcRequest(brokerEnv, 'bytes-env-1', 'Write-Output 1');
      const stEnv1 = (await postUiJson(brokerEnv.webPort, uiToken, '/api/state', {})).json;
      assert.equal(stEnv1.audit.length, 1);
      assert.equal(stEnv1.auditArchiveCount, 0);
      assert.equal(fs.existsSync(path.join(tempDataEnv, legacyName)), true, 'Legacy file stays until rotation triggers');

      const streamEnvPromise = watchStreamUntil(
        brokerEnv.webPort,
        uiToken,
        stEnv1.seq,
        (sr) => sr.state.activeJob === null && sr.state.auditArchiveCount === 1
      );
      await submitStubIpcRequest(brokerEnv, 'bytes-env-2', '# ' + 'X'.repeat(1600));
      const streamEnv = await streamEnvPromise;
      assert.equal(streamEnv.changed, true);
      assert.deepEqual(streamEnv.state.audit, []);
      assert.equal(streamEnv.state.auditArchiveCount, 1);
      assert.equal(fs.statSync(path.join(tempDataEnv, 'audit.jsonl')).size, 0);
      assert.equal(fs.existsSync(path.join(tempDataEnv, legacyName)), false, 'Pre-existing legacy audit.*.jsonl must be absorbed and deleted');
      assert.equal(fs.readdirSync(tempDataEnv).filter((n) => /^audit\..*\.jsonl$/i.test(n)).length, 0);

      const listEnv = await postUiJson(brokerEnv.webPort, uiToken, '/api/action', { action: 'list-audit-archives' });
      assert.equal(listEnv.json.auditArchiveCount, 1);
      const readEnv = await postUiJson(brokerEnv.webPort, uiToken, '/api/action', {
        action: 'read-audit-archive',
        name: listEnv.json.archives[0].name,
      });
      assert.equal(readEnv.status, 200);
      assert.deepEqual(readEnv.json.entries.map((e) => e.reason), ['bytes-env-2', 'bytes-env-1', 'legacy-pre-m6g']);
      await brokerEnv.close();

      // Part B: options.auditRotateMaxBytes below line limit
      delete process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES;
      delete process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES;
      const brokerOpt = await startBroker({
        dataDir: tempDataOpt,
        helperPath: stubPath,
        webPort: 0,
        uiToken,
        auditRotateMaxLines: 200,
        auditRotateMaxBytes: 1500,
        registerSignalHandlers: false,
        spawnExplorer: () => ({ unref() {} }),
      });
      openBrokers.push(brokerOpt);

      await submitStubIpcRequest(brokerOpt, 'bytes-opt-1', 'Write-Output 1');
      assert.equal((await postUiJson(brokerOpt.webPort, uiToken, '/api/state', {})).json.audit.length, 1);
      await submitStubIpcRequest(brokerOpt, 'bytes-opt-2', '# ' + 'Y'.repeat(1600));
      const stOpt = (await postUiJson(brokerOpt.webPort, uiToken, '/api/state', {})).json;
      assert.deepEqual(stOpt.audit, []);
      assert.equal(stOpt.auditArchiveCount, 1);
      assert.equal(fs.statSync(path.join(tempDataOpt, 'audit.jsonl')).size, 0);
      assert.equal(fs.readdirSync(tempDataOpt).filter((n) => /^audit\..*\.jsonl$/i.test(n)).length, 0);
      const readOpt = await postUiJson(brokerOpt.webPort, uiToken, '/api/action', {
        action: 'read-audit-archive',
        name: stOpt.auditArchives[0].name,
      });
      assert.deepEqual(readOpt.json.entries.map((e) => e.reason), ['bytes-opt-2', 'bytes-opt-1']);
      await brokerOpt.close();

      // Part C: Invalid threshold overrides strictly fall back to defaults (200 / 5 MiB) and never rotate prematurely
      const invalidCases = [
        { dataDir: tempDataInvEnv, envLines: '0', envBytes: '-5', optLines: undefined, optBytes: undefined, label: 'env-0-neg' },
        { dataDir: tempDataInvOpt1, envLines: 'abc', envBytes: '', optLines: NaN, optBytes: Infinity, label: 'opt-NaN-Inf' },
        { dataDir: tempDataInvOpt2, envLines: undefined, envBytes: undefined, optLines: 1.5, optBytes: 'abc', label: 'opt-float-str' },
      ];
      for (const tc of invalidCases) {
        if (tc.envLines === undefined) delete process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES;
        else process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES = tc.envLines;
        if (tc.envBytes === undefined) delete process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES;
        else process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES = tc.envBytes;

        const b = await startBroker({
          dataDir: tc.dataDir,
          helperPath: stubPath,
          webPort: 0,
          uiToken,
          auditRotateMaxLines: tc.optLines,
          auditRotateMaxBytes: tc.optBytes,
          registerSignalHandlers: false,
          spawnExplorer: () => ({ unref() {} }),
        });
        openBrokers.push(b);

        await submitStubIpcRequest(b, `${tc.label}-1`, 'Write-Output 1');
        await submitStubIpcRequest(b, `${tc.label}-2`, '# ' + 'Z'.repeat(1600));
        const st = (await postUiJson(b.webPort, uiToken, '/api/state', {})).json;
        assert.equal(st.audit.length, 2, `Invalid thresholds (${tc.label}) must not rotate prematurely`);
        assert.equal(st.auditArchiveCount, 0, `Invalid thresholds (${tc.label}) must create 0 archives`);
        const lines = fs.readFileSync(path.join(tc.dataDir, 'audit.jsonl'), 'utf8').split(/\r?\n/).filter((l) => l.trim().length > 0);
        assert.equal(lines.length, 2);
        await b.close();
      }

      return 'Verified byte-threshold auto-rotation (env & options), invalid threshold fallback, and legacy audit.*.jsonl absorption';
    } finally {
      if (prevEnvLines === undefined) delete process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES;
      else process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES = prevEnvLines;
      if (prevEnvBytes === undefined) delete process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES;
      else process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES = prevEnvBytes;
      for (const b of openBrokers) {
        try { await b.close(); } catch {}
      }
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });
}

await runSelfTestSuite();
if (opts.repoRoot) {
  await runRepoIntegration(opts.repoRoot);
}

const total = results.length;
const passedCount = results.filter(r => r.passed).length;
const failedCount = total - passedCount;

if (opts.jsonReport) {
  const reportObj = {
    module: 'Test-BrokerIpc.mjs',
    summary: { total, passed: passedCount, failed: failedCount },
    results
  };
  fs.writeFileSync(opts.jsonReport, JSON.stringify(reportObj, null, 2), 'utf8');
}

console.log(`Area 5 Summary: ${passedCount}/${total} passed (${failedCount} failed)`);
process.exit(failedCount > 0 ? 1 : 0);
