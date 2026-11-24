import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { execFile, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { StringDecoder } from 'node:string_decoder';
import { SidecarApp, Response } from 'sidecar_sdk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BOOT_ASSET_VERSION = Date.now().toString(36);
const DEFAULT_RUNNER_PATH = 'C:\\Program Files\\AgentElevation\\Invoke-ElevatedRunner.ps1';
const RUNNER_PATH = process.env.ELEVATED_EXEC_RUNNER_PATH || DEFAULT_RUNNER_PATH;
const HELPER_PATH = path.join(__dirname, 'broker_helper.ps1');
const LOGO_PATH = path.resolve(__dirname, '..', '..', 'assets', 'logo.svg');

const MAX_MANIFEST_BYTES = 10 * 1024 * 1024;
const MAX_IPC_BODY_BYTES = 11 * 1024 * 1024;
const RING_BUFFER_MAX_BYTES = 512 * 1024;
const HELPER_PREVIEW_MAX_BYTES = 64 * 1024;
const AUDIT_PREVIEW_MAX_BYTES = 4096;
const AUDIT_ROTATE_MAX_LINES = 200;
const AUDIT_ROTATE_MAX_BYTES = 5 * 1024 * 1024;
const SSE_KEEPALIVE_MS = 15000;
const MAX_STREAM_WAIT_MS = 15000;
const PREFLIGHT_TIMEOUT_MS = 3900;
const AGENTAPI_TIMEOUT_MS = 1500;
const AGENTAPI_MAX_BUFFER = 16 * 1024 * 1024;

const VALID_MODES = new Set(['ScriptBlock', 'ScriptText', 'ScriptFile', 'FilePath']);
const VALID_ENCODINGS = new Set(['auto', 'utf8', 'oem', 'utf16']);

function resolveDataDir() {
  if (process.env.ANTIGRAVITY_EXECUTABLE_DATA_DIR && process.env.ANTIGRAVITY_EXECUTABLE_DATA_DIR.trim()) {
    return path.resolve(process.env.ANTIGRAVITY_EXECUTABLE_DATA_DIR.trim());
  }
  const appDataRoot = process.env.ANTIGRAVITY_APP_DATA_DIR && process.env.ANTIGRAVITY_APP_DATA_DIR.trim()
    ? process.env.ANTIGRAVITY_APP_DATA_DIR.trim()
    : path.join(os.homedir(), '.gemini', 'antigravity');
  return path.join(appDataRoot, 'sidecar_data', 'elevated-exec', 'broker', 'data');
}

function ensureDataDirsAndSweep(dataDir, stagedDir, runtimePath) {
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(stagedDir, { recursive: true });

  for (const entry of fs.readdirSync(stagedDir)) {
    try {
      fs.rmSync(path.join(stagedDir, entry), { recursive: true, force: true });
    } catch {
      // Best-effort sweep of stale staged manifests
    }
  }
  try {
    fs.rmSync(runtimePath, { force: true });
  } catch {
    // Best-effort sweep of stale runtime.json
  }
}

function hardenDataDirAclsAsync(dataDir) {
  execFile('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { timeout: 1000, windowsHide: true }, (err, stdout) => {
    if (err || !stdout) return;
    const match = String(stdout).match(/"(S-1-[0-9-]+)"/);
    if (!match) return;
    const userSid = match[1];
    execFile(
      'icacls.exe',
      [
        dataDir,
        '/inheritance:r',
        '/grant:r',
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F',
        `*${userSid}:(OI)(CI)F`,
      ],
      { timeout: 1500, windowsHide: true },
      () => {
        // Non-blocking best-effort ACL hardening
      }
    );
  });
}

function writeAtomicUtf8(targetPath, content) {
  const tmpPath = `${targetPath}.tmp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmpPath, content, 'utf8');
  fs.renameSync(tmpPath, targetPath);
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function toDosDateTime(dateInput) {
  const d = dateInput instanceof Date && !Number.isNaN(dateInput.getTime()) ? dateInput : new Date();
  const year = Math.max(1980, Math.min(2107, d.getFullYear()));
  const month = d.getMonth() + 1;
  const day = d.getDate();
  const hours = d.getHours();
  const minutes = d.getMinutes();
  const seconds = Math.floor(d.getSeconds() / 2);
  const dosTime = ((hours & 0x1f) << 11) | ((minutes & 0x3f) << 5) | (seconds & 0x1f);
  const dosDate = (((year - 1980) & 0x7f) << 9) | ((month & 0x0f) << 5) | (day & 0x1f);
  return { dosTime: dosTime >>> 0, dosDate: dosDate >>> 0 };
}

export function buildZipBuffer(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(String(entry.name), 'utf8');
    const rawData = Buffer.isBuffer(entry.data)
      ? entry.data
      : Buffer.from(String(entry.data ?? ''), 'utf8');
    const compressed = zlib.deflateRawSync(rawData);
    const crc = crc32(rawData);
    const { dosTime, dosDate } = toDosDateTime(entry.mtime);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0x0800, 6);
    localHeader.writeUInt16LE(8, 8);
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length >>> 0, 18);
    localHeader.writeUInt32LE(rawData.length >>> 0, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    const localOffset = offset;
    localParts.push(localHeader, nameBuf, compressed);
    offset += localHeader.length + nameBuf.length + compressed.length;

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressed.length >>> 0, 20);
    centralHeader.writeUInt32LE(rawData.length >>> 0, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(localOffset >>> 0, 42);

    centralParts.push(centralHeader, nameBuf);
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

const ARCHIVE_NAME_REGEX = /^audit-[A-Za-z0-9._-]+\.zip$/;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES = 16 * 1024 * 1024;
const MAX_ARCHIVE_RAW_ZIP_BYTES = 17 * 1024 * 1024;
const MAX_ARCHIVE_ENTRY_COUNT = 1000;

class ZipReadError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ZipReadError';
    this.status = status;
  }
}

export function parseZipEntries(zipBuf, { maxTotalBytes = MAX_ARCHIVE_UNCOMPRESSED_BYTES } = {}) {
  if (!Buffer.isBuffer(zipBuf) || zipBuf.length < 22) {
    throw new ZipReadError(422, 'Invalid or truncated ZIP archive');
  }
  const budgetCap = Number.isInteger(maxTotalBytes) && maxTotalBytes >= 1
    ? maxTotalBytes
    : MAX_ARCHIVE_UNCOMPRESSED_BYTES;

  const minScan = Math.max(0, zipBuf.length - 65557);
  let eocdPos = -1;
  for (let i = zipBuf.length - 22; i >= minScan; i--) {
    if (zipBuf.readUInt32LE(i) === 0x06054b50) {
      const commentLen = zipBuf.readUInt16LE(i + 20);
      if (i + 22 + commentLen === zipBuf.length) {
        eocdPos = i;
        break;
      }
    }
  }
  if (eocdPos < 0) {
    throw new ZipReadError(422, 'Missing ZIP end-of-central-directory record');
  }
  if (eocdPos >= 20 && zipBuf.readUInt32LE(eocdPos - 20) === 0x07064b50) {
    throw new ZipReadError(422, 'ZIP64 archives are not supported');
  }

  const diskNum = zipBuf.readUInt16LE(eocdPos + 4);
  const cdDiskNum = zipBuf.readUInt16LE(eocdPos + 6);
  const diskEntries = zipBuf.readUInt16LE(eocdPos + 8);
  const totalEntries = zipBuf.readUInt16LE(eocdPos + 10);
  const cdSize = zipBuf.readUInt32LE(eocdPos + 12);
  const cdOffset = zipBuf.readUInt32LE(eocdPos + 16);

  if (
    diskNum !== 0 ||
    cdDiskNum !== 0 ||
    diskEntries !== totalEntries ||
    diskEntries === 0xffff ||
    totalEntries === 0xffff ||
    cdSize === 0xffffffff ||
    cdOffset === 0xffffffff
  ) {
    throw new ZipReadError(422, 'Unsupported ZIP64 or multi-disk archive');
  }
  if (totalEntries > MAX_ARCHIVE_ENTRY_COUNT) {
    throw new ZipReadError(422, `ZIP entry count (${totalEntries}) exceeds limit (${MAX_ARCHIVE_ENTRY_COUNT})`);
  }
  const cdEnd = cdOffset + cdSize;
  if (cdOffset > eocdPos || cdEnd > eocdPos) {
    throw new ZipReadError(422, 'Corrupt ZIP central directory bounds');
  }

  const cdRecords = [];
  let pos = cdOffset;
  let declaredTotalUncomp = 0;

  for (let idx = 0; idx < totalEntries; idx++) {
    if (pos + 46 > cdEnd || zipBuf.readUInt32LE(pos) !== 0x02014b50) {
      throw new ZipReadError(422, 'Corrupt ZIP central directory header');
    }
    const flags = zipBuf.readUInt16LE(pos + 8);
    const method = zipBuf.readUInt16LE(pos + 10);
    const cdCrc = zipBuf.readUInt32LE(pos + 16);
    const cdCompSize = zipBuf.readUInt32LE(pos + 20);
    const cdUncompSize = zipBuf.readUInt32LE(pos + 24);
    const nameLen = zipBuf.readUInt16LE(pos + 28);
    const extraLen = zipBuf.readUInt16LE(pos + 30);
    const commentLen = zipBuf.readUInt16LE(pos + 32);
    const localHeaderOffset = zipBuf.readUInt32LE(pos + 42);

    const recordEnd = pos + 46 + nameLen + extraLen + commentLen;
    if (recordEnd > cdEnd) {
      throw new ZipReadError(422, 'Truncated ZIP central directory record');
    }
    if ((flags & 0x0001) !== 0) {
      throw new ZipReadError(422, 'Encrypted ZIP entries are not supported');
    }
    if (cdCompSize === 0xffffffff || cdUncompSize === 0xffffffff || localHeaderOffset === 0xffffffff) {
      throw new ZipReadError(422, 'ZIP64 entries are not supported');
    }
    if (method !== 0 && method !== 8) {
      throw new ZipReadError(422, `Unsupported ZIP compression method: ${method}`);
    }

    const name = zipBuf.subarray(pos + 46, pos + 46 + nameLen).toString('utf8');
    pos = recordEnd;

    if (cdUncompSize > budgetCap) {
      throw new ZipReadError(413, 'Archive uncompressed size exceeds 16 MiB limit');
    }
    declaredTotalUncomp += cdUncompSize;
    if (declaredTotalUncomp > budgetCap) {
      throw new ZipReadError(413, 'Archive cumulative uncompressed size exceeds 16 MiB limit');
    }

    cdRecords.push({
      name,
      method,
      cdCrc,
      cdCompSize,
      cdUncompSize,
      localHeaderOffset,
    });
  }

  if (pos !== cdEnd) {
    throw new ZipReadError(422, 'ZIP central directory size mismatch');
  }

  const parsedEntries = [];
  let actualTotalUncomp = 0;

  for (const rec of cdRecords) {
    const { name, method, cdCrc, cdCompSize, cdUncompSize, localHeaderOffset } = rec;

    if (localHeaderOffset + 30 > cdOffset || zipBuf.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
      throw new ZipReadError(422, 'Corrupt ZIP local file header');
    }
    const lfhFlags = zipBuf.readUInt16LE(localHeaderOffset + 6);
    const lfhMethod = zipBuf.readUInt16LE(localHeaderOffset + 8);
    const lfhCrc = zipBuf.readUInt32LE(localHeaderOffset + 14);
    const lfhCompSize = zipBuf.readUInt32LE(localHeaderOffset + 18);
    const lfhUncompSize = zipBuf.readUInt32LE(localHeaderOffset + 22);
    const lfhNameLen = zipBuf.readUInt16LE(localHeaderOffset + 26);
    const lfhExtraLen = zipBuf.readUInt16LE(localHeaderOffset + 28);

    if (lfhMethod !== method) {
      throw new ZipReadError(422, 'ZIP local header compression method mismatch');
    }
    if (lfhUncompSize > budgetCap) {
      throw new ZipReadError(413, 'Archive uncompressed size exceeds 16 MiB limit');
    }
    if ((lfhFlags & 0x0008) === 0) {
      if (lfhCrc !== cdCrc || lfhCompSize !== cdCompSize || lfhUncompSize !== cdUncompSize) {
        throw new ZipReadError(422, 'ZIP local header metadata mismatch');
      }
    }

    const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
    const dataEnd = dataStart + cdCompSize;
    if (dataStart > cdOffset || dataEnd > cdOffset) {
      throw new ZipReadError(422, 'Corrupt ZIP member data bounds');
    }
    const compSlice = zipBuf.subarray(dataStart, dataEnd);

    const remainingBudget = budgetCap - actualTotalUncomp;
    let rawBytes;
    if (method === 0) {
      if (compSlice.length > remainingBudget) {
        throw new ZipReadError(413, 'Archive uncompressed size exceeds 16 MiB limit');
      }
      if (compSlice.length !== cdUncompSize) {
        throw new ZipReadError(422, 'Stored ZIP entry size mismatch');
      }
      rawBytes = Buffer.from(compSlice);
    } else {
      try {
        rawBytes = zlib.inflateRawSync(compSlice, { maxOutputLength: Math.max(1, remainingBudget) });
      } catch (err) {
        if (err && err.code === 'ERR_BUFFER_TOO_LARGE') {
          throw new ZipReadError(413, 'Archive decompressed output exceeds 16 MiB limit');
        }
        throw new ZipReadError(422, 'Corrupt DEFLATE stream in ZIP archive');
      }
      if (rawBytes.length > remainingBudget) {
        throw new ZipReadError(413, 'Archive decompressed output exceeds 16 MiB limit');
      }
      if (rawBytes.length !== cdUncompSize) {
        throw new ZipReadError(422, 'ZIP entry uncompressed size mismatch');
      }
    }

    actualTotalUncomp += rawBytes.length;
    if (crc32(rawBytes) !== (cdCrc >>> 0)) {
      throw new ZipReadError(422, 'ZIP entry CRC-32 checksum mismatch');
    }

    parsedEntries.push({
      name,
      data: rawBytes,
      method,
      crc32: cdCrc >>> 0,
    });
  }

  return parsedEntries;
}

function truncateUtf8Head(str, maxBytes = AUDIT_PREVIEW_MAX_BYTES) {
  const text = String(str ?? '');
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= maxBytes) return text;
  let end = maxBytes;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) {
    end--;
  }
  return buf.subarray(0, end).toString('utf8');
}

function truncateUtf8Tail(str, maxBytes = AUDIT_PREVIEW_MAX_BYTES) {
  const text = String(str ?? '');
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= maxBytes) return text;
  let start = buf.length - maxBytes;
  while (start < buf.length && (buf[start] & 0xc0) === 0x80) {
    start++;
  }
  return buf.subarray(start).toString('utf8');
}

function parseStrictTimeoutSeconds(raw) {
  if (typeof raw === 'number') {
    return Number.isInteger(raw) && raw >= 0 && raw <= 86400 ? raw : null;
  }
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!/^\d+$/.test(trimmed)) return null;
    const val = Number(trimmed);
    return Number.isInteger(val) && val >= 0 && val <= 86400 ? val : null;
  }
  return null;
}

function parseStrictPositiveInt(raw, fallback) {
  if (typeof raw === 'number') {
    return Number.isSafeInteger(raw) && raw >= 1 ? raw : fallback;
  }
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!/^\d+$/.test(trimmed)) return fallback;
    const val = Number(trimmed);
    return Number.isSafeInteger(val) && val >= 1 ? val : fallback;
  }
  return fallback;
}

function resolveRotateThreshold(optionVal, envVal, fallback) {
  if (optionVal !== undefined && optionVal !== null) {
    return parseStrictPositiveInt(optionVal, fallback);
  }
  if (envVal !== undefined && envVal !== null && String(envVal).trim() !== '') {
    return parseStrictPositiveInt(envVal, fallback);
  }
  return fallback;
}

function normalizeConfig(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { click1TimeoutSeconds: 300, reminderIntervalSeconds: 300 };
  }
  const click1 = parseStrictTimeoutSeconds(raw.click1TimeoutSeconds);
  const reminder = parseStrictTimeoutSeconds(raw.reminderIntervalSeconds);
  return {
    click1TimeoutSeconds: click1 !== null ? click1 : 300,
    reminderIntervalSeconds: reminder !== null ? reminder : 300,
  };
}

function loadConfig(configPath) {
  try {
    if (fs.existsSync(configPath)) {
      const parsed = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      return normalizeConfig(parsed);
    }
  } catch {
    // Fall back to defaults on corrupt config
  }
  return { click1TimeoutSeconds: 300, reminderIntervalSeconds: 300 };
}

class OutputRingBuffer {
  constructor(maxBytes = RING_BUFFER_MAX_BYTES) {
    this.maxBytes = maxBytes;
    this.chunks = [];
    this.totalBytes = 0;
    this.nextChunkSeq = 1;
    this.truncated = false;
  }

  append(stream, text) {
    const str = String(text ?? '');
    if (!str) return;
    let safeText = str;
    let byteLen = Buffer.byteLength(safeText, 'utf8');
    if (byteLen > this.maxBytes) {
      safeText = truncateUtf8Tail(safeText, this.maxBytes);
      byteLen = Buffer.byteLength(safeText, 'utf8');
      this.truncated = true;
    }
    this.chunks.push({
      seq: this.nextChunkSeq++,
      stream: stream === 'stderr' ? 'stderr' : 'stdout',
      text: safeText,
      byteLen,
      ts: new Date().toISOString(),
    });
    this.totalBytes += byteLen;
    while (this.totalBytes > this.maxBytes && this.chunks.length > 0) {
      const removed = this.chunks.shift();
      this.totalBytes -= removed.byteLen;
      this.truncated = true;
    }
  }

  getTailText() {
    return this.chunks.map((c) => c.text).join('');
  }

  getSnapshot() {
    return {
      totalBytes: this.totalBytes,
      truncated: this.truncated,
      chunks: this.chunks.map(({ seq, stream, text, ts }) => ({ seq, stream, text, ts })),
    };
  }
}

function sanitizeSourceMeta(rawSourceMeta) {
  let conversationId = '';
  let stepIndex = 0;
  let toolCallId = '';

  if (rawSourceMeta && typeof rawSourceMeta === 'object') {
    if (typeof rawSourceMeta.conversationId === 'string') {
      conversationId = rawSourceMeta.conversationId.trim();
    }
    if (Number.isFinite(Number(rawSourceMeta.stepIndex))) {
      stepIndex = Number(rawSourceMeta.stepIndex);
    }
    if (typeof rawSourceMeta.toolCallId === 'string') {
      toolCallId = rawSourceMeta.toolCallId.trim();
    }
  }

  if (!conversationId && process.env.ANTIGRAVITY_SOURCE_METADATA) {
    try {
      const envMeta = JSON.parse(process.env.ANTIGRAVITY_SOURCE_METADATA);
      const tool = envMeta?.tool && typeof envMeta.tool === 'object' ? envMeta.tool : envMeta;
      if (typeof tool?.conversationId === 'string') {
        conversationId = tool.conversationId.trim();
      }
      if (!stepIndex && Number.isFinite(Number(tool?.stepIndex))) {
        stepIndex = Number(tool.stepIndex);
      }
      if (!toolCallId && typeof tool?.toolCall?.id === 'string') {
        toolCallId = tool.toolCall.id.trim();
      }
    } catch {
      // Ignore unparseable ANTIGRAVITY_SOURCE_METADATA
    }
  }

  return { conversationId, stepIndex, toolCallId };
}

function sanitizeTargetMeta(rawTargetMeta) {
  if (!rawTargetMeta || typeof rawTargetMeta !== 'object') return null;
  const pickStr = (v) => (typeof v === 'string' && v.trim() ? v.trim() : '');
  const meta = {
    originalPath: pickStr(rawTargetMeta.originalPath),
    canonicalPath: pickStr(rawTargetMeta.canonicalPath),
    extension: pickStr(rawTargetMeta.extension),
    subsystem: pickStr(rawTargetMeta.subsystem),
    publisher: pickStr(rawTargetMeta.publisher),
  };
  if (!meta.originalPath && !meta.canonicalPath && !meta.extension && !meta.subsystem && !meta.publisher) {
    return null;
  }
  return meta;
}

function decodeWorkspaceUri(uriOrPath) {
  const raw = String(uriOrPath || '').trim();
  if (!raw) return '';
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    decoded = raw;
  }
  if (decoded.toLowerCase().startsWith('file:///')) {
    decoded = decoded.slice('file:///'.length);
    if (/^[a-zA-Z]:/.test(decoded)) {
      decoded = decoded.replace(/\//g, '\\');
    }
  }
  return decoded;
}

function resolveAttributionAsync(safeSourceMeta, workDir) {
  const fallbackWorkspacePath = String(workDir || '');
  const fallbackWorkspace = path.basename(fallbackWorkspacePath) || fallbackWorkspacePath || 'unknown';
  const base = {
    conversationId: safeSourceMeta.conversationId,
    stepIndex: safeSourceMeta.stepIndex,
    toolCallId: safeSourceMeta.toolCallId,
    workspace: fallbackWorkspace,
    workspacePath: fallbackWorkspacePath,
    isSubagent: false,
    role: '',
    agentLabel: 'Agent',
    summary: '',
  };
  base.summary = base.conversationId
    ? `${base.agentLabel} from workspace '${base.workspace}' (conv ${base.conversationId.slice(0, 8)})`
    : `${base.agentLabel} from workspace '${base.workspace}'`;

  const agentApiExe = process.env.ANTIGRAVITY_AGENTAPI_EXE;
  if (!safeSourceMeta.conversationId || !agentApiExe) {
    return Promise.resolve(base);
  }

  return new Promise((resolve) => {
    execFile(
      agentApiExe,
      ['agentapi', 'get-conversation-metadata', safeSourceMeta.conversationId],
      { maxBuffer: AGENTAPI_MAX_BUFFER, timeout: AGENTAPI_TIMEOUT_MS, windowsHide: true },
      (err, stdout) => {
        if (err || !stdout) {
          resolve(base);
          return;
        }
        try {
          const parsed = JSON.parse(stdout);
          const meta =
            parsed?.response?.conversationMetadata?.metadata ||
            parsed?.response?.conversation_metadata?.metadata ||
            parsed?.metadata ||
            null;
          if (!meta || typeof meta !== 'object') {
            resolve(base);
            return;
          }

          const uriCandidate =
            meta?.workspaces?.[0]?.workspaceFolderAbsoluteUri ||
            (Array.isArray(meta?.workspaceUris) ? meta.workspaceUris[0] : '') ||
            meta?.workspaces?.[0]?.repository?.computedName ||
            '';
          const decodedPath = decodeWorkspaceUri(uriCandidate);
          if (decodedPath) {
            base.workspacePath = decodedPath;
            base.workspace = path.basename(decodedPath) || decodedPath;
          }

          const spec = meta?.subagentSpec;
          if (spec && typeof spec === 'object') {
            const role = typeof spec.role === 'string' && spec.role.trim()
              ? spec.role.trim()
              : (typeof spec.typeName === 'string' ? spec.typeName.trim() : '');
            base.isSubagent = true;
            base.role = role;
            base.agentLabel = role ? `Subagent (${role})` : 'Subagent';
          } else {
            base.isSubagent = false;
            base.role = '';
            base.agentLabel = 'Main Agent';
          }

          base.summary = `${base.agentLabel} from workspace '${base.workspace}' (conv ${base.conversationId.slice(0, 8)})`;
          resolve(base);
        } catch {
          resolve(base);
        }
      }
    );
  });
}

function runPreflightOnly(helperPath, runnerPath) {
  if (!fs.existsSync(helperPath)) {
    return Promise.resolve({
      ok: false,
      code: 'E_RUNNER_INVALID',
      exitCode: 1204,
      detail: `Helper script missing: ${helperPath}`,
    });
  }
  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', helperPath, '-PreflightOnly', '-RunnerPath', runnerPath],
      { windowsHide: true, timeout: PREFLIGHT_TIMEOUT_MS, maxBuffer: 1024 * 1024 },
      (err, stdout, stderr) => {
        const lines = String(stdout || '')
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter(Boolean);
        if (lines.length > 0) {
          try {
            const last = JSON.parse(lines[lines.length - 1]);
            if (typeof last.ok === 'boolean') {
              resolve({
                ok: last.ok,
                code: String(last.code || (last.ok ? 'OK' : 'E_SESSION_NOT_INTERACTIVE')),
                exitCode: Number.isInteger(last.exitCode) ? last.exitCode : (last.ok ? 0 : 1202),
                detail: String(last.detail || ''),
              });
              return;
            }
          } catch {
            // Fall through to fail-closed error
          }
        }
        const detail = String(stderr || err?.message || 'Pre-flight check failed').trim();
        resolve({
          ok: false,
          code: 'E_RUNNER_INVALID',
          exitCode: 1204,
          detail,
        });
      }
    );
  });
}

function loadAuditCache(auditPath) {
  const items = [];
  try {
    if (!fs.existsSync(auditPath)) return items;
    const raw = fs.readFileSync(auditPath, 'utf8');
    const lines = raw.split(/\r?\n/).filter(Boolean);
    for (const line of lines.slice(-50)) {
      try {
        items.push(JSON.parse(line));
      } catch {
        // Ignore malformed historical line
      }
    }
  } catch {
    // Ignore audit load failures
  }
  return items;
}

export async function startBroker(options = {}) {
  const DATA_DIR = options.dataDir ? path.resolve(options.dataDir) : resolveDataDir();
  const STAGED_DIR = path.join(DATA_DIR, 'staged');
  const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');
  const RUNTIME_PATH = path.join(DATA_DIR, 'runtime.json');
  const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
  const AUDIT_PATH = path.join(DATA_DIR, 'audit.jsonl');
  const RUNNER_PATH = options.runnerPath || process.env.ELEVATED_EXEC_RUNNER_PATH || DEFAULT_RUNNER_PATH;
  const HELPER_PATH = options.helperPath || path.join(__dirname, 'broker_helper.ps1');
  const auditRotateMaxLines = resolveRotateThreshold(
    options.auditRotateMaxLines,
    process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_LINES,
    AUDIT_ROTATE_MAX_LINES
  );
  const auditRotateMaxBytes = resolveRotateThreshold(
    options.auditRotateMaxBytes,
    process.env.ELEVATED_EXEC_AUDIT_ROTATE_MAX_BYTES,
    AUDIT_ROTATE_MAX_BYTES
  );
  const spawnExplorerFn = typeof options.spawnExplorer === 'function' ? options.spawnExplorer : spawn;
  const openArchiveDir = typeof options.openArchiveDir === 'function'
    ? options.openArchiveDir
    : (dir) => {
        const child = spawnExplorerFn('explorer.exe', [dir], {
          detached: true,
          stdio: 'ignore',
          windowsHide: false,
        });
        child?.unref?.();
        return child;
      };
  const registerSignalHandlers = options.registerSignalHandlers ?? true;

  ensureDataDirsAndSweep(DATA_DIR, STAGED_DIR, RUNTIME_PATH);
  hardenDataDirAclsAsync(DATA_DIR);

  let config = loadConfig(CONFIG_PATH);
  const auditCache = loadAuditCache(AUDIT_PATH);
  let auditArchivesCache = [];
  let stateSeq = 1;
  const streamWaiters = new Set();

  let activeJob = null;
  const queue = [];
  let reminderTimer = null;
  let reminderHelper = null;
  let reminderActive = false;
  let reminderPending = false;
  let reminderLastShownAt = null;
  let ipcPort = 0;
  let ipcBearerToken = '';
  let shuttingDown = false;

function bumpSeq() {
  stateSeq++;
  flushStreamWaiters();
}

function flushStreamWaiters() {
  for (const waiter of Array.from(streamWaiters)) {
    streamWaiters.delete(waiter);
    clearTimeout(waiter.timer);
    waiter.resolve(true);
  }
}

function sendSse(job, eventName, dataObj) {
  if (!job || job.detached || !job.res || job.res.writableEnded) return;
  try {
    job.res.write(`event: ${eventName}\ndata: ${JSON.stringify(dataObj)}\n\n`);
  } catch {
    // Ignore write error on closing socket; res.on('close') handles cleanup
  }
}

function sendHelperCmd(job, cmdObj) {
  if (!job || !job.helper || !job.helper.stdin || job.helper.stdin.destroyed || !job.helper.stdin.writable) {
    return false;
  }
  try {
    job.helper.stdin.write(JSON.stringify(cmdObj) + '\n', 'utf8');
    return true;
  } catch {
    return false;
  }
}

function isReminderEligible() {
  return (
    !shuttingDown &&
    Boolean(activeJob) &&
    activeJob.state === 'RUNNING' &&
    queue.length > 0 &&
    config.reminderIntervalSeconds > 0
  );
}

function clearReminderTimerOnly() {
  if (reminderTimer) {
    clearTimeout(reminderTimer);
    reminderTimer = null;
  }
}

function closeReminderHelper() {
  const rh = reminderHelper;
  reminderHelper = null;
  const wasActiveOrPending = reminderActive || reminderPending;
  reminderActive = false;
  reminderPending = false;
  if (rh) {
    try {
      if (rh.stdin && !rh.stdin.destroyed && rh.stdin.writable) {
        rh.stdin.write(JSON.stringify({ cmd: 'shutdown' }) + '\n', 'utf8');
        rh.stdin.end();
      }
    } catch {
      // Ignore stdin close error
    }
    setTimeout(() => {
      try {
        if (rh.exitCode === null) rh.kill();
      } catch {
        // Ignore kill error
      }
    }, 1500).unref();
  }
  return wasActiveOrPending;
}

function stopReminderTimer() {
  clearReminderTimerOnly();
  closeReminderHelper();
}

function scheduleReminderIfEligible({ reset = false } = {}) {
  if (!isReminderEligible()) {
    clearReminderTimerOnly();
    if (!activeJob || activeJob.state !== 'RUNNING' || queue.length === 0 || config.reminderIntervalSeconds <= 0) {
      closeReminderHelper();
    }
    return;
  }
  if (reminderActive || reminderPending || reminderHelper) {
    return;
  }
  if (reminderTimer) {
    if (!reset) return;
    clearReminderTimerOnly();
  }
  const delayMs = config.reminderIntervalSeconds * 1000;
  reminderTimer = setTimeout(() => {
    reminderTimer = null;
    if (!isReminderEligible()) {
      stopReminderTimer();
      return;
    }
    triggerReminder();
  }, delayMs);
  reminderTimer.unref();
}

function triggerReminder() {
  if (!isReminderEligible()) {
    return;
  }
  if (reminderActive || reminderPending || reminderHelper) {
    return;
  }
  if (!fs.existsSync(HELPER_PATH)) {
    return;
  }

  reminderPending = true;
  const rh = spawn(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', HELPER_PATH],
    { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }
  );
  reminderHelper = rh;

  const stdoutDecoder = new StringDecoder('utf8');
  const stderrDecoder = new TextDecoder('gb18030', { fatal: false });
  let stdoutBuf = '';

  const handleReminderEvent = (ev) => {
    if (!ev || typeof ev !== 'object' || reminderHelper !== rh) return;
    if (ev.event === 'reminder_shown') {
      reminderPending = false;
      reminderActive = true;
      reminderLastShownAt = new Date().toISOString();
      bumpSeq();
    } else if (ev.event === 'reminder_dismissed' || ev.event === 'reminder_skipped') {
      reminderHelper = null;
      reminderPending = false;
      reminderActive = false;
      try {
        if (rh.stdin && !rh.stdin.destroyed && rh.stdin.writable) {
          rh.stdin.write(JSON.stringify({ cmd: 'shutdown' }) + '\n', 'utf8');
          rh.stdin.end();
        }
      } catch {
        // Ignore stdin close error
      }
      setTimeout(() => {
        try {
          if (rh.exitCode === null) rh.kill();
        } catch {
          // Ignore kill error
        }
      }, 1500).unref();
      scheduleReminderIfEligible();
      bumpSeq();
    }
  };

  rh.stdout.on('data', (chunk) => {
    stdoutBuf += stdoutDecoder.write(chunk);
    let nlIdx;
    while ((nlIdx = stdoutBuf.indexOf('\n')) >= 0) {
      const line = stdoutBuf.slice(0, nlIdx).replace(/\r$/, '').trim();
      stdoutBuf = stdoutBuf.slice(nlIdx + 1);
      if (!line) continue;
      try {
        handleReminderEvent(JSON.parse(line));
      } catch {
        // Ignore non-JSON diagnostic noise
      }
    }
  });

  rh.stderr.on('data', (chunk) => {
    stderrDecoder.decode(chunk, { stream: true });
  });

  rh.on('error', () => {
    if (reminderHelper === rh) {
      reminderHelper = null;
      const changed = reminderActive || reminderPending;
      reminderActive = false;
      reminderPending = false;
      if (changed) {
        scheduleReminderIfEligible();
        bumpSeq();
      }
    }
  });

  rh.on('close', () => {
    const rest = stdoutBuf + stdoutDecoder.end();
    for (const rawLine of rest.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) continue;
      try {
        handleReminderEvent(JSON.parse(line));
      } catch {
        // Ignore trailing non-JSON
      }
    }
    stderrDecoder.decode();
    if (reminderHelper === rh) {
      reminderHelper = null;
      const changed = reminderActive || reminderPending;
      reminderActive = false;
      reminderPending = false;
      if (changed) {
        scheduleReminderIfEligible();
        bumpSeq();
      }
    }
  });

  try {
    if (rh.stdin && !rh.stdin.destroyed && rh.stdin.writable) {
      rh.stdin.write(
        JSON.stringify({
          cmd: 'show_reminder',
          activeSummary: `${activeJob.reason} (${activeJob.requestId})`,
          queueCount: queue.length,
        }) + '\n',
        'utf8'
      );
    } else {
      closeReminderHelper();
    }
  } catch {
    closeReminderHelper();
  }
}

function listLegacyRotatedAuditFiles() {
  return fs.readdirSync(DATA_DIR)
    .filter((name) => /^audit\.\d+\.[0-9a-f]+\.jsonl$/i.test(name))
    .sort((a, b) => {
      const tsA = Number(a.split('.')[1] || 0);
      const tsB = Number(b.split('.')[1] || 0);
      if (tsA !== tsB) return tsA - tsB;
      return a.localeCompare(b);
    });
}

function appendAuditRecord(job) {
  const entry = {
    requestId: job.requestId,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    mode: job.mode,
    reason: job.reason,
    workDir: job.workDir,
    args: job.args,
    encoding: job.encoding,
    normalWindow: job.normalWindow,
    targetMeta: job.targetMeta,
    attribution: job.attribution,
    manifestSha256: job.manifestSha256,
    outcome: job.outcome,
    exitCode: job.exitCode,
    message: job.message,
    scriptPreview: truncateUtf8Head(job.script, AUDIT_PREVIEW_MAX_BYTES),
    outputTail: truncateUtf8Tail(job.ring.getTailText(), AUDIT_PREVIEW_MAX_BYTES),
  };

  let rotated = false;
  try {
    fs.appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n', 'utf8');
    const stat = fs.statSync(AUDIT_PATH);
    let shouldRotate = stat.size >= auditRotateMaxBytes;
    if (!shouldRotate) {
      const content = fs.readFileSync(AUDIT_PATH, 'utf8');
      const lineCount = content.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
      if (lineCount >= auditRotateMaxLines) {
        shouldRotate = true;
      }
    }
    if (shouldRotate) {
      const rotatedNames = listLegacyRotatedAuditFiles();
      const entries = [];
      for (const rName of rotatedNames) {
        const rPath = path.join(DATA_DIR, rName);
        const rBuf = fs.readFileSync(rPath);
        if (rBuf.length === 0) continue;
        const rLineCount = rBuf.toString('utf8').split(/\r?\n/).filter((l) => l.trim().length > 0).length;
        if (rLineCount === 0) continue;
        const rStat = fs.statSync(rPath);
        entries.push({ name: rName, data: rBuf, mtime: rStat.mtime });
      }
      const auditBuf = fs.readFileSync(AUDIT_PATH);
      entries.push({ name: 'audit.jsonl', data: auditBuf, mtime: stat.mtime });

      writeEntriesToArchiveZip(entries);
      writeAtomicUtf8(AUDIT_PATH, '');
      for (const rName of rotatedNames) {
        try {
          fs.rmSync(path.join(DATA_DIR, rName), { force: true });
        } catch {
          // Best-effort cleanup of absorbed legacy rotated file
        }
      }
      rotated = true;
    }
  } catch {
    // Non-fatal audit write/rotation failure
  }

  if (rotated) {
    auditCache.length = 0;
    refreshAuditArchivesCache({ strict: false });
  } else {
    auditCache.push(entry);
    while (auditCache.length > 50) {
      auditCache.shift();
    }
  }
}

function validateArchiveDirNonSymlink({ createIfMissing = false } = {}) {
  let dirStat;
  try {
    dirStat = fs.lstatSync(ARCHIVE_DIR);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      if (!createIfMissing) return null;
      fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
      dirStat = fs.lstatSync(ARCHIVE_DIR);
    } else {
      throw new ZipReadError(400, `Cannot inspect archive directory: ${err.message}`);
    }
  }
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
    throw new ZipReadError(400, 'Archive directory must be a real non-symlink directory');
  }
  return fs.realpathSync(ARCHIVE_DIR);
}

function writeEntriesToArchiveZip(entries) {
  const realArchiveDir = validateArchiveDirNonSymlink({ createIfMissing: true });
  const zipBuf = buildZipBuffer(entries);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  let archiveName = '';
  let archivePath = '';
  for (let attempt = 0; attempt < 16; attempt++) {
    const hexBytes = attempt < 4 ? 2 : 4;
    const candidateName = `audit-${stamp}-${crypto.randomBytes(hexBytes).toString('hex')}.zip`;
    const candidatePath = path.join(realArchiveDir, candidateName);
    if (!fs.existsSync(candidatePath)) {
      archiveName = candidateName;
      archivePath = candidatePath;
      break;
    }
  }
  if (!archiveName) {
    archiveName = `audit-${stamp}-${crypto.randomUUID()}.zip`;
    archivePath = path.join(realArchiveDir, archiveName);
  }
  const tmpZipPath = `${archivePath}.tmp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`;
  try {
    fs.writeFileSync(tmpZipPath, zipBuf);
    fs.renameSync(tmpZipPath, archivePath);
  } catch (err) {
    try {
      fs.rmSync(tmpZipPath, { force: true });
    } catch {
      // Best-effort temp file cleanup
    }
    throw err;
  }
  return {
    archiveName,
    archivePath: path.join(ARCHIVE_DIR, archiveName),
    archiveSizeBytes: zipBuf.length,
  };
}

function refreshAuditArchivesCache({ strict = false } = {}) {
  let realArchiveDir = null;
  try {
    realArchiveDir = validateArchiveDirNonSymlink({ createIfMissing: false });
  } catch (err) {
    auditArchivesCache = [];
    if (strict) throw err;
    return [];
  }
  if (!realArchiveDir) {
    auditArchivesCache = [];
    return [];
  }
  let dirEntries;
  try {
    dirEntries = fs.readdirSync(realArchiveDir);
  } catch (err) {
    auditArchivesCache = [];
    if (strict) throw new ZipReadError(400, `Cannot list archive directory: ${err.message}`);
    return [];
  }
  const items = [];
  for (const name of dirEntries) {
    if (!ARCHIVE_NAME_REGEX.test(name) || name.includes('..')) continue;
    const fullPath = path.join(realArchiveDir, name);
    try {
      const st = fs.lstatSync(fullPath);
      if (st.isSymbolicLink() || !st.isFile()) continue;
      items.push({
        name,
        sizeBytes: st.size,
        createdAt: st.mtime.toISOString(),
        _sortMs: st.mtimeMs,
      });
    } catch {
      // Ignore transient/unreadable entry
    }
  }
  items.sort((a, b) => (b._sortMs - a._sortMs) || b.name.localeCompare(a.name));
  auditArchivesCache = items.map(({ name, sizeBytes, createdAt }) => ({ name, sizeBytes, createdAt }));
  return auditArchivesCache.map((a) => ({ ...a }));
}

refreshAuditArchivesCache({ strict: false });

function sortArchiveJsonlMembers(members) {
  const classify = (memberName) => {
    const base = path.posix.basename(String(memberName || '').replace(/\\/g, '/'));
    if (base.toLowerCase() === 'audit.jsonl') {
      return { group: 2, ts: 0, base };
    }
    const m = base.match(/^audit\.(\d+)\.[0-9a-f]+\.jsonl$/i);
    if (m) {
      return { group: 0, ts: Number(m[1] || 0), base };
    }
    return { group: 1, ts: 0, base };
  };
  return [...members].sort((a, b) => {
    const ca = classify(a.name);
    const cb = classify(b.name);
    if (ca.group !== cb.group) return ca.group - cb.group;
    if (ca.ts !== cb.ts) return ca.ts - cb.ts;
    return ca.base.localeCompare(cb.base);
  });
}

function readAuditArchive(rawName) {
  if (typeof rawName !== 'string' || !ARCHIVE_NAME_REGEX.test(rawName) || rawName.includes('..')) {
    throw new ZipReadError(400, 'Invalid audit archive filename');
  }
  const realArchiveDir = validateArchiveDirNonSymlink({ createIfMissing: false });
  if (!realArchiveDir) {
    throw new ZipReadError(404, 'Audit archive not found');
  }

  const baseArchiveDir = path.resolve(ARCHIVE_DIR);
  const candidatePath = path.resolve(baseArchiveDir, rawName);
  const sameDir = process.platform === 'win32'
    ? path.dirname(candidatePath).toLowerCase() === baseArchiveDir.toLowerCase()
    : path.dirname(candidatePath) === baseArchiveDir;
  if (!sameDir) {
    throw new ZipReadError(400, 'Invalid audit archive path');
  }

  let fileLstat;
  try {
    fileLstat = fs.lstatSync(candidatePath);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      throw new ZipReadError(404, 'Audit archive not found');
    }
    throw new ZipReadError(400, `Cannot inspect audit archive: ${err.message}`);
  }
  if (fileLstat.isSymbolicLink() || !fileLstat.isFile()) {
    throw new ZipReadError(400, 'Audit archive must be a regular non-symlink file');
  }

  const realFilePath = fs.realpathSync(candidatePath);
  const expectedRealFile = path.join(realArchiveDir, rawName);
  const rel = path.relative(realArchiveDir, realFilePath);
  const exactChildMatch = process.platform === 'win32'
    ? realFilePath.toLowerCase() === expectedRealFile.toLowerCase()
    : realFilePath === expectedRealFile;
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel) || rel.includes('\\') || rel.includes('/') || !exactChildMatch) {
    throw new ZipReadError(400, 'Audit archive path escapes archive directory');
  }

  if (fileLstat.size > MAX_ARCHIVE_RAW_ZIP_BYTES) {
    throw new ZipReadError(413, 'Audit archive file exceeds maximum allowed size');
  }

  let zipBuf;
  const fd = fs.openSync(realFilePath, 'r');
  try {
    const fst = fs.fstatSync(fd);
    if (!fst.isFile()) {
      throw new ZipReadError(400, 'Audit archive target is not a regular file');
    }
    if (fst.ino !== fileLstat.ino || fst.dev !== fileLstat.dev) {
      throw new ZipReadError(400, 'Audit archive identity changed during read');
    }
    if (fst.size > MAX_ARCHIVE_RAW_ZIP_BYTES) {
      throw new ZipReadError(413, 'Audit archive file exceeds maximum allowed size');
    }
    zipBuf = Buffer.allocUnsafe(fst.size);
    let offset = 0;
    while (offset < fst.size) {
      const n = fs.readSync(fd, zipBuf, offset, fst.size - offset, offset);
      if (n <= 0) break;
      offset += n;
    }
    if (offset !== fst.size) {
      throw new ZipReadError(422, 'Unexpected EOF while reading audit archive');
    }
  } finally {
    fs.closeSync(fd);
  }

  const parsedMembers = parseZipEntries(zipBuf, { maxTotalBytes: MAX_ARCHIVE_UNCOMPRESSED_BYTES });
  const jsonlMembers = parsedMembers.filter((m) => {
    const norm = String(m.name || '').replace(/\\/g, '/');
    if (!norm || norm.endsWith('/')) return false;
    return /\.jsonl$/i.test(path.posix.basename(norm));
  });
  if (jsonlMembers.length === 0) {
    throw new ZipReadError(422, 'Audit archive contains no JSONL audit files');
  }

  const orderedMembers = sortArchiveJsonlMembers(jsonlMembers);
  const entries = [];
  for (const member of orderedMembers) {
    const text = member.data.toString('utf8');
    const lines = text.split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;
      try {
        const obj = JSON.parse(line);
        if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
          entries.push(obj);
        }
      } catch {
        // Skip malformed individual JSONL line
      }
    }
  }

  entries.reverse();
  return {
    ok: true,
    name: rawName,
    sizeBytes: fileLstat.size,
    entries,
  };
}

function clearAuditHistory() {
  validateArchiveDirNonSymlink({ createIfMissing: true });

  const rotatedNames = listLegacyRotatedAuditFiles();

  const candidateFiles = [
    ...rotatedNames.map((name) => ({ name, filePath: path.join(DATA_DIR, name) })),
  ];
  if (fs.existsSync(AUDIT_PATH)) {
    candidateFiles.push({ name: 'audit.jsonl', filePath: AUDIT_PATH });
  }

  const entries = [];
  let clearedCount = 0;

  for (const item of candidateFiles) {
    const buf = fs.readFileSync(item.filePath);
    if (buf.length === 0) continue;
    const text = buf.toString('utf8');
    const lineCount = text.split(/\r?\n/).filter((l) => l.trim().length > 0).length;
    if (lineCount === 0) continue;
    const stat = fs.statSync(item.filePath);
    entries.push({ name: item.name, data: buf, mtime: stat.mtime });
    clearedCount += lineCount;
  }

  if (entries.length === 0) {
    let changed = false;
    if (fs.existsSync(AUDIT_PATH) && fs.statSync(AUDIT_PATH).size > 0) {
      writeAtomicUtf8(AUDIT_PATH, '');
    }
    for (const rName of rotatedNames) {
      try {
        fs.rmSync(path.join(DATA_DIR, rName), { force: true });
      } catch {
        // Best-effort cleanup of empty rotated file
      }
    }
    if (auditCache.length > 0) {
      auditCache.length = 0;
      changed = true;
    }
    refreshAuditArchivesCache({ strict: false });
    if (changed) bumpSeq();
    return {
      ok: true,
      clearedCount: 0,
      archivePath: null,
      archiveName: null,
      archiveSizeBytes: 0,
      archiveDir: ARCHIVE_DIR,
      state: buildStateSnapshot(),
    };
  }

  const { archiveName, archivePath, archiveSizeBytes } = writeEntriesToArchiveZip(entries);

  if (fs.existsSync(AUDIT_PATH)) {
    writeAtomicUtf8(AUDIT_PATH, '');
  }
  for (const rName of rotatedNames) {
    try {
      fs.rmSync(path.join(DATA_DIR, rName), { force: true });
    } catch {
      // Best-effort cleanup of archived rotated file
    }
  }

  auditCache.length = 0;
  refreshAuditArchivesCache({ strict: false });
  bumpSeq();

  return {
    ok: true,
    clearedCount,
    archivePath,
    archiveName,
    archiveSizeBytes,
    archiveDir: ARCHIVE_DIR,
    state: buildStateSnapshot(),
  };
}

function finalizeJob(job, outcome, exitCode, message) {
  if (!job || job.finished) return;
  job.finished = true;

  if (job.keepaliveTimer) {
    clearInterval(job.keepaliveTimer);
    job.keepaliveTimer = null;
  }
  if (job.click1BackupTimer) {
    clearTimeout(job.click1BackupTimer);
    job.click1BackupTimer = null;
  }
  if (job.cancelFallbackTimer) {
    clearTimeout(job.cancelFallbackTimer);
    job.cancelFallbackTimer = null;
  }

  job.state = outcome;
  job.outcome = outcome;
  job.exitCode = Number.isInteger(exitCode) ? exitCode : 1204;
  job.message = String(message || '');
  job.finishedAt = new Date().toISOString();
  job.click1DeadlineAt = null;

  appendAuditRecord(job);

  if (!job.detached && job.res && !job.res.writableEnded) {
    sendSse(job, 'outcome', {
      outcome: job.outcome,
      exitCode: job.exitCode,
      message: job.message,
    });
    try {
      job.res.end();
    } catch {
      // Ignore stream close errors
    }
  }

  if (job.manifestFile) {
    try {
      fs.rmSync(job.manifestFile, { force: true });
    } catch {
      // Ignore cleanup error
    }
  }

  if (job.helper) {
    const h = job.helper;
    job.helper = null;
    try {
      if (h.stdin && !h.stdin.destroyed && h.stdin.writable) {
        h.stdin.write(JSON.stringify({ cmd: 'shutdown' }) + '\n', 'utf8');
        h.stdin.end();
      }
    } catch {
      // Ignore stdin close error
    }
    setTimeout(() => {
      try {
        if (h.exitCode === null) h.kill();
      } catch {
        // Ignore kill error
      }
    }, 1500).unref();
  }

  if (activeJob === job) {
    stopReminderTimer();
    activeJob = null;
  } else {
    const qIdx = queue.indexOf(job);
    if (qIdx >= 0) queue.splice(qIdx, 1);
    if (queue.length === 0) {
      stopReminderTimer();
    }
  }

  bumpSeq();

  if (!shuttingDown && !activeJob && queue.length > 0) {
    const nextJob = queue.shift();
    startActiveJob(nextJob);
  }
}

function handleHelperEvent(job, ev) {
  if (!ev || typeof ev !== 'object' || job.finished) return;
  if (ev.requestId && ev.requestId !== job.requestId) return;

  switch (ev.event) {
    case 'preflight_result': {
      if (!ev.ok) {
        const isRunnerErr = ev.code === 'E_RUNNER_INVALID' || ev.exitCode === 1204;
        finalizeJob(
          job,
          isRunnerErr ? 'RUNNER_INVALID' : 'SESSION_NOT_INTERACTIVE',
          isRunnerErr ? 1204 : 1202,
          ev.detail || 'Pre-flight check failed'
        );
      }
      break;
    }
    case 'click1_shown': {
      job.click1Shown = true;
      if (job.click1TimeoutSeconds > 0) {
        const parsedDeadline = Number(ev.click1DeadlineAt);
        job.click1DeadlineAt =
          Number.isFinite(parsedDeadline) && parsedDeadline > 0
            ? Math.trunc(parsedDeadline)
            : Date.now() + job.click1TimeoutSeconds * 1000;
        if (job.click1BackupTimer) {
          clearTimeout(job.click1BackupTimer);
          job.click1BackupTimer = null;
        }
        job.click1BackupTimer = setTimeout(() => {
          if (!job.finished && job.state === 'AWAITING_CLICK1') {
            sendHelperCmd(job, { cmd: 'cancel', requestId: job.requestId });
            finalizeJob(job, 'TIMEOUT_CLICK1', 1460, 'Click-1 confirmation timed out');
          }
        }, Math.max(0, job.click1DeadlineAt - Date.now()) + 3000);
        job.click1BackupTimer.unref();
      }
      sendSse(job, 'state', {
        requestId: job.requestId,
        state: 'AWAITING_CLICK1',
        click1Shown: true,
        click1TimeoutSeconds: job.click1TimeoutSeconds,
        click1DeadlineAt: job.click1DeadlineAt,
      });
      bumpSeq();
      break;
    }
    case 'click1_decision': {
      if (job.click1BackupTimer) {
        clearTimeout(job.click1BackupTimer);
        job.click1BackupTimer = null;
      }
      if (ev.decision === 'proceed') {
        job.state = 'AWAITING_UAC';
        job.click1DeadlineAt = null;
        sendSse(job, 'state', { requestId: job.requestId, state: 'AWAITING_UAC' });
        bumpSeq();
      } else if (ev.decision === 'deny') {
        finalizeJob(job, 'DENIED_CLICK1', 1223, 'Denied by user in Click-1 confirmation');
      } else if (ev.decision === 'timeout') {
        finalizeJob(job, 'TIMEOUT_CLICK1', 1460, 'Click-1 confirmation timed out');
      }
      break;
    }
    case 'uac_started': {
      job.state = 'AWAITING_UAC';
      job.click1DeadlineAt = null;
      sendSse(job, 'state', { requestId: job.requestId, state: 'AWAITING_UAC' });
      bumpSeq();
      break;
    }
    case 'uac_denied': {
      if (job.cancelFallbackTimer) {
        clearTimeout(job.cancelFallbackTimer);
        job.cancelFallbackTimer = null;
      }
      finalizeJob(job, 'DENIED_UAC', 1223, 'Denied at Windows UAC prompt');
      break;
    }
    case 'runner_connected': {
      if (job.cancelFallbackTimer) {
        clearTimeout(job.cancelFallbackTimer);
        job.cancelFallbackTimer = null;
      }
      job.state = 'RUNNING';
      job.click1DeadlineAt = null;
      sendSse(job, 'state', { requestId: job.requestId, state: 'RUNNING' });
      scheduleReminderIfEligible();
      bumpSeq();
      break;
    }
    case 'runner_preconnect_exit': {
      if (job.cancelFallbackTimer) {
        clearTimeout(job.cancelFallbackTimer);
        job.cancelFallbackTimer = null;
      }
      const code = Number.isInteger(ev.exitCode) ? ev.exitCode : 1204;
      finalizeJob(job, 'RUNNER_PRECONNECT_EXIT', 1204, `Elevated runner exited before pipe connect (exit=${code})`);
      break;
    }
    case 'stdout': {
      const text = String(ev.text ?? '');
      job.ring.append('stdout', text);
      sendSse(job, 'stdout', { text });
      bumpSeq();
      break;
    }
    case 'stderr': {
      const text = String(ev.text ?? '');
      job.ring.append('stderr', text);
      sendSse(job, 'stderr', { text });
      bumpSeq();
      break;
    }
    case 'runner_error': {
      if (ev.code === 'SHA256_MISMATCH') {
        finalizeJob(job, 'SHA256_MISMATCH', 1205, ev.detail || 'Manifest SHA-256 verification failed');
      } else {
        finalizeJob(job, 'RUNNER_INVALID', 1204, ev.detail || 'Runner reported an error');
      }
      break;
    }
    case 'exit': {
      const exitCode = Number.isInteger(Number(ev.exitCode)) ? Number(ev.exitCode) : 0;
      finalizeJob(job, 'COMPLETED', exitCode, `Completed with exit code ${exitCode}`);
      break;
    }
    case 'killed': {
      finalizeJob(job, 'KILLED', 1207, 'Killed by user from Side Panel');
      break;
    }
    case 'cancelled': {
      finalizeJob(job, 'CANCELLED', 1201, 'Request cancelled');
      break;
    }
    case 'reminder_shown': {
      reminderPending = false;
      reminderActive = true;
      reminderLastShownAt = new Date().toISOString();
      bumpSeq();
      break;
    }
    case 'reminder_dismissed':
    case 'reminder_skipped': {
      reminderPending = false;
      reminderActive = false;
      bumpSeq();
      break;
    }
    default:
      break;
  }
}

function startActiveJob(job) {
  if (!job || job.finished || shuttingDown) return;

  activeJob = job;
  job.state = 'AWAITING_CLICK1';
  job.click1Shown = false;
  job.startedAt = new Date().toISOString();
  const timeoutSec = Number(config.click1TimeoutSeconds) || 0;
  job.click1TimeoutSeconds = timeoutSec;
  job.click1DeadlineAt = null;

  sendSse(job, 'state', {
    requestId: job.requestId,
    state: 'AWAITING_CLICK1',
    click1TimeoutSeconds: timeoutSec,
    click1DeadlineAt: job.click1DeadlineAt,
  });
  bumpSeq();

  if (!fs.existsSync(HELPER_PATH)) {
    finalizeJob(job, 'RUNNER_INVALID', 1204, `Helper missing: ${HELPER_PATH}`);
    return;
  }

  const helper = spawn(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', HELPER_PATH],
    { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }
  );
  job.helper = helper;

  const stdoutDecoder = new StringDecoder('utf8');
  const stderrDecoder = new TextDecoder('gb18030', { fatal: false });
  let stdoutBuf = '';
  let stderrTail = '';

  helper.stdout.on('data', (chunk) => {
    stdoutBuf += stdoutDecoder.write(chunk);
    let nlIdx;
    while ((nlIdx = stdoutBuf.indexOf('\n')) >= 0) {
      const line = stdoutBuf.slice(0, nlIdx).replace(/\r$/, '').trim();
      stdoutBuf = stdoutBuf.slice(nlIdx + 1);
      if (!line) continue;
      try {
        const ev = JSON.parse(line);
        handleHelperEvent(job, ev);
      } catch {
        // Ignore non-JSON diagnostic noise
      }
    }
  });

  helper.stderr.on('data', (chunk) => {
    const text = stderrDecoder.decode(chunk, { stream: true });
    if (text) {
      stderrTail = truncateUtf8Tail(stderrTail + text, 1024);
    }
  });

  helper.on('error', (err) => {
    finalizeJob(job, 'RUNNER_INVALID', 1204, `Failed to spawn helper: ${err.message}`);
  });

  helper.on('close', (code) => {
    const rest = stdoutBuf + stdoutDecoder.end();
    for (const rawLine of rest.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) continue;
      try {
        handleHelperEvent(job, JSON.parse(line));
      } catch {
        // Ignore trailing non-JSON
      }
    }
    const errRest = stderrDecoder.decode();
    if (errRest) stderrTail = truncateUtf8Tail(stderrTail + errRest, 1024);

    if (!job.finished) {
      if (job.cancelRequested) {
        finalizeJob(job, 'CANCELLED', 1201, 'Cancelled');
      } else if (job.killRequested) {
        finalizeJob(job, 'KILLED', 1207, 'Killed by user');
      } else {
        const detail = stderrTail.trim() ? `Helper exited unexpectedly (${code}): ${stderrTail.trim()}` : `Helper exited unexpectedly (${code})`;
        finalizeJob(job, 'RUNNER_PRECONNECT_EXIT', 1204, detail);
      }
    }
  });

  const scriptByteLen = Buffer.byteLength(job.script, 'utf8');
  const scriptPreview = truncateUtf8Head(job.script, HELPER_PREVIEW_MAX_BYTES);
  const scriptTruncated = scriptByteLen > HELPER_PREVIEW_MAX_BYTES;

  sendHelperCmd(job, {
    cmd: 'start_request',
    requestId: job.requestId,
    runnerPath: RUNNER_PATH,
    manifestFile: job.manifestFile,
    manifestSha256: job.manifestSha256,
    normalWindow: job.normalWindow,
    click1TimeoutSeconds: timeoutSec,
    reason: job.reason,
    workDir: job.workDir,
    args: job.args,
    scriptPreview,
    scriptTruncated,
    targetMeta: job.targetMeta,
    attribution: job.attribution,
  });

  if (timeoutSec > 0) {
    job.click1BackupTimer = setTimeout(() => {
      if (!job.finished && job.state === 'AWAITING_CLICK1') {
        sendHelperCmd(job, { cmd: 'cancel', requestId: job.requestId });
        finalizeJob(job, 'TIMEOUT_CLICK1', 1460, 'Click-1 confirmation timed out');
      }
    }, timeoutSec * 1000 + 15000);
    job.click1BackupTimer.unref();
  }
}

function handleClientDisconnect(job) {
  if (!job || job.finished) return;
  if (job.state === 'RUNNING') {
    job.detached = true;
    if (job.keepaliveTimer) {
      clearInterval(job.keepaliveTimer);
      job.keepaliveTimer = null;
    }
    bumpSeq();
    return;
  }

  if (job.state === 'QUEUED') {
    finalizeJob(job, 'CANCELLED', 1201, 'Cancelled by client disconnect while queued');
    return;
  }

  if (job.state === 'AWAITING_CLICK1' || job.state === 'AWAITING_UAC') {
    job.cancelRequested = true;
    sendHelperCmd(job, { cmd: 'cancel', requestId: job.requestId });
    if (!job.cancelFallbackTimer) {
      job.cancelFallbackTimer = setTimeout(() => {
        if (!job.finished) {
          finalizeJob(job, 'CANCELLED', 1201, 'Cancelled by client disconnect');
        }
      }, 1000);
      job.cancelFallbackTimer.unref();
    }
  }
}

function serializeJobForUi(job, includeOutput = false) {
  if (!job) return null;
  const obj = {
    requestId: job.requestId,
    state: job.state,
    click1Shown: Boolean(job.click1Shown),
    detached: Boolean(job.detached),
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    click1TimeoutSeconds: job.click1TimeoutSeconds,
    click1DeadlineAt: job.click1DeadlineAt,
    mode: job.mode,
    reason: job.reason,
    workDir: job.workDir,
    args: job.args,
    encoding: job.encoding,
    normalWindow: job.normalWindow,
    targetMeta: job.targetMeta,
    attribution: job.attribution,
    manifestSha256: job.manifestSha256,
    script: job.script,
  };
  if (includeOutput) {
    obj.output = job.ring.getSnapshot();
  }
  return obj;
}

function buildStateSnapshot() {
  return {
    seq: stateSeq,
    activeJob: serializeJobForUi(activeJob, true),
    queue: queue.map((q) => serializeJobForUi(q, false)),
    config: { ...config },
    reminder: {
      active: reminderActive,
      lastShownAt: reminderLastShownAt,
    },
    audit: auditCache.slice(-50).reverse(),
    auditArchiveCount: auditArchivesCache.length,
    auditArchives: auditArchivesCache.map((a) => ({ ...a })),
    sidecarInfo: {
      pid: process.pid,
      ipcPort,
      dataDir: DATA_DIR,
      archiveDir: ARCHIVE_DIR,
    },
  };
}

function sendJsonResponse(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function createIpcServer() {
  return http.createServer((req, res) => {
    const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method !== 'POST' || reqUrl.pathname !== '/ipc/requests') {
      req.resume();
      req.on('end', () => {
        sendJsonResponse(res, reqUrl.pathname === '/ipc/requests' ? 405 : 404, {
          ok: false,
          error: 'not_found',
        });
      });
      return;
    }

    const chunks = [];
    let totalBytes = 0;
    let bodyTooLarge = false;
    let aborted = false;
    let resClosed = false;
    let job = null;

    req.on('aborted', () => {
      aborted = true;
    });

    res.on('close', () => {
      resClosed = true;
      if (job && !res.writableEnded && !job.finished) {
        handleClientDisconnect(job);
      }
    });

    req.on('data', (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes <= MAX_IPC_BODY_BYTES) {
        chunks.push(chunk);
      } else {
        bodyTooLarge = true;
        chunks.length = 0;
      }
    });

    req.on('end', async () => {
      if (aborted || resClosed || res.destroyed || res.writableEnded || shuttingDown) return;

      // Always drain complete POST body before checking Bearer auth or writing status/headers
      const authHeader = String(req.headers.authorization || '');
      const expectedAuth = `Bearer ${ipcBearerToken}`;
      const authBuf = Buffer.from(authHeader, 'utf8');
      const expectedBuf = Buffer.from(expectedAuth, 'utf8');
      const authValid =
        authBuf.length === expectedBuf.length &&
        crypto.timingSafeEqual(authBuf, expectedBuf);

      if (!authValid) {
        sendJsonResponse(res, 401, { error: 'unauthorized' });
        return;
      }

      if (bodyTooLarge) {
        sendJsonResponse(res, 413, {
          ok: false,
          outcome: 'INVALID_ARGS',
          exitCode: 1206,
          message: 'Request payload exceeds maximum allowed size',
        });
        return;
      }

      let payload;
      try {
        const rawText = Buffer.concat(chunks).toString('utf8');
        payload = JSON.parse(rawText);
      } catch {
        sendJsonResponse(res, 400, {
          ok: false,
          outcome: 'INVALID_ARGS',
          exitCode: 1206,
          message: 'Malformed JSON request body',
        });
        return;
      }

      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        sendJsonResponse(res, 400, {
          ok: false,
          outcome: 'INVALID_ARGS',
          exitCode: 1206,
          message: 'Payload must be a JSON object',
        });
        return;
      }

      if (!VALID_MODES.has(payload.mode)) {
        sendJsonResponse(res, 400, {
          ok: false,
          outcome: 'INVALID_ARGS',
          exitCode: 1206,
          message: 'mode must be one of ScriptBlock, ScriptText, ScriptFile, FilePath',
        });
        return;
      }

      if (typeof payload.reason !== 'string' || !payload.reason.trim()) {
        sendJsonResponse(res, 400, {
          ok: false,
          outcome: 'INVALID_ARGS',
          exitCode: 1206,
          message: 'reason must be a non-empty string',
        });
        return;
      }

      if (typeof payload.script !== 'string') {
        sendJsonResponse(res, 400, {
          ok: false,
          outcome: 'INVALID_ARGS',
          exitCode: 1206,
          message: 'script must be a string',
        });
        return;
      }

      if (typeof payload.workDir !== 'string' || !payload.workDir.trim()) {
        sendJsonResponse(res, 400, {
          ok: false,
          outcome: 'INVALID_ARGS',
          exitCode: 1206,
          message: 'workDir must be a non-empty string',
        });
        return;
      }

      let normalizedArgs = [];
      if (payload.args !== undefined && payload.args !== null) {
        if (!Array.isArray(payload.args)) {
          sendJsonResponse(res, 400, {
            ok: false,
            outcome: 'INVALID_ARGS',
            exitCode: 1206,
            message: 'args must be an array of strings',
          });
          return;
        }
        normalizedArgs = payload.args.map((a) => String(a));
      }

      const normalizedEncoding =
        payload.encoding === undefined || payload.encoding === null || payload.encoding === ''
          ? 'auto'
          : String(payload.encoding);
      if (!VALID_ENCODINGS.has(normalizedEncoding)) {
        sendJsonResponse(res, 400, {
          ok: false,
          outcome: 'INVALID_ARGS',
          exitCode: 1206,
          message: 'encoding must be one of auto, utf8, oem, utf16',
        });
        return;
      }

      const safeSourceMeta = sanitizeSourceMeta(payload.sourceMeta);
      const safeTargetMeta = sanitizeTargetMeta(payload.targetMeta);

      const manifestObj = {
        script: payload.script,
        args: normalizedArgs,
        workDir: payload.workDir,
        encoding: normalizedEncoding,
      };
      const manifestBuf = Buffer.from(JSON.stringify(manifestObj), 'utf8');
      if (manifestBuf.length < 1 || manifestBuf.length > MAX_MANIFEST_BYTES) {
        sendJsonResponse(res, 413, {
          ok: false,
          outcome: 'INVALID_ARGS',
          exitCode: 1206,
          message: 'Serialized manifest exceeds 10 MiB limit',
        });
        return;
      }

      // Run arrival pre-flight immediately (with attribution in parallel so 409 returns fast)
      const preflightPromise = runPreflightOnly(HELPER_PATH, RUNNER_PATH);
      const attributionPromise = resolveAttributionAsync(safeSourceMeta, payload.workDir);

      const pf = await preflightPromise;
      if (aborted || resClosed || res.destroyed || res.writableEnded || shuttingDown) return;

      if (!pf.ok) {
        const isRunnerErr = pf.code === 'E_RUNNER_INVALID' || pf.exitCode === 1204;
        sendJsonResponse(res, 409, {
          ok: false,
          outcome: isRunnerErr ? 'RUNNER_INVALID' : 'SESSION_NOT_INTERACTIVE',
          exitCode: isRunnerErr ? 1204 : 1202,
          message: pf.detail || 'Arrival pre-flight check failed',
        });
        return;
      }

      const attribution = await attributionPromise;
      if (aborted || resClosed || res.destroyed || res.writableEnded || shuttingDown) return;

      const requestId = `req-${crypto.randomBytes(6).toString('hex')}`;
      const manifestSha256 = crypto.createHash('sha256').update(manifestBuf).digest('hex');
      const manifestFile = path.join(STAGED_DIR, `${requestId}.json`);
      fs.writeFileSync(manifestFile, manifestBuf);

      const initialState = activeJob || queue.length > 0 ? 'QUEUED' : 'AWAITING_CLICK1';
      job = {
        requestId,
        createdAt: new Date().toISOString(),
        startedAt: null,
        finishedAt: null,
        state: initialState,
        click1Shown: false,
        detached: false,
        finished: false,
        cancelRequested: false,
        killRequested: false,
        mode: payload.mode,
        reason: payload.reason.trim(),
        script: payload.script,
        args: normalizedArgs,
        workDir: payload.workDir,
        encoding: normalizedEncoding,
        normalWindow: Boolean(payload.normalWindow),
        targetMeta: safeTargetMeta,
        attribution,
        manifestFile,
        manifestSha256,
        ring: new OutputRingBuffer(RING_BUFFER_MAX_BYTES),
        click1TimeoutSeconds: null,
        click1DeadlineAt: null,
        res,
        keepaliveTimer: null,
        click1BackupTimer: null,
        cancelFallbackTimer: null,
        helper: null,
        outcome: null,
        exitCode: null,
        message: null,
      };

      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });
      res.flushHeaders();
      res.write(': keepalive\n\n');
      sendSse(job, 'pending', { requestId: job.requestId, state: initialState });

      job.keepaliveTimer = setInterval(() => {
        if (!job.detached && !job.finished && !res.writableEnded) {
          try {
            res.write(': keepalive\n\n');
          } catch {
            // Ignore write errors
          }
        }
      }, SSE_KEEPALIVE_MS);
      job.keepaliveTimer.unref();

      if (!activeJob && queue.length === 0) {
        startActiveJob(job);
      } else {
        queue.push(job);
        if (activeJob?.state === 'RUNNING') {
          scheduleReminderIfEligible();
        }
        bumpSeq();
      }
    });
  });
}

const ipcServer = createIpcServer();
await new Promise((resolve, reject) => {
  ipcServer.once('error', reject);
  ipcServer.listen(0, '127.0.0.1', () => {
    ipcServer.removeListener('error', reject);
    resolve();
  });
});

ipcPort = ipcServer.address().port;
ipcBearerToken = crypto.randomBytes(32).toString('hex');
writeAtomicUtf8(
  RUNTIME_PATH,
  JSON.stringify({
    port: ipcPort,
    token: ipcBearerToken,
    pid: process.pid,
    startedAt: new Date().toISOString(),
  })
);

  const hasCustomWebPort = options.webPort !== undefined && options.webPort !== null;
  const hasCustomUiToken = options.uiToken !== undefined && options.uiToken !== null;
  const savedSidecarEnv = {
    ANTIGRAVITY_LS_ADDRESS: process.env.ANTIGRAVITY_LS_ADDRESS,
    ANTIGRAVITY_CSRF_TOKEN: process.env.ANTIGRAVITY_CSRF_TOKEN,
    ANTIGRAVITY_SIDECAR_WEB_PORT: process.env.ANTIGRAVITY_SIDECAR_WEB_PORT,
    ANTIGRAVITY_SIDECAR_UI_TOKEN: process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN,
  };
  let app;
  try {
    if (hasCustomWebPort || hasCustomUiToken) {
      if (!process.env.ANTIGRAVITY_LS_ADDRESS) process.env.ANTIGRAVITY_LS_ADDRESS = '127.0.0.1:1';
      if (!process.env.ANTIGRAVITY_CSRF_TOKEN) process.env.ANTIGRAVITY_CSRF_TOKEN = 'sidecar-local';
    }
    if (hasCustomWebPort) {
      process.env.ANTIGRAVITY_SIDECAR_WEB_PORT = String(options.webPort);
    }
    if (hasCustomUiToken) {
      process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN = String(options.uiToken);
    }
    app = new SidecarApp();
  } finally {
    if (hasCustomWebPort || hasCustomUiToken) {
      for (const [k, v] of Object.entries(savedSidecarEnv)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  }

app.page('/', () => {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const renderedHtml = html
    .replace('href="/styles.css"', `href="/styles.css?v=${BOOT_ASSET_VERSION}"`)
    .replace('src="/app.js"', `src="/app.js?v=${BOOT_ASSET_VERSION}"`);
  return new Response(renderedHtml, {
    contentType: 'text/html; charset=utf-8',
    headers: { 'Cache-Control': 'no-store' },
  });
});

app.api(
  '/styles.css',
  () =>
    new Response(fs.readFileSync(path.join(__dirname, 'styles.css'), 'utf8'), {
      contentType: 'text/css; charset=utf-8',
      headers: { 'Cache-Control': 'no-store' },
    }),
  'GET'
);

app.api(
  '/app.js',
  () =>
    new Response(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), {
      contentType: 'application/javascript; charset=utf-8',
      headers: { 'Cache-Control': 'no-store' },
    }),
  'GET'
);

app.api(
  '/assets/logo.svg',
  () =>
    new Response(fs.readFileSync(LOGO_PATH, 'utf8'), {
      contentType: 'image/svg+xml; charset=utf-8',
      headers: { 'Cache-Control': 'no-store' },
    }),
  'GET'
);

app.api(
  '/api/state',
  () => {
    refreshAuditArchivesCache({ strict: false });
    return buildStateSnapshot();
  },
  'POST'
);

app.api(
  '/api/stream',
  async (data) => {
    const sinceSeq = Number(data?.sinceSeq ?? 0);
    const rawWait = Number(data?.waitMs ?? 12000);
    const waitMs = Number.isFinite(rawWait)
      ? Math.min(Math.max(0, rawWait), MAX_STREAM_WAIT_MS)
      : 12000;

    if (stateSeq > sinceSeq || waitMs === 0) {
      return {
        seq: stateSeq,
        changed: stateSeq > sinceSeq,
        state: buildStateSnapshot(),
      };
    }

    const changed = await new Promise((resolve) => {
      const waiter = {
        resolve,
        timer: null,
      };
      waiter.timer = setTimeout(() => {
        streamWaiters.delete(waiter);
        resolve(false);
      }, waitMs);
      streamWaiters.add(waiter);
    });

    return {
      seq: stateSeq,
      changed: Boolean(changed) || stateSeq > sinceSeq,
      state: buildStateSnapshot(),
    };
  },
  'POST'
);

app.api(
  '/api/action',
  async (data) => {
    const action = typeof data?.action === 'string' ? data.action.trim() : '';
    const requestId = typeof data?.requestId === 'string' ? data.requestId.trim() : '';

    if (action === 'approve' || action === 'approve-click1') {
      if (!activeJob || activeJob.state !== 'AWAITING_CLICK1') {
        return new Response(JSON.stringify({ ok: false, error: 'No active request awaiting Click-1' }), {
          status: 409,
          contentType: 'application/json; charset=utf-8',
        });
      }
      if (requestId && activeJob.requestId !== requestId) {
        return new Response(JSON.stringify({ ok: false, error: 'Request ID mismatch' }), {
          status: 409,
          contentType: 'application/json; charset=utf-8',
        });
      }
      if (!activeJob.click1Shown) {
        return new Response(JSON.stringify({ ok: false, error: 'Click-1 dialog is still initializing; please retry in a moment' }), {
          status: 409,
          contentType: 'application/json; charset=utf-8',
        });
      }
      sendHelperCmd(activeJob, { cmd: 'approve', requestId: activeJob.requestId });
      return { ok: true, state: buildStateSnapshot() };
    }

    if (action === 'deny') {
      if (!activeJob || activeJob.state !== 'AWAITING_CLICK1') {
        return new Response(JSON.stringify({ ok: false, error: 'No active request awaiting Click-1' }), {
          status: 409,
          contentType: 'application/json; charset=utf-8',
        });
      }
      if (requestId && activeJob.requestId !== requestId) {
        return new Response(JSON.stringify({ ok: false, error: 'Request ID mismatch' }), {
          status: 409,
          contentType: 'application/json; charset=utf-8',
        });
      }
      if (!activeJob.click1Shown) {
        return new Response(JSON.stringify({ ok: false, error: 'Click-1 dialog is still initializing; please retry in a moment' }), {
          status: 409,
          contentType: 'application/json; charset=utf-8',
        });
      }
      sendHelperCmd(activeJob, { cmd: 'deny', requestId: activeJob.requestId });
      return { ok: true, state: buildStateSnapshot() };
    }

    if (action === 'cancel') {
      if (requestId) {
        const qJob = queue.find((q) => q.requestId === requestId);
        if (qJob) {
          finalizeJob(qJob, 'CANCELLED', 1201, 'Cancelled from Side Panel');
          return { ok: true, state: buildStateSnapshot() };
        }
      }
      if (
        activeJob &&
        (activeJob.state === 'AWAITING_CLICK1' || activeJob.state === 'AWAITING_UAC') &&
        (!requestId || activeJob.requestId === requestId)
      ) {
        activeJob.cancelRequested = true;
        sendHelperCmd(activeJob, { cmd: 'cancel', requestId: activeJob.requestId });
        if (!activeJob.cancelFallbackTimer) {
          const targetJob = activeJob;
          targetJob.cancelFallbackTimer = setTimeout(() => {
            if (!targetJob.finished) {
              finalizeJob(targetJob, 'CANCELLED', 1201, 'Cancelled from Side Panel');
            }
          }, 1000);
          targetJob.cancelFallbackTimer.unref();
        }
        return { ok: true, state: buildStateSnapshot() };
      }
      return new Response(JSON.stringify({ ok: false, error: 'No cancellable request matched' }), {
        status: 409,
        contentType: 'application/json; charset=utf-8',
      });
    }

    if (action === 'kill') {
      if (!activeJob || activeJob.state !== 'RUNNING') {
        return new Response(JSON.stringify({ ok: false, error: 'No running request to kill' }), {
          status: 409,
          contentType: 'application/json; charset=utf-8',
        });
      }
      if (requestId && activeJob.requestId !== requestId) {
        return new Response(JSON.stringify({ ok: false, error: 'Request ID mismatch' }), {
          status: 409,
          contentType: 'application/json; charset=utf-8',
        });
      }
      activeJob.killRequested = true;
      sendHelperCmd(activeJob, { cmd: 'kill', requestId: activeJob.requestId });
      return { ok: true, state: buildStateSnapshot() };
    }

    if (action === 'save-config') {
      const incoming = data?.config;
      if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
        return new Response(JSON.stringify({ ok: false, error: 'Missing config object' }), {
          status: 400,
          contentType: 'application/json; charset=utf-8',
        });
      }
      const nextConfig = { ...config };
      if (Object.prototype.hasOwnProperty.call(incoming, 'click1TimeoutSeconds')) {
        const val = parseStrictTimeoutSeconds(incoming.click1TimeoutSeconds);
        if (val === null) {
          return new Response(JSON.stringify({ ok: false, error: 'click1TimeoutSeconds must be integer 0..86400' }), {
            status: 400,
            contentType: 'application/json; charset=utf-8',
          });
        }
        nextConfig.click1TimeoutSeconds = val;
      }
      if (Object.prototype.hasOwnProperty.call(incoming, 'reminderIntervalSeconds')) {
        const val = parseStrictTimeoutSeconds(incoming.reminderIntervalSeconds);
        if (val === null) {
          return new Response(JSON.stringify({ ok: false, error: 'reminderIntervalSeconds must be integer 0..86400' }), {
            status: 400,
            contentType: 'application/json; charset=utf-8',
          });
        }
        nextConfig.reminderIntervalSeconds = val;
      }
      const prevReminderSec = config.reminderIntervalSeconds;
      config = nextConfig;
      writeAtomicUtf8(CONFIG_PATH, JSON.stringify(config, null, 2));
      if (config.reminderIntervalSeconds <= 0) {
        stopReminderTimer();
      } else if (activeJob?.state === 'RUNNING') {
        scheduleReminderIfEligible({ reset: prevReminderSec !== config.reminderIntervalSeconds });
      }
      bumpSeq();
      return { ok: true, config: { ...config }, state: buildStateSnapshot() };
    }

    if (action === 'dismiss-reminder') {
      const wasActiveOrPending = closeReminderHelper();
      if (wasActiveOrPending) {
        scheduleReminderIfEligible();
        bumpSeq();
      }
      return { ok: true, state: buildStateSnapshot() };
    }

    if (action === 'clear-audit' || action === 'archive-audit') {
      try {
        return clearAuditHistory();
      } catch (err) {
        if (err instanceof ZipReadError) {
          return new Response(JSON.stringify({ ok: false, error: err.message }), {
            status: err.status,
            contentType: 'application/json; charset=utf-8',
          });
        }
        throw err;
      }
    }

    if (action === 'list-audit-archives') {
      try {
        const archives = refreshAuditArchivesCache({ strict: true });
        return { ok: true, archives, auditArchiveCount: archives.length };
      } catch (err) {
        if (err instanceof ZipReadError) {
          return new Response(JSON.stringify({ ok: false, error: err.message }), {
            status: err.status,
            contentType: 'application/json; charset=utf-8',
          });
        }
        throw err;
      }
    }

    if (action === 'read-audit-archive') {
      try {
        return readAuditArchive(data?.name);
      } catch (err) {
        if (err instanceof ZipReadError) {
          return new Response(JSON.stringify({ ok: false, error: err.message }), {
            status: err.status,
            contentType: 'application/json; charset=utf-8',
          });
        }
        throw err;
      }
    }

    if (action === 'open-audit-archives') {
      try {
        validateArchiveDirNonSymlink({ createIfMissing: true });
      } catch (err) {
        if (err instanceof ZipReadError) {
          return new Response(JSON.stringify({ ok: false, error: err.message }), {
            status: err.status,
            contentType: 'application/json; charset=utf-8',
          });
        }
        throw err;
      }
      refreshAuditArchivesCache({ strict: false });
      await openArchiveDir(ARCHIVE_DIR);
      return { ok: true, archiveDir: ARCHIVE_DIR };
    }

    return new Response(JSON.stringify({ ok: false, error: `Unknown action: ${action}` }), {
      status: 400,
      contentType: 'application/json; charset=utf-8',
    });
  },
  'POST'
);

  const removeRuntimeIfOwned = () => {
    try {
      if (fs.existsSync(RUNTIME_PATH)) {
        const currentRt = JSON.parse(fs.readFileSync(RUNTIME_PATH, 'utf8'));
        if (currentRt?.pid === process.pid && currentRt?.port === ipcPort) {
          fs.rmSync(RUNTIME_PATH, { force: true });
        }
      }
    } catch {
      // Ignore runtime.json removal error
    }
  };

  let onSigInt = null;
  let onSigTerm = null;
  let onExit = null;

  async function shutdown({ exitProcess = true } = {}) {
    if (shuttingDown) return;
    shuttingDown = true;

    if (registerSignalHandlers) {
      if (onSigInt) process.off('SIGINT', onSigInt);
      if (onSigTerm) process.off('SIGTERM', onSigTerm);
      if (onExit) process.off('exit', onExit);
    }

    stopReminderTimer();
    flushStreamWaiters();

    if (activeJob && !activeJob.finished) {
      try {
        if (activeJob.helper?.stdin && !activeJob.helper.stdin.destroyed && activeJob.helper.stdin.writable) {
          activeJob.helper.stdin.write(JSON.stringify({ cmd: 'shutdown' }) + '\n', 'utf8');
          activeJob.helper.stdin.end();
        }
      } catch {
        // Ignore helper shutdown error
      }
      if (activeJob.keepaliveTimer) clearInterval(activeJob.keepaliveTimer);
      if (activeJob.manifestFile) {
        try {
          fs.rmSync(activeJob.manifestFile, { force: true });
        } catch {}
      }
    }
    for (const q of queue) {
      if (q.keepaliveTimer) clearInterval(q.keepaliveTimer);
      if (q.manifestFile) {
        try {
          fs.rmSync(q.manifestFile, { force: true });
        } catch {}
      }
    }

    removeRuntimeIfOwned();

    try {
      ipcServer.close();
    } catch {}
    try {
      await app.close();
    } catch {}
    if (exitProcess) {
      process.exit(0);
    }
  }

  if (registerSignalHandlers) {
    onSigInt = () => shutdown({ exitProcess: true });
    onSigTerm = () => shutdown({ exitProcess: true });
    onExit = () => removeRuntimeIfOwned();
    process.on('SIGINT', onSigInt);
    process.on('SIGTERM', onSigTerm);
    process.on('exit', onExit);
  }

  const webServer = await app.run();
  const webPort = webServer.address()?.port ?? 0;

  return {
    app,
    ipcServer,
    ipcPort,
    ipcBearerToken,
    webServer,
    webPort,
    dataDir: DATA_DIR,
    archiveDir: ARCHIVE_DIR,
    close: () => shutdown({ exitProcess: false }),
  };
}

function isEntrypoint() {
  if (!process.argv[1]) return false;
  try {
    const argPath = fs.realpathSync(process.argv[1]);
    const selfPath = fs.realpathSync(__filename);
    return process.platform === 'win32'
      ? argPath.toLowerCase() === selfPath.toLowerCase()
      : argPath === selfPath;
  } catch {
    const argPath = path.resolve(process.argv[1]);
    const selfPath = path.resolve(__filename);
    return process.platform === 'win32'
      ? argPath.toLowerCase() === selfPath.toLowerCase()
      : argPath === selfPath;
  }
}

if (isEntrypoint()) {
  await startBroker();
}
