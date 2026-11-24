/*
 * Elevated Execution Auxiliary Side Pane Frontend.
 * Uses window.sidecar.fetch + preload.js theme tokens + cursor long-polling on POST /api/stream.
 */
(() => {
  const $ = (id) => document.getElementById(id);

  const state = {
    seq: 0,
    snapshot: null,
    pollAbort: null,
    pollRunning: false,
    pollGen: 0,
    paneVisible: true,
    actionBusy: false,
    scriptCollapsed: false,
    followOutput: true,
    lastActiveKey: '',
    lastRenderedChunkSeq: 0,
    lastOutputRequestId: '',
    lastQueueKey: '',
    lastAuditKey: '',
    lastConfigKey: '',
  };

  const CLEAR_AUDIT_GUARD_MS = 250;
  const CLEAR_AUDIT_TIMEOUT_MS = 1500;
  const clearAuditState = {
    armed: false,
    armedAt: 0,
    timerId: null,
    inFlight: false,
  };
  let openArchivesBusy = false;
  const auditUiState = {
    activeTab: 'live',
    archives: [],
    archivesLoaded: false,
    lastArchivesKey: '',
    selectedArchive: '',
    loadedArchiveName: '',
    loadedArchiveEntries: [],
    failedArchiveName: '',
    failedArchiveKey: '',
    loadingList: false,
    loadingEntries: false,
    loadError: '',
    loadGen: 0,
    openLiveIds: new Set(),
    openArchivedIds: new Map(),
  };

  // ---------- Host Theme Synchronization ----------
  function syncThemeScheme() {
    const probe = document.createElement('span');
    probe.style.cssText = 'position:absolute;visibility:hidden;color:var(--background, #f7f7f8)';
    document.documentElement.appendChild(probe);
    const computed = getComputedStyle(probe).color;
    probe.remove();
    const nums = (computed.match(/[\d.]+/g) || []).map(Number);
    if (nums.length < 3) return;
    const scale = computed.startsWith('color(') ? 1 : 255;
    const [r, g, b] = nums.slice(0, 3).map((v) => v / scale);
    const lum = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    const theme = lum < 0.5 ? 'dark' : 'light';
    if (document.documentElement.dataset.theme !== theme) {
      document.documentElement.dataset.theme = theme;
    }
  }
  syncThemeScheme();
  new MutationObserver(syncThemeScheme).observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['style'],
  });

  // ---------- Authenticated Sidecar API Helpers ----------
  function apiFetch(path, options = {}) {
    if (window.sidecar?.fetch) {
      return window.sidecar.fetch(path, options);
    }
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    return fetch(path, { ...options, headers });
  }

  async function apiPostJson(path, payload = {}, signal = undefined) {
    const res = await apiFetch(path, {
      method: 'POST',
      body: JSON.stringify(payload),
      signal,
    });
    let data = null;
    try {
      data = await res.json();
    } catch {
      throw new Error(`HTTP ${res.status}`);
    }
    if (!res.ok) {
      throw new Error(data?.error || `HTTP ${res.status}`);
    }
    return data;
  }

  function showToast(msg, isError = false) {
    const banner = $('toast-banner');
    banner.textContent = msg;
    banner.classList.toggle('error', isError);
    banner.classList.remove('hidden');
    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => {
      banner.classList.add('hidden');
    }, 3500);
  }

  function formatShaGroups(sha) {
    const clean = String(sha || '').trim();
    if (!clean) return '';
    return clean.match(/.{1,4}/g)?.join(' ') || clean;
  }

  function formatBytes(bytes) {
    const n = Number(bytes || 0);
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  }

  function stateBadgeClass(s) {
    if (s === 'AWAITING_CLICK1') return 'awaiting-click1';
    if (s === 'AWAITING_UAC') return 'awaiting-uac';
    if (s === 'RUNNING') return 'running';
    if (s === 'COMPLETED') return 'completed';
    return 'failed';
  }

  function updateCountdown() {
    const job = state.snapshot?.activeJob;
    const wrap = $('countdown-wrap');
    const textEl = $('countdown-text');
    const barEl = $('countdown-bar');
    if (!job || job.state !== 'AWAITING_CLICK1') {
      wrap.classList.add('hidden');
      return;
    }
    wrap.classList.remove('hidden');
    const totalSec = Number(job.click1TimeoutSeconds ?? state.snapshot?.config?.click1TimeoutSeconds ?? 0);
    let nextText;
    let nextWidth;
    if (totalSec <= 0) {
      nextText = 'No timeout (manual decision required)';
      nextWidth = '100%';
    } else if (!job.click1Shown || !job.click1DeadlineAt) {
      const mm = String(Math.floor(totalSec / 60)).padStart(2, '0');
      const ss = String(totalSec % 60).padStart(2, '0');
      nextText = `Auto-cancels in ${mm}:${ss}`;
      nextWidth = '100%';
    } else {
      const remMs = Math.max(0, job.click1DeadlineAt - Date.now());
      const remSec = Math.ceil(remMs / 1000);
      const mm = String(Math.floor(remSec / 60)).padStart(2, '0');
      const ss = String(remSec % 60).padStart(2, '0');
      nextText = `Auto-cancels in ${mm}:${ss}`;
      const pct = Math.max(0, Math.min(100, (remMs / (totalSec * 1000)) * 100));
      nextWidth = `${pct.toFixed(1)}%`;
    }
    if (textEl.textContent !== nextText) {
      textEl.textContent = nextText;
    }
    if (barEl.style.width !== nextWidth) {
      barEl.style.width = nextWidth;
    }
  }

  function renderHeaderAndReminder(snap) {
    const badge = $('summary-badge');
    const active = snap.activeJob;
    const qLen = snap.queue?.length || 0;

    badge.className = 'summary-badge';
    if (!active && qLen === 0) {
      badge.textContent = 'Idle';
    } else if (active?.state === 'AWAITING_CLICK1') {
      badge.textContent = qLen > 0 ? `Click-1 (+${qLen})` : 'Awaiting Click-1';
      badge.classList.add('warn');
    } else if (active?.state === 'AWAITING_UAC') {
      badge.textContent = qLen > 0 ? `UAC (+${qLen})` : 'Awaiting UAC';
      badge.classList.add('info');
    } else if (active?.state === 'RUNNING') {
      badge.textContent = qLen > 0 ? `Running (+${qLen})` : 'Running';
      badge.classList.add('live');
    } else {
      badge.textContent = `Queued: ${qLen}`;
    }

    const remBanner = $('reminder-banner');
    if (snap.reminder?.active && qLen > 0) {
      $('reminder-summary').textContent = `${qLen} elevation request(s) waiting while active job runs.`;
      remBanner.classList.remove('hidden');
    } else {
      remBanner.classList.add('hidden');
    }
  }

  function renderConfig(snap) {
    const cfg = snap.config || { click1TimeoutSeconds: 300, reminderIntervalSeconds: 300 };
    const cfgKey = `${cfg.click1TimeoutSeconds}:${cfg.reminderIntervalSeconds}`;
    if (cfgKey === state.lastConfigKey) return;
    state.lastConfigKey = cfgKey;
    $('input-click1-timeout').value = String(cfg.click1TimeoutSeconds ?? 300);
    $('input-reminder-interval').value = String(cfg.reminderIntervalSeconds ?? 300);
  }

  function renderActiveJob(snap) {
    const job = snap.activeJob;
    const qLen = snap.queue?.length || 0;
    const emptyEl = $('empty-state');
    const cardEl = $('active-card');

    if (!job) {
      cardEl.classList.add('hidden');
      emptyEl.classList.toggle('hidden', qLen > 0);
      state.lastActiveKey = '';
      state.lastOutputRequestId = '';
      state.lastRenderedChunkSeq = 0;
      return;
    }

    emptyEl.classList.add('hidden');
    cardEl.classList.remove('hidden');

    const activeKey = [
      job.requestId,
      job.state,
      job.click1Shown ? '1' : '0',
      job.detached ? '1' : '0',
      job.click1DeadlineAt || '',
      state.actionBusy ? '1' : '0',
    ].join('|');

    if (activeKey !== state.lastActiveKey) {
      state.lastActiveKey = activeKey;

      $('active-id').textContent = job.requestId;
      const stBadge = $('active-state-badge');
      stBadge.textContent = job.state;
      stBadge.className = `state-badge ${stateBadgeClass(job.state)}`;
      $('active-detached-badge').classList.toggle('hidden', !job.detached);

      $('active-reason').textContent = job.reason || '(no reason)';

      const attr = job.attribution || {};
      const attrParts = [];
      if (attr.agentLabel) attrParts.push(attr.agentLabel);
      if (attr.workspace) attrParts.push(`workspace "${attr.workspace}"`);
      if (attr.conversationId) attrParts.push(`conv ${attr.conversationId.slice(0, 8)} (step ${attr.stepIndex ?? 0})`);
      $('active-attribution').textContent = attrParts.join(' · ') || 'Local CLI';

      $('active-mode').textContent = `${job.mode} / ${job.encoding}${job.normalWindow ? ' (NormalWindow)' : ''}`;
      $('active-workdir').textContent = job.workDir || '';

      const argsRow = $('active-args-row');
      const argsBox = $('active-args');
      argsBox.textContent = '';
      if (Array.isArray(job.args) && job.args.length > 0) {
        argsRow.classList.remove('hidden');
        for (const arg of job.args) {
          const chip = document.createElement('span');
          chip.className = 'arg-chip';
          chip.textContent = String(arg);
          argsBox.appendChild(chip);
        }
      } else {
        argsRow.classList.add('hidden');
      }

      const targetRow = $('active-target-row');
      const targetEl = $('active-target');
      if (job.targetMeta) {
        const tm = job.targetMeta;
        const details = [tm.canonicalPath || tm.originalPath, tm.subsystem ? `[${tm.subsystem}]` : '', tm.publisher ? `Publisher: ${tm.publisher}` : 'Unsigned / Unknown publisher']
          .filter(Boolean)
          .join(' · ');
        targetEl.textContent = details;
        targetRow.classList.remove('hidden');
      } else {
        targetRow.classList.add('hidden');
      }

      $('active-sha').textContent = formatShaGroups(job.manifestSha256);

      const scriptText = String(job.script ?? '');
      $('active-script').textContent = scriptText;
      $('script-size-badge').textContent = `(${formatBytes(new TextEncoder().encode(scriptText).length)})`;

      const actionBox = $('action-buttons');
      actionBox.textContent = '';
      const uacHint = $('uac-hint');
      uacHint.classList.add('hidden');

      if (job.state === 'AWAITING_CLICK1') {
        const click1Ready = Boolean(job.click1Shown);
        const btnApprove = document.createElement('button');
        btnApprove.type = 'button';
        btnApprove.className = 'primary-btn';
        btnApprove.textContent = 'Approve → UAC';
        btnApprove.disabled = state.actionBusy || !click1Ready;
        btnApprove.addEventListener('click', () => runAction('approve', job.requestId));

        const btnDeny = document.createElement('button');
        btnDeny.type = 'button';
        btnDeny.className = 'danger-btn';
        btnDeny.textContent = 'Deny';
        btnDeny.disabled = state.actionBusy || !click1Ready;
        btnDeny.addEventListener('click', () => runAction('deny', job.requestId));

        const btnCancel = document.createElement('button');
        btnCancel.type = 'button';
        btnCancel.className = 'ghost-btn';
        btnCancel.textContent = 'Cancel';
        btnCancel.disabled = state.actionBusy;
        btnCancel.addEventListener('click', () => runAction('cancel', job.requestId));

        actionBox.append(btnApprove, btnDeny, btnCancel);
        if (!click1Ready) {
          uacHint.textContent = 'Initializing Click-1 dialog...';
          uacHint.classList.remove('hidden');
        }
      } else if (job.state === 'AWAITING_UAC') {
        const btnCancel = document.createElement('button');
        btnCancel.type = 'button';
        btnCancel.className = 'ghost-btn';
        btnCancel.textContent = 'Cancel';
        btnCancel.disabled = state.actionBusy;
        btnCancel.addEventListener('click', () => runAction('cancel', job.requestId));
        actionBox.append(btnCancel);
        uacHint.textContent = 'Waiting for Windows UAC prompt on WinSta0\\Default...';
        uacHint.classList.remove('hidden');
      } else if (job.state === 'RUNNING') {
        const btnKill = document.createElement('button');
        btnKill.type = 'button';
        btnKill.className = 'danger-btn';
        btnKill.textContent = 'Kill Process Tree';
        btnKill.disabled = state.actionBusy;
        btnKill.addEventListener('click', () => runAction('kill', job.requestId));
        actionBox.append(btnKill);
      }
    }

    updateCountdown();
    renderLiveOutput(job);
  }

  function renderLiveOutput(job) {
    const vp = $('output-viewport');
    const out = job.output || { chunks: [], totalBytes: 0, truncated: false };
    $('output-size-badge').textContent = `(${formatBytes(out.totalBytes)}${out.truncated ? ', 512 KB cap' : ''})`;

    if (state.lastOutputRequestId !== job.requestId) {
      state.lastOutputRequestId = job.requestId;
      state.lastRenderedChunkSeq = 0;
      vp.textContent = '';
    }

    const chunks = Array.isArray(out.chunks) ? out.chunks : [];
    if (chunks.length === 0) {
      if (!vp.firstChild) {
        const empty = document.createElement('span');
        empty.className = 'out-empty';
        empty.textContent = job.state === 'RUNNING' ? 'Waiting for output...' : 'Output will appear once elevated execution starts.';
        vp.appendChild(empty);
      }
      return;
    }

    // Clear placeholder if real chunks arrived
    if (vp.firstChild && vp.firstChild.classList?.contains('out-empty')) {
      vp.textContent = '';
    }

    // If ring buffer evicted chunks we previously showed or reset, rebuild cleanly
    if (chunks[0].seq > state.lastRenderedChunkSeq + 1 && state.lastRenderedChunkSeq > 0) {
      vp.textContent = '';
      state.lastRenderedChunkSeq = 0;
    }

    let appended = false;
    for (const c of chunks) {
      if (c.seq <= state.lastRenderedChunkSeq) continue;
      const span = document.createElement('span');
      span.className = `out-chunk ${c.stream === 'stderr' ? 'stderr' : 'stdout'}`;
      span.textContent = c.text;
      vp.appendChild(span);
      state.lastRenderedChunkSeq = c.seq;
      appended = true;
    }

    if (appended && state.followOutput) {
      vp.scrollTop = vp.scrollHeight;
    }
  }

  function renderQueue(snap) {
    const queue = Array.isArray(snap.queue) ? snap.queue : [];
    const sec = $('queue-section');
    const list = $('queue-list');
    $('queue-count-badge').textContent = String(queue.length);

    if (queue.length === 0) {
      sec.classList.add('hidden');
      list.textContent = '';
      state.lastQueueKey = '';
      return;
    }
    sec.classList.remove('hidden');

    const key = queue.map((q) => q.requestId).join(',');
    if (key === state.lastQueueKey) return;
    state.lastQueueKey = key;

    list.textContent = '';
    queue.forEach((item, idx) => {
      const row = document.createElement('div');
      row.className = 'queue-item';

      const info = document.createElement('div');
      info.className = 'queue-info';

      const reason = document.createElement('div');
      reason.className = 'queue-reason';
      reason.textContent = `#${idx + 1} · ${item.reason}`;

      const meta = document.createElement('div');
      meta.className = 'queue-meta';
      const shaPrefix = String(item.manifestSha256 || '').slice(0, 12);
      const attrSummary = item.attribution?.workspace || item.workDir;
      meta.textContent = `${item.requestId} · ${attrSummary} · SHA ${shaPrefix}…`;

      info.append(reason, meta);

      const btnCancel = document.createElement('button');
      btnCancel.type = 'button';
      btnCancel.className = 'ghost-btn';
      btnCancel.textContent = 'Cancel';
      btnCancel.addEventListener('click', () => runAction('cancel', item.requestId));

      row.append(info, btnCancel);
      list.appendChild(row);
    });
  }

  function disarmClearAudit() {
    if (clearAuditState.timerId !== null) {
      clearTimeout(clearAuditState.timerId);
      clearAuditState.timerId = null;
    }
    if (!clearAuditState.armed) return;
    clearAuditState.armed = false;
    clearAuditState.armedAt = 0;
    const btn = $('btn-clear-audit');
    const label = $('btn-clear-audit-label');
    if (btn) {
      btn.classList.remove('armed');
      btn.setAttribute('aria-label', 'Archive completed audit history');
      if (!clearAuditState.inFlight) {
        const count = Array.isArray(state.snapshot?.audit) ? state.snapshot.audit.length : 0;
        btn.disabled = count === 0;
      }
    }
    if (label) {
      label.textContent = 'Archive';
    }
  }

  function armClearAudit() {
    if (clearAuditState.timerId !== null) {
      clearTimeout(clearAuditState.timerId);
      clearAuditState.timerId = null;
    }
    clearAuditState.armed = true;
    clearAuditState.armedAt = Date.now();
    const btn = $('btn-clear-audit');
    const label = $('btn-clear-audit-label');
    if (btn) {
      btn.classList.remove('armed');
      void btn.offsetWidth;
      btn.classList.add('armed');
      btn.setAttribute('aria-label', 'Confirm archiving audit history');
    }
    if (label) {
      label.textContent = 'Confirm';
    }
    clearAuditState.timerId = setTimeout(() => {
      clearAuditState.timerId = null;
      disarmClearAudit();
    }, CLEAR_AUDIT_TIMEOUT_MS);
  }

  async function executeClearAudit() {
    disarmClearAudit();
    clearAuditState.inFlight = true;
    const btn = $('btn-clear-audit');
    if (btn) btn.disabled = true;
    try {
      const res = await apiPostJson('/api/action', { action: 'archive-audit' });
      const count = Number(res?.clearedCount || 0);
      if (count > 0 && res?.archiveName) {
        auditUiState.selectedArchive = res.archiveName;
        auditUiState.loadedArchiveName = '';
        auditUiState.loadedArchiveEntries = [];
        auditUiState.failedArchiveName = '';
        auditUiState.failedArchiveKey = '';
        auditUiState.loadError = '';
      }
      if (res?.state) {
        applySnapshot(res.state);
      } else {
        await refreshState();
      }
      if (count > 0 && !Array.isArray(res?.state?.auditArchives)) {
        await refreshArchiveList();
      }
      showToast(count > 0 ? `Archived ${count} audit entry(s)` : 'No completed audit entries to archive');
    } catch (err) {
      showToast(`Action "archive-audit" failed: ${err.message}`, true);
    } finally {
      clearAuditState.inFlight = false;
      if (btn && !clearAuditState.armed) {
        const count = Array.isArray(state.snapshot?.audit) ? state.snapshot.audit.length : 0;
        btn.disabled = count === 0;
      }
    }
  }

  async function handleOpenArchives() {
    if (openArchivesBusy) return;
    openArchivesBusy = true;
    const btn = $('btn-open-archives');
    if (btn) btn.disabled = true;
    try {
      await apiPostJson('/api/action', { action: 'open-audit-archives' });
    } catch (err) {
      showToast(`Failed to open archives folder: ${err.message}`, true);
    } finally {
      openArchivesBusy = false;
      if (btn) btn.disabled = false;
    }
  }

  function formatAuditTimestamp(iso) {
    if (!iso) return { label: '', iso: '' };
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return { label: String(iso), iso: '' };
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    const hh = String(d.getHours()).padStart(2, '0');
    const mi = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    return {
      label: `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`,
      iso: d.toISOString(),
    };
  }

  function formatArchiveOptionLabel(arch) {
    const ts = formatAuditTimestamp(arch?.createdAt);
    const shortTs = ts.label ? ts.label.slice(0, 16) : String(arch?.name || '');
    return `${shortTs} (${formatBytes(arch?.sizeBytes)})`;
  }

  function createAuditEntryElement(entry, isOpen, onToggle) {
    const reqId = String(entry?.requestId || '');
    const details = document.createElement('details');
    details.className = 'audit-item';
    if (reqId) details.dataset.requestId = reqId;
    details.open = Boolean(isOpen);
    if (typeof onToggle === 'function' && reqId) {
      details.addEventListener('toggle', () => {
        onToggle(reqId, Boolean(details.open));
      });
    }

    const summary = document.createElement('summary');
    summary.className = 'audit-summary';

    const top = document.createElement('div');
    top.className = 'audit-top';

    const badges = document.createElement('div');
    badges.className = 'audit-badges';

    const outcomeBadge = document.createElement('span');
    outcomeBadge.className = `state-badge ${entry.outcome === 'COMPLETED' && entry.exitCode === 0 ? 'completed' : 'failed'}`;
    outcomeBadge.textContent = `${entry.outcome} (${entry.exitCode})`;

    const idSpan = document.createElement('span');
    idSpan.className = 'mono-id';
    idSpan.textContent = reqId;

    badges.append(outcomeBadge, idSpan);

    const timeSpan = document.createElement('span');
    timeSpan.className = 'audit-time';
    const tsInfo = formatAuditTimestamp(entry.finishedAt);
    timeSpan.textContent = tsInfo.label;
    if (tsInfo.iso) timeSpan.title = tsInfo.iso;

    top.append(badges, timeSpan);

    const reason = document.createElement('div');
    reason.className = 'audit-reason';
    reason.textContent = entry.reason || '(no reason)';

    summary.append(top, reason);

    const body = document.createElement('div');
    body.className = 'audit-detail';

    const metaLine = document.createElement('div');
    metaLine.className = 'queue-meta mono';
    metaLine.textContent = `WorkDir: ${entry.workDir} | SHA-256: ${String(entry.manifestSha256 || '').slice(0, 16)}…`;
    body.appendChild(metaLine);

    if (entry.scriptPreview) {
      const lbl = document.createElement('div');
      lbl.className = 'meta-label';
      lbl.textContent = 'Script Preview (<= 4 KB)';
      const pre = document.createElement('pre');
      pre.className = 'audit-pre';
      pre.textContent = entry.scriptPreview;
      body.append(lbl, pre);
    }

    if (entry.outputTail) {
      const lbl = document.createElement('div');
      lbl.className = 'meta-label';
      lbl.textContent = 'Output Tail (<= 4 KB)';
      const pre = document.createElement('pre');
      pre.className = 'audit-pre';
      pre.textContent = entry.outputTail;
      body.append(lbl, pre);
    }

    details.append(summary, body);
    return details;
  }

  function renderAuditEntries(listEl, entries, openIdsSet) {
    if (!listEl) return;
    if (openIdsSet && listEl.children && typeof listEl.children.length === 'number') {
      for (let i = 0; i < listEl.children.length; i += 1) {
        const ch = listEl.children[i];
        const chId = ch?.dataset?.requestId;
        if (chId) {
          if (ch.open) openIdsSet.add(chId);
          else openIdsSet.delete(chId);
        }
      }
    }
    if (openIdsSet) {
      const currentIds = new Set(entries.map((e) => String(e?.requestId || '')).filter(Boolean));
      for (const id of Array.from(openIdsSet)) {
        if (!currentIds.has(id)) openIdsSet.delete(id);
      }
    }
    listEl.textContent = '';
    for (const entry of entries) {
      const reqId = String(entry?.requestId || '');
      const isOpen = Boolean(openIdsSet && reqId && openIdsSet.has(reqId));
      const el = createAuditEntryElement(entry, isOpen, (id, openNow) => {
        if (!openIdsSet) return;
        if (openNow) openIdsSet.add(id);
        else openIdsSet.delete(id);
      });
      listEl.appendChild(el);
    }
  }

  function updateArchiveStatusBanner() {
    const statusEl = $('archive-status');
    const emptyEl = $('archive-empty');
    const listEl = $('archive-list');
    if (!statusEl || !emptyEl || !listEl) return;

    if (auditUiState.loadError) {
      emptyEl.classList.add('hidden');
      statusEl.classList.remove('hidden');
      statusEl.classList.add('error');
      statusEl.textContent = `Failed to load archive: ${auditUiState.loadError}`;
      return;
    }

    if (auditUiState.archives.length === 0) {
      emptyEl.classList.remove('hidden');
      statusEl.classList.add('hidden');
      statusEl.classList.remove('error');
      statusEl.textContent = '';
      listEl.textContent = '';
      return;
    }

    emptyEl.classList.add('hidden');
    if (auditUiState.loadingList || auditUiState.loadingEntries) {
      statusEl.classList.remove('hidden', 'error');
      statusEl.textContent = 'Loading archive...';
      return;
    }
    if (auditUiState.loadedArchiveName === auditUiState.selectedArchive && auditUiState.loadedArchiveEntries.length === 0) {
      statusEl.classList.remove('hidden', 'error');
      statusEl.textContent = 'Archive contains no entries.';
      return;
    }
    statusEl.classList.add('hidden');
    statusEl.classList.remove('error');
    statusEl.textContent = '';
  }

  function getArchiveMetaKeyFromList(archives, name) {
    if (!name || !Array.isArray(archives)) return '';
    const arch = archives.find((a) => a.name === name);
    return arch ? `${arch.name}:${arch.sizeBytes}:${arch.createdAt}` : '';
  }

  function renderArchiveSelect() {
    const badge = $('archive-count-badge');
    const select = $('archive-select');
    const archives = auditUiState.archives;
    if (badge) badge.textContent = String(archives.length);

    if (archives.length === 0) {
      auditUiState.selectedArchive = '';
      auditUiState.loadedArchiveName = '';
      auditUiState.loadedArchiveEntries = [];
      auditUiState.failedArchiveName = '';
      auditUiState.failedArchiveKey = '';
      auditUiState.loadError = '';
      auditUiState.lastArchivesKey = '__empty__';
      if (select) {
        select.textContent = '';
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No archives';
        opt.disabled = true;
        opt.selected = true;
        select.appendChild(opt);
        select.value = '';
        select.disabled = true;
      }
      updateArchiveStatusBanner();
      return;
    }

    if (!auditUiState.selectedArchive || !archives.some((a) => a.name === auditUiState.selectedArchive)) {
      auditUiState.selectedArchive = archives[0].name;
    }

    const key = archives.map((a) => `${a.name}:${a.sizeBytes}:${a.createdAt}`).join('|');
    if (select && key !== auditUiState.lastArchivesKey) {
      auditUiState.lastArchivesKey = key;
      select.textContent = '';
      for (const arch of archives) {
        const opt = document.createElement('option');
        opt.value = arch.name;
        opt.textContent = formatArchiveOptionLabel(arch);
        opt.selected = arch.name === auditUiState.selectedArchive;
        select.appendChild(opt);
      }
      select.disabled = false;
      select.value = auditUiState.selectedArchive;
    } else if (select) {
      select.disabled = false;
      if (select.value !== auditUiState.selectedArchive) {
        select.value = auditUiState.selectedArchive;
      }
    }

    updateArchiveStatusBanner();
  }

  async function loadArchiveEntries(name) {
    if (!name) {
      auditUiState.loadGen++;
      auditUiState.loadingEntries = false;
      auditUiState.loadedArchiveName = '';
      auditUiState.loadedArchiveEntries = [];
      auditUiState.failedArchiveName = '';
      auditUiState.failedArchiveKey = '';
      auditUiState.loadError = '';
      const listEl = $('archive-list');
      if (listEl) listEl.textContent = '';
      updateArchiveStatusBanner();
      return;
    }
    const gen = ++auditUiState.loadGen;
    auditUiState.loadingEntries = true;
    auditUiState.failedArchiveName = '';
    auditUiState.failedArchiveKey = '';
    auditUiState.loadError = '';
    const listEl = $('archive-list');
    if (listEl) listEl.textContent = '';
    updateArchiveStatusBanner();

    try {
      const res = await apiPostJson('/api/action', { action: 'read-audit-archive', name });
      if (gen !== auditUiState.loadGen || auditUiState.selectedArchive !== name) return;
      const entries = Array.isArray(res?.entries) ? res.entries : [];
      auditUiState.loadedArchiveName = name;
      auditUiState.loadedArchiveEntries = entries;
      auditUiState.failedArchiveName = '';
      auditUiState.failedArchiveKey = '';
      auditUiState.loadError = '';
      let openSet = auditUiState.openArchivedIds.get(name);
      if (!openSet) {
        openSet = new Set();
        auditUiState.openArchivedIds.set(name, openSet);
      }
      renderAuditEntries(listEl, entries, openSet);
    } catch (err) {
      if (gen !== auditUiState.loadGen || auditUiState.selectedArchive !== name) return;
      auditUiState.loadedArchiveName = '';
      auditUiState.loadedArchiveEntries = [];
      auditUiState.failedArchiveName = name;
      auditUiState.failedArchiveKey = getArchiveMetaKeyFromList(auditUiState.archives, name);
      auditUiState.loadError = err?.message || 'Unknown error';
      if (listEl) listEl.textContent = '';
    } finally {
      if (gen === auditUiState.loadGen) {
        auditUiState.loadingEntries = false;
        updateArchiveStatusBanner();
      }
    }
  }

  async function refreshArchiveList({ loadIfArchived = false } = {}) {
    let shouldLoadEntries = false;
    let targetArchive = '';
    auditUiState.loadingList = true;
    if (auditUiState.activeTab === 'archived') {
      updateArchiveStatusBanner();
    }
    try {
      const res = await apiPostJson('/api/action', { action: 'list-audit-archives' });
      const archives = Array.isArray(res?.archives) ? res.archives : [];
      const prevSelected = auditUiState.selectedArchive;
      const nextSelected = (prevSelected && archives.some((a) => a.name === prevSelected))
        ? prevSelected
        : (archives[0]?.name || '');
      const selectionChanged = nextSelected !== prevSelected;

      if (selectionChanged) {
        auditUiState.failedArchiveName = '';
        auditUiState.failedArchiveKey = '';
        if (!auditUiState.loadingEntries) {
          auditUiState.loadError = '';
        }
      } else if (auditUiState.failedArchiveName && auditUiState.failedArchiveName === nextSelected) {
        const currentKey = getArchiveMetaKeyFromList(archives, nextSelected);
        if (currentKey !== auditUiState.failedArchiveKey) {
          auditUiState.failedArchiveName = '';
          auditUiState.failedArchiveKey = '';
          auditUiState.loadError = '';
        }
      } else if (!auditUiState.loadingEntries) {
        auditUiState.loadError = '';
      }

      auditUiState.archives = archives;
      auditUiState.archivesLoaded = true;
      renderArchiveSelect();

      targetArchive = auditUiState.selectedArchive;
      const isFailedForTarget = Boolean(targetArchive) && (
        auditUiState.failedArchiveName === targetArchive ||
        Boolean(auditUiState.loadError)
      );
      shouldLoadEntries = Boolean(
        loadIfArchived &&
        auditUiState.activeTab === 'archived' &&
        targetArchive &&
        auditUiState.loadedArchiveName !== targetArchive &&
        !auditUiState.loadingEntries &&
        !isFailedForTarget
      );
    } catch (err) {
      const hasFailedTarget = Boolean(auditUiState.selectedArchive) && auditUiState.failedArchiveName === auditUiState.selectedArchive;
      if (!auditUiState.loadingEntries && !hasFailedTarget) {
        auditUiState.loadError = err?.message || 'Failed to list archives';
      }
      if (auditUiState.activeTab === 'archived') {
        updateArchiveStatusBanner();
      }
    } finally {
      auditUiState.loadingList = false;
      if (auditUiState.activeTab === 'archived') {
        updateArchiveStatusBanner();
      }
    }

    if (shouldLoadEntries && targetArchive && auditUiState.selectedArchive === targetArchive) {
      await loadArchiveEntries(targetArchive);
    }
  }

  async function ensureArchivesLoaded() {
    renderArchiveSelect();
    await refreshArchiveList({ loadIfArchived: true });
  }

  function setAuditTab(tab) {
    const prevTab = auditUiState.activeTab;
    const nextTab = tab === 'archived' ? 'archived' : 'live';
    if (nextTab !== 'live') {
      disarmClearAudit();
    }
    auditUiState.activeTab = nextTab;

    const tabLive = $('tab-audit-live');
    const tabArchived = $('tab-audit-archived');
    const panelLive = $('audit-panel-live');
    const panelArchived = $('audit-panel-archived');

    if (tabLive) {
      tabLive.classList.toggle('active', nextTab === 'live');
      tabLive.setAttribute('aria-selected', nextTab === 'live' ? 'true' : 'false');
    }
    if (tabArchived) {
      tabArchived.classList.toggle('active', nextTab === 'archived');
      tabArchived.setAttribute('aria-selected', nextTab === 'archived' ? 'true' : 'false');
    }
    if (panelLive) panelLive.classList.toggle('hidden', nextTab !== 'live');
    if (panelArchived) panelArchived.classList.toggle('hidden', nextTab !== 'archived');

    if (nextTab === 'archived') {
      if (prevTab !== 'archived' && !auditUiState.loadingEntries) {
        auditUiState.failedArchiveName = '';
        auditUiState.failedArchiveKey = '';
        auditUiState.loadError = '';
      }
      ensureArchivesLoaded();
    }
  }

  function syncArchiveMetaFromSnapshot(snap) {
    if (!snap || typeof snap !== 'object') return;
    if (Array.isArray(snap.auditArchives)) {
      const prevSelected = auditUiState.selectedArchive;
      const prevFailedName = auditUiState.failedArchiveName;
      const prevFailedKey = auditUiState.failedArchiveKey;
      const nextArchives = snap.auditArchives;
      const nextSelected = (prevSelected && nextArchives.some((a) => a.name === prevSelected))
        ? prevSelected
        : (nextArchives[0]?.name || '');
      const selectionChanged = nextSelected !== prevSelected;

      if (selectionChanged) {
        auditUiState.failedArchiveName = '';
        auditUiState.failedArchiveKey = '';
        if (!auditUiState.loadingEntries) {
          auditUiState.loadError = '';
        }
      } else if (prevFailedName && nextSelected && prevFailedName === nextSelected) {
        const nextKey = getArchiveMetaKeyFromList(nextArchives, nextSelected);
        if (nextKey !== prevFailedKey) {
          auditUiState.failedArchiveName = '';
          auditUiState.failedArchiveKey = '';
          auditUiState.loadError = '';
        }
      }

      auditUiState.archives = nextArchives;
      auditUiState.archivesLoaded = true;
      renderArchiveSelect();

      const target = auditUiState.selectedArchive;
      const isFailedForTarget = Boolean(target) && (
        auditUiState.failedArchiveName === target ||
        Boolean(auditUiState.loadError)
      );
      if (
        auditUiState.activeTab === 'archived' &&
        target &&
        auditUiState.loadedArchiveName !== target &&
        !auditUiState.loadingList &&
        !auditUiState.loadingEntries &&
        !isFailedForTarget
      ) {
        loadArchiveEntries(target);
      }
    } else if (typeof snap.auditArchiveCount === 'number') {
      const badge = $('archive-count-badge');
      if (badge) badge.textContent = String(snap.auditArchiveCount);
    }
  }

  function renderAudit(snap) {
    const audit = Array.isArray(snap.audit) ? snap.audit : [];
    const list = $('audit-list');
    const empty = $('audit-empty');
    $('audit-count-badge').textContent = String(audit.length);

    const btnClear = $('btn-clear-audit');
    if (btnClear && !clearAuditState.armed && !clearAuditState.inFlight) {
      btnClear.disabled = audit.length === 0;
    }

    if (audit.length === 0) {
      empty.classList.remove('hidden');
      list.textContent = '';
      auditUiState.openLiveIds.clear();
      state.lastAuditKey = '';
      return;
    }
    empty.classList.add('hidden');

    const key = audit.map((a) => `${a.requestId}:${a.finishedAt}`).join('|');
    if (key === state.lastAuditKey) return;
    state.lastAuditKey = key;

    renderAuditEntries(list, audit, auditUiState.openLiveIds);
  }

  function applySnapshot(snap) {
    if (!snap || typeof snap !== 'object') return;
    state.snapshot = snap;
    if (typeof snap.seq === 'number') {
      state.seq = snap.seq;
    }
    renderHeaderAndReminder(snap);
    renderConfig(snap);
    renderActiveJob(snap);
    renderQueue(snap);
    renderAudit(snap);
    syncArchiveMetaFromSnapshot(snap);
  }

  async function runAction(action, requestId = '', extra = {}) {
    if (state.actionBusy) return;
    state.actionBusy = true;
    if (state.snapshot) renderActiveJob(state.snapshot);
    try {
      const payload = { action, ...extra };
      if (requestId) payload.requestId = requestId;
      const res = await apiPostJson('/api/action', payload);
      if (res?.state) {
        applySnapshot(res.state);
      }
      if (action === 'save-config') {
        const st = $('settings-status');
        st.textContent = 'Saved';
        setTimeout(() => {
          if (st.textContent === 'Saved') st.textContent = '';
        }, 2500);
      }
    } catch (err) {
      showToast(`Action "${action}" failed: ${err.message}`, true);
    } finally {
      state.actionBusy = false;
      if (state.snapshot) renderActiveJob(state.snapshot);
    }
  }

  async function refreshState(signal = undefined, gen = state.pollGen) {
    try {
      const snap = await apiPostJson('/api/state', {}, signal);
      if (signal?.aborted || gen !== state.pollGen) return;
      applySnapshot(snap);
    } catch (err) {
      if (signal?.aborted || err?.name === 'AbortError' || gen !== state.pollGen) return;
      showToast(`Failed to load state: ${err.message}`, true);
    }
  }

  function cancelPoll() {
    state.pollGen++;
    if (state.pollAbort) {
      state.pollAbort.abort();
      state.pollAbort = null;
    }
    state.pollRunning = false;
  }

  async function startPollLoop() {
    if (state.pollRunning || !state.paneVisible) return;
    const gen = ++state.pollGen;
    state.pollRunning = true;

    const initAc = new AbortController();
    state.pollAbort = initAc;
    try {
      await refreshState(initAc.signal, gen);
    } finally {
      if (state.pollAbort === initAc) state.pollAbort = null;
    }

    while (state.pollRunning && state.paneVisible && gen === state.pollGen) {
      const ac = new AbortController();
      state.pollAbort = ac;
      try {
        const res = await apiPostJson('/api/stream', { sinceSeq: state.seq, waitMs: 12000 }, ac.signal);
        if (gen !== state.pollGen) break;
        if (res?.state) {
          applySnapshot(res.state);
        }
      } catch (err) {
        if (ac.signal.aborted || !state.paneVisible || gen !== state.pollGen) break;
        await new Promise((r) => setTimeout(r, 900));
      } finally {
        if (state.pollAbort === ac) state.pollAbort = null;
      }
    }

    if (gen === state.pollGen) {
      state.pollRunning = false;
    }
  }

  // ---------- Event Wiring ----------
  $('btn-refresh').addEventListener('click', () => refreshState());

  $('btn-settings').addEventListener('click', () => {
    const drawer = $('settings-drawer');
    const open = drawer.classList.toggle('hidden');
    $('btn-settings').setAttribute('aria-expanded', String(!open));
  });

  document.querySelectorAll('.preset-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.target;
      const val = btn.dataset.val;
      if (target === 'click1') $('input-click1-timeout').value = val;
      if (target === 'reminder') $('input-reminder-interval').value = val;
    });
  });

  $('btn-save-config').addEventListener('click', () => {
    const rawC1 = $('input-click1-timeout').value.trim();
    const rawRem = $('input-reminder-interval').value.trim();
    if (!/^\d+$/.test(rawC1) || !/^\d+$/.test(rawRem)) {
      $('settings-status').textContent = '';
      showToast('Timeouts must be whole integers between 0 and 86400 (0 = disabled/no timeout)', true);
      return;
    }
    const c1 = Number(rawC1);
    const rem = Number(rawRem);
    if (!Number.isInteger(c1) || c1 < 0 || c1 > 86400 || !Number.isInteger(rem) || rem < 0 || rem > 86400) {
      $('settings-status').textContent = '';
      showToast('Timeouts must be integers between 0 and 86400 (0 = disabled/no timeout)', true);
      return;
    }
    runAction('save-config', '', {
      config: { click1TimeoutSeconds: c1, reminderIntervalSeconds: rem },
    });
  });

  $('btn-dismiss-reminder').addEventListener('click', () => {
    runAction('dismiss-reminder');
  });

  $('btn-open-archives').addEventListener('click', handleOpenArchives);

  $('tab-audit-live').addEventListener('click', () => setAuditTab('live'));
  $('tab-audit-archived').addEventListener('click', () => setAuditTab('archived'));

  $('archive-select').addEventListener('change', (e) => {
    const nextName = String(e?.target?.value ?? $('archive-select').value ?? '');
    auditUiState.selectedArchive = nextName;
    auditUiState.loadedArchiveName = '';
    auditUiState.loadedArchiveEntries = [];
    auditUiState.failedArchiveName = '';
    auditUiState.failedArchiveKey = '';
    auditUiState.loadError = '';
    loadArchiveEntries(nextName);
  });

  $('btn-clear-audit').addEventListener('click', () => {
    if (clearAuditState.inFlight) return;
    if (!clearAuditState.armed) {
      const auditCount = Array.isArray(state.snapshot?.audit) ? state.snapshot.audit.length : 0;
      if (auditCount === 0) return;
      armClearAudit();
      return;
    }
    if (Date.now() - clearAuditState.armedAt < CLEAR_AUDIT_GUARD_MS) {
      return;
    }
    executeClearAudit();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && clearAuditState.armed) {
      disarmClearAudit();
    }
  });

  $('btn-copy-sha').addEventListener('click', async () => {
    const sha = state.snapshot?.activeJob?.manifestSha256;
    if (!sha) return;
    try {
      await navigator.clipboard.writeText(sha);
      showToast('Copied ManifestSha256');
    } catch {
      showToast('Clipboard write unavailable', true);
    }
  });

  $('btn-copy-script').addEventListener('click', async () => {
    const script = state.snapshot?.activeJob?.script;
    if (script === undefined) return;
    try {
      await navigator.clipboard.writeText(script);
      showToast('Copied script');
    } catch {
      showToast('Clipboard write unavailable', true);
    }
  });

  $('btn-toggle-script').addEventListener('click', () => {
    state.scriptCollapsed = !state.scriptCollapsed;
    $('active-script').classList.toggle('hidden', state.scriptCollapsed);
    $('btn-toggle-script').textContent = state.scriptCollapsed ? 'Expand' : 'Collapse';
  });

  $('btn-follow-output').addEventListener('click', () => {
    state.followOutput = !state.followOutput;
    $('btn-follow-output').classList.toggle('active', state.followOutput);
    if (state.followOutput) {
      const vp = $('output-viewport');
      vp.scrollTop = vp.scrollHeight;
    }
  });

  $('output-viewport').addEventListener('scroll', () => {
    const vp = $('output-viewport');
    const atBottom = vp.scrollHeight - vp.scrollTop - vp.clientHeight <= 24;
    if (atBottom !== state.followOutput) {
      state.followOutput = atBottom;
      $('btn-follow-output').classList.toggle('active', atBottom);
    }
  });

  // ---------- Visibility & Lifecycle Management ----------
  function computePaneVisible() {
    if (document.visibilityState === 'hidden') return false;
    const docEl = document.documentElement;
    return docEl.clientWidth > 16 && docEl.clientHeight > 16;
  }

  function updatePaneVisibility() {
    const visible = computePaneVisible();
    if (visible === state.paneVisible) return;
    state.paneVisible = visible;
    if (!visible) {
      disarmClearAudit();
      cancelPoll();
    } else {
      startPollLoop();
    }
  }

  state.paneVisible = computePaneVisible();
  document.addEventListener('visibilitychange', updatePaneVisibility);
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(updatePaneVisibility).observe(document.documentElement);
  }
  window.addEventListener('pagehide', () => {
    disarmClearAudit();
    cancelPoll();
  });
  window.addEventListener('blur', () => {
    disarmClearAudit();
  });

  setInterval(() => updateCountdown(), 200);

  if (state.paneVisible) {
    startPollLoop();
  }
})();
