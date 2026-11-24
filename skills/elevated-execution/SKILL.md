---
name: elevated-execution
description: >-
  Run rare OS-level Windows administrative commands with interactive two-click
  UAC elevation via Invoke-Elevated.ps1 and the elevated-exec Antigravity sidecar
  on WinSta0\Default. Activate only when a task genuinely requires Administrator
  privileges (e.g., drivers, system services, HKLM, firewall, Program Files) or
  when opening the Elevated Execution side panel; never use for routine
  user-space development.
---

# Elevated Execution (`elevated-exec`)

Concise agent manual for running rare Administrator-only commands on Windows via the `elevated-exec` Antigravity sidecar plugin (`WinSta0\Default`) and two-click UAC flow.

For architecture, security internals, Side Panel UI details, programmatic tests, and future work, see [README.md](../../README.md).

---

## 1. Open the Side Panel

To surface a clickable pill in chat that opens or toggles the **Elevated Execution** Auxiliary Side Pane *(only emit when the plugin is enabled and running)*:

```markdown
[Elevated Execution](sidecar://elevated-exec/broker/)
```

---

## 2. Scope & Hard Rules

- **Non-elevated by default**: Routine user-space development (package managers, Git/GitHub, language toolchains, builds) must stay strictly non-elevated.
- **Rare OS-level exceptions only**: Drivers, Windows services, `HKLM`, Windows Firewall, `C:\Program Files\`, and `C:\ProgramData\`.
- **Never run raw `Start-Process -Verb RunAs` in `run_command`**: `run_command` executes on hidden `WinSta0\exebox-*` desktops where UAC renders invisibly and hangs.
- **Never auto-retry on denial (`1223`)**: Stop immediately on `DENIED_CLICK1` or `DENIED_UAC`, report what was denied, and ask the user how to proceed.

---

## 3. How to Invoke

Call the forwarding shim installed by `Register-Plugin.ps1`:

```powershell
& "$HOME\Documents\AgentTooling\Invoke-Elevated.ps1" ...
```

All 4 parameter sets require **`-Reason`** (shown in Click 1, Side Panel, and audit history) and accept optional `-WorkDir <path>`, `-Encoding <auto|utf8|oem|utf16>` (default `auto`), and `-NormalWindow`. Use **`-ArgumentList`** (not `-Args`); there is no `-NoWait`.

| Mode | Required Flag | Notes |
| :--- | :--- | :--- |
| `ScriptBlock` *(default)* | `-ScriptBlock { ... }` | Sends literal source text — **no** outer variable or `$using:` capture. |
| `ScriptText` | `-ScriptText "..."` | Explicit inline script string. |
| `ScriptFile` | `-ScriptFile <path.ps1>` | Must be **self-contained** (no relative `$PSScriptRoot` dot-sourcing). Accepts `-ArgumentList`. UTF-8 BOM or BOM-less UTF-8 (`-Encoding oem` for CP936). |
| `FilePath` | `-FilePath <target>` | Convenience wrapper for `.exe`, `.com`, `.msc`, `.cpl`, `.msi` only (`.ps1` → use `-ScriptFile`; `.bat`/`.cmd`/`.lnk`/UNC/device/URI rejected `1206`). Accepts `-ArgumentList`. Unqualified names resolve strictly from `System32` / `HKLM PATH`. |

```powershell
# Inline commands (always propagate native exit code)
& "$HOME\Documents\AgentTooling\Invoke-Elevated.ps1" `
    -ScriptBlock { sc.exe query Appinfo; exit $LASTEXITCODE } `
    -Reason "Inspect Appinfo service status"

# Direct executable (or self-contained -ScriptFile) with arguments
& "$HOME\Documents\AgentTooling\Invoke-Elevated.ps1" `
    -FilePath "whoami.exe" -ArgumentList @("/groups") `
    -Reason "Verify High-IL token groups"
```

---

## 4. `run_command` & PowerShell 5.1 Rules

- **Reactive wakeup (`WaitMsBeforeAsync = 5000`)**: Briefly pre-announce the request in chat, then run `Invoke-Elevated.ps1` with `WaitMsBeforeAsync = 5000` (never `IsDaemon = true`).
  - Pre-flight errors (`1202`, `1203`, `1204`, `1206`) fail synchronously in `< 4 s`.
  - Valid requests print `ELEVATION_PENDING: <requestId>` and background at `5 s`. Tell the user Click 1 + UAC awaits on their desktop or in [Elevated Execution](sidecar://elevated-exec/broker/) and **end your turn without polling** — Antigravity wakes you reactively on completion, denial, or timeout.
- **Exit codes**: Always end elevated scripts calling native EXEs with `exit $LASTEXITCODE`.
- **`CONOUT$` prompts**: `Read-Host`, `Read-Host -AsSecureString`, and `-Confirm` bypass stdout/stderr; instruct the user to restore the minimized taskbar PowerShell window to reply.
- **Native UTF-8 output**: Never capture UTF-8 native EXE output into a PS 5.1 variable (`$x = netsh.exe ...` decodes as CP936); let it stream directly to stdout.
- **Disconnect behavior**: Cancelling while `QUEUED` / `AWAITING_CLICK1` / `AWAITING_UAC` aborts pre-execution (`1201`). Cancelling while `RUNNING` detaches safely so OS changes finish cleanly; use Side Panel **`Kill Process Tree`** to terminate (`1207`).

---

## 5. Exit Codes & Quick Troubleshooting

Every run ends with `[elevated-exec] OUTCOME=<OUTCOME> EXIT=<int32>`:

| Exit | Outcome | Meaning / Action |
| :--- | :--- | :--- |
| `0` *(or child)* | `COMPLETED` | Finished; `EXIT` is the child's exact `Int32` exit code. |
| `1201` | `CANCELLED` | Cancelled before execution. |
| `1202` | `SESSION_NOT_INTERACTIVE` | Desktop locked (`Win+L`), disconnected, or Secure Desktop active — ask user to unlock `WinSta0\Default`. |
| `1203` | `SIDECAR_UNAVAILABLE` | Sidecar stopped or `runtime.json` stale — confirm plugin is enabled or run `Register-Plugin.ps1` (non-elevated). |
| `1204` | `RUNNER_INVALID` / `RUNNER_PRECONNECT_EXIT` | Runner ACL/integrity check failed or pre-connect exit — inspect admin-only `C:\ProgramData\AgentElevation\tmp\last-error.log` or re-run `Install-ElevationRunner.ps1` as Administrator. |
| `1205` | `SHA256_MISMATCH` | Frozen manifest SHA-256 verification failed in runner. |
| `1206` | `INVALID_ARGS` | Bad parameter, disallowed `-FilePath` type/UNC/device/URI path, or invalid UTF-8 script. |
| `1207` | `KILLED` | Terminated via Side Panel **`Kill Process Tree`**. |
| `1223` | `DENIED_CLICK1` / `DENIED_UAC` | User denied Click 1 or UAC — **do not retry automatically**. |
| `1460` | `TIMEOUT_CLICK1` | Click-1 countdown expired before approval. |
