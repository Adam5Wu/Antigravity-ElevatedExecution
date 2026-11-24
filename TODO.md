# Future Enhancements / TODO (`elevated-exec`)

## 1. High-IL Immutable Execution Audit Log (Optional Future Security Enhancement)

### Goal & Threat Model
- Separate **Medium-IL Side Panel activity history** (`DATA_DIR\audit.jsonl` + `DATA_DIR\archives\`, user-writable, tracking all request outcomes including `DENIED_CLICK1`, `TIMEOUT_CLICK1`, `DENIED_UAC`, `CANCELLED`, `COMPLETED`, and `KILLED`) from an **OS-enforced immutable proof of executed High-IL commands**.
- Ensure non-elevated users and agents can inspect executed command history (`Users:RX`) while preventing any non-elevated process from modifying, forging, or deleting records of commands that actually crossed the UAC boundary without Administrator elevation.

### Proposed High-IL Design
1. **Admin-Hardened Audit Directory (`Install-ElevationRunner.ps1`)**:
   - Provision `C:\ProgramData\AgentElevation\audit\` using `Install-HardenedDirectory` / `New-HardenedDirectorySecurity -IncludeUsersReadExecute $true` (matching `C:\Program Files\AgentElevation` ACL rules):
     - `Owner`: `Administrators` (`S-1-5-32-544`)
     - Inheritance: Disabled (`SetAccessRuleProtection($true, $false)`)
     - Explicit ACEs (`ContainerInherit | ObjectInherit`, `Allow` only): `SYSTEM` (`S-1-5-18`) `FullControl` (`F`), `Administrators` (`S-1-5-32-544`) `FullControl` (`F`), `Users` (`S-1-5-32-545`) `ReadAndExecute` (`RX`).
   - Enforce `Assert-AncestryNoReparsePoint` on `C:\ProgramData\AgentElevation\audit\` and validate raw-SID compliance (`Test-RawSidAclCompliance`).
   - Keep parent `C:\ProgramData\AgentElevation\` and `C:\ProgramData\AgentElevation\tmp\` strictly admin-only (`SYSTEM:F`, `Administrators:F`, inheritance disabled), relying on Windows' default `SeChangeNotifyPrivilege` (bypass traverse checking) for direct `Users:RX` reads inside `C:\ProgramData\AgentElevation\audit\`.

2. **High-IL Runner Logging (`runner\Invoke-ElevatedRunner.ps1`)**:
   - Verify `C:\ProgramData\AgentElevation\audit\` (non-reparse ancestry, `Owner=S-1-5-32-544`/`S-1-5-18`, `AreAccessRulesProtected = $true`, exact raw-SID ACEs) alongside `Test-RunnerTmpDirectory` before writing.
   - Include `requestId` in the frozen manifest JSON (`{ requestId, script, args, workDir, encoding }` in `sidecars\broker\main.mjs` rather than passing an unauthenticated CLI flag or parsing the filename stem) so `ManifestSha256` cryptographically authenticates `requestId` as well.
   - Append one UTF-8 (no-BOM) JSONL record per *actually executed* High-IL invocation to `C:\ProgramData\AgentElevation\audit\exec-audit.jsonl` (rotated by the High-IL runner itself, since Medium-IL cannot rotate or truncate files in `audit\`):
     - `timestamp` (UTC ISO-8601)
     - `requestId` (authenticated via `ManifestSha256`)
     - `manifestSha256` (`$manifest.Sha256`)
     - `workDir` (`$manifest.WorkDir`)
     - `scriptPreview` (truncated UTF-8 head, e.g. `4096` bytes matching `AUDIT_PREVIEW_MAX_BYTES`)
     - `exitCode` (`Int32` from `[AgentElevation.JobProcessRunner]::Run(...)` / `unchecked((int)rawExit)`)

3. **Optional Read-Only Side Panel / CLI Inspection**:
   - Optionally expose a read-only viewer or verification cross-check against `C:\ProgramData\AgentElevation\audit\` without requiring UAC.

### Why NTFS Append-Only ACLs on Medium-IL `DATA_DIR` Are Not Recommended
- The Sidecar Broker's `DATA_DIR` (`%ANTIGRAVITY_EXECUTABLE_DATA_DIR%` or `%USERPROFILE%\.gemini\antigravity\sidecar_data\elevated-exec\broker\data`) is intentionally granted `FullControl` to the current user (`hardenDataDirAclsAsync` in `sidecars\broker\main.mjs`) so the Medium-IL Side Panel stays fast and zero-UAC.
- Both the Side Panel's 2-click **`Archive`** action (`clearAuditHistory()`) and automatic `200`-line / `5 MB` rotation (`appendAuditRecord()`) package `audit.jsonl` into `.zip` archives under `DATA_DIR\archives\` and atomically truncate `DATA_DIR\audit.jsonl` via temp-file + `fs.renameSync` (`writeAtomicUtf8`).
- Enforcing NTFS append-only or `Users:RX` ACLs on `DATA_DIR` (`audit.jsonl` or `archives\`) would cause `EACCES` failures or UAC elevation friction on manual `Archive` and automatic log rotation, while offering weak tamper resistance inside a user-owned profile directory anyway.
- Keeping Medium-IL `DATA_DIR` (`Live` / `Archived` tabs) zero-UAC and isolating any immutable execution audit trail under Admin-hardened `C:\ProgramData\AgentElevation\audit\` cleanly separates Side Panel UX from the OS privilege boundary.
