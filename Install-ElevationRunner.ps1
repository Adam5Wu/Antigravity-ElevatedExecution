#Requires -Version 5.1
<#
.SYNOPSIS
    One-time elevated bootstrap for the High-IL Antigravity elevation runner.
.DESCRIPTION
    Creates and hardens C:\Program Files\AgentElevation\ and
    C:\ProgramData\AgentElevation\tmp\ with raw-SID ACLs and disabled inheritance,
    deploys and unblocks runner\Invoke-ElevatedRunner.ps1, optionally reaps an
    orphaned consent.exe PID when -StaleConsentPid is specified, and performs
    raw-SID self-verification.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$StaleConsentPid = 0
)

Set-StrictMode -Version Latest

$script:ProgramFilesDir   = 'C:\Program Files\AgentElevation'
$script:RunnerDestPath    = 'C:\Program Files\AgentElevation\Invoke-ElevatedRunner.ps1'
$script:ProgramDataDir    = 'C:\ProgramData\AgentElevation'
$script:ProgramDataTmpDir = 'C:\ProgramData\AgentElevation\tmp'
$script:StaleConsentPid   = $StaleConsentPid

$script:SidSystem       = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$script:SidAdmins       = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$script:SidUsers        = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$script:SidTrustedInst  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')

function Test-IsAdministrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PathNoReparsePoint {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not ([System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path))) {
        return $false
    }
    $attrs = [System.IO.File]::GetAttributes($Path)
    return (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -eq 0)
}

function Assert-AncestryNoReparsePoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$CheckChildren
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }
    if ($Path -notmatch '^[A-Za-z]:\\' -or -not [System.IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) {
        throw "Path '$Path' must be a rooted local path."
    }

    $rawParts = $Path.Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($rawParts -contains '..') {
        throw "Path '$Path' must not contain '..' traversal segments."
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($fullPath)

    if ($fullPath.Length -le $root.Length) {
        $segments = @($root)
    } else {
        $rel = $fullPath.Substring($root.Length)
        $parts = @($rel.Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries))
        $segments = New-Object System.Collections.Generic.List[string]
        $segments.Add($root)
        $acc = $root.TrimEnd('\')
        foreach ($p in $parts) {
            $acc = "$acc\$p"
            $segments.Add($acc)
        }
    }

    for ($i = 0; $i -lt $segments.Count; $i++) {
        $seg = $segments[$i]
        $existsDir = [System.IO.Directory]::Exists($seg)
        $existsFile = [System.IO.File]::Exists($seg)
        if (-not $existsDir -and -not $existsFile) {
            continue
        }

        $attrs = [System.IO.File]::GetAttributes($seg)
        if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "ReparsePoint detected at path segment '$seg'."
        }

        if ($i -lt ($segments.Count - 1) -and -not $existsDir) {
            throw "Intermediate path segment '$seg' is not a directory."
        }
    }

    if ($CheckChildren -and [System.IO.Directory]::Exists($fullPath)) {
        $di = New-Object System.IO.DirectoryInfo($fullPath)
        foreach ($child in $di.GetFileSystemInfos()) {
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "ReparsePoint detected on child item '$($child.FullName)'."
            }
        }
    }
}

function New-HardenedDirectorySecurity {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.DirectorySecurity])]
    param(
        [bool]$IncludeUsersReadExecute = $false
    )

    $ds = New-Object System.Security.AccessControl.DirectorySecurity
    $ds.SetOwner($script:SidAdmins)
    $ds.SetAccessRuleProtection($true, $false)

    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $prop = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $ruleSys = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $script:SidSystem,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $prop,
        $allow
    )
    $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $script:SidAdmins,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $prop,
        $allow
    )

    $ds.AddAccessRule($ruleSys)
    $ds.AddAccessRule($ruleAdmins)

    if ($IncludeUsersReadExecute) {
        $ruleUsers = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $script:SidUsers,
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $inherit,
            $prop,
            $allow
        )
        $ds.AddAccessRule($ruleUsers)
    }

    return $ds
}

function Install-HardenedDirectory {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [bool]$IncludeUsersReadExecute = $false
    )

    Assert-AncestryNoReparsePoint -Path $Path -CheckChildren
    if ([System.IO.File]::Exists($Path)) {
        throw "Target directory path '$Path' exists as a regular file."
    }

    $desc = if ($IncludeUsersReadExecute) {
        'Create/harden directory (Owner=Administrators, inheritance disabled, SYSTEM:F, Administrators:F, Users:RX)'
    } else {
        'Create/harden admin-only directory (Owner=Administrators, inheritance disabled, SYSTEM:F, Administrators:F ONLY)'
    }

    if ($PSCmdlet.ShouldProcess($Path, $desc)) {
        $ds = New-HardenedDirectorySecurity -IncludeUsersReadExecute:$IncludeUsersReadExecute
        if (-not (Test-Path -LiteralPath $Path)) {
            [System.IO.Directory]::CreateDirectory($Path, $ds) | Out-Null
            Assert-AncestryNoReparsePoint -Path $Path -CheckChildren
        } else {
            Assert-AncestryNoReparsePoint -Path $Path -CheckChildren
            [System.IO.Directory]::SetAccessControl($Path, $ds)
        }
    }
}

function Test-RunnerSourceFile {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath
    )

    Assert-AncestryNoReparsePoint -Path $SourcePath
    if (-not [System.IO.File]::Exists($SourcePath)) {
        throw "Source runner script not found: '$SourcePath'."
    }

    $fs = [System.IO.File]::Open($SourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($fs.Length -lt 3) {
            throw "Source runner '$SourcePath' is too small to contain a UTF-8 BOM."
        }
        $bom = New-Object byte[] 3
        $read = $fs.Read($bom, 0, 3)
        if ($read -ne 3 -or $bom[0] -ne 0xEF -or $bom[1] -ne 0xBB -or $bom[2] -ne 0xBF) {
            throw "Source runner '$SourcePath' must have a UTF-8 BOM (EF BB BF)."
        }
    } finally {
        $fs.Dispose()
    }

    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -gt 0) {
        $first = $parseErrors[0]
        throw "Source runner '$SourcePath' failed PS 5.1 syntax parse at line $($first.Extent.StartLineNumber): $($first.Message)"
    }

    return $true
}

function Deploy-RunnerArtifact {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$DestPath
    )

    Test-RunnerSourceFile -SourcePath $SourcePath | Out-Null
    Assert-AncestryNoReparsePoint -Path $DestPath

    if ($PSCmdlet.ShouldProcess($DestPath, "Deploy, unblock, and harden runner from '$SourcePath'")) {
        Copy-Item -LiteralPath $SourcePath -Destination $DestPath -Force
        Assert-AncestryNoReparsePoint -Path $DestPath
        Unblock-File -LiteralPath $DestPath

        $fs = [System.IO.File]::GetAccessControl(
            $DestPath,
            [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Access
        )
        $fs.SetOwner($script:SidAdmins)
        $fs.SetAccessRuleProtection($false, $false)
        $existingRules = @($fs.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
        foreach ($r in $existingRules) {
            [void]$fs.RemoveAccessRuleSpecific($r)
        }
        [System.IO.File]::SetAccessControl($DestPath, $fs)
    }
}

function Test-ObjectSecurityCompliance {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.ObjectSecurity]$SecurityDescriptor,

        [Parameter(Mandatory = $true)]
        [ValidateSet('ProgramFilesDir', 'ProgramFilesFile', 'ProgramDataAdminOnly')]
        [string]$Mode,

        [string]$TargetLabel = '<ObjectSecurity>',

        [string[]]$AllowedOwnerSids = @('S-1-5-32-544')
    )

    $ownerSid = $SecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($AllowedOwnerSids -notcontains $ownerSid) {
        throw "ACL owner mismatch on '$TargetLabel': expected [$($AllowedOwnerSids -join ', ')], actual '$ownerSid'."
    }

    if ($Mode -eq 'ProgramFilesDir' -or $Mode -eq 'ProgramDataAdminOnly') {
        if (-not $SecurityDescriptor.AreAccessRulesProtected) {
            throw "ACL inheritance is NOT disabled on '$TargetLabel' (AreAccessRulesProtected=False)."
        }
    }

    $rules = @($SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -eq 0) {
        throw "No access rules present on '$TargetLabel'."
    }

    $isDirMode = ($Mode -eq 'ProgramFilesDir' -or $Mode -eq 'ProgramDataAdminOnly')
    $requiredInherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit

    $hasSystemFull = $false
    $hasAdminsFull = $false
    $hasUsersRx = $false

    $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $rxRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $allowedRxMask = $rxRights -bor [System.Security.AccessControl.FileSystemRights]::Synchronize

    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            throw "Prohibited non-Allow ACE ($($rule.AccessControlType)) found on '$TargetLabel' for SID '$($rule.IdentityReference.Value)'."
        }

        $sid = $rule.IdentityReference.Value
        $rights = $rule.FileSystemRights
        $isEffectiveOnSelf = (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0)
        $hasValidInheritance = $true
        if ($isDirMode) {
            $hasValidInheritance = (
                (($rule.InheritanceFlags -band $requiredInherit) -eq $requiredInherit) -and
                (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) -eq 0)
            )
        }

        if ($Mode -eq 'ProgramDataAdminOnly') {
            if ($sid -ne 'S-1-5-18' -and $sid -ne 'S-1-5-32-544') {
                throw "Prohibited SID '$sid' found in admin-only ACL on '$TargetLabel'."
            }
        } else {
            if ($sid -ne 'S-1-5-18' -and $sid -ne 'S-1-5-32-544' -and $sid -ne 'S-1-5-32-545') {
                throw "Unexpected SID '$sid' found in Program Files ACL on '$TargetLabel'."
            }
        }

        if ($sid -eq 'S-1-5-18' -and $isEffectiveOnSelf -and $hasValidInheritance -and (($rights -band $fullControl) -eq $fullControl)) {
            $hasSystemFull = $true
        } elseif ($sid -eq 'S-1-5-32-544' -and $isEffectiveOnSelf -and $hasValidInheritance -and (($rights -band $fullControl) -eq $fullControl)) {
            $hasAdminsFull = $true
        } elseif ($sid -eq 'S-1-5-32-545') {
            $extraBits = ([int]$rights) -band (-bnot [int]$allowedRxMask)
            if ($extraBits -ne 0) {
                throw "Prohibited extra rights (0x$($extraBits.ToString('X'))) granted to Users (S-1-5-32-545) on '$TargetLabel'."
            }
            if ($isEffectiveOnSelf -and $hasValidInheritance -and (($rights -band $rxRights) -eq $rxRights)) {
                $hasUsersRx = $true
            }
        }
    }

    if (-not $hasSystemFull) {
        throw "Missing SYSTEM (S-1-5-18) FullControl ACE on '$TargetLabel'."
    }
    if (-not $hasAdminsFull) {
        throw "Missing Administrators (S-1-5-32-544) FullControl ACE on '$TargetLabel'."
    }
    if ($Mode -ne 'ProgramDataAdminOnly' -and -not $hasUsersRx) {
        throw "Missing Users (S-1-5-32-545) ReadAndExecute ACE on '$TargetLabel'."
    }

    return $true
}

function Test-RawSidAclCompliance {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('ProgramFilesDir', 'ProgramFilesFile', 'ProgramDataAdminOnly')]
        [string]$Mode,

        [string[]]$AllowedOwnerSids = @('S-1-5-32-544')
    )

    if ($Mode -eq 'ProgramFilesFile') {
        Assert-AncestryNoReparsePoint -Path $Path
        if (-not [System.IO.File]::Exists($Path)) {
            throw "Target file does not exist: '$Path'."
        }
        $zoneStream = Get-Item -LiteralPath $Path -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
        if ($null -ne $zoneStream) {
            throw "Zone.Identifier alternate data stream still present on '$Path'."
        }
        $sd = [System.IO.File]::GetAccessControl(
            $Path,
            [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Access
        )
    } else {
        Assert-AncestryNoReparsePoint -Path $Path -CheckChildren
        if (-not [System.IO.Directory]::Exists($Path)) {
            throw "Target directory does not exist: '$Path'."
        }
        $sd = [System.IO.Directory]::GetAccessControl(
            $Path,
            [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Access
        )
    }

    return (Test-ObjectSecurityCompliance -SecurityDescriptor $sd -Mode $Mode -TargetLabel $Path -AllowedOwnerSids $AllowedOwnerSids)
}

function Invoke-StaleConsentCleanup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [int]$TargetPid = $script:StaleConsentPid
    )

    if ($TargetPid -le 0) {
        return
    }

    $proc = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
    if ($null -eq $proc) {
        Write-Host "Orphaned consent.exe check: PID $TargetPid is not running."
        return
    }

    if ($proc.ProcessName -ine 'consent') {
        Write-Warning "PID $TargetPid is process '$($proc.ProcessName)', not 'consent'; skipping termination."
        return
    }

    if ($PSCmdlet.ShouldProcess("PID $TargetPid (consent.exe)", 'Terminate orphaned consent.exe process')) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $taskkillExe = Join-Path $env:SystemRoot 'System32\taskkill.exe'
            $output = & $taskkillExe /F /PID $TargetPid 2>&1
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevEap
        }

        if ($exitCode -eq 0) {
            Write-Host "Terminated orphaned consent.exe PID $TargetPid." -ForegroundColor Green
        } else {
            $msg = (@($output) -join ' ').Trim()
            Write-Warning "Unable to terminate orphaned consent.exe PID $TargetPid (exit $exitCode`: $msg). Windows PPL/runtime protection may block termination even as Administrator; sign out or reboot Windows to clear PID $TargetPid and its leaked exebox-* desktop."
        }
    }
}

function Invoke-InstallElevationRunnerMain {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Set-StrictMode -Version Latest

    if (-not (Test-IsAdministrator)) {
        if ($WhatIfPreference) {
            Write-Warning 'Not running as Administrator; continuing -WhatIf dry-run without modifying host paths.'
        } else {
            throw 'Install-ElevationRunner.ps1 must be run from an Administrator PowerShell window.'
        }
    }

    $sourceRunner = Join-Path $PSScriptRoot 'runner\Invoke-ElevatedRunner.ps1'

    Install-HardenedDirectory -Path $script:ProgramFilesDir -IncludeUsersReadExecute $true
    Deploy-RunnerArtifact -SourcePath $sourceRunner -DestPath $script:RunnerDestPath
    Install-HardenedDirectory -Path $script:ProgramDataDir -IncludeUsersReadExecute $false
    Install-HardenedDirectory -Path $script:ProgramDataTmpDir -IncludeUsersReadExecute $false
    Invoke-StaleConsentCleanup -TargetPid $script:StaleConsentPid

    if (-not $WhatIfPreference) {
        Test-RawSidAclCompliance -Path $script:ProgramFilesDir -Mode 'ProgramFilesDir' | Out-Null
        Test-RawSidAclCompliance -Path $script:RunnerDestPath -Mode 'ProgramFilesFile' | Out-Null
        Test-RawSidAclCompliance -Path $script:ProgramDataDir -Mode 'ProgramDataAdminOnly' | Out-Null
        Test-RawSidAclCompliance -Path $script:ProgramDataTmpDir -Mode 'ProgramDataAdminOnly' | Out-Null

        Write-Host ''
        Write-Host '=== AgentElevation Host Bootstrap Verification ===' -ForegroundColor Green
        Write-Host "  [OK] $($script:ProgramFilesDir) (Owner=S-1-5-32-544, Protected=True, SYSTEM:F, Admins:F, Users:RX)"
        Write-Host "  [OK] $($script:RunnerDestPath) (Owner=S-1-5-32-544, Unblocked, Non-Reparse)"
        Write-Host "  [OK] $($script:ProgramDataDir) (Owner=S-1-5-32-544, Protected=True, SYSTEM:F, Admins:F ONLY)"
        Write-Host "  [OK] $($script:ProgramDataTmpDir) (Owner=S-1-5-32-544, Protected=True, SYSTEM:F, Admins:F ONLY)"
    } else {
        Write-Host 'Dry-run (-WhatIf) completed. No host files or ACLs were modified.'
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    Invoke-InstallElevationRunnerMain
}
