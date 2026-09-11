# Native Windows AccessCheck oracle for the bounded V1–V43 catalog.
# Emits windows-host-observed JSON. Does not copy microsoft-docs outcomes.
#
# Run elevated on an NTFS volume (GitHub windows-latest is fine):
#   pwsh -File scripts/windows-host-oracle.ps1 `
#     -CatalogPath winfs/oracle/catalog.json `
#     -OutputPath artifacts/windows_host_observed.json
#
# Requires permission to create local users/groups and call advapi32 AccessCheck.
# Does not implement SACLs, conditional ACEs, or privileges.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CatalogPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

$NativeSource = @"
using System;
using System.Runtime.InteropServices;

public static class WinfsNativeAccessCheck {
    public const uint OWNER_SECURITY_INFORMATION = 0x00000001;
    public const uint GROUP_SECURITY_INFORMATION = 0x00000002;
    public const uint DACL_SECURITY_INFORMATION  = 0x00000004;
    public const uint SD_INFO = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    public const int LOGON32_LOGON_NETWORK = 3;
    public const int LOGON32_PROVIDER_DEFAULT = 0;
    public const int SecurityImpersonation = 2;
    public const int TokenImpersonation = 2;

    [StructLayout(LayoutKind.Sequential)]
    public struct GENERIC_MAPPING {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool GetFileSecurity(string file, uint info, byte[] sd, uint len, out uint needed);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr sa, int impersonation, int type, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AccessCheck(
        byte[] sd,
        IntPtr token,
        uint desired,
        ref GENERIC_MAPPING mapping,
        IntPtr privs,
        ref uint privLen,
        out uint granted,
        out bool status);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    public static GENERIC_MAPPING FileMapping() {
        GENERIC_MAPPING m = new GENERIC_MAPPING();
        m.GenericRead = 0x00120089;
        m.GenericWrite = 0x00120116;
        m.GenericExecute = 0x001200A0;
        m.GenericAll = 0x001F01FF;
        return m;
    }

    public static byte[] ReadSecurityDescriptor(string path) {
        uint needed;
        GetFileSecurity(path, SD_INFO, null, 0, out needed);
        byte[] sd = new byte[needed];
        if (!GetFileSecurity(path, SD_INFO, sd, needed, out needed)) {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "GetFileSecurity failed");
        }
        return sd;
    }

    public static bool Check(string path, string user, string domain, string password, uint desired) {
        IntPtr logon = IntPtr.Zero;
        IntPtr impersonation = IntPtr.Zero;
        try {
            if (!LogonUser(user, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out logon)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "LogonUser failed for " + user);
            }
            if (!DuplicateTokenEx(logon, 0xF01FF, IntPtr.Zero, SecurityImpersonation, TokenImpersonation, out impersonation)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed");
            }
            byte[] sd = ReadSecurityDescriptor(path);
            GENERIC_MAPPING mapping = FileMapping();
            uint privLen = 1024;
            IntPtr privs = Marshal.AllocHGlobal((int)privLen);
            try {
                uint granted;
                bool allowed;
                if (!AccessCheck(sd, impersonation, desired, ref mapping, privs, ref privLen, out granted, out allowed)) {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "AccessCheck failed");
                }
                return allowed;
            } finally {
                Marshal.FreeHGlobal(privs);
            }
        } finally {
            if (impersonation != IntPtr.Zero) CloseHandle(impersonation);
            if (logon != IntPtr.Zero) CloseHandle(logon);
        }
    }
}
"@

Add-Type -TypeDefinition $NativeSource -Language CSharp

function Get-AccountSid([string]$Name) {
    return (New-Object System.Security.Principal.NTAccount($Name)).Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
}

function Set-WinfsSddl([string]$Path, [string]$Sddl) {
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $sec = New-Object System.Security.AccessControl.DirectorySecurity
        $sec.SetSecurityDescriptorSddlForm($Sddl)
        [System.IO.Directory]::SetAccessControl($Path, $sec)
    } else {
        $sec = New-Object System.Security.AccessControl.FileSecurity
        $sec.SetSecurityDescriptorSddlForm($Sddl)
        [System.IO.File]::SetAccessControl($Path, $sec)
    }
}

function Protect-WinfsAcl([string]$Path, [bool]$Preserve) {
    $item = Get-Item -LiteralPath $Path
    $acl = $item.GetAccessControl()
    $acl.SetAccessRuleProtection($true, $Preserve)
    $item.SetAccessControl($acl)
}

function New-WinfsDir([string]$Path) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function New-WinfsFile([string]$Path) {
    New-Item -ItemType File -Force -Path $Path | Out-Null
}

$catalog = Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json
if ($catalog.provenance -ne "microsoft-docs") {
    throw "Catalog provenance must remain microsoft-docs; refusing to run."
}

$passwordText = "Winfs!Oracle-" + [guid]::NewGuid().ToString("N").Substring(0, 10)
$secure = ConvertTo-SecureString $passwordText -AsPlainText -Force
$domain = $env:COMPUTERNAME
$users = @{
    alice = "winfs-alice"
    bob   = "winfs-bob"
    carol = "winfs-carol"
    admin = "winfs-admin"
}
$groupName = "winfs-eng"
$createdUsers = @()
$createdGroup = $false
$root = Join-Path $env:TEMP ("winfs-oracle-" + [guid]::NewGuid().ToString("N"))

try {
    foreach ($name in $users.Values) {
        if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name $name
        }
        New-LocalUser -Name $name -Password $secure -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires | Out-Null
        $createdUsers += $name
    }
    if (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue) {
        Remove-LocalGroup -Name $groupName
    }
    New-LocalGroup -Name $groupName -Description "django-trusts-windows-acl oracle" | Out-Null
    $createdGroup = $true
    Add-LocalGroupMember -Group $groupName -Member $users.alice, $users.bob

    $sid = @{
        alice        = Get-AccountSid $users.alice
        bob          = Get-AccountSid $users.bob
        carol        = Get-AccountSid $users.carol
        admin        = Get-AccountSid $users.admin
        eng          = Get-AccountSid $groupName
        ownerRights  = "S-1-3-4"
    }

    New-WinfsDir $root
    icacls $root /inheritance:r | Out-Null
    Set-WinfsSddl $root ("O:{0}D:P(A;OICI;FA;;;{0})" -f (Get-AccountSid $env:USERNAME))

    $R = [uint32]0x1
    $W = [uint32]0x2
    $WD = [uint32]0x40000

    function New-CaseRoot([string]$Id) {
        $path = Join-Path $root $Id
        New-WinfsDir $path
        Set-WinfsSddl $path ("O:{0}D:P(A;OICI;FA;;;{0})" -f (Get-AccountSid $env:USERNAME))
        return $path
    }

    function New-NotesFile([string]$CaseRoot, [string]$OwnerSid) {
        $notes = Join-Path $CaseRoot "notes.txt"
        New-WinfsFile $notes
        return $notes
    }

    function New-TreePaths([string]$CaseRoot) {
        $proj = Join-Path $CaseRoot "proj"
        $secret = Join-Path $proj "secret"
        $notes = Join-Path $secret "notes.txt"
        $readme = Join-Path $proj "readme.txt"
        return @{
            proj   = $proj
            secret = $secret
            notes  = $notes
            readme = $readme
        }
    }

    function New-EmptyProj([string]$CaseRoot) {
        $tree = New-TreePaths $CaseRoot
        New-WinfsDir $tree.proj
        return $tree
    }

    $observed = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[object]

    function Add-Observed($Id, $Allowed, $Desired, $Path, $Notes) {
        $observed.Add([pscustomobject]@{
            id              = $Id
            provenance      = "windows-host-observed"
            status          = "observed"
            allowed         = [bool]$Allowed
            desired_access  = [int]$Desired
            path            = $Path
            notes           = $Notes
        }) | Out-Null
    }

    function Add-Skipped($Id, $Reason) {
        $skipped.Add([pscustomobject]@{
            id     = $Id
            status = "skipped"
            reason = $Reason
        }) | Out-Null
    }

    function Invoke-Check([string]$UserKey, [string]$Path, [uint32]$Desired) {
        return [WinfsNativeAccessCheck]::Check($Path, $users[$UserKey], $domain, $passwordText, $Desired)
    }

    foreach ($vector in $catalog.vectors) {
        $id = $vector.id
        $hostOracle = $vector.host_oracle
        if (-not $hostOracle.representable) {
            Add-Skipped $id "catalog host_oracle.representable=false"
            continue
        }
        try {
            $case = New-CaseRoot $id
            switch ($id) {
                "V1" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes $R) $R $notes "empty DACL"
                }
                "V3" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(A;;0x1;;;{0})" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes $R) $R $notes "explicit allow"
                }
                "V4" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(D;;0x1;;;{0})(A;;0x1;;;{0})" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes $R) $R $notes "deny then allow"
                }
                "V5" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(A;;0x1;;;{0})(D;;0x1;;;{0})" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes $R) $R $notes "allow then deny"
                }
                "V6" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(D;;0x1;;;{0})(A;;0x1;;;{1})" -f $sid.alice, $sid.eng)
                    Add-Observed $id (Invoke-Check "alice" $notes $R) $R $notes "user deny before group allow"
                }
                "V7" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(D;;0x1;;;{0})(A;;0x1;;;{1})" -f $sid.alice, $sid.eng)
                    Add-Observed $id (Invoke-Check "bob" $notes $R) $R $notes "group allow for other member"
                }
                "V8" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(D;;0x1;;;{0})(A;;0x1;;;{1})" -f $sid.alice, $sid.eng)
                    Add-Observed $id (Invoke-Check "carol" $notes $R) $R $notes "non-member"
                }
                "V9" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(A;;0x1;;;{0})" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes ($R -bor $W)) ($R -bor $W) $notes "partial bits"
                }
                "V10" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(A;;0x1;;;{0})(A;;0x2;;;{0})" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes ($R -bor $W)) ($R -bor $W) $notes "accumulate"
                }
                "V11" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(A;;0x3;;;{0})(D;;0x2;;;{0})" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes $W) $W $notes "allow then deny write"
                }
                "V12" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(A;;0x3;;;{0})(D;;0x2;;;{0})" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes ($R -bor $W)) ($R -bor $W) $notes "allow then deny combined"
                }
                "V13" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(A;;0x1;;;{0})(D;;0x2;;;{0})" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes ($R -bor $W)) ($R -bor $W) $notes "remaining write denied"
                }
                "V14" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes $WD) $WD $notes "owner WRITE_DAC"
                }
                "V15" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes $R) $R $notes "owner is not FILE_READ_DATA"
                }
                "V16" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(D;;0x40000;;;{0})" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $notes $WD) $WD $notes "owner pre-grant vs deny WD"
                }
                "V17" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsFile $tree.readme
                    Add-Observed $id (Invoke-Check "alice" $tree.readme $R) $R $tree.readme "OI file inherit"
                }
                "V18" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    Add-Observed $id (Invoke-Check "alice" $tree.proj $R) $R $tree.proj "CI effective"
                }
                "V19" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;CI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsFile $tree.readme
                    Add-Observed $id (Invoke-Check "alice" $tree.readme $R) $R $tree.readme "CI only"
                }
                "V20" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    Add-Observed $id (Invoke-Check "alice" $tree.proj $R) $R $tree.proj "OI effective on container"
                }
                "V21" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsFile $tree.readme
                    Add-Observed $id (Invoke-Check "alice" $tree.readme $R) $R $tree.readme "OI file"
                }
                "V22" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsDir $tree.secret
                    Add-Observed $id (Invoke-Check "alice" $tree.secret $R) $R $tree.secret "OI child container"
                }
                "V23" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsDir $tree.secret
                    New-WinfsFile $tree.notes
                    Add-Observed $id (Invoke-Check "alice" $tree.notes $R) $R $tree.notes "OI grandchild file"
                }
                "V24" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICINP;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsDir $tree.secret
                    Add-Observed $id (Invoke-Check "alice" $tree.secret $R) $R $tree.secret "NP immediate"
                }
                "V25" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICINP;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsDir $tree.secret
                    New-WinfsFile $tree.notes
                    Add-Observed $id (Invoke-Check "alice" $tree.notes $R) $R $tree.notes "NP grandchild"
                }
                "V26" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsDir $tree.secret
                    Protect-WinfsAcl $tree.secret $false
                    Add-Observed $id (Invoke-Check "alice" $tree.secret $R) $R $tree.secret "protected empty"
                }
                "V27" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsDir $tree.secret
                    Protect-WinfsAcl $tree.secret $false
                    New-WinfsFile $tree.notes
                    Add-Observed $id (Invoke-Check "alice" $tree.notes $R) $R $tree.notes "protect stops walk"
                }
                "V28" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsDir $tree.secret
                    Protect-WinfsAcl $tree.secret $true
                    Add-Observed $id (Invoke-Check "alice" $tree.secret $R) $R $tree.secret "preserve inherited"
                }
                "V29" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsDir $tree.secret
                    Protect-WinfsAcl $tree.secret $true
                    New-WinfsFile $tree.notes
                    Add-Observed $id (Invoke-Check "alice" $tree.notes $R) $R $tree.notes "preserve children"
                }
                "V30" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICIO;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    Add-Observed $id (Invoke-Check "alice" $tree.proj $R) $R $tree.proj "inherit-only on container"
                }
                "V31" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICIO;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    New-WinfsFile $tree.readme
                    Add-Observed $id (Invoke-Check "alice" $tree.readme $R) $R $tree.readme "IO still inheritable"
                }
                "V32" {
                    $tree = New-EmptyProj $case
                    New-WinfsDir $tree.secret
                    New-WinfsFile $tree.notes
                    Set-WinfsSddl $tree.notes ("O:{0}D:P(A;;0x1;;;{0})" -f $sid.alice)
                    Set-WinfsSddl $tree.secret ("O:{0}D:P" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $tree.secret $R) $R $tree.secret "child read is not parent list"
                }
                "V33" {
                    $tree = New-EmptyProj $case
                    New-WinfsFile $tree.readme
                    Set-WinfsSddl $tree.proj ("O:{0}D:P(A;;0x1;;;{1})" -f $sid.admin, $sid.bob)
                    Set-WinfsSddl $tree.readme ("O:{0}D:P(D;;0x1;;;{1})" -f $sid.admin, $sid.bob)
                    Add-Observed $id (Invoke-Check "bob" $tree.proj $R) $R $tree.proj "folder list"
                }
                "V34" {
                    $tree = New-EmptyProj $case
                    New-WinfsFile $tree.readme
                    Set-WinfsSddl $tree.proj ("O:{0}D:P(A;;0x1;;;{1})" -f $sid.admin, $sid.bob)
                    Set-WinfsSddl $tree.readme ("O:{0}D:P(D;;0x1;;;{1})" -f $sid.admin, $sid.bob)
                    Add-Observed $id (Invoke-Check "bob" $tree.readme $R) $R $tree.readme "name visibility is not read"
                }
                "V35" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(A;;0x1;;;{1})(D;;0x1;;;{0})" -f $sid.alice, $sid.eng)
                    Add-Observed $id (Invoke-Check "alice" $notes $R) $R $notes "group allow before user deny"
                }
                "V39" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICI;0x1;;;{1})" -f $sid.admin, $sid.eng)
                    $newFile = Join-Path $tree.proj "new.txt"
                    New-WinfsFile $newFile
                    Add-Observed $id (Invoke-Check "alice" $newFile $R) $R $newFile "new child inherits"
                }
                "V40" {
                    $notes = New-NotesFile $case $sid.alice
                    Set-WinfsSddl $notes ("O:{0}D:P(A;;0x40000;;;{1})" -f $sid.alice, $sid.ownerRights)
                    Add-Observed $id (Invoke-Check "alice" $notes $WD) $WD $notes "OWNER_RIGHTS explicit; expected-divergence vs evaluator reject"
                }
                "V41" {
                    $notes = New-NotesFile $case $sid.eng
                    Set-WinfsSddl $notes ("O:{0}D:P" -f $sid.eng)
                    Add-Observed $id (Invoke-Check "alice" $notes $WD) $WD $notes "group owner"
                }
                "V42" {
                    $notes = New-NotesFile $case $sid.eng
                    Set-WinfsSddl $notes ("O:{0}D:P" -f $sid.eng)
                    Add-Observed $id (Invoke-Check "carol" $notes $WD) $WD $notes "non-member group owner"
                }
                "V43" {
                    $tree = New-EmptyProj $case
                    Set-WinfsSddl $tree.proj ("O:{0}D:(A;OICI;0x40000;;;{1})" -f $sid.admin, $sid.ownerRights)
                    New-WinfsDir $tree.secret
                    New-WinfsFile $tree.notes
                    Set-WinfsSddl $tree.notes ("O:{0}D:P" -f $sid.alice)
                    Add-Observed $id (Invoke-Check "alice" $tree.notes $WD) $WD $tree.notes "inherited OWNER_RIGHTS; expected-divergence"
                }
                default {
                    Add-Skipped $id "representable catalog row has no Windows builder"
                }
            }
        } catch {
            Add-Skipped $id ("oracle error: " + $_.Exception.Message)
        }
    }

    $status = if ($observed.Count -eq 0) {
        "pending-host-capture"
    } elseif ($skipped.Count -gt 0) {
        "partial"
    } else {
        "captured"
    }
    if ($observed.Count -eq 0) {
        throw "Oracle produced no windows-host-observed rows."
    }

    $doc = [ordered]@{
        schema_version = 1
        provenance     = "windows-host-observed"
        status         = $status
        host           = [ordered]@{
            computer        = $env:COMPUTERNAME
            os              = [string][System.Environment]::OSVersion.VersionString
            captured_at     = [DateTime]::UtcNow.ToString("o")
            accesscheck_api = "advapi32.AccessCheck"
        }
        results        = @($observed)
        skipped        = @($skipped)
        notes          = "Native AccessCheck captures only. Do not merge microsoft-docs rows into results."
    }

    $outDir = Split-Path -Parent $OutputPath
    if ($outDir) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }
    $json = $doc | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $OutputPath -Value $json -Encoding utf8
    Write-Host "Wrote $($observed.Count) observed rows ($status) to $OutputPath"
}
finally {
    if (Test-Path -LiteralPath $root) {
        try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
    foreach ($name in $createdUsers) {
        try { Remove-LocalUser -Name $name -ErrorAction SilentlyContinue } catch { }
    }
    if ($createdGroup) {
        try { Remove-LocalGroup -Name $groupName -ErrorAction SilentlyContinue } catch { }
    }
}
