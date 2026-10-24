<#
.SYNOPSIS
    Deep-dive diagnostic auditor for Active Directory machine trust state, LSA secret synchronization,
    SYSTEM/User Kerberos ticket caches, cached credential overrides, and DC socket/LDAP latency.

.DESCRIPTION
    Test-ADTrustAndIdentityState.ps1 isolates low-level root causes behind broken domain trust
    relationships, intermittent LDAP bind drops, Kerberos encryption mismatches, and stale cached
    identity lockouts following password rotations or VPN state transitions.

    Root Mechanics:
      1. Secure Channel & LSA Machine Password Synchronization:
         - Executes `nltest /sc_query` against the joined domain to verify netlogon secure channel state.
         - Reads the local LSA machine account password timestamp from
           `HKLM:\SECURITY\Policy\Secrets\$MACHINE.ACC\CupdTime` (using direct registry access when
           running as SYSTEM, or token privilege adjustment with SeBackupPrivilege + RegOpenKeyEx
           REG_OPTION_BACKUP_RESTORE when running as an elevated Administrator without mutating ACLs).
         - Queries Active Directory via ADSI (`[System.DirectoryServices.DirectorySearcher]`) for the
           computer object's `pwdLastSet` and `msDS-SupportedEncryptionTypes` attributes, calculating
           exact password drift between local LSA state and AD replication.
         - Correlates recent Netlogon (Event IDs 3210, 5719, 5721, 5722, 5723, 5805) and Kerberos
           (Event IDs 3, 4, 6, 7, 14, 27) System log events.

      2. SYSTEM & Interactive Kerberos Ticket Cache Inspection:
         - Parses `klist -lh 0 -li 0x3e7` (SYSTEM LogonSession) and the current session's `klist` output.
         - Flags legacy weak encryption fallbacks (DES, RC4-HMAC vs. AES128/AES256) in either the
           KerbTicket or Session Key, as well as expired or near-expiry TGTs/service tickets.

      3. Credential Manager & LSASS LogonSession Override Audit:
         - Parses `cmdkey /list` to expose stored Domain Password or Generic credentials that silently
           override machine or interactive tokens during outbound SMB/LDAP negotiation.
         - Correlates `Win32_LogonSession`, `Win32_LoggedOnUser`, and active SMB mappings (`MSFT_SmbConnection`)
           to surface CachedInteractive (LogonType 11), NewCredentials (LogonType 9 / `runas /netonly`),
           and sessions predating the latest AD password rotation.

      4. Domain Controller Raw Socket & RootDSE Bind Telemetry:
         - Discovers site and domain DCs via `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`
           with automatic DNS SRV (`_ldap._tcp.dc._msdcs.<domain>`) fallback when trust is broken.
         - Measures raw TCP handshake latency across ports 389 (LDAP), 636 (LDAPS), 3268 (GC), and 88 (Kerberos).
         - Sends an ASN.1 BER CLDAP RootDSE probe over UDP 389 and a Kerberos probe over UDP 88.
         - Performs timed LDAP RootDSE binds to measure directory response latency and calculate exact
           endpoint-to-DC clock skew against `RootDSE.currentTime`.

.PARAMETER DomainName
    Optional target Active Directory DNS domain name. Defaults to the local computer's joined domain.

.PARAMETER Server
    Optional specific Domain Controller FQDN(s) to test in addition to or instead of auto-discovered DCs.

.PARAMETER AllDomainControllers
    When specified, tests all Domain Controllers in the domain rather than limiting discovery to the
    endpoint's current Active Directory Site.

.PARAMETER SocketTimeoutMs
    Timeout in milliseconds for raw TCP/UDP socket probes. Default is 1500ms.

.PARAMETER EventLookbackHours
    Number of hours to look back in the System event log for Netlogon and Kerberos errors. Default is 24.

.PARAMETER Json
    Serializes the diagnostic output object to a compressed/formatted JSON string for RMM custom fields
    or automated ticket ingestion.

.PARAMETER PassThru
    Returns the structured [PSCustomObject] directly to the pipeline (default behavior when -Json is not set).

.EXAMPLE
    .\Test-ADTrustAndIdentityState.ps1
    Runs a full machine trust, Kerberos, cached credential, and site DC diagnostic, outputting a
    structured PSCustomObject to the pipeline.

.EXAMPLE
    .\Test-ADTrustAndIdentityState.ps1 -AllDomainControllers -Json
    Audits trust state and tests reachability/latency against all DCs in the domain, emitting JSON
    suitable for RMM ingestion.

.OUTPUTS
    PSCustomObject or String (when -Json is specified)

.NOTES
    Author:  Jaylin Tech (jaylin.tech)
    Repo:    github.com/jaylintech/Windows-Scripts-Tools
    Requires: Windows PowerShell 5.1 or PowerShell 7+ (Run as Administrator or SYSTEM for full LSA/0x3e7 visibility)
#>
[CmdletBinding()]
[OutputType([PSCustomObject], [string])]
param(
    [Parameter(Mandatory = $false)]
    [string]$DomainName,

    [Parameter(Mandatory = $false)]
    [string[]]$Server,

    [Parameter(Mandatory = $false)]
    [switch]$AllDomainControllers,

    [Parameter(Mandatory = $false)]
    [ValidateRange(100, 30000)]
    [int]$SocketTimeoutMs = 1500,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 720)]
    [int]$EventLookbackHours = 24,

    [Parameter(Mandatory = $false)]
    [switch]$Json,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Native Win32 Helper for Read-Only LSA CupdTime Access via SeBackupPrivilege ---
function Initialize-AdvapiBackupReader {
    if (-not ('LsaRegistryBackupReader' -as [type])) {
        $typeDef = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class LsaRegistryBackupReader
{
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const int REG_OPTION_BACKUP_RESTORE = 0x00000004;
    private const int KEY_READ = 0x20019;
    private const int ERROR_SUCCESS = 0;
    private static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int RegOpenKeyEx(
        IntPtr hKey,
        string lpSubKey,
        int ulOptions,
        int samDesired,
        out IntPtr phkResult);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int RegQueryValueEx(
        IntPtr hKey,
        string lpValueName,
        IntPtr lpReserved,
        out uint lpType,
        byte[] lpData,
        ref uint lpcbData);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegCloseKey(IntPtr hKey);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static bool EnablePrivilege(string privilegeName)
    {
        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            return false;

        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid))
                return false;

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SE_PRIVILEGE_ENABLED
            };

            return AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) &&
                   Marshal.GetLastWin32Error() == ERROR_SUCCESS;
        }
        finally
        {
            CloseHandle(hToken);
        }
    }

    public static byte[] ReadHklmDefaultBinaryValue(string subKeyPath)
    {
        EnablePrivilege("SeBackupPrivilege");

        IntPtr hKey;
        int status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKeyPath, REG_OPTION_BACKUP_RESTORE, KEY_READ, out hKey);
        if (status != ERROR_SUCCESS)
            throw new Win32Exception(status, string.Format("RegOpenKeyEx failed for {0} (Win32Error {1}: {2})", subKeyPath, status, new Win32Exception(status).Message));

        try
        {
            uint type;
            uint size = 0;
            status = RegQueryValueEx(hKey, null, IntPtr.Zero, out type, null, ref size);
            if (status != ERROR_SUCCESS || size == 0)
                throw new Win32Exception(status, string.Format("RegQueryValueEx size probe failed for {0} (Win32Error {1}: {2})", subKeyPath, status, new Win32Exception(status).Message));

            byte[] buffer = new byte[size];
            status = RegQueryValueEx(hKey, null, IntPtr.Zero, out type, buffer, ref size);
            if (status != ERROR_SUCCESS)
                throw new Win32Exception(status, string.Format("RegQueryValueEx data read failed for {0} (Win32Error {1}: {2})", subKeyPath, status, new Win32Exception(status).Message));

            return buffer;
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }
}
'@
        Add-Type -TypeDefinition $typeDef -ErrorAction Stop
    }
}
#endregion

#region --- Helper: Read Local Machine Account CupdTime ---
function Get-LocalMachineCupdTime {
    [CmdletBinding()]
    param()

    $subKeyPath = 'SECURITY\Policy\Secrets\$MACHINE.ACC\CupdTime'
    $rawBytes = $null
    $accessMethod = 'None'
    $errorMsg = $null

    # Attempt 1: Standard Registry API (succeeds when running as NT AUTHORITY\SYSTEM)
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKeyPath, $false)
        if ($null -ne $regKey) {
            try {
                $rawBytes = [byte[]]$regKey.GetValue($null)
                if ($null -ne $rawBytes -and $rawBytes.Length -ge 8) {
                    $accessMethod = 'DirectRegistry'
                }
            }
            finally {
                $regKey.Dispose()
            }
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
    }

    # Attempt 2: SeBackupPrivilege + REG_OPTION_BACKUP_RESTORE (succeeds as elevated Local Admin without ACL modification)
    if ($null -eq $rawBytes -or $rawBytes.Length -lt 8) {
        try {
            Initialize-AdvapiBackupReader
            $rawBytes = [LsaRegistryBackupReader]::ReadHklmDefaultBinaryValue($subKeyPath)
            if ($null -ne $rawBytes -and $rawBytes.Length -ge 8) {
                $accessMethod = 'SeBackupPrivilege'
                $errorMsg = $null
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
        }
    }

    $cupdTimeUtc = $null
    $fileTimeInt64 = $null
    if ($null -ne $rawBytes -and $rawBytes.Length -ge 8) {
        try {
            $fileTimeInt64 = [BitConverter]::ToInt64($rawBytes, 0)
            if ($fileTimeInt64 -gt 0) {
                $cupdTimeUtc = [DateTime]::FromFileTimeUtc($fileTimeInt64)
            }
        }
        catch {
            $errorMsg = "Failed to decode FILETIME from CupdTime bytes: $($_.Exception.Message)"
        }
    }

    [PSCustomObject]@{
        RegistryPath  = "HKLM:\$subKeyPath"
        AccessMethod  = $accessMethod
        FileTimeRaw   = $fileTimeInt64
        CupdTimeUtc   = $cupdTimeUtc
        CupdTimeLocal = if ($null -ne $cupdTimeUtc) { $cupdTimeUtc.ToLocalTime() } else { $null }
        AgeDays       = if ($null -ne $cupdTimeUtc) { [math]::Round(([DateTime]::UtcNow - $cupdTimeUtc).TotalDays, 2) } else { $null }
        Error         = $errorMsg
    }
}
#endregion

#region --- Helper: Convert Kerberos Encryption Bitmask to Readable Names ---
function ConvertFrom-EncryptionTypesBitmask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [Nullable[int]]$Bitmask
    )

    if ($null -eq $Bitmask -or $Bitmask -eq 0) {
        return @('NotConfigured (Defaults apply)')
    }

    $flags = [ordered]@{
        0x01 = 'DES_CBC_CRC'
        0x02 = 'DES_CBC_MD5'
        0x04 = 'RC4_HMAC_MD5'
        0x08 = 'AES128_CTS_HMAC_SHA1_96'
        0x10 = 'AES256_CTS_HMAC_SHA1_96'
        0x20 = 'FAST_Supported'
        0x40 = 'CompoundIdentity_Supported'
        0x80 = 'Claims_Supported'
    }

    $enabled = New-Object System.Collections.Generic.List[string]
    foreach ($kvp in $flags.GetEnumerator()) {
        if (($Bitmask -band $kvp.Key) -eq $kvp.Key) {
            $enabled.Add($kvp.Value)
        }
    }
    return $enabled.ToArray()
}
#endregion

#region --- Helper: Execute Native Binary with Captured Output ---
function Invoke-NativeCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [string]$Arguments = '',

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMs = 10000
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    try {
        [void]$proc.Start()
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()

        $completed = $proc.WaitForExit($TimeoutMs)
        if (-not $completed) {
            try { $proc.Kill() } catch {}
            return [PSCustomObject]@{
                ExitCode = -1
                StdOut   = ''
                StdErr   = "Process timed out after ${TimeoutMs}ms."
                TimedOut = $true
            }
        }

        $proc.WaitForExit()
        return [PSCustomObject]@{
            ExitCode = $proc.ExitCode
            StdOut   = $stdoutTask.GetAwaiter().GetResult()
            StdErr   = $stderrTask.GetAwaiter().GetResult()
            TimedOut = $false
        }
    }
    finally {
        $proc.Dispose()
    }
}
#endregion

#region --- 1. Machine Trust & LSA vs AD Password State ---
function Test-MachineTrustState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TargetDomain,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [bool]$IsPartOfDomain
    )

    $cupdInfo = Get-LocalMachineCupdTime

    # Read local Netlogon parameters (DisablePasswordChange, MaximumPasswordAge)
    $netlogonParamsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $disablePwdChange = $null
    $maxPwdAgeDays = 30
    try {
        $nlProps = Get-ItemProperty -Path $netlogonParamsPath -ErrorAction SilentlyContinue
        if ($null -ne $nlProps) {
            if ($nlProps.PSObject.Properties.Match('DisablePasswordChange').Count -gt 0) {
                $disablePwdChange = [bool]([int]$nlProps.DisablePasswordChange -ne 0)
            }
            if ($nlProps.PSObject.Properties.Match('MaximumPasswordAge').Count -gt 0 -and [int]$nlProps.MaximumPasswordAge -gt 0) {
                $maxPwdAgeDays = [int]$nlProps.MaximumPasswordAge
            }
        }
    }
    catch {}

    # Read local Kerberos SupportedEncryptionTypes policy
    $kerbPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    $localKerbEncBitmask = $null
    try {
        if (Test-Path -Path $kerbPolicyPath) {
            $kp = Get-ItemProperty -Path $kerbPolicyPath -Name 'SupportedEncryptionTypes' -ErrorAction SilentlyContinue
            if ($null -ne $kp -and $kp.PSObject.Properties.Match('SupportedEncryptionTypes').Count -gt 0) {
                $localKerbEncBitmask = [int]$kp.SupportedEncryptionTypes
            }
        }
    }
    catch {}

    $nltestResult = [PSCustomObject]@{
        Executed                = $false
        Healthy                 = $false
        TrustedDCName           = $null
        Flags                   = $null
        ConnectionStatus        = $null
        TrustVerificationStatus = $null
        ExitCode                = $null
        RawSummary              = $null
    }

    if ($IsPartOfDomain -and -not [string]::IsNullOrWhiteSpace($TargetDomain)) {
        try {
            $nl = Invoke-NativeCommand -FilePath 'nltest.exe' -Arguments "/sc_query:$TargetDomain" -TimeoutMs 8000
            $combined = ($nl.StdOut + "`n" + $nl.StdErr).Trim()
            $nltestResult.Executed = $true
            $nltestResult.ExitCode = $nl.ExitCode
            $nltestResult.RawSummary = ($combined -split '\r?\n' | Where-Object { $_ -match '\S' }) -join ' | '

            if ($combined -match 'Flags:\s*([^\r\n]+)') {
                $nltestResult.Flags = $Matches[1].Trim()
            }
            if ($combined -match 'Trusted DC Name\s*([^\r\n]+)') {
                $nltestResult.TrustedDCName = $Matches[1].Trim()
            }
            if ($combined -match 'Trusted DC Connection Status Status\s*=\s*([^\r\n]+)') {
                $nltestResult.ConnectionStatus = $Matches[1].Trim()
            }
            if ($combined -match 'Trust Verification Status\s*=\s*([^\r\n]+)') {
                $nltestResult.TrustVerificationStatus = $Matches[1].Trim()
            }

            if ($nl.ExitCode -eq 0 -and
                $nltestResult.ConnectionStatus -match 'NERR_Success' -and
                ($null -eq $nltestResult.TrustVerificationStatus -or $nltestResult.TrustVerificationStatus -match 'NERR_Success')) {
                $nltestResult.Healthy = $true
            }
        }
        catch {
            $nltestResult.RawSummary = "Failed to execute nltest.exe: $($_.Exception.Message)"
        }
    }
    else {
        $nltestResult.RawSummary = 'Endpoint is not joined to an Active Directory domain.'
    }

    # Query Active Directory Computer Object via ADSI DirectorySearcher
    $adComputer = [PSCustomObject]@{
        Queried                      = $false
        BindSucceeded                = $false
        DistinguishedName            = $null
        DnsHostName                  = $null
        PwdLastSetRaw                = $null
        PwdLastSetUtc                = $null
        PwdLastSetLocal              = $null
        PwdAgeDays                   = $null
        WhenChangedUtc               = $null
        UserAccountControl           = $null
        SupportedEncryptionBitmask   = $null
        SupportedEncryptionTypes     = @()
        ServicePrincipalNames        = @()
        Error                        = $null
    }

    if ($IsPartOfDomain -and -not [string]::IsNullOrWhiteSpace($TargetDomain)) {
        $adComputer.Queried = $true
        try {
            $preferredDc = $null
            if (-not [string]::IsNullOrWhiteSpace($nltestResult.TrustedDCName)) {
                $preferredDc = $nltestResult.TrustedDCName.TrimStart('\')
            }

            $ldapServer = if (-not [string]::IsNullOrWhiteSpace($preferredDc)) { $preferredDc } else { $TargetDomain }
            $rootDse = [ADSI]"LDAP://$ldapServer/RootDSE"
            $defaultNamingContext = [string]$rootDse.Properties['defaultNamingContext'][0]

            $searchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ldapServer/$defaultNamingContext")
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
            $samAccount = "$ComputerName$"
            $searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=$samAccount))"
            $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds(8)
            [void]$searcher.PropertiesToLoad.AddRange(@(
                'distinguishedName',
                'dNSHostName',
                'pwdLastSet',
                'whenChanged',
                'userAccountControl',
                'msDS-SupportedEncryptionTypes',
                'servicePrincipalName'
            ))

            $searchResult = $searcher.FindOne()
            if ($null -ne $searchResult) {
                $adComputer.BindSucceeded = $true
                $props = $searchResult.Properties

                if ($props['distinguishedname'].Count -gt 0) {
                    $adComputer.DistinguishedName = [string]$props['distinguishedname'][0]
                }
                if ($props['dnshostname'].Count -gt 0) {
                    $adComputer.DnsHostName = [string]$props['dnshostname'][0]
                }
                if ($props['pwdlastset'].Count -gt 0) {
                    $pwdFileTime = [int64]$props['pwdlastset'][0]
                    $adComputer.PwdLastSetRaw = $pwdFileTime
                    if ($pwdFileTime -gt 0) {
                        $pwdUtc = [DateTime]::FromFileTimeUtc($pwdFileTime)
                        $adComputer.PwdLastSetUtc = $pwdUtc
                        $adComputer.PwdLastSetLocal = $pwdUtc.ToLocalTime()
                        $adComputer.PwdAgeDays = [math]::Round(([DateTime]::UtcNow - $pwdUtc).TotalDays, 2)
                    }
                }
                if ($props['whenchanged'].Count -gt 0) {
                    $adComputer.WhenChangedUtc = ([DateTime]$props['whenchanged'][0]).ToUniversalTime()
                }
                if ($props['useraccountcontrol'].Count -gt 0) {
                    $adComputer.UserAccountControl = [int]$props['useraccountcontrol'][0]
                }
                if ($props['msds-supportedencryptiontypes'].Count -gt 0) {
                    $encMask = [int]$props['msds-supportedencryptiontypes'][0]
                    $adComputer.SupportedEncryptionBitmask = $encMask
                    $adComputer.SupportedEncryptionTypes = [string[]]@(ConvertFrom-EncryptionTypesBitmask -Bitmask $encMask)
                }
                else {
                    $adComputer.SupportedEncryptionTypes = [string[]]@(ConvertFrom-EncryptionTypesBitmask -Bitmask $null)
                }
                if ($props['serviceprincipalname'].Count -gt 0) {
                    $spns = New-Object System.Collections.Generic.List[string]
                    foreach ($spn in $props['serviceprincipalname']) {
                        $spns.Add([string]$spn)
                    }
                    $adComputer.ServicePrincipalNames = $spns.ToArray()
                }
            }
            else {
                $adComputer.Error = "Computer object '$samAccount' not found in '$defaultNamingContext'."
            }

            $searcher.Dispose()
            $searchRoot.Dispose()
        }
        catch {
            $adComputer.Error = $_.Exception.Message
        }
    }

    # Compare Local LSA CupdTime against AD pwdLastSet
    $driftSeconds = $null
    $driftMinutes = $null
    $syncState = 'Unknown'

    if ($null -ne $cupdInfo.CupdTimeUtc -and $null -ne $adComputer.PwdLastSetUtc) {
        $diff = ($cupdInfo.CupdTimeUtc - $adComputer.PwdLastSetUtc).TotalSeconds
        $driftSeconds = [math]::Round($diff, 2)
        $driftMinutes = [math]::Round(($diff / 60.0), 2)

        # Within 120 seconds is normal transaction/clock delta during machine password rotation
        if ([math]::Abs($diff) -le 120) {
            $syncState = 'InSync'
        }
        elseif ($diff -gt 120) {
            $syncState = 'LocalAheadOfAD (Unreplicated DC or Uncommitted Local Rotation)'
        }
        else {
            $syncState = 'ADAheadOfLocal (Snapshot Revert, Split-Brain VM, or Reset in AD)'
        }
    }
    elseif (-not $IsPartOfDomain) {
        $syncState = 'NotDomainJoined'
    }
    elseif ($null -eq $cupdInfo.CupdTimeUtc) {
        $syncState = 'LocalLsaUnreadable (Run as SYSTEM or Elevated Administrator)'
    }
    elseif (-not $adComputer.BindSucceeded) {
        $syncState = 'ADBindFailed (Cannot read AD pwdLastSet)'
    }

    [PSCustomObject]@{
        ComputerName                 = $ComputerName
        DomainName                   = $TargetDomain
        PartOfDomain                 = $IsPartOfDomain
        SecureChannel                = $nltestResult
        LocalLsaSecret               = $cupdInfo
        ADComputerObject             = $adComputer
        PasswordDriftSeconds         = $driftSeconds
        PasswordDriftMinutes         = $driftMinutes
        PasswordSyncState            = $syncState
        DisablePasswordChange        = $disablePwdChange
        MaximumPasswordAgeDays       = $maxPwdAgeDays
        LocalKerberosEncryptionMask  = $localKerbEncBitmask
        LocalKerberosEncryptionTypes = [string[]]@(ConvertFrom-EncryptionTypesBitmask -Bitmask $localKerbEncBitmask)
    }
}
#endregion

#region --- 2. SYSTEM (0x3e7) & Current Session Kerberos Ticket Cache Inspector ---
function ConvertFrom-KlistOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$RawText,

        [Parameter(Mandatory = $true)]
        [string]$SessionLabel
    )

    $currentLogonId = $null
    $targetedLogonId = $null
    if ($RawText -match 'Current LogonId is\s+([^\r\n]+)') {
        $currentLogonId = $Matches[1].Trim()
    }
    if ($RawText -match 'Targeted LogonId is\s+([^\r\n]+)') {
        $targetedLogonId = $Matches[1].Trim()
    }

    $tickets = New-Object System.Collections.Generic.List[PSCustomObject]
    $blocks = $RawText -split '(?m)^\s*#(\d+)>\s*'

    # $blocks[0] is header; subsequent pairs are (index, body)
    for ($i = 1; $i -lt $blocks.Count; $i += 2) {
        $ticketIndex = [int]$blocks[$i]
        $body = $blocks[$i + 1]

        $client = if ($body -match 'Client:\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }
        $server = if ($body -match 'Server:\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }
        $ticketEnc = if ($body -match 'KerbTicket Encryption Type:\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }
        $sessionKeyEnc = if ($body -match 'Session Key Type:\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }
        $flags = if ($body -match 'Ticket Flags\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }
        $startRaw = if ($body -match 'Start Time:\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }
        $endRaw = if ($body -match 'End Time:\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }
        $renewRaw = if ($body -match 'Renew Time:\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }
        $cacheFlags = if ($body -match 'Cache Flags:\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }
        $kdcCalled = if ($body -match 'Kdc Called:\s*([^\r\n]+)') { $Matches[1].Trim() } else { $null }

        $startTime = $null
        $endTime = $null
        $renewTime = $null
        if ($null -ne $startRaw) {
            $cleanStart = ($startRaw -replace '\s*\([^\)]+\)\s*$', '').Trim()
            $parsed = [DateTime]::MinValue
            if ([DateTime]::TryParse($cleanStart, [ref]$parsed)) { $startTime = $parsed }
        }
        if ($null -ne $endRaw) {
            $cleanEnd = ($endRaw -replace '\s*\([^\)]+\)\s*$', '').Trim()
            $parsed = [DateTime]::MinValue
            if ([DateTime]::TryParse($cleanEnd, [ref]$parsed)) { $endTime = $parsed }
        }
        if ($null -ne $renewRaw) {
            $cleanRenew = ($renewRaw -replace '\s*\([^\)]+\)\s*$', '').Trim()
            $parsed = [DateTime]::MinValue
            if ([DateTime]::TryParse($cleanRenew, [ref]$parsed)) { $renewTime = $parsed }
        }

        $now = Get-Date
        $isExpired = if ($null -ne $endTime) { $endTime -lt $now } else { $false }
        $minutesRemaining = if ($null -ne $endTime) { [math]::Round(($endTime - $now).TotalMinutes, 1) } else { $null }

        $usesWeakTicketEnc = ($ticketEnc -match 'RC4|DES|NULL|EXPORT')
        $usesWeakSessionKey = ($sessionKeyEnc -match 'RC4|DES|NULL|EXPORT')
        $encryptionMismatch = ($null -ne $ticketEnc -and $null -ne $sessionKeyEnc -and ($usesWeakTicketEnc -ne $usesWeakSessionKey))

        $tickets.Add([PSCustomObject]@{
            SessionLabel          = $SessionLabel
            TicketIndex           = $ticketIndex
            Client                = $client
            Server                = $server
            IsTgt                 = ($server -match '^krbtgt/')
            KerbTicketEncryption  = $ticketEnc
            SessionKeyEncryption  = $sessionKeyEnc
            UsesWeakEncryption    = [bool]($usesWeakTicketEnc -or $usesWeakSessionKey)
            EncryptionKeyMismatch = [bool]$encryptionMismatch
            StartTimeLocal        = if ($null -ne $startTime) { $startTime.ToString('o') } else { $null }
            EndTimeLocal          = if ($null -ne $endTime) { $endTime.ToString('o') } else { $null }
            RenewTimeLocal        = if ($null -ne $renewTime) { $renewTime.ToString('o') } else { $null }
            MinutesRemaining      = $minutesRemaining
            IsExpired             = $isExpired
            TicketFlags           = $flags
            CacheFlags            = $cacheFlags
            KdcCalled             = $kdcCalled
        })
    }

    [PSCustomObject]@{
        SessionLabel            = $SessionLabel
        CurrentLogonId          = $currentLogonId
        TargetedLogonId         = $targetedLogonId
        TicketCount             = $tickets.Count
        HasTgt                  = [bool]($tickets | Where-Object { $_.IsTgt } | Select-Object -First 1)
        ExpiredTicketCount      = @($tickets | Where-Object { $_.IsExpired }).Count
        WeakCryptoTicketCount   = @($tickets | Where-Object { $_.UsesWeakEncryption }).Count
        KeyMismatchTicketCount  = @($tickets | Where-Object { $_.EncryptionKeyMismatch }).Count
        Tickets                 = $tickets.ToArray()
    }
}

function Get-KerberosTicketState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$IsElevated
    )

    # 1. Inspect SYSTEM (0x3e7) session via `klist -lh 0 -li 0x3e7`
    $systemSession = $null
    $systemError = $null
    if ($IsElevated) {
        try {
            $res = Invoke-NativeCommand -FilePath 'klist.exe' -Arguments '-lh 0 -li 0x3e7' -TimeoutMs 6000
            if ($res.ExitCode -eq 0 -or $res.StdOut -match 'Cached Tickets') {
                $systemSession = ConvertFrom-KlistOutput -RawText $res.StdOut -SessionLabel 'SYSTEM (0:0x3e7)'
            }
            else {
                $systemError = ($res.StdOut + ' ' + $res.StdErr).Trim()
            }
        }
        catch {
            $systemError = $_.Exception.Message
        }
    }
    else {
        $systemError = 'Elevation required to inspect SYSTEM (0x3e7) Kerberos ticket cache.'
    }

    # 2. Inspect Current Caller Session via `klist.exe`
    $callerSession = $null
    $callerError = $null
    try {
        $resCaller = Invoke-NativeCommand -FilePath 'klist.exe' -Arguments '' -TimeoutMs 6000
        if ($resCaller.ExitCode -eq 0 -or $resCaller.StdOut -match 'Cached Tickets') {
            $callerSession = ConvertFrom-KlistOutput -RawText $resCaller.StdOut -SessionLabel 'CurrentCaller'
        }
        else {
            $callerError = ($resCaller.StdOut + ' ' + $resCaller.StdErr).Trim()
        }
    }
    catch {
        $callerError = $_.Exception.Message
    }

    [PSCustomObject]@{
        SystemLogonSession      = $systemSession
        SystemSessionError      = $systemError
        CurrentCallerSession    = $callerSession
        CurrentCallerError      = $callerError
    }
}
#endregion

#region --- 3. Credential Manager & LSASS Cached Session Inspector ---
function Get-CredentialAndSessionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [Nullable[DateTime]]$MachinePwdLastSetUtc
    )

    # 1. Parse `cmdkey /list`
    $credEntries = New-Object System.Collections.Generic.List[PSCustomObject]
    $cmdkeyError = $null
    try {
        $ck = Invoke-NativeCommand -FilePath 'cmdkey.exe' -Arguments '/list' -TimeoutMs 6000
        $raw = $ck.StdOut
        $lines = $raw -split '\r?\n'

        $curTarget = $null
        $curType = $null
        $curUser = $null
        $curPersistence = $null

        foreach ($line in $lines) {
            if ($line -match '^\s*Target:\s*(.+)$') {
                if ($null -ne $curTarget) {
                    $isDomainOverrideRisk = (
                        $curType -match 'Domain' -or
                        $curTarget -match '(?i)Domain:target=|TERMSRV/|\bldap\b|\bcifs\b' -or
                        (-not [string]::IsNullOrWhiteSpace($TargetDomain) -and $curTarget -match [regex]::Escape($TargetDomain))
                    )
                    $credEntries.Add([PSCustomObject]@{
                        Target               = $curTarget
                        Type                 = $curType
                        User                 = $curUser
                        Persistence          = $curPersistence
                        IsDomainOverrideRisk = [bool]$isDomainOverrideRisk
                    })
                }
                $curTarget = $Matches[1].Trim()
                $curType = $null
                $curUser = $null
                $curPersistence = $null
            }
            elseif ($null -ne $curTarget -and $line -match '^\s*Type:\s*(.+)$') {
                $curType = $Matches[1].Trim()
            }
            elseif ($null -ne $curTarget -and $line -match '^\s*User:\s*(.+)$') {
                $curUser = $Matches[1].Trim()
            }
            elseif ($null -ne $curTarget -and $line -match '^\s*(Local machine persistence|Enterprise persistence|Saved for this logon only)\s*$') {
                $curPersistence = $Matches[1].Trim()
            }
        }

        if ($null -ne $curTarget) {
            $isDomainOverrideRisk = (
                $curType -match 'Domain' -or
                $curTarget -match '(?i)Domain:target=|TERMSRV/|\bldap\b|\bcifs\b' -or
                (-not [string]::IsNullOrWhiteSpace($TargetDomain) -and $curTarget -match [regex]::Escape($TargetDomain))
            )
            $credEntries.Add([PSCustomObject]@{
                Target               = $curTarget
                Type                 = $curType
                User                 = $curUser
                Persistence          = $curPersistence
                IsDomainOverrideRisk = [bool]$isDomainOverrideRisk
            })
        }
    }
    catch {
        $cmdkeyError = $_.Exception.Message
    }

    # 2. Enumerate WinNT/LSASS Logon Sessions via CIM (Win32_LogonSession + Win32_LoggedOnUser)
    $logonTypeMap = @{
        [uint32]0  = 'System'
        [uint32]2  = 'Interactive'
        [uint32]3  = 'Network'
        [uint32]4  = 'Batch'
        [uint32]5  = 'Service'
        [uint32]7  = 'Unlock'
        [uint32]8  = 'NetworkCleartext'
        [uint32]9  = 'NewCredentials (runas /netonly)'
        [uint32]10 = 'RemoteInteractive (RDP)'
        [uint32]11 = 'CachedInteractive (Offline Domain Cache)'
        [uint32]12 = 'CachedRemoteInteractive'
        [uint32]13 = 'CachedUnlock'
    }

    $lsassSessions = New-Object System.Collections.Generic.List[PSCustomObject]
    try {
        $sessions = Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop
        $links = Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction SilentlyContinue

        $userByLogonId = @{}
        if ($null -ne $links) {
            foreach ($link in $links) {
                $id = $link.Dependent.LogonId
                $acctDomain = $link.Antecedent.Domain
                $acctName = $link.Antecedent.Name
                if (-not [string]::IsNullOrWhiteSpace($id) -and -not [string]::IsNullOrWhiteSpace($acctName)) {
                    $userByLogonId[$id] = "$acctDomain\$acctName"
                }
            }
        }

        foreach ($s in $sessions) {
            $ltCode = [uint32]$s.LogonType
            # Filter out routine anonymous/system noise unless it's SYSTEM (999) or an interactive/cached/service/netonly session
            if ($ltCode -in @(2, 3, 4, 5, 8, 9, 10, 11, 12, 13) -or $s.LogonId -eq '999') {
                $account = if ($userByLogonId.ContainsKey($s.LogonId)) { $userByLogonId[$s.LogonId] } else { 'Unknown' }
                # Skip Window Manager / Font Driver Host pseudo-accounts to keep telemetry high-signal
                if ($account -match '^(Window Manager|Font Driver Host)\\') {
                    continue
                }

                $ltName = if ($logonTypeMap.ContainsKey($ltCode)) { $logonTypeMap[$ltCode] } else { "Type_$ltCode" }
                $startTimeUtc = if ($null -ne $s.StartTime) { ([DateTime]$s.StartTime).ToUniversalTime() } else { $null }
                $predatesMachinePwd = ($null -ne $startTimeUtc -and $null -ne $MachinePwdLastSetUtc -and $startTimeUtc -lt $MachinePwdLastSetUtc)

                $lsassSessions.Add([PSCustomObject]@{
                    LogonId                  = $s.LogonId
                    LogonIdHex               = ('0x{0:x}' -f [uint64]$s.LogonId)
                    Account                  = $account
                    AuthenticationPackage    = $s.AuthenticationPackage
                    LogonTypeCode            = $ltCode
                    LogonType                = $ltName
                    StartTimeLocal           = if ($null -ne $s.StartTime) { ([DateTime]$s.StartTime).ToString('o') } else { $null }
                    IsCachedLogon            = ($ltCode -in @(11, 12, 13))
                    IsNewCredentialsOverride = ($ltCode -eq 9)
                    PredatesMachineRotation  = [bool]$predatesMachinePwd
                })
            }
        }
    }
    catch {}

    # 3. Inspect Active Outbound SMB Connections (`MSFT_SmbConnection`)
    $smbConnections = New-Object System.Collections.Generic.List[PSCustomObject]
    try {
        $smbRaw = Get-CimInstance -Namespace 'root/Microsoft/Windows/SMB' -ClassName 'MSFT_SmbConnection' -ErrorAction SilentlyContinue
        if ($null -ne $smbRaw) {
            foreach ($conn in $smbRaw) {
                $credUsed = [string]$conn.Credential
                $userUsed = [string]$conn.UserName
                $isExplicitOverride = (-not [string]::IsNullOrWhiteSpace($credUsed) -and $credUsed -ne $userUsed)
                $smbConnections.Add([PSCustomObject]@{
                    ServerName           = $conn.ServerName
                    ShareName            = $conn.ShareName
                    UserName             = $userUsed
                    Credential           = $credUsed
                    Dialect              = $conn.Dialect
                    NumOpens             = $conn.NumOpens
                    Signed               = $conn.Signed
                    Encrypted            = $conn.Encrypted
                    HasCredentialOverride = $isExplicitOverride
                })
            }
        }
    }
    catch {}

    # 4. Read Winlogon CachedLogonsCount policy
    $cachedLogonsCount = $null
    try {
        $wl = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -ErrorAction SilentlyContinue
        if ($null -ne $wl -and $wl.PSObject.Properties.Match('CachedLogonsCount').Count -gt 0) {
            $cachedLogonsCount = [int]$wl.CachedLogonsCount
        }
    }
    catch {}

    [PSCustomObject]@{
        WinlogonCachedLogonsCount      = $cachedLogonsCount
        CredentialManagerCount         = $credEntries.Count
        DomainOverrideRiskCredCount    = @($credEntries | Where-Object { $_.IsDomainOverrideRisk }).Count
        CredentialManagerEntries       = $credEntries.ToArray()
        CredentialManagerError         = $cmdkeyError
        CachedInteractiveSessionCount  = @($lsassSessions | Where-Object { $_.IsCachedLogon }).Count
        NewCredentialsSessionCount     = @($lsassSessions | Where-Object { $_.IsNewCredentialsOverride }).Count
        ActiveLogonSessions            = $lsassSessions.ToArray()
        ActiveSmbConnections           = $smbConnections.ToArray()
    }
}
#endregion

#region --- 4. Raw TCP/UDP Socket Reachability & LDAP RootDSE Bind Latency ---
function Test-TcpPortLatency {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutMs
    )

    $tcp = New-Object System.Net.Sockets.TcpClient
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $connectTask = $tcp.ConnectAsync($TargetHost, $Port)
        if ($connectTask.Wait($TimeoutMs) -and $tcp.Connected) {
            $sw.Stop()
            return [PSCustomObject]@{
                Reachable = $true
                LatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                Error     = $null
            }
        }
        else {
            $sw.Stop()
            return [PSCustomObject]@{
                Reachable = $false
                LatencyMs = $null
                Error     = "Timeout (${TimeoutMs}ms)"
            }
        }
    }
    catch {
        $sw.Stop()
        $innerMsg = if ($null -ne $_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        return [PSCustomObject]@{
            Reachable = $false
            LatencyMs = $null
            Error     = $innerMsg
        }
    }
    finally {
        $tcp.Close()
        $tcp.Dispose()
    }
}

function Test-UdpCldapProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutMs
    )

    # Minimal 38-byte ASN.1 BER LDAPv3 RootDSE base-scope SearchRequest for (objectClass=*) requesting attribute "1.1"
    [byte[]]$cldapPayload = @(
        0x30, 0x24,
        0x02, 0x01, 0x01,
        0x63, 0x1f,
        0x04, 0x00,
        0x0a, 0x01, 0x00,
        0x0a, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x01, 0x01, 0x00,
        0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73,
        0x30, 0x05, 0x04, 0x03, 0x31, 0x2e, 0x31
    )

    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = $TimeoutMs
    $udp.Client.SendTimeout = $TimeoutMs
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp.Connect($TargetHost, 389)
        [void]$udp.Send($cldapPayload, $cldapPayload.Length)
        $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remoteEp)
        $sw.Stop()

        $validLdap = ($null -ne $resp -and $resp.Length -gt 2 -and $resp[0] -eq 0x30)
        return [PSCustomObject]@{
            Reachable = [bool]$validLdap
            LatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error     = if ($validLdap) { $null } else { 'Unexpected UDP 389 response header' }
        }
    }
    catch {
        $sw.Stop()
        return [PSCustomObject]@{
            Reachable = $false
            LatencyMs = $null
            Error     = $_.Exception.Message
        }
    }
    finally {
        $udp.Close()
        $udp.Dispose()
    }
}

function Test-UdpKerberos88Probe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutMs
    )

    # Minimal ASN.1 Kerberos AS-REQ header frame to elicit a KRB-ERROR (0x7e) or verify socket reachability on UDP 88
    [byte[]]$krbProbe = @(
        0x6a, 0x16, 0x30, 0x14,
        0xa1, 0x03, 0x02, 0x01, 0x05,
        0xa2, 0x03, 0x02, 0x01, 0x0a,
        0xa4, 0x0a, 0x30, 0x08, 0xa0, 0x06, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00
    )

    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = $TimeoutMs
    $udp.Client.SendTimeout = $TimeoutMs
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp.Connect($TargetHost, 88)
        [void]$udp.Send($krbProbe, $krbProbe.Length)
        $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remoteEp)
        $sw.Stop()

        return [PSCustomObject]@{
            Reachable = ($null -ne $resp -and $resp.Length -gt 0)
            Status    = 'Responded'
            LatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error     = $null
        }
    }
    catch [System.Net.Sockets.SocketException] {
        $sw.Stop()
        # WSAECONNRESET (10054) indicates ICMP Port Unreachable (closed UDP port)
        if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
            return [PSCustomObject]@{
                Reachable = $false
                Status    = 'Refused (ICMP Port Unreachable)'
                LatencyMs = $null
                Error     = $_.Exception.Message
            }
        }
        return [PSCustomObject]@{
            Reachable = $false
            Status    = 'NoResponseOrFiltered'
            LatencyMs = $null
            Error     = $_.Exception.Message
        }
    }
    catch {
        $sw.Stop()
        return [PSCustomObject]@{
            Reachable = $false
            Status    = 'Error'
            LatencyMs = $null
            Error     = $_.Exception.Message
        }
    }
    finally {
        $udp.Close()
        $udp.Dispose()
    }
}

function Test-DomainControllerConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TargetDomain,

        [Parameter(Mandatory = $false)]
        [string[]]$ExplicitServers,

        [Parameter(Mandatory = $true)]
        [bool]$QueryAllDCs,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutMs
    )

    $endpointSiteName = $null
    $siteDiscoveryError = $null
    $discoveryMethod = 'None'
    $dcList = New-Object System.Collections.Generic.List[PSCustomObject]

    # 1. Discover Endpoint's Current AD Site
    try {
        $siteObj = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()
        if ($null -ne $siteObj) {
            $endpointSiteName = $siteObj.Name
        }
    }
    catch {
        $siteDiscoveryError = $_.Exception.Message
    }

    # 2. Discover Domain Controllers via [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    if (-not [string]::IsNullOrWhiteSpace($TargetDomain)) {
        try {
            $currentDom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $foundControllers = $null
            if (-not $QueryAllDCs -and -not [string]::IsNullOrWhiteSpace($endpointSiteName)) {
                try {
                    $foundControllers = $currentDom.FindAllDomainControllers($endpointSiteName)
                    if ($null -ne $foundControllers -and $foundControllers.Count -gt 0) {
                        $discoveryMethod = "ADSI.FindAllDomainControllers(Site:$endpointSiteName)"
                    }
                }
                catch {}
            }

            if ($null -eq $foundControllers -or $foundControllers.Count -eq 0) {
                $foundControllers = $currentDom.FindAllDomainControllers()
                $discoveryMethod = 'ADSI.FindAllDomainControllers(All)'
            }

            foreach ($dc in $foundControllers) {
                $dcList.Add([PSCustomObject]@{
                    HostName  = $dc.Name
                    IPAddress = $dc.IPAddress
                    SiteName  = $dc.SiteName
                    Roles     = @($dc.Roles | ForEach-Object { $_.ToString() })
                })
            }
        }
        catch {
            # Fallback to DNS SRV lookup (`_ldap._tcp.dc._msdcs.<domain>`) when trust/ADSI fails
            try {
                $srvQuery = if (-not $QueryAllDCs -and -not [string]::IsNullOrWhiteSpace($endpointSiteName)) {
                    "_ldap._tcp.$endpointSiteName._sites.dc._msdcs.$TargetDomain"
                }
                else {
                    "_ldap._tcp.dc._msdcs.$TargetDomain"
                }

                $srvRecords = Resolve-DnsName -Name $srvQuery -Type SRV -ErrorAction Stop |
                    Where-Object { $_.QueryType -eq 'SRV' }
                if ($null -ne $srvRecords) {
                    $discoveryMethod = "DNS_SRV ($srvQuery)"
                    foreach ($srv in ($srvRecords | Select-Object -ExpandProperty NameTarget -Unique)) {
                        $dcList.Add([PSCustomObject]@{
                            HostName  = $srv.TrimEnd('.')
                            IPAddress = $null
                            SiteName  = $endpointSiteName
                            Roles     = @()
                        })
                    }
                }
            }
            catch {}
        }
    }

    # Add any user-supplied -Server FQDNs
    if ($null -ne $ExplicitServers) {
        foreach ($s in $ExplicitServers) {
            if (-not [string]::IsNullOrWhiteSpace($s) -and -not ($dcList | Where-Object { $_.HostName -ieq $s })) {
                $dcList.Add([PSCustomObject]@{
                    HostName  = $s
                    IPAddress = $null
                    SiteName  = 'ExplicitParameter'
                    Roles     = @()
                })
            }
        }
    }

    # 3. Probe each Domain Controller across TCP 389, 636, 3268, 88 + UDP 389, 88 + LDAP RootDSE Bind
    $dcResults = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($dc in $dcList) {
        $hostName = $dc.HostName
        $resolvedIp = $dc.IPAddress
        if ([string]::IsNullOrWhiteSpace($resolvedIp)) {
            try {
                $addrs = [System.Net.Dns]::GetHostAddresses($hostName)
                if ($addrs.Count -gt 0) {
                    $ipv4Addr = $addrs | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
                    if ($null -ne $ipv4Addr) {
                        $resolvedIp = $ipv4Addr.IPAddressToString
                    }
                    else {
                        $resolvedIp = $addrs[0].IPAddressToString
                    }
                }
            }
            catch {}
        }

        $targetAddr = if (-not [string]::IsNullOrWhiteSpace($resolvedIp)) { $resolvedIp } else { $hostName }

        $tcp389  = Test-TcpPortLatency -TargetHost $targetAddr -Port 389  -TimeoutMs $TimeoutMs
        $tcp636  = Test-TcpPortLatency -TargetHost $targetAddr -Port 636  -TimeoutMs $TimeoutMs
        $tcp3268 = Test-TcpPortLatency -TargetHost $targetAddr -Port 3268 -TimeoutMs $TimeoutMs
        $tcp88   = Test-TcpPortLatency -TargetHost $targetAddr -Port 88   -TimeoutMs $TimeoutMs
        $udp389  = Test-UdpCldapProbe  -TargetHost $targetAddr -TimeoutMs $TimeoutMs
        $udp88   = Test-UdpKerberos88Probe -TargetHost $targetAddr -TimeoutMs $TimeoutMs

        # Timed LDAP RootDSE Bind & Clock Skew Calculation
        $rootDseBindSucceeded = $false
        $rootDseLatencyMs = $null
        $dcCurrentTimeUtc = $null
        $clockSkewSeconds = $null
        $isSynchronized = $null
        $isGlobalCatalogReady = $null
        $rootDseError = $null

        if ($tcp389.Reachable) {
            $swLdap = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $dse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$hostName`:389/RootDSE")
                $dse.RefreshCache(@('currentTime', 'isSynchronized', 'isGlobalCatalogReady', 'defaultNamingContext'))
                $swLdap.Stop()

                $rootDseBindSucceeded = $true
                $rootDseLatencyMs = [math]::Round($swLdap.Elapsed.TotalMilliseconds, 2)

                if ($dse.Properties['isSynchronized'].Count -gt 0) {
                    $isSynchronized = ([string]$dse.Properties['isSynchronized'][0] -ieq 'TRUE')
                }
                if ($dse.Properties['isGlobalCatalogReady'].Count -gt 0) {
                    $isGlobalCatalogReady = ([string]$dse.Properties['isGlobalCatalogReady'][0] -ieq 'TRUE')
                }
                if ($dse.Properties['currentTime'].Count -gt 0) {
                    $rawTime = [string]$dse.Properties['currentTime'][0]
                    # Format: yyyyMMddHHmmss.0Z
                    if ($rawTime -match '^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})') {
                        $dcCurrentTimeUtc = [DateTime]::new(
                            [int]$Matches[1], [int]$Matches[2], [int]$Matches[3],
                            [int]$Matches[4], [int]$Matches[5], [int]$Matches[6],
                            [DateTimeKind]::Utc
                        )
                        $clockSkewSeconds = [math]::Round(([DateTime]::UtcNow - $dcCurrentTimeUtc).TotalSeconds, 2)
                    }
                }
                $dse.Dispose()
            }
            catch {
                $swLdap.Stop()
                $rootDseError = $_.Exception.Message
            }
        }
        else {
            $rootDseError = 'Skipped RootDSE bind because TCP 389 is unreachable.'
        }

        $dcResults.Add([PSCustomObject]@{
            HostName             = $hostName
            IPAddress            = $resolvedIp
            SiteName             = $dc.SiteName
            Roles                = $dc.Roles
            Tcp389Reachable      = $tcp389.Reachable
            Tcp389LatencyMs      = $tcp389.LatencyMs
            Tcp636Reachable      = $tcp636.Reachable
            Tcp636LatencyMs      = $tcp636.LatencyMs
            Tcp3268Reachable     = $tcp3268.Reachable
            Tcp3268LatencyMs     = $tcp3268.LatencyMs
            Tcp88Reachable       = $tcp88.Reachable
            Tcp88LatencyMs       = $tcp88.LatencyMs
            Udp389CldapReachable = $udp389.Reachable
            Udp389CldapLatencyMs = $udp389.LatencyMs
            Udp88KdcReachable    = $udp88.Reachable
            Udp88KdcLatencyMs    = $udp88.LatencyMs
            Udp88Status          = $udp88.Status
            RootDseBindSucceeded = $rootDseBindSucceeded
            RootDseBindLatencyMs = $rootDseLatencyMs
            DcCurrentTimeUtc     = $dcCurrentTimeUtc
            ClockSkewSeconds     = $clockSkewSeconds
            IsSynchronized       = $isSynchronized
            IsGlobalCatalogReady = $isGlobalCatalogReady
            RootDseError         = $rootDseError
        })
    }

    [PSCustomObject]@{
        EndpointADSite       = $endpointSiteName
        SiteDiscoveryError   = $siteDiscoveryError
        DiscoveryMethod      = $discoveryMethod
        TestedDCCount        = $dcResults.Count
        ReachableDCCount     = @($dcResults | Where-Object { $_.Tcp389Reachable -and $_.Tcp88Reachable }).Count
        DomainControllers    = $dcResults.ToArray()
    }
}
#endregion

#region --- 5. Correlate Recent Netlogon & Kerberos System Event Logs ---
function Get-RecentIdentityEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$LookbackHours
    )

    $startTime = (Get-Date).AddHours(-1 * $LookbackHours)
    $events = New-Object System.Collections.Generic.List[PSCustomObject]

    # Netlogon Event IDs: 3210 (Auth failed), 5719 (No DC available), 5721, 5722 (Session setup failed), 5723, 5805
    # Kerberos Event IDs: 3, 4 (KRB_AP_ERR_MODIFIED), 6, 7, 14 (Cred error), 27 (KDC_ERR_ETYPE_NOSUPP)
    $filterXml = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
      *[System[
        Provider[@Name='NETLOGON' or @Name='Microsoft-Windows-Security-Kerberos' or @Name='LsaSrv']
        and (Level=1 or Level=2 or Level=3)
        and TimeCreated[@SystemTime &gt;= '$($startTime.ToUniversalTime().ToString("o"))']
      ]]
    </Select>
  </Query>
</QueryList>
"@

    try {
        $rawEvents = Get-WinEvent -FilterXml $filterXml -MaxEvents 25 -ErrorAction SilentlyContinue
        if ($null -ne $rawEvents) {
            foreach ($ev in $rawEvents) {
                $msgFirstLine = (($ev.Message -split '\r?\n')[0]).Trim()
                $events.Add([PSCustomObject]@{
                    TimeCreated = if ($null -ne $ev.TimeCreated) { ([DateTime]$ev.TimeCreated).ToString('o') } else { $null }
                    Provider    = $ev.ProviderName
                    EventId     = $ev.Id
                    Level       = $ev.LevelDisplayName
                    Summary     = $msgFirstLine
                })
            }
        }
    }
    catch {}

    return ,$events.ToArray()
}
#endregion

#region --- Main Execution & Root-Cause Synthesis ---
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystem = $identity.IsSystem

$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$partOfDomain = [bool]$cs.PartOfDomain
$computerName = [string]$cs.Name
$effectiveDomain = if (-not [string]::IsNullOrWhiteSpace($DomainName)) {
    $DomainName
}
elseif ($partOfDomain) {
    [string]$cs.Domain
}
else {
    $null
}

Write-Verbose "Starting AD Trust & Identity State audit on '$computerName' (Domain: '$effectiveDomain', Elevated: $isElevated, SYSTEM: $isSystem)..."

$trustState     = Test-MachineTrustState -TargetDomain $effectiveDomain -ComputerName $computerName -IsPartOfDomain $partOfDomain
$kerberosState  = Get-KerberosTicketState -IsElevated $isElevated
$credState      = Get-CredentialAndSessionState -TargetDomain $effectiveDomain -MachinePwdLastSetUtc $trustState.ADComputerObject.PwdLastSetUtc
$dcConnectivity = Test-DomainControllerConnectivity -TargetDomain $effectiveDomain -ExplicitServers $Server -QueryAllDCs $AllDomainControllers.IsPresent -TimeoutMs $SocketTimeoutMs
$recentEvents   = Get-RecentIdentityEvents -LookbackHours $EventLookbackHours

# Synthesize Findings & Overall Health Verdict
$findings = New-Object System.Collections.Generic.List[PSCustomObject]
$healthStatus = 'Healthy'

function Add-DiagnosticFinding {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Warning', 'Critical')]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Finding,

        [Parameter(Mandatory = $true)]
        [string]$Remediation
    )

    $findings.Add([PSCustomObject]@{
        Severity    = $Severity
        Category    = $Category
        Finding     = $Finding
        Remediation = $Remediation
    })

    if ($Severity -eq 'Critical') {
        $script:healthStatus = 'Critical'
    }
    elseif ($Severity -eq 'Warning' -and $script:healthStatus -ne 'Critical') {
        $script:healthStatus = 'Warning'
    }
}

if (-not $partOfDomain -and [string]::IsNullOrWhiteSpace($DomainName)) {
    Add-DiagnosticFinding -Severity 'Info' -Category 'DomainMembership' `
        -Finding "Endpoint '$computerName' is currently in a Workgroup ($($cs.Domain)), not joined to an Active Directory domain." `
        -Remediation 'Verify whether the machine should be domain-joined or pass -DomainName / -Server to test DC reachability prior to join.'
}
else {
    # Check Secure Channel
    if ($trustState.SecureChannel.Executed -and -not $trustState.SecureChannel.Healthy) {
        Add-DiagnosticFinding -Severity 'Critical' -Category 'SecureChannel' `
            -Finding "Netlogon secure channel verification failed: $($trustState.SecureChannel.RawSummary)" `
            -Remediation 'Verify DC reachability first. If local CupdTime and AD pwdLastSet have diverged, run Test-ComputerSecureChannel -Repair -Credential (Get-Credential).'
    }

    # Check LSA CupdTime vs AD pwdLastSet drift
    if ($trustState.PasswordSyncState -match '^LocalAheadOfAD') {
        Add-DiagnosticFinding -Severity 'Warning' -Category 'LsaSecretSync' `
            -Finding "Local LSA `$MACHINE.ACC\CupdTime ($($trustState.LocalLsaSecret.CupdTimeUtc)) is ahead of AD pwdLastSet ($($trustState.ADComputerObject.PwdLastSetUtc)) by $($trustState.PasswordDriftMinutes) minutes." `
            -Remediation 'Check AD replication health between site DCs or verify whether a local machine password rotation failed to commit.'
    }
    elseif ($trustState.PasswordSyncState -match '^ADAheadOfLocal') {
        Add-DiagnosticFinding -Severity 'Critical' -Category 'LsaSecretSync' `
            -Finding "AD pwdLastSet ($($trustState.ADComputerObject.PwdLastSetUtc)) is newer than local LSA `$MACHINE.ACC\CupdTime ($($trustState.LocalLsaSecret.CupdTimeUtc)) by $([math]::Abs($trustState.PasswordDriftMinutes)) minutes." `
            -Remediation 'Machine was likely reverted to a VM snapshot/image backup or another host joined with the same computer name. Run Test-ComputerSecureChannel -Repair.'
    }

    # Check AD Subnet / Site Mapping
    if ([string]::IsNullOrWhiteSpace($dcConnectivity.EndpointADSite)) {
        Add-DiagnosticFinding -Severity 'Warning' -Category 'ADSiteMapping' `
            -Finding "Endpoint could not map its current IP subnet to an Active Directory Site ($($dcConnectivity.SiteDiscoveryError))." `
            -Remediation 'Associate the endpoint or VPN subnet with an Active Directory Site in AD Sites and Services to prevent cross-WAN DC binds.'
    }

    # Check DC Reachability & Clock Skew
    if ($dcConnectivity.TestedDCCount -eq 0) {
        Add-DiagnosticFinding -Severity 'Critical' -Category 'DCReachability' `
            -Finding "Zero Domain Controllers could be discovered for domain '$effectiveDomain'." `
            -Remediation 'Verify DNS client servers point to internal AD DNS and _ldap._tcp.dc._msdcs SRV records resolve.'
    }
    elseif ($dcConnectivity.ReachableDCCount -eq 0) {
        Add-DiagnosticFinding -Severity 'Critical' -Category 'DCReachability' `
            -Finding "All $($dcConnectivity.TestedDCCount) discovered Domain Controllers failed TCP 389/88 reachability." `
            -Remediation 'Check VPN tunnel routing, firewall rules, or NDIS filter drivers blocking TCP/UDP 88 and 389.'
    }

    foreach ($dc in $dcConnectivity.DomainControllers) {
        if ($null -ne $dc.ClockSkewSeconds -and [math]::Abs($dc.ClockSkewSeconds) -gt 180) {
            $sev = if ([math]::Abs($dc.ClockSkewSeconds) -ge 300) { 'Critical' } else { 'Warning' }
            Add-DiagnosticFinding -Severity $sev -Category 'KerberosClockSkew' `
                -Finding "Clock skew against DC '$($dc.HostName)' is $($dc.ClockSkewSeconds) seconds (Kerberos maximum tolerance is 300s)." `
                -Remediation 'Resynchronize Windows Time service (`w32tm /resync /rediscover`) and verify hypervisor host time sync settings.'
        }
        if ($dc.Tcp389Reachable -and -not $dc.Udp389CldapReachable) {
            Add-DiagnosticFinding -Severity 'Warning' -Category 'CLDAPBlocked' `
                -Finding "DC '$($dc.HostName)' is reachable on TCP 389 but failed UDP 389 CLDAP ping." `
                -Remediation 'UDP 389 (CLDAP) is required for DC Locator (`DsGetDcName`) and GPO discovery; inspect VPN/firewall UDP filtering.'
        }
    }
}

# Check Kerberos Weak Crypto / Expired Tickets
foreach ($sess in @($kerberosState.SystemLogonSession, $kerberosState.CurrentCallerSession)) {
    if ($null -ne $sess) {
        if ($sess.WeakCryptoTicketCount -gt 0) {
            Add-DiagnosticFinding -Severity 'Warning' -Category 'KerberosEncryption' `
                -Finding "Session '$($sess.SessionLabel)' contains $($sess.WeakCryptoTicketCount) Kerberos ticket(s) using weak encryption (RC4/DES)." `
                -Remediation 'Audit `msDS-SupportedEncryptionTypes` on the computer/service account and local Kerberos encryption policy to ensure AES256-CTS-HMAC-SHA1-96 is enabled.'
        }
        if ($sess.ExpiredTicketCount -gt 0) {
            Add-DiagnosticFinding -Severity 'Warning' -Category 'KerberosTicketCache' `
                -Finding "Session '$($sess.SessionLabel)' contains $($sess.ExpiredTicketCount) expired Kerberos ticket(s)." `
                -Remediation 'Purge stale tickets using `klist -lh 0 -li 0x3e7 purge` (for SYSTEM) or `klist purge` (for user session).'
        }
    }
}

# Check Credential Manager & LSASS Session Overrides
if ($credState.DomainOverrideRiskCredCount -gt 0) {
    Add-DiagnosticFinding -Severity 'Warning' -Category 'CachedCredentials' `
        -Finding "Found $($credState.DomainOverrideRiskCredCount) stored credential(s) in Windows Credential Manager targeting domain/SMB/RDP resources." `
        -Remediation 'Inspect `CredentialManager.CredentialManagerEntries` and remove stale entries via `cmdkey /delete:<target>` to stop silent outbound token overrides.'
}
if ($credState.NewCredentialsSessionCount -gt 0) {
    Add-DiagnosticFinding -Severity 'Warning' -Category 'LsassSessions' `
        -Finding "Detected $($credState.NewCredentialsSessionCount) active LogonType 9 (NewCredentials / `runas /netonly`) LSASS session(s)." `
        -Remediation 'LogonType 9 sessions override outbound network credentials without changing the local identity. Terminate stale processes or log off the session.'
}
if ($credState.CachedInteractiveSessionCount -gt 0) {
    Add-DiagnosticFinding -Severity 'Info' -Category 'LsassSessions' `
        -Finding "Detected $($credState.CachedInteractiveSessionCount) CachedInteractive (LogonType 11) logon session(s) authenticated via offline domain verifier." `
        -Remediation 'If the user recently rotated their AD password over VPN, lock and unlock the workstation while connected to the DC to refresh LSASS supplemental credentials.'
}

$report = [PSCustomObject]@{
    PSTypeName             = 'JaylinTech.ADTrustAndIdentityReport'
    TimestampUtc           = [DateTime]::UtcNow.ToString('o')
    ComputerName           = $computerName
    DomainName             = $effectiveDomain
    ExecutedAs             = $identity.Name
    IsElevated             = $isElevated
    IsSystem               = $isSystem
    HealthStatus           = $healthStatus
    FindingCount           = $findings.Count
    Findings               = $findings.ToArray()
    MachineTrust           = $trustState
    KerberosTickets        = $kerberosState
    CredentialAndSessions  = $credState
    DomainControllers      = $dcConnectivity
    RecentIdentityEvents   = $recentEvents
}

if ($Json.IsPresent) {
    return ($report | ConvertTo-Json -Depth 8)
}
else {
    return $report
}
