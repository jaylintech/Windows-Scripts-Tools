<#
.SYNOPSIS
    Read-only Cloud Identity IR auditor for Microsoft 365 / Entra ID persistence mechanisms,
    OAuth app consent grants, refresh token lifetimes, hidden Exchange mailbox rules, and
    Windows endpoint PRT/WAM telemetry correlation.

.DESCRIPTION
    Invoke-M365IdentityPersistenceAudit.ps1 audits the four layers attackers abuse to keep
    access to a Microsoft 365 account even after a helpdesk password reset:

      1. Refresh Token & Session Validity + Auth Methods / Registered Devices:
         - Compares `signInSessionsValidFromDateTime` and `refreshTokensValidFromDateTime`
           against `lastPasswordChangeDateTime` via Microsoft Graph to flag password resets
           that did not revoke existing refresh tokens.
         - Audits registered MFA methods (`/authentication/methods`) and Entra-registered
           devices (`/registeredDevices`) for rogue persistence added inside the lookback window.

      2. OAuth App Consent Grants & Delegated/Application Permissions:
         - Enumerates user-scoped `oauth2PermissionGrants`, `appRoleAssignments`, and
           optionally tenant-wide `AllPrincipals` grants.
         - Resolves each `clientId` to its Service Principal (`appId`, `displayName`,
           `appOwnerOrganizationId`, `verifiedPublisher`) and flags non-Microsoft or
           unverified apps holding high-risk mail/file/directory scopes—especially paired
           with `offline_access`.

      3. Exchange Online Mailbox & Transport Persistence:
         - When an Exchange Online PowerShell session is active (`Connect-ExchangeOnline`),
           audits `Get-InboxRule -IncludeHidden` (flagging hidden rules, external forwarding,
           folder-hiding moves, delete/mark-as-read evasion, and BEC/security keywords),
           mailbox-level `ForwardingSmtpAddress` / `ForwardingAddress`, non-standard
           `FullAccess` / `SendAs` delegates, and optionally tenant `Get-TransportRule` rules.

      4. Entra ID Sign-In Logs & Windows Endpoint PRT Correlation:
         - Queries `/v1.0/auditLogs/signIns` over `-LookbackDays` (when Entra ID P1/P2 and
           `AuditLog.Read.All` are available) to flag legacy authentication, unmanaged device
           sign-ins, multi-country sessions, and post-reset token replay.
         - When `-CorrelateLocalEndpoint` or `-EndpointOnly` is specified, parses local
           `dsregcmd /status` (DeviceId, AzureAdPrt, PRT update/expiry timestamps) and
           `Microsoft-Windows-AAD/Operational` Event IDs (1097, 1098, 1104) to compare
           managed-device token activity against cloud sign-in records.

.PARAMETER UserPrincipalName
    Target user's UPN (for example, `jdoe@contoso.com`). Required unless `-EndpointOnly` is set.

.PARAMETER LookbackDays
    Number of days to inspect for sign-in logs, newly added MFA methods/devices, and local AAD
    Operational events. Default is 14 (valid range: 1 to 30).

.PARAMETER IncludeTenantWideGrants
    Also audits tenant-wide (`AllPrincipals`) OAuth permission grants for risky mail/directory
    scopes from non-Microsoft or unverified publishers.

.PARAMETER IncludeTenantTransportRules
    When connected to Exchange Online, also audits org-wide Exchange transport rules for
    suspicious BCC, redirect, or delete actions.

.PARAMETER CorrelateLocalEndpoint
    Collects local Windows `dsregcmd /status` and `Microsoft-Windows-AAD/Operational` telemetry
    and cross-checks the local Entra DeviceId and PRT activity against cloud sign-in logs.

.PARAMETER AadEvtxPath
    Optional path to an exported offline `Microsoft-Windows-AAD%4Operational.evtx` file for
    endpoint correlation on an analyst workstation.

.PARAMETER EndpointOnly
    Skips Microsoft Graph and Exchange Online calls and collects only local Windows Entra ID
    join / PRT / WAM telemetry.

.PARAMETER AutoConnect
    If no Microsoft Graph session is active, automatically calls `Connect-MgGraph` with the
    minimum read-only scopes required for the audit.

.PARAMETER Json
    Serializes the diagnostic report object to JSON for SIEM ingestion, RMM output, or IR
    ticket documentation.

.EXAMPLE
    Connect-MgGraph -Scopes User.Read.All,UserAuthenticationMethod.Read.All,DelegatedPermissionGrant.Read.All,Application.Read.All,AuditLog.Read.All,Directory.Read.All
    Connect-ExchangeOnline -ShowBanner:$false
    $Audit = .\Invoke-M365IdentityPersistenceAudit.ps1 -UserPrincipalName "user@contoso.com" -LookbackDays 14
    $Audit.Findings | Format-Table Severity, Category, Finding, Recommendation -Wrap

.EXAMPLE
    .\Invoke-M365IdentityPersistenceAudit.ps1 -UserPrincipalName "user@contoso.com" -CorrelateLocalEndpoint -Json

.EXAMPLE
    .\Invoke-M365IdentityPersistenceAudit.ps1 -EndpointOnly

.OUTPUTS
    PSCustomObject or String (when -Json is specified)

.NOTES
    Author:   Jaylin Halteman (jaylin.tech)
    Repo:     github.com/jaylintech/Windows-Scripts-Tools
    Requires: PowerShell 5.1 or PowerShell 7+
              Microsoft.Graph.Authentication (for Graph REST queries)
              ExchangeOnlineManagement (optional, for mailbox/transport rule checks)
#>
[CmdletBinding(DefaultParameterSetName = 'CloudAudit')]
[OutputType([PSCustomObject], [string])]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'CloudAudit', Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 30)]
    [int]$LookbackDays = 14,

    [Parameter(Mandatory = $false, ParameterSetName = 'CloudAudit')]
    [switch]$IncludeTenantWideGrants,

    [Parameter(Mandatory = $false, ParameterSetName = 'CloudAudit')]
    [switch]$IncludeTenantTransportRules,

    [Parameter(Mandatory = $false, ParameterSetName = 'CloudAudit')]
    [switch]$CorrelateLocalEndpoint,

    [Parameter(Mandatory = $false)]
    [string]$AadEvtxPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'EndpointOnly')]
    [switch]$EndpointOnly,

    [Parameter(Mandatory = $false, ParameterSetName = 'CloudAudit')]
    [switch]$AutoConnect,

    [Parameter(Mandatory = $false)]
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Constants & Reference Lists ---
$script:RequiredGraphScopes = @(
    'User.Read.All',
    'UserAuthenticationMethod.Read.All',
    'DelegatedPermissionGrant.Read.All',
    'Application.Read.All',
    'AuditLog.Read.All',
    'Directory.Read.All'
)

# Known Microsoft first-party owning tenant IDs
$script:MicrosoftOwnerTenantIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a', # Microsoft Services
    '72f988bf-86f1-41af-91ab-2d7cd011db47'  # Microsoft Corp
)

$script:CriticalOAuthScopes = @(
    'Mail.ReadWrite',
    'Mail.ReadWrite.Shared',
    'Mail.Send',
    'Mail.Send.Shared',
    'MailboxSettings.ReadWrite',
    'full_access_as_app',
    'EWS.AccessAsUser.All',
    'Directory.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory',
    'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All',
    'Files.ReadWrite.All',
    'Sites.FullControl.All',
    'UserAuthenticationMethod.ReadWrite.All'
)

$script:WarningOAuthScopes = @(
    'Mail.Read',
    'Mail.Read.Shared',
    'Mail.ReadBasic',
    'Files.Read.All',
    'Sites.Read.All',
    'User.ReadWrite.All',
    'Notes.Read.All',
    'Chat.Read',
    'Chat.ReadWrite',
    'IMAP.AccessAsUser.All',
    'POP.AccessAsUser.All',
    'SMTP.Send'
)

$script:SuspiciousRuleFolders = @(
    'rss feeds',
    'rss subscriptions',
    'conversation history',
    'junk email',
    'deleted items',
    'archive',
    'sync issues',
    'clutter'
)

$script:SuspiciousRuleKeywords = @(
    'invoice', 'wire', 'payment', 'ach', 'bank', 'remittance',
    'security', 'alert', 'password', 'mfa', 'microsoft',
    'unauthorized', 'phish', 'compromise', 'helpdesk', 'it support'
)

$script:LegacyAuthClients = @(
    'IMAP4', 'POP3', 'SMTP', 'Authenticated SMTP',
    'Exchange ActiveSync', 'Exchange Web Services',
    'AutoDiscover', 'MAPI Over HTTP', 'Other clients'
)

$script:ServicePrincipalCache = @{}
#endregion

#region --- Utility & Graph REST Helpers ---
function ConvertTo-NullableUtcDate {
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }

    $raw = [string]$Value
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    $parsed = [DateTime]::MinValue
    if ([DateTime]::TryParse($raw, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }
    return $null
}

function Format-UtcIso {
    param([object]$DateValue)

    $dt = ConvertTo-NullableUtcDate -Value $DateValue
    if ($null -eq $dt) { return $null }
    return $dt.ToString('o')
}

function Get-ErrorSummary {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    if ($null -eq $ErrorRecord) { return 'Unknown error' }
    $msg = if ($null -ne $ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        $ErrorRecord.ErrorDetails.Message
    }
    else {
        $ErrorRecord.Exception.Message
    }
    return (($msg -replace '\r?\n', ' ').Trim())
}

function Invoke-GraphRestGetAll {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [int]$MaxPages = 10
    )

    $items = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri
    $pageCount = 0

    while (-not [string]::IsNullOrWhiteSpace($nextUri) -and $pageCount -lt $MaxPages) {
        $pageCount++
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri -OutputType PSObject -ErrorAction Stop

        if ($null -eq $response) {
            break
        }

        $hasValueProp = $null -ne $response.PSObject.Properties['value']
        if ($hasValueProp) {
            if ($null -ne $response.value) {
                foreach ($entry in @($response.value)) {
                    $items.Add($entry)
                }
            }
            $nextLinkProp = $response.PSObject.Properties['@odata.nextLink']
            $nextUri = if ($null -ne $nextLinkProp -and -not [string]::IsNullOrWhiteSpace([string]$nextLinkProp.Value)) {
                [string]$nextLinkProp.Value
            }
            else {
                $null
            }
        }
        else {
            $items.Add($response)
            $nextUri = $null
        }
    }

    return ,$items.ToArray()
}

function Resolve-ServicePrincipalInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId
    )

    if ($script:ServicePrincipalCache.ContainsKey($ServicePrincipalId)) {
        return $script:ServicePrincipalCache[$ServicePrincipalId]
    }

    $info = [PSCustomObject]@{
        ServicePrincipalId     = $ServicePrincipalId
        AppId                  = $null
        DisplayName            = $null
        PublisherName          = $null
        AppOwnerOrganizationId = $null
        IsMicrosoftFirstParty  = $false
        VerifiedPublisherName  = $null
        IsVerifiedPublisher    = $false
        CreatedDateTimeUtc     = $null
        LookupError            = $null
    }

    try {
        $encodedId = [System.Uri]::EscapeDataString($ServicePrincipalId)
        $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/${encodedId}?`$select=id,appId,displayName,publisherName,appOwnerOrganizationId,verifiedPublisher,createdDateTime"
        $sp = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop

        if ($null -ne $sp) {
            $info.AppId = $sp.appId
            $info.DisplayName = $sp.displayName
            $info.PublisherName = $sp.publisherName
            $info.AppOwnerOrganizationId = $sp.appOwnerOrganizationId
            $info.IsMicrosoftFirstParty = ($null -ne $sp.appOwnerOrganizationId) -and ($script:MicrosoftOwnerTenantIds -contains ([string]$sp.appOwnerOrganizationId).ToLowerInvariant())
            if ($null -ne $sp.PSObject.Properties['verifiedPublisher'] -and $null -ne $sp.verifiedPublisher) {
                $vpId = $sp.verifiedPublisher.verifiedPublisherId
                $vpName = $sp.verifiedPublisher.displayName
                $info.VerifiedPublisherName = $vpName
                $info.IsVerifiedPublisher = -not [string]::IsNullOrWhiteSpace([string]$vpId)
            }
            $info.CreatedDateTimeUtc = Format-UtcIso -DateValue $sp.createdDateTime
        }
    }
    catch {
        $info.LookupError = Get-ErrorSummary -ErrorRecord $_
    }

    $script:ServicePrincipalCache[$ServicePrincipalId] = $info
    return $info
}

function Initialize-GraphSession {
    param([switch]$AllowAutoConnect)

    $graphStatus = [PSCustomObject]@{
        Connected   = $false
        TenantId    = $null
        Account     = $null
        AuthType    = $null
        Scopes      = @()
        MissingScopes = @()
        Error       = $null
    }

    if (-not (Get-Command -Name 'Get-MgContext' -ErrorAction SilentlyContinue)) {
        $graphStatus.Error = 'Microsoft.Graph.Authentication module is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
        return $graphStatus
    }

    $ctx = Get-MgContext
    if ($null -eq $ctx -and $AllowAutoConnect.IsPresent) {
        try {
            Connect-MgGraph -Scopes $script:RequiredGraphScopes -NoWelcome -ErrorAction Stop | Out-Null
            $ctx = Get-MgContext
        }
        catch {
            $graphStatus.Error = "Connect-MgGraph failed: $(Get-ErrorSummary -ErrorRecord $_)"
            return $graphStatus
        }
    }

    if ($null -eq $ctx) {
        $graphStatus.Error = "No active Microsoft Graph session. Run Connect-MgGraph -Scopes '$($script:RequiredGraphScopes -join "','")' or pass -AutoConnect."
        return $graphStatus
    }

    $currentScopes = @($ctx.Scopes)
    $missing = @($script:RequiredGraphScopes | Where-Object { $currentScopes -notcontains $_ })

    $graphStatus.Connected = $true
    $graphStatus.TenantId = $ctx.TenantId
    $graphStatus.Account = $ctx.Account
    $graphStatus.AuthType = $ctx.AuthType
    $graphStatus.Scopes = $currentScopes
    $graphStatus.MissingScopes = $missing
    return $graphStatus
}
#endregion

#region --- Pillar 1: User Identity, Refresh Tokens, MFA Methods & Devices ---
function Get-EntraIdentityAndTokenState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetUpn,

        [Parameter(Mandatory = $true)]
        [DateTime]$CutoffUtc
    )

    $result = [PSCustomObject]@{
        Collected                      = $false
        Error                          = $null
        UserId                         = $null
        UserPrincipalName              = $TargetUpn
        DisplayName                    = $null
        AccountEnabled                 = $null
        OnPremisesSyncEnabled          = $null
        LastPasswordChangeUtc          = $null
        SignInSessionsValidFromUtc     = $null
        RefreshTokensValidFromUtc      = $null
        TokenRevocationGapDetected     = $false
        TokenRevocationGapMinutes      = $null
        SessionEpochAgeDays            = $null
        AuthenticationMethods          = @()
        RecentlyAddedAuthMethods       = @()
        AuthMethodsError               = $null
        RegisteredDevices              = @()
        RecentlyRegisteredDevices      = @()
        RegisteredDevicesError         = $null
    }

    try {
        $encodedUpn = [System.Uri]::EscapeDataString($TargetUpn)
        $selectFields = 'id,userPrincipalName,displayName,accountEnabled,createdDateTime,lastPasswordChangeDateTime,signInSessionsValidFromDateTime,refreshTokensValidFromDateTime,onPremisesSyncEnabled'
        $userUri = "https://graph.microsoft.com/v1.0/users/${encodedUpn}?`$select=${selectFields}"
        $user = Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject -ErrorAction Stop

        $result.Collected = $true
        $result.UserId = [string]$user.id
        $result.UserPrincipalName = [string]$user.userPrincipalName
        $result.DisplayName = [string]$user.displayName
        $result.AccountEnabled = [bool]$user.accountEnabled
        $result.OnPremisesSyncEnabled = [bool]$user.onPremisesSyncEnabled

        $pwdUtc = ConvertTo-NullableUtcDate -Value $user.lastPasswordChangeDateTime
        $sessUtc = ConvertTo-NullableUtcDate -Value $user.signInSessionsValidFromDateTime
        $rtUtc = ConvertTo-NullableUtcDate -Value $user.refreshTokensValidFromDateTime

        $result.LastPasswordChangeUtc = Format-UtcIso -DateValue $pwdUtc
        $result.SignInSessionsValidFromUtc = Format-UtcIso -DateValue $sessUtc
        $result.RefreshTokensValidFromUtc = Format-UtcIso -DateValue $rtUtc

        $effectiveRevokeUtc = if ($null -ne $sessUtc) { $sessUtc } else { $rtUtc }
        if ($null -ne $effectiveRevokeUtc) {
            $result.SessionEpochAgeDays = [math]::Round(([DateTime]::UtcNow - $effectiveRevokeUtc).TotalDays, 1)
        }

        if ($null -ne $pwdUtc -and $null -ne $effectiveRevokeUtc) {
            $gapMinutes = [math]::Round(($pwdUtc - $effectiveRevokeUtc).TotalMinutes, 1)
            $result.TokenRevocationGapMinutes = $gapMinutes
            # Allow 5-minute clock/processing slack between password reset and revokeSignInSessions
            if ($gapMinutes -gt 5) {
                $result.TokenRevocationGapDetected = $true
            }
        }
    }
    catch {
        $result.Error = Get-ErrorSummary -ErrorRecord $_
        return $result
    }

    # Authentication Methods
    try {
        $encodedId = [System.Uri]::EscapeDataString($result.UserId)
        $rawMethods = Invoke-GraphRestGetAll -Uri "https://graph.microsoft.com/v1.0/users/${encodedId}/authentication/methods"
        $methodList = New-Object System.Collections.Generic.List[PSCustomObject]
        $recentMethodList = New-Object System.Collections.Generic.List[PSCustomObject]

        foreach ($m in $rawMethods) {
            $odataType = if ($null -ne $m.PSObject.Properties['@odata.type']) { [string]$m.'@odata.type' } else { 'unknown' }
            $shortType = $odataType -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''
            $createdUtc = if ($null -ne $m.PSObject.Properties['createdDateTime']) { ConvertTo-NullableUtcDate -Value $m.createdDateTime } else { $null }
            $detail = $null
            if ($null -ne $m.PSObject.Properties['displayName'] -and -not [string]::IsNullOrWhiteSpace([string]$m.displayName)) {
                $detail = [string]$m.displayName
            }
            elseif ($null -ne $m.PSObject.Properties['phoneNumber'] -and -not [string]::IsNullOrWhiteSpace([string]$m.phoneNumber)) {
                $detail = [string]$m.phoneNumber
            }
            elseif ($null -ne $m.PSObject.Properties['emailAddress'] -and -not [string]::IsNullOrWhiteSpace([string]$m.emailAddress)) {
                $detail = [string]$m.emailAddress
            }
            elseif ($null -ne $m.PSObject.Properties['model'] -and -not [string]::IsNullOrWhiteSpace([string]$m.model)) {
                $detail = [string]$m.model
            }

            $isRecent = ($null -ne $createdUtc) -and ($createdUtc -ge $CutoffUtc) -and ($shortType -ne 'password')
            $obj = [PSCustomObject]@{
                Id                 = if ($null -ne $m.PSObject.Properties['id']) { [string]$m.id } else { $null }
                MethodType         = $shortType
                Detail             = $detail
                CreatedDateTimeUtc = Format-UtcIso -DateValue $createdUtc
                AddedWithinWindow  = $isRecent
            }
            $methodList.Add($obj)
            if ($isRecent -or $shortType -eq 'temporaryAccessPass') {
                $recentMethodList.Add($obj)
            }
        }

        $result.AuthenticationMethods = $methodList.ToArray()
        $result.RecentlyAddedAuthMethods = $recentMethodList.ToArray()
    }
    catch {
        $result.AuthMethodsError = Get-ErrorSummary -ErrorRecord $_
    }

    # Registered Devices
    try {
        $encodedId = [System.Uri]::EscapeDataString($result.UserId)
        $devUri = "https://graph.microsoft.com/v1.0/users/${encodedId}/registeredDevices?`$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime,registrationDateTime"
        $rawDevices = Invoke-GraphRestGetAll -Uri $devUri
        $deviceList = New-Object System.Collections.Generic.List[PSCustomObject]
        $recentDeviceList = New-Object System.Collections.Generic.List[PSCustomObject]

        foreach ($d in $rawDevices) {
            $regUtc = if ($null -ne $d.PSObject.Properties['registrationDateTime']) { ConvertTo-NullableUtcDate -Value $d.registrationDateTime } else { $null }
            $lastSignInUtc = if ($null -ne $d.PSObject.Properties['approximateLastSignInDateTime']) { ConvertTo-NullableUtcDate -Value $d.approximateLastSignInDateTime } else { $null }
            $isManaged = if ($null -ne $d.PSObject.Properties['isManaged']) { [bool]$d.isManaged } else { $false }
            $isCompliant = if ($null -ne $d.PSObject.Properties['isCompliant']) { [bool]$d.isCompliant } else { $false }
            $isRecent = ($null -ne $regUtc) -and ($regUtc -ge $CutoffUtc)

            $devObj = [PSCustomObject]@{
                ObjectId            = if ($null -ne $d.PSObject.Properties['id']) { [string]$d.id } else { $null }
                DeviceId            = if ($null -ne $d.PSObject.Properties['deviceId']) { [string]$d.deviceId } else { $null }
                DisplayName         = if ($null -ne $d.PSObject.Properties['displayName']) { [string]$d.displayName } else { $null }
                OperatingSystem     = if ($null -ne $d.PSObject.Properties['operatingSystem']) { [string]$d.operatingSystem } else { $null }
                TrustType           = if ($null -ne $d.PSObject.Properties['trustType']) { [string]$d.trustType } else { $null }
                IsManaged           = $isManaged
                IsCompliant         = $isCompliant
                RegistrationDateUtc = Format-UtcIso -DateValue $regUtc
                LastSignInUtc       = Format-UtcIso -DateValue $lastSignInUtc
                AddedWithinWindow   = $isRecent
            }
            $deviceList.Add($devObj)
            if ($isRecent) {
                $recentDeviceList.Add($devObj)
            }
        }

        $result.RegisteredDevices = $deviceList.ToArray()
        $result.RecentlyRegisteredDevices = $recentDeviceList.ToArray()
    }
    catch {
        $result.RegisteredDevicesError = Get-ErrorSummary -ErrorRecord $_
    }

    return $result
}
#endregion

#region --- Pillar 2: OAuth App Consent Grants & App Role Assignments ---
function Get-EntraOAuthPersistenceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeTenantWide
    )

    $result = [PSCustomObject]@{
        Collected                 = $false
        Error                     = $null
        UserDelegatedGrants       = @()
        TenantWideDelegatedGrants = @()
        HighRiskGrants            = @()
        AppRoleAssignments        = @()
    }

    $highRisk = New-Object System.Collections.Generic.List[PSCustomObject]

    function Convert-OAuthGrantRecord {
        param(
            [object]$Grant,
            [string]$GrantScopeLabel
        )

        $clientId = [string]$Grant.clientId
        $spInfo = Resolve-ServicePrincipalInfo -ServicePrincipalId $clientId
        $scopeList = @(([string]$Grant.scope) -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $matchedCritical = @($scopeList | Where-Object { $script:CriticalOAuthScopes -contains $_ })
        $matchedWarning = @($scopeList | Where-Object { $script:WarningOAuthScopes -contains $_ })
        $hasOfflineAccess = $scopeList -contains 'offline_access'

        $riskLevel = 'Low'
        $reasons = New-Object System.Collections.Generic.List[string]

        if ($matchedCritical.Count -gt 0 -and -not $spInfo.IsMicrosoftFirstParty) {
            $riskLevel = 'Critical'
            $reasons.Add("Non-Microsoft app holds critical scope(s): $($matchedCritical -join ', ')")
        }
        elseif ($matchedWarning.Count -gt 0 -and -not $spInfo.IsMicrosoftFirstParty) {
            $riskLevel = 'Warning'
            $reasons.Add("Non-Microsoft app holds sensitive scope(s): $($matchedWarning -join ', ')")
        }

        if ($hasOfflineAccess -and ($matchedCritical.Count -gt 0 -or $matchedWarning.Count -gt 0) -and -not $spInfo.IsMicrosoftFirstParty) {
            $reasons.Add('Includes offline_access (persistent refresh tokens survive password reset until revoked)')
        }
        if (-not $spInfo.IsMicrosoftFirstParty -and -not $spInfo.IsVerifiedPublisher -and ($matchedCritical.Count -gt 0 -or $matchedWarning.Count -gt 0)) {
            $reasons.Add('Publisher is unverified')
        }

        return [PSCustomObject]@{
            GrantId               = [string]$Grant.id
            ConsentType           = [string]$Grant.consentType
            GrantScope            = $GrantScopeLabel
            ClientSpId            = $clientId
            AppId                 = $spInfo.AppId
            AppDisplayName        = $spInfo.DisplayName
            PublisherName         = $spInfo.PublisherName
            IsMicrosoftFirstParty = $spInfo.IsMicrosoftFirstParty
            IsVerifiedPublisher   = $spInfo.IsVerifiedPublisher
            Scopes                = $scopeList
            HasOfflineAccess      = $hasOfflineAccess
            CriticalScopes        = $matchedCritical
            WarningScopes         = $matchedWarning
            RiskLevel             = $riskLevel
            RiskReasons           = $reasons.ToArray()
        }
    }

    try {
        $encodedId = [System.Uri]::EscapeDataString($UserId)
        $rawUserGrants = Invoke-GraphRestGetAll -Uri "https://graph.microsoft.com/v1.0/users/${encodedId}/oauth2PermissionGrants"
        $userGrants = New-Object System.Collections.Generic.List[PSCustomObject]

        foreach ($g in $rawUserGrants) {
            $rec = Convert-OAuthGrantRecord -Grant $g -GrantScopeLabel 'UserPrincipal'
            $userGrants.Add($rec)
            if ($rec.RiskLevel -in @('Critical', 'Warning')) {
                $highRisk.Add($rec)
            }
        }
        $result.UserDelegatedGrants = $userGrants.ToArray()
        $result.Collected = $true
    }
    catch {
        $result.Error = "User oauth2PermissionGrants query failed: $(Get-ErrorSummary -ErrorRecord $_)"
    }

    if ($IncludeTenantWide.IsPresent) {
        try {
            $tenantFilter = [System.Uri]::EscapeDataString("consentType eq 'AllPrincipals'")
            $rawTenantGrants = Invoke-GraphRestGetAll -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=${tenantFilter}"
            $tenantGrants = New-Object System.Collections.Generic.List[PSCustomObject]

            foreach ($tg in $rawTenantGrants) {
                $rec = Convert-OAuthGrantRecord -Grant $tg -GrantScopeLabel 'TenantAllPrincipals'
                $tenantGrants.Add($rec)
                if ($rec.RiskLevel -in @('Critical', 'Warning')) {
                    $highRisk.Add($rec)
                }
            }
            $result.TenantWideDelegatedGrants = $tenantGrants.ToArray()
        }
        catch {
            $errMsg = "Tenant-wide oauth2PermissionGrants query failed: $(Get-ErrorSummary -ErrorRecord $_)"
            $result.Error = if ([string]::IsNullOrWhiteSpace($result.Error)) { $errMsg } else { "$($result.Error); $errMsg" }
        }
    }

    try {
        $encodedId = [System.Uri]::EscapeDataString($UserId)
        $rawRoles = Invoke-GraphRestGetAll -Uri "https://graph.microsoft.com/v1.0/users/${encodedId}/appRoleAssignments"
        $roleList = New-Object System.Collections.Generic.List[PSCustomObject]
        foreach ($r in $rawRoles) {
            $roleList.Add([PSCustomObject]@{
                AssignmentId        = [string]$r.id
                ResourceDisplayName = [string]$r.resourceDisplayName
                ResourceId          = [string]$r.resourceId
                AppRoleId           = [string]$r.appRoleId
                CreatedDateTimeUtc  = Format-UtcIso -DateValue $r.createdDateTime
            })
        }
        $result.AppRoleAssignments = $roleList.ToArray()
    }
    catch {
        $errMsg = "appRoleAssignments query failed: $(Get-ErrorSummary -ErrorRecord $_)"
        $result.Error = if ([string]::IsNullOrWhiteSpace($result.Error)) { $errMsg } else { "$($result.Error); $errMsg" }
    }

    $result.HighRiskGrants = $highRisk.ToArray()
    return $result
}
#endregion

#region --- Pillar 3: Exchange Online Mailbox & Transport Persistence ---
function Get-ExchangeMailboxPersistenceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetUpn,

        [Parameter(Mandatory = $false)]
        [switch]$CheckTenantTransportRules
    )

    $result = [PSCustomObject]@{
        Connected                   = $false
        Status                      = 'Skipped'
        Error                       = $null
        ForwardingSmtpAddress       = $null
        ForwardingAddress           = $null
        DeliverToMailboxAndForward  = $null
        MailboxAuditEnabled         = $null
        InboxRuleCount              = 0
        SuspiciousInboxRules        = @()
        NonDefaultDelegates         = @()
        SuspiciousTransportRules    = @()
    }

    $hasExoCmdlets = ($null -ne (Get-Command -Name 'Get-InboxRule' -ErrorAction SilentlyContinue)) -and
                     ($null -ne (Get-Command -Name 'Get-Mailbox' -ErrorAction SilentlyContinue))

    if (-not $hasExoCmdlets) {
        $result.Error = 'ExchangeOnlineManagement cmdlets not loaded. Run Connect-ExchangeOnline to include hidden inbox rules, forwarding, and delegate checks.'
        return $result
    }

    try {
        $mbx = Get-Mailbox -Identity $TargetUpn -ErrorAction Stop
        $result.Connected = $true
        $result.Status = 'Collected'
        $result.ForwardingSmtpAddress = if ($null -ne $mbx.ForwardingSmtpAddress) { [string]$mbx.ForwardingSmtpAddress } else { $null }
        $result.ForwardingAddress = if ($null -ne $mbx.ForwardingAddress) { [string]$mbx.ForwardingAddress } else { $null }
        $result.DeliverToMailboxAndForward = [bool]$mbx.DeliverToMailboxAndForward
        $result.MailboxAuditEnabled = [bool]$mbx.AuditEnabled
    }
    catch {
        $result.Error = "Exchange Online session unavailable or Get-Mailbox failed: $(Get-ErrorSummary -ErrorRecord $_)"
        return $result
    }

    # Hidden & standard inbox rules
    try {
        $visibleRules = @(Get-InboxRule -Mailbox $TargetUpn -ErrorAction Stop)
        $allRules = @(Get-InboxRule -Mailbox $TargetUpn -IncludeHidden -ErrorAction Stop)
        $visibleIds = @($visibleRules | ForEach-Object { [string]$_.RuleIdentity })

        $result.InboxRuleCount = $allRules.Count
        $suspiciousRules = New-Object System.Collections.Generic.List[PSCustomObject]

        foreach ($rule in $allRules) {
            $flags = New-Object System.Collections.Generic.List[string]
            $ruleId = [string]$rule.RuleIdentity
            $isHidden = $visibleIds -notcontains $ruleId

            if ($isHidden) {
                $flags.Add('HiddenRule (only returned with -IncludeHidden)')
            }
            if ($null -ne $rule.ForwardTo -and @($rule.ForwardTo).Count -gt 0) {
                $flags.Add("ForwardTo: $(@($rule.ForwardTo) -join ', ')")
            }
            if ($null -ne $rule.ForwardAsAttachmentTo -and @($rule.ForwardAsAttachmentTo).Count -gt 0) {
                $flags.Add("ForwardAsAttachmentTo: $(@($rule.ForwardAsAttachmentTo) -join ', ')")
            }
            if ($null -ne $rule.RedirectTo -and @($rule.RedirectTo).Count -gt 0) {
                $flags.Add("RedirectTo: $(@($rule.RedirectTo) -join ', ')")
            }
            if ($rule.DeleteMessage -eq $true -or $rule.SoftDeleteMessage -eq $true) {
                $flags.Add('DeletesMatchingMessages')
            }
            if ($rule.MarkAsRead -eq $true) {
                $flags.Add('MarksAsRead')
            }

            $moveTarget = [string]$rule.MoveToFolder
            if (-not [string]::IsNullOrWhiteSpace($moveTarget)) {
                $lowerFolder = $moveTarget.ToLowerInvariant()
                foreach ($sf in $script:SuspiciousRuleFolders) {
                    if ($lowerFolder -like "*$sf*") {
                        $flags.Add("MovesToLowVisibilityFolder: $moveTarget")
                        break
                    }
                }
            }

            $textBlob = (@(
                [string]$rule.Name,
                (@($rule.SubjectContainsWords) -join ' '),
                (@($rule.BodyContainsWords) -join ' '),
                (@($rule.SubjectOrBodyContainsWords) -join ' ')
            ) -join ' ').ToLowerInvariant()

            $matchedKw = @($script:SuspiciousRuleKeywords | Where-Object { $textBlob -match "\b$([regex]::Escape($_))\b" })
            if ($matchedKw.Count -gt 0 -and $flags.Count -gt 0) {
                $flags.Add("MatchesKeywords: $($matchedKw -join ', ')")
            }

            if ($flags.Count -gt 0) {
                $suspiciousRules.Add([PSCustomObject]@{
                    Name         = [string]$rule.Name
                    RuleIdentity = $ruleId
                    Enabled      = [bool]$rule.Enabled
                    IsHidden     = $isHidden
                    Priority     = $rule.Priority
                    Flags        = $flags.ToArray()
                    Description  = [string]$rule.Description
                })
            }
        }

        $result.SuspiciousInboxRules = $suspiciousRules.ToArray()
    }
    catch {
        $result.Error = "Get-InboxRule failed: $(Get-ErrorSummary -ErrorRecord $_)"
    }

    # Mailbox FullAccess and SendAs delegates
    $delegates = New-Object System.Collections.Generic.List[PSCustomObject]
    try {
        $fullAccess = @(Get-MailboxPermission -Identity $TargetUpn -ErrorAction SilentlyContinue | Where-Object {
            -not $_.IsInherited -and
            [string]$_.User -ne 'NT AUTHORITY\SELF' -and
            [string]$_.User -notlike 'S-1-5-*'
        })
        foreach ($perm in $fullAccess) {
            $delegates.Add([PSCustomObject]@{
                PermissionType = 'FullAccess'
                Trustee        = [string]$perm.User
                AccessRights   = (@($perm.AccessRights) -join ', ')
            })
        }

        if (Get-Command -Name 'Get-RecipientPermission' -ErrorAction SilentlyContinue) {
            $sendAs = @(Get-RecipientPermission -Identity $TargetUpn -ErrorAction SilentlyContinue | Where-Object {
                -not $_.IsInherited -and
                [string]$_.Trustee -ne 'NT AUTHORITY\SELF'
            })
            foreach ($sp in $sendAs) {
                $delegates.Add([PSCustomObject]@{
                    PermissionType = 'SendAs'
                    Trustee        = [string]$sp.Trustee
                    AccessRights   = (@($sp.AccessRights) -join ', ')
                })
            }
        }
    }
    catch {
        $errMsg = "Delegate permission query failed: $(Get-ErrorSummary -ErrorRecord $_)"
        $result.Error = if ([string]::IsNullOrWhiteSpace($result.Error)) { $errMsg } else { "$($result.Error); $errMsg" }
    }
    $result.NonDefaultDelegates = $delegates.ToArray()

    # Optional tenant-wide transport rules
    if ($CheckTenantTransportRules.IsPresent -and (Get-Command -Name 'Get-TransportRule' -ErrorAction SilentlyContinue)) {
        try {
            $trList = New-Object System.Collections.Generic.List[PSCustomObject]
            foreach ($tr in @(Get-TransportRule -ErrorAction Stop)) {
                $trFlags = New-Object System.Collections.Generic.List[string]
                if ($null -ne $tr.BlindCopyTo -and @($tr.BlindCopyTo).Count -gt 0) {
                    $trFlags.Add("BlindCopyTo: $(@($tr.BlindCopyTo) -join ', ')")
                }
                if ($null -ne $tr.RedirectMessageTo -and @($tr.RedirectMessageTo).Count -gt 0) {
                    $trFlags.Add("RedirectMessageTo: $(@($tr.RedirectMessageTo) -join ', ')")
                }
                if ($null -ne $tr.CopyTo -and @($tr.CopyTo).Count -gt 0) {
                    $trFlags.Add("CopyTo: $(@($tr.CopyTo) -join ', ')")
                }
                if ($tr.DeleteMessage -eq $true) {
                    $trFlags.Add('DeleteMessage')
                }

                if ($trFlags.Count -gt 0) {
                    $trList.Add([PSCustomObject]@{
                        Name        = [string]$tr.Name
                        State       = [string]$tr.State
                        Priority    = $tr.Priority
                        Flags       = $trFlags.ToArray()
                        Description = [string]$tr.Description
                    })
                }
            }
            $result.SuspiciousTransportRules = $trList.ToArray()
        }
        catch {
            $errMsg = "Get-TransportRule failed: $(Get-ErrorSummary -ErrorRecord $_)"
            $result.Error = if ([string]::IsNullOrWhiteSpace($result.Error)) { $errMsg } else { "$($result.Error); $errMsg" }
        }
    }

    return $result
}
#endregion

#region --- Pillar 4: Entra Sign-In Logs & Local Windows Endpoint PRT Correlation ---
function Get-EntraSignInTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetUpn,

        [Parameter(Mandatory = $true)]
        [DateTime]$CutoffUtc,

        [Parameter(Mandatory = $false)]
        [object]$LastPasswordChangeUtc,

        [Parameter(Mandatory = $false)]
        [bool]$TokenRevocationGapDetected
    )

    $result = [PSCustomObject]@{
        Collected                 = $false
        Error                     = $null
        TotalSignInsReviewed      = 0
        SuccessfulSignIns         = 0
        DistinctSourceIps         = @()
        DistinctCountries         = @()
        LegacyAuthSuccesses       = @()
        UnmanagedDeviceSuccesses  = @()
        PostResetTokenReplays     = @()
        SignInRecords             = @()
    }

    try {
        $escapedUpn = $TargetUpn.Replace("'", "''")
        $cutoffStr = $CutoffUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filterExpr = "userPrincipalName eq '$escapedUpn' and createdDateTime ge $cutoffStr"
        $encodedFilter = [System.Uri]::EscapeDataString($filterExpr)
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=${encodedFilter}&`$top=100"

        $rawSignIns = Invoke-GraphRestGetAll -Uri $uri -MaxPages 5
        $result.Collected = $true
        $result.TotalSignInsReviewed = $rawSignIns.Count

        $ips = New-Object System.Collections.Generic.HashSet[string]
        $countries = New-Object System.Collections.Generic.HashSet[string]
        $records = New-Object System.Collections.Generic.List[PSCustomObject]
        $legacyList = New-Object System.Collections.Generic.List[PSCustomObject]
        $unmanagedList = New-Object System.Collections.Generic.List[PSCustomObject]
        $postResetList = New-Object System.Collections.Generic.List[PSCustomObject]
        $pwdUtc = ConvertTo-NullableUtcDate -Value $LastPasswordChangeUtc

        foreach ($s in $rawSignIns) {
            $errCode = if ($null -ne $s.status -and $null -ne $s.status.PSObject.Properties['errorCode']) { [int]$s.status.errorCode } else { -1 }
            $isSuccess = ($errCode -eq 0)
            $createdUtc = ConvertTo-NullableUtcDate -Value $s.createdDateTime
            $ip = [string]$s.ipAddress
            $country = if ($null -ne $s.location -and $null -ne $s.location.PSObject.Properties['countryOrRegion']) { [string]$s.location.countryOrRegion } else { $null }
            $city = if ($null -ne $s.location -and $null -ne $s.location.PSObject.Properties['city']) { [string]$s.location.city } else { $null }
            $devId = if ($null -ne $s.deviceDetail -and $null -ne $s.deviceDetail.PSObject.Properties['deviceId']) { [string]$s.deviceDetail.deviceId } else { $null }
            $devOs = if ($null -ne $s.deviceDetail -and $null -ne $s.deviceDetail.PSObject.Properties['operatingSystem']) { [string]$s.deviceDetail.operatingSystem } else { $null }
            $isManaged = if ($null -ne $s.deviceDetail -and $null -ne $s.deviceDetail.PSObject.Properties['isManaged']) { [bool]$s.deviceDetail.isManaged } else { $false }
            $clientApp = [string]$s.clientAppUsed
            $appName = [string]$s.appDisplayName
            $caStatus = [string]$s.conditionalAccessStatus

            $rec = [PSCustomObject]@{
                CreatedDateTimeUtc      = Format-UtcIso -DateValue $createdUtc
                Success                 = $isSuccess
                ErrorCode               = $errCode
                IpAddress               = $ip
                Country                 = $country
                City                    = $city
                AppDisplayName          = $appName
                ClientAppUsed           = $clientApp
                DeviceId                = $devId
                DeviceOS                = $devOs
                IsManagedDevice         = $isManaged
                ConditionalAccessStatus = $caStatus
                CorrelationId           = [string]$s.correlationId
            }
            $records.Add($rec)

            if ($isSuccess) {
                $result.SuccessfulSignIns++
                if (-not [string]::IsNullOrWhiteSpace($ip)) { [void]$ips.Add($ip) }
                if (-not [string]::IsNullOrWhiteSpace($country)) { [void]$countries.Add($country) }

                if ($script:LegacyAuthClients -contains $clientApp) {
                    $legacyList.Add($rec)
                }
                if ([string]::IsNullOrWhiteSpace($devId) -or -not $isManaged) {
                    $unmanagedList.Add($rec)
                }
                if ($TokenRevocationGapDetected -and $null -ne $pwdUtc -and $null -ne $createdUtc -and $createdUtc -gt $pwdUtc -and ([string]::IsNullOrWhiteSpace($devId) -or -not $isManaged)) {
                    $postResetList.Add($rec)
                }
            }
        }

        $result.DistinctSourceIps = @($ips)
        $result.DistinctCountries = @($countries)
        $result.LegacyAuthSuccesses = $legacyList.ToArray()
        $result.UnmanagedDeviceSuccesses = $unmanagedList.ToArray()
        $result.PostResetTokenReplays = $postResetList.ToArray()
        $result.SignInRecords = $records.ToArray()
    }
    catch {
        $result.Error = Get-ErrorSummary -ErrorRecord $_
    }

    return $result
}

function Get-LocalWindowsAadTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$CutoffUtc,

        [Parameter(Mandatory = $false)]
        [string]$EvtxFilePath
    )

    $result = [PSCustomObject]@{
        Collected           = $false
        ComputerName        = $env:COMPUTERNAME
        AzureAdJoined       = $null
        DomainJoined        = $null
        DeviceId            = $null
        TenantId            = $null
        AzureAdPrt          = $null
        AzureAdPrtUpdateUtc = $null
        AzureAdPrtExpiryUtc = $null
        AadEventSource      = $null
        AadOperationalCount = 0
        AadEvents           = @()
        Error               = $null
    }

    # Parse dsregcmd /status on live Windows host
    if ([string]::IsNullOrWhiteSpace($EvtxFilePath)) {
        try {
            $dsregOutput = & dsregcmd.exe /status 2>&1
            foreach ($line in @($dsregOutput)) {
                $text = [string]$line
                if ($text -match '^\s*AzureAdJoined\s*:\s*(\S+)') { $result.AzureAdJoined = ($Matches[1] -eq 'YES') }
                elseif ($text -match '^\s*DomainJoined\s*:\s*(\S+)') { $result.DomainJoined = ($Matches[1] -eq 'YES') }
                elseif ($text -match '^\s*DeviceId\s*:\s*(\S+)') { $result.DeviceId = $Matches[1].Trim() }
                elseif ($text -match '^\s*TenantId\s*:\s*(\S+)') { $result.TenantId = $Matches[1].Trim() }
                elseif ($text -match '^\s*AzureAdPrt\s*:\s*(\S+)') { $result.AzureAdPrt = ($Matches[1] -eq 'YES') }
                elseif ($text -match '^\s*AzureAdPrtUpdateTime\s*:\s*(.+)$') { $result.AzureAdPrtUpdateUtc = Format-UtcIso -DateValue ($Matches[1].Trim() -replace '\s*UTC$', 'Z') }
                elseif ($text -match '^\s*AzureAdPrtExpiryTime\s*:\s*(.+)$') { $result.AzureAdPrtExpiryUtc = Format-UtcIso -DateValue ($Matches[1].Trim() -replace '\s*UTC$', 'Z') }
            }
            $result.Collected = $true
        }
        catch {
            $result.Error = "dsregcmd /status failed: $(Get-ErrorSummary -ErrorRecord $_)"
        }
    }

    # Read Microsoft-Windows-AAD/Operational events (1097/1098/1104/1089/1090)
    $eventList = New-Object System.Collections.Generic.List[PSCustomObject]
    try {
        $filterHash = @{
            Id        = @(1089, 1090, 1097, 1098, 1104)
            StartTime = $CutoffUtc.ToLocalTime()
        }

        if (-not [string]::IsNullOrWhiteSpace($EvtxFilePath)) {
            if (-not (Test-Path -LiteralPath $EvtxFilePath)) {
                throw "EVTX file not found: $EvtxFilePath"
            }
            $filterHash['Path'] = $EvtxFilePath
            $result.AadEventSource = $EvtxFilePath
        }
        else {
            $filterHash['LogName'] = 'Microsoft-Windows-AAD/Operational'
            $result.AadEventSource = 'Microsoft-Windows-AAD/Operational'
        }

        $rawEvents = @(Get-WinEvent -FilterHashtable $filterHash -MaxEvents 100 -ErrorAction SilentlyContinue)
        foreach ($ev in $rawEvents) {
            $firstLine = if (-not [string]::IsNullOrWhiteSpace($ev.Message)) { (($ev.Message -split '\r?\n')[0]).Trim() } else { '' }
            $eventList.Add([PSCustomObject]@{
                TimeCreatedUtc = if ($null -ne $ev.TimeCreated) { ([DateTime]$ev.TimeCreated).ToUniversalTime().ToString('o') } else { $null }
                EventId        = $ev.Id
                Level          = $ev.LevelDisplayName
                Summary        = $firstLine
            })
        }
        $result.Collected = $true
        $result.AadEvents = $eventList.ToArray()
        $result.AadOperationalCount = $eventList.Count
    }
    catch {
        $errMsg = "AAD Operational log query failed: $(Get-ErrorSummary -ErrorRecord $_)"
        $result.Error = if ([string]::IsNullOrWhiteSpace($result.Error)) { $errMsg } else { "$($result.Error); $errMsg" }
    }

    return $result
}
#endregion

#region --- Main Execution & Findings Engine ---
$cutoffUtc = [DateTime]::UtcNow.AddDays(-$LookbackDays)
$findings = New-Object System.Collections.Generic.List[PSCustomObject]
$script:healthStatus = 'Healthy'

function Add-AuditFinding {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Warning', 'Critical')]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Finding,

        [Parameter(Mandatory = $true)]
        [string]$Recommendation
    )

    $findings.Add([PSCustomObject]@{
        Severity       = $Severity
        Category       = $Category
        Finding        = $Finding
        Recommendation = $Recommendation
    })

    if ($Severity -eq 'Critical') {
        $script:healthStatus = 'Critical'
    }
    elseif ($Severity -eq 'Warning' -and $script:healthStatus -ne 'Critical') {
        $script:healthStatus = 'Warning'
    }
}

$graphSession = $null
$identityState = $null
$oauthState = $null
$exchangeState = $null
$signInState = $null
$endpointState = $null
$endpointCorrelation = $null

if (-not $EndpointOnly.IsPresent) {
    $graphSession = Initialize-GraphSession -AllowAutoConnect:$AutoConnect

    if (-not $graphSession.Connected) {
        Add-AuditFinding -Severity 'Critical' -Category 'GraphSession' `
            -Finding $graphSession.Error `
            -Recommendation "Connect with Connect-MgGraph -Scopes '$($script:RequiredGraphScopes -join "','")' and re-run."
    }
    else {
        if ($graphSession.MissingScopes.Count -gt 0) {
            Add-AuditFinding -Severity 'Info' -Category 'GraphScopes' `
                -Finding "Active Graph session is missing optional/recommended read scopes: $($graphSession.MissingScopes -join ', ')." `
                -Recommendation 'Reconnect with all read-only scopes for complete sign-in, MFA, and OAuth visibility.'
        }

        $identityState = Get-EntraIdentityAndTokenState -TargetUpn $UserPrincipalName -CutoffUtc $cutoffUtc

        if (-not $identityState.Collected) {
            Add-AuditFinding -Severity 'Critical' -Category 'UserLookup' `
                -Finding "Failed to query user '$UserPrincipalName' in Microsoft Graph: $($identityState.Error)" `
                -Recommendation 'Verify the UPN spelling and confirm the Graph session has User.Read.All.'
        }
        else {
            # Token revocation gap check
            if ($identityState.TokenRevocationGapDetected) {
                Add-AuditFinding -Severity 'Critical' -Category 'RefreshTokenPersistence' `
                    -Finding "Password was changed at $($identityState.LastPasswordChangeUtc), but signInSessionsValidFromDateTime is older ($($identityState.SignInSessionsValidFromUtc)) by $($identityState.TokenRevocationGapMinutes) minutes." `
                    -Recommendation "Run Revoke-MgUserSignInSession -UserId '$($identityState.UserId)' immediately so pre-reset refresh tokens and PRTs are invalidated."
            }
            elseif ($null -ne $identityState.SessionEpochAgeDays -and $identityState.SessionEpochAgeDays -gt 90) {
                Add-AuditFinding -Severity 'Info' -Category 'RefreshTokenPersistence' `
                    -Finding "User sign-in sessions have not been revoked in $($identityState.SessionEpochAgeDays) days (valid from $($identityState.SignInSessionsValidFromUtc))." `
                    -Recommendation 'If compromise is suspected, call Revoke-MgUserSignInSession before resetting the password.'
            }

            # Recently added MFA methods or TAP
            if ($identityState.RecentlyAddedAuthMethods.Count -gt 0) {
                $summary = ($identityState.RecentlyAddedAuthMethods | ForEach-Object { "$($_.MethodType) ($($_.Detail), added $($_.CreatedDateTimeUtc))" }) -join '; '
                Add-AuditFinding -Severity 'Warning' -Category 'MfaPersistence' `
                    -Finding "Detected $($identityState.RecentlyAddedAuthMethods.Count) MFA/authentication method(s) added in the last $LookbackDays days or active TAP: $summary" `
                    -Recommendation 'Verify each method directly with the user out-of-band and remove unauthorized MFA devices before re-enabling access.'
            }

            # Recently registered unmanaged devices
            $unmanagedRecent = @($identityState.RecentlyRegisteredDevices | Where-Object { -not $_.IsManaged })
            if ($unmanagedRecent.Count -gt 0) {
                $devSummary = ($unmanagedRecent | ForEach-Object { "$($_.DisplayName) [$($_.OperatingSystem), $($_.TrustType), reg $($_.RegistrationDateUtc)]" }) -join '; '
                Add-AuditFinding -Severity 'Warning' -Category 'DevicePersistence' `
                    -Finding "Detected $($unmanagedRecent.Count) unmanaged device(s) registered to the user in the last $LookbackDays days: $devSummary" `
                    -Recommendation 'Confirm ownership with the user and disable/delete unknown Entra-registered devices.'
            }

            # OAuth grants
            $oauthState = Get-EntraOAuthPersistenceState -UserId $identityState.UserId -IncludeTenantWide:$IncludeTenantWideGrants
            foreach ($hr in $oauthState.HighRiskGrants) {
                $sev = if ($hr.RiskLevel -eq 'Critical') { 'Critical' } else { 'Warning' }
                Add-AuditFinding -Severity $sev -Category 'OAuthConsentPersistence' `
                    -Finding "App '$($hr.AppDisplayName)' (AppId: $($hr.AppId), Scope: $($hr.GrantScope)) flagged: $($hr.RiskReasons -join '; ')." `
                    -Recommendation "Audit app usage and remove unauthorized grant via Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId '$($hr.GrantId)'."
            }

            # Sign-in logs
            $signInState = Get-EntraSignInTelemetry `
                -TargetUpn $identityState.UserPrincipalName `
                -CutoffUtc $cutoffUtc `
                -LastPasswordChangeUtc $identityState.LastPasswordChangeUtc `
                -TokenRevocationGapDetected $identityState.TokenRevocationGapDetected

            if (-not $signInState.Collected) {
                Add-AuditFinding -Severity 'Info' -Category 'SignInLogs' `
                    -Finding "Could not read /auditLogs/signIns ($($signInState.Error)). Entra ID P1/P2 and AuditLog.Read.All are required for sign-in log API queries." `
                    -Recommendation 'Verify AuditLog.Read.All scope and tenant P1/P2 licensing, or inspect Microsoft Purview Unified Audit Log.'
            }
            else {
                if ($signInState.LegacyAuthSuccesses.Count -gt 0) {
                    $clients = (@($signInState.LegacyAuthSuccesses | Select-Object -ExpandProperty ClientAppUsed -Unique)) -join ', '
                    Add-AuditFinding -Severity 'Critical' -Category 'LegacyAuthSignIn' `
                        -Finding "Observed $($signInState.LegacyAuthSuccesses.Count) successful legacy authentication sign-in(s) ($clients) in the last $LookbackDays days." `
                        -Recommendation 'Block legacy authentication via Conditional Access and audit mailbox/IMAP/SMTP access from those IPs.'
                }
                if ($signInState.DistinctCountries.Count -gt 1) {
                    Add-AuditFinding -Severity 'Warning' -Category 'SignInGeography' `
                        -Finding "Successful sign-ins originated from $($signInState.DistinctCountries.Count) distinct countries ($($signInState.DistinctCountries -join ', ')) across $($signInState.DistinctSourceIps.Count) IP(s)." `
                        -Recommendation 'Verify whether travel or VPN egress explains the country spread; correlate source IPs with ASN reputation and user timeline.'
                }
                if ($signInState.PostResetTokenReplays.Count -gt 0) {
                    Add-AuditFinding -Severity 'Critical' -Category 'PostResetTokenReplay' `
                        -Finding "Found $($signInState.PostResetTokenReplays.Count) successful unmanaged-device sign-in(s) AFTER the last password change while refresh tokens were not revoked." `
                        -Recommendation 'Revoke all refresh tokens immediately, review OAuth grants, and check for AiTM session cookie theft.'
                }
            }
        }

        # Exchange Online mailbox & transport persistence
        $exchangeState = Get-ExchangeMailboxPersistenceState -TargetUpn $UserPrincipalName -CheckTenantTransportRules:$IncludeTenantTransportRules
        if (-not $exchangeState.Connected) {
            Add-AuditFinding -Severity 'Info' -Category 'ExchangeOnline' `
                -Finding $exchangeState.Error `
                -Recommendation 'Run Connect-ExchangeOnline in the same PowerShell session to inspect hidden inbox rules, forwarding, and delegates.'
        }
        else {
            if (-not [string]::IsNullOrWhiteSpace($exchangeState.ForwardingSmtpAddress) -or -not [string]::IsNullOrWhiteSpace($exchangeState.ForwardingAddress)) {
                Add-AuditFinding -Severity 'Critical' -Category 'MailboxForwarding' `
                    -Finding "Mailbox-level forwarding is configured (ForwardingSmtpAddress='$($exchangeState.ForwardingSmtpAddress)', ForwardingAddress='$($exchangeState.ForwardingAddress)', DeliverAndForward=$($exchangeState.DeliverToMailboxAndForward))." `
                    -Recommendation "Clear unauthorized forwarding via Set-Mailbox -Identity '$UserPrincipalName' -ForwardingSmtpAddress `$null -ForwardingAddress `$null."
            }
            foreach ($rule in $exchangeState.SuspiciousInboxRules) {
                $sev = if ($rule.IsHidden -or ($rule.Flags -match 'Forward|Redirect')) { 'Critical' } else { 'Warning' }
                Add-AuditFinding -Severity $sev -Category 'InboxRulePersistence' `
                    -Finding "Suspicious inbox rule '$($rule.Name)' (Enabled=$($rule.Enabled), Hidden=$($rule.IsHidden)): $($rule.Flags -join '; ')." `
                    -Recommendation "Inspect full rule logic and remove if unauthorized via Remove-InboxRule -Mailbox '$UserPrincipalName' -Identity '$($rule.RuleIdentity)'."
            }
            if ($exchangeState.NonDefaultDelegates.Count -gt 0) {
                $delSummary = ($exchangeState.NonDefaultDelegates | ForEach-Object { "$($_.Trustee) ($($_.PermissionType))" }) -join '; '
                Add-AuditFinding -Severity 'Warning' -Category 'MailboxDelegates' `
                    -Finding "Found $($exchangeState.NonDefaultDelegates.Count) non-default mailbox delegate(s): $delSummary" `
                    -Recommendation 'Confirm business justification for each FullAccess/SendAs grant and strip unauthorized trustees.'
            }
            foreach ($tr in $exchangeState.SuspiciousTransportRules) {
                Add-AuditFinding -Severity 'Warning' -Category 'TransportRulePersistence' `
                    -Finding "Tenant transport rule '$($tr.Name)' (State=$($tr.State)) performs copy/redirect/delete: $($tr.Flags -join '; ')." `
                    -Recommendation 'Verify this transport rule against change-management records.'
            }
        }
    }
}

# Local Windows Endpoint PRT / WAM Telemetry & Cross-Correlation
if ($EndpointOnly.IsPresent -or $CorrelateLocalEndpoint.IsPresent -or -not [string]::IsNullOrWhiteSpace($AadEvtxPath)) {
    $endpointState = Get-LocalWindowsAadTelemetry -CutoffUtc $cutoffUtc -EvtxFilePath $AadEvtxPath

    if ($null -ne $signInState -and $signInState.Collected -and $null -ne $endpointState -and -not [string]::IsNullOrWhiteSpace($endpointState.DeviceId)) {
        $localDevLower = $endpointState.DeviceId.ToLowerInvariant()
        $matched = @($signInState.SignInRecords | Where-Object { $_.Success -and -not [string]::IsNullOrWhiteSpace($_.DeviceId) -and $_.DeviceId.ToLowerInvariant() -eq $localDevLower })
        $unmatched = @($signInState.SignInRecords | Where-Object { $_.Success -and ([string]::IsNullOrWhiteSpace($_.DeviceId) -or $_.DeviceId.ToLowerInvariant() -ne $localDevLower) })

        $endpointCorrelation = [PSCustomObject]@{
            LocalDeviceId                 = $endpointState.DeviceId
            MatchedCloudSuccessCount      = $matched.Count
            UnmatchedCloudSuccessCount    = $unmatched.Count
            UnmatchedSourceIps            = @($unmatched | Select-Object -ExpandProperty IpAddress -Unique)
            UnmatchedApps                 = @($unmatched | Select-Object -ExpandProperty AppDisplayName -Unique)
        }

        if ($unmatched.Count -gt 0) {
            Add-AuditFinding -Severity 'Warning' -Category 'EndpointCloudCorrelation' `
                -Finding "$($unmatched.Count) successful cloud sign-in(s) did NOT match this managed Windows endpoint's DeviceId ($($endpointState.DeviceId)). Unmatched IPs: $($endpointCorrelation.UnmatchedSourceIps -join ', ')." `
                -Recommendation 'Verify whether those sessions belong to the user''s mobile phone or indicate off-device token/cookie replay.'
        }
    }
}

$report = [PSCustomObject]@{
    PSTypeName          = 'JaylinTech.M365IdentityPersistenceReport'
    TimestampUtc        = [DateTime]::UtcNow.ToString('o')
    TargetUser          = if ($EndpointOnly.IsPresent) { $null } else { $UserPrincipalName }
    LookbackDays        = $LookbackDays
    HealthStatus        = $script:healthStatus
    FindingCount        = $findings.Count
    Findings            = $findings.ToArray()
    GraphSession        = $graphSession
    IdentityAndTokens   = $identityState
    OAuthPersistence    = $oauthState
    ExchangePersistence = $exchangeState
    SignInTelemetry     = $signInState
    EndpointTelemetry   = $endpointState
    EndpointCorrelation = $endpointCorrelation
}

if ($Json.IsPresent) {
    return ($report | ConvertTo-Json -Depth 8)
}
else {
    return $report
}
