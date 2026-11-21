# M365-EntraID-IR

Read-only PowerShell incident response tooling for auditing Microsoft 365 and Entra ID persistence mechanisms—refresh token gaps, illicit OAuth consent grants, hidden Exchange inbox rules, and cloud-to-Windows endpoint PRT correlation.

---

## `Invoke-M365IdentityPersistenceAudit.ps1`

Built for rapid account-compromise triage when a helpdesk password reset alone isn't enough to prove an attacker is actually out of a Microsoft 365 mailbox or Entra ID session.

### What It Audits

1. **Refresh Token & Session Validity (`signInSessionsValidFromDateTime` vs. `lastPasswordChangeDateTime`)**
   - Queries Microsoft Graph (`/v1.0/users/{upn}`) and flags accounts where a password was rotated without revoking existing refresh tokens and PRTs (`Revoke-MgUserSignInSession`).
   - Audits `/authentication/methods` for newly added MFA devices or active Temporary Access Passes (TAP) and `/registeredDevices` for recently registered unmanaged/BYOD devices.

2. **OAuth App Consent Grants & Delegated Permissions**
   - Enumerates user-scoped `oauth2PermissionGrants`, `appRoleAssignments`, and optionally tenant-wide `AllPrincipals` grants (`-IncludeTenantWideGrants`).
   - Resolves each `clientId` to its Service Principal (`appId`, `displayName`, `appOwnerOrganizationId`, `verifiedPublisher`) and flags non-Microsoft or unverified apps holding high-risk scopes (`Mail.ReadWrite`, `Mail.Send`, `MailboxSettings.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, etc.)—especially when paired with `offline_access`.

3. **Exchange Online Mailbox & Transport Persistence**
   - When connected to Exchange Online (`Connect-ExchangeOnline`), runs `Get-InboxRule -IncludeHidden` to catch hidden rules (`PR_RULE_MSG_PROVIDER` tampering), external forwarding/redirection, delete/mark-as-read evasion, moves into low-visibility folders (`RSS Feeds`, `Conversation History`, `Archive`), and BEC/security-alert keyword filters.
   - Checks mailbox-level `ForwardingSmtpAddress` / `ForwardingAddress`, non-default `FullAccess` / `SendAs` delegates, and optionally tenant-wide `Get-TransportRule` rules (`-IncludeTenantTransportRules`).

4. **Entra ID Sign-In Logs & Windows Endpoint PRT/WAM Correlation**
   - Queries `/v1.0/auditLogs/signIns` over `-LookbackDays` (requires Entra ID P1/P2 + `AuditLog.Read.All`) to flag legacy authentication (`IMAP4`, `POP3`, `SMTP`, `EAS`), unmanaged-device successes, multi-country sessions, and post-reset token replay.
   - With `-CorrelateLocalEndpoint` (or `-EndpointOnly` / `-AadEvtxPath`), parses local `dsregcmd /status` (`DeviceId`, `AzureAdPrt`, PRT update/expiry times) and `Microsoft-Windows-AAD/Operational` Event IDs (`1089`, `1090`, `1097`, `1098`, `1104`) to highlight cloud sign-ins that don't match the user's managed Windows device.

### Required Read-Only Permissions

- **Microsoft Graph (`Microsoft.Graph.Authentication`):**
  - `User.Read.All`
  - `UserAuthenticationMethod.Read.All`
  - `DelegatedPermissionGrant.Read.All`
  - `Application.Read.All`
  - `AuditLog.Read.All` *(requires Entra ID P1/P2 for `/auditLogs/signIns`)*
  - `Directory.Read.All`
- **Exchange Online (`ExchangeOnlineManagement`, optional):** View-Only Recipients / Security Reader or Exchange Administrator.

### Usage

```powershell
# 1. Connect with read-only Graph scopes (and optionally Exchange Online)
Connect-MgGraph -Scopes User.Read.All,UserAuthenticationMethod.Read.All,DelegatedPermissionGrant.Read.All,Application.Read.All,AuditLog.Read.All,Directory.Read.All -NoWelcome
Connect-ExchangeOnline -ShowBanner:$false

# 2. Run a full account persistence audit and view prioritized findings
$Audit = .\Invoke-M365IdentityPersistenceAudit.ps1 -UserPrincipalName "user@contoso.com" -LookbackDays 14
$Audit.Findings | Format-Table Severity, Category, Finding, Recommendation -Wrap

# 3. Correlate cloud sign-ins against the local Windows endpoint (or offline AAD .evtx) and emit JSON
.\Invoke-M365IdentityPersistenceAudit.ps1 -UserPrincipalName "user@contoso.com" -CorrelateLocalEndpoint -IncludeTenantWideGrants -Json

# 4. Collect local Windows Entra join / PRT / WAM telemetry only (no Graph session needed)
.\Invoke-M365IdentityPersistenceAudit.ps1 -EndpointOnly
```
