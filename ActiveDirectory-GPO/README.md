# ActiveDirectory-GPO

Low-level PowerShell diagnostic tools for isolating Active Directory trust failures, Kerberos ticket/encryption mismatches, cached credential lockouts, and Group Policy processing bottlenecks without requiring RSAT or third-party modules.

---

## `Test-ADTrustAndIdentityState.ps1`

Built for endpoints suffering from broken domain trust relationships, intermittent LDAP bind drops, or stale cached identity locks after password rotations or VPN state transitions.

### Root Mechanics

1. **Machine Trust & LSA Secret Synchronization (`$MACHINE.ACC\CupdTime` vs. AD `pwdLastSet`)**
   - Validates the Netlogon secure channel via `nltest /sc_query:<Domain>`.
   - Reads the local LSA machine password timestamp (`HKLM:\SECURITY\Policy\Secrets\$MACHINE.ACC\CupdTime`) directly when running as `SYSTEM` or via `SeBackupPrivilege` + `RegOpenKeyEx(..., REG_OPTION_BACKUP_RESTORE, ...)` when running as an elevated Administrator—without modifying DACLs on `HKLM:\SECURITY`.
   - Binds to Active Directory via `[System.DirectoryServices.DirectorySearcher]` to retrieve the computer object's `pwdLastSet`, `msDS-SupportedEncryptionTypes`, and SPNs, calculating exact password drift (`InSync`, `LocalAheadOfAD`, or `ADAheadOfLocal`).

2. **`SYSTEM` (`0x3e7`) & Interactive Kerberos Ticket Cache Inspection**
   - Parses `klist -lh 0 -li 0x3e7` (`SYSTEM` LogonSession) and the current session's `klist` output.
   - Flags legacy encryption fallbacks (`RC4-HMAC`, `DES`), ticket/session key encryption mismatches, and expired TGTs or service tickets.

3. **Credential Manager & LSASS LogonSession Override Audit**
   - Parses `cmdkey /list` to expose stored `Domain Password` or generic credentials that silently override machine or interactive tokens during outbound SMB/LDAP negotiation.
   - Correlates `Win32_LogonSession`, `Win32_LoggedOnUser`, and `MSFT_SmbConnection` to surface `LogonType 9` (`NewCredentials` / `runas /netonly`), `LogonType 11` (`CachedInteractive`), and sessions predating the latest machine password rotation.

4. **Domain Controller Raw Socket & RootDSE Bind Telemetry**
   - Discovers current site DCs via `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindAllDomainControllers()`, falling back to `_ldap._tcp.dc._msdcs.<domain>` DNS SRV resolution if the trust is broken.
   - Measures raw TCP handshake latency across ports `389` (LDAP), `636` (LDAPS), `3268` (Global Catalog), and `88` (Kerberos).
   - Sends a 44-byte ASN.1 BER CLDAP RootDSE `SearchRequest` over UDP `389` and a Kerberos probe over UDP `88`, distinguishing live KDC/CLDAP responses from `ICMP Port Unreachable` (`WSAECONNRESET`) and silent firewall drops.
   - Performs timed LDAP RootDSE binds and parses `RootDSE.currentTime` to compute exact endpoint-to-DC clock skew in seconds.

### Usage

```powershell
# Run default diagnostic (outputs structured [PSCustomObject] to the pipeline)
$Audit = .\Test-ADTrustAndIdentityState.ps1
$Audit.Findings | Format-Table Severity, Category, Finding -Wrap

# Inspect per-DC socket and RootDSE latency + Kerberos clock skew
$Audit.DomainControllers.DomainControllers |
    Format-Table HostName, Tcp389LatencyMs, Udp389CldapLatencyMs, RootDseBindLatencyMs, ClockSkewSeconds

# Audit all DCs in the domain and output JSON for RMM custom fields or ticket notes
.\Test-ADTrustAndIdentityState.ps1 -AllDomainControllers -Json
```
