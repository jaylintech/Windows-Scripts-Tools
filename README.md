# Windows-Scripts-Tools

PowerShell diagnostic auditors and Batch/CMD utilities for Active Directory trust & Kerberos forensics, Windows endpoint administration, Microsoft 365 Outlook maintenance, and desktop application remediation.

This repository consolidates standalone troubleshooting utilities alongside deep-dive PowerShell diagnostic tooling. Each tool lives in its own folder with dedicated documentation.

## Tools

| Tool | What it does | Admin required |
|---|---|---|
| [ActiveDirectory-GPO/Test-ADTrustAndIdentityState.ps1](ActiveDirectory-GPO/) | Deep-dive PowerShell diagnostic for AD machine trust (`nltest` + LSA `$MACHINE.ACC\CupdTime` vs. AD `pwdLastSet`), `SYSTEM` (`0x3e7`) Kerberos ticket/encryption state, Credential Manager/LSASS session overrides, and DC TCP/UDP/RootDSE latency. | Recommended (`SYSTEM` or Admin for LSA secret & `0x3e7` cache) |
| [Fix-QuickBooks](Fix-QuickBooks/) | Terminates hung QuickBooks Online Desktop processes, clears corrupted Electron state (`config.json`) and Chromium/GPU cache directories under `%APPDATA%`, and relaunches the latest binary from `%LOCALAPPDATA%` with `--disable-gpu-shader-disk-cache`. | No — touches only `%APPDATA%` and `%LOCALAPPDATA%` |
| [Disable-New-Outlook](Disable-New-Outlook/) | Sets registry values that hide the "New Outlook" toggle and block auto-migration from Outlook Classic (`HKCU` for current user, plus machine-wide `HKLM` policy when run elevated). | Optional (standard user for `HKCU`; Admin for machine-wide `HKLM`) |
| [Reset-New-Outlook](Reset-New-Outlook/) | Deletes the New Outlook (Olk) `EBWebView` cache folder and `UserSettings.json` to force a clean reload. | No — touches only `%LOCALAPPDATA%` |
| [Reset-Outlook-Classic-Cache](Reset-Outlook-Classic-Cache/) | Closes Outlook, optionally deletes `.ost` offline cache files (scheduling locked ones for deletion on reboot), and clears the Outlook temp file cache. | No |
| [WindowsSystemInfo_Report](WindowsSystemInfo_Report/) | Writes `SystemInfo_Report.txt` to the Desktop listing recently installed KB updates, mapped network drives, and installed printers. | No |

## Usage

Clone the repository or download the specific script needed for the endpoint:

```bash
git clone https://github.com/jaylintech/Windows-Scripts-Tools.git
```

- **PowerShell Diagnostics (`.ps1`):** Run from an elevated PowerShell prompt (or via RMM as `SYSTEM`) to output structured `[PSCustomObject]` or `-Json` telemetry. See [ActiveDirectory-GPO/README.md](ActiveDirectory-GPO/README.md) for parameters and examples.
- **Batch / CMD Utilities (`.bat` / `.cmd`):** Double-click to run as the current user, or right-click and choose **Run as administrator** where the table above indicates elevation is required.

## Notes

- **ActiveDirectory-GPO (`Test-ADTrustAndIdentityState.ps1`)** uses `SeBackupPrivilege` and `REG_OPTION_BACKUP_RESTORE` to read `HKLM:\SECURITY\Policy\Secrets\$MACHINE.ACC\CupdTime` without mutating registry DACLs.
- **Fix-QuickBooks (`Fix-QuickBooks.cmd`)** can be placed directly on a user's Desktop as a single portable self-service fix for wedged QuickBooks Online Electron sessions.
- **Disable-New-Outlook** targets Office `16.0` registry paths (Microsoft 365 / Office 2016–2024).
- **Reset-Outlook-Classic-Cache** prompts before deleting `.ost` files. Deleting them is safe for accounts that sync from a server — Outlook rebuilds the cache on next launch — but any data that exists *only* in a local `.ost` would be lost.
- Review any script before running it in a production environment.

## Source repositories

Consolidated from:

- [Reset-New-Outlook](https://github.com/jaylintech/Reset-New-Outlook)
- [Disable-New-Outlook](https://github.com/jaylintech/Disable-New-Outlook)
- [Reset-Outlook-Classic-Cache](https://github.com/jaylintech/Reset-Outlook-Classic-Cache)
- [WindowsSystemInfo_Report](https://github.com/jaylintech/WindowsSystemInfo_Report)
