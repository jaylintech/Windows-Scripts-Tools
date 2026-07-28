# Windows-Scripts-Tools

A collection of batch scripts for Windows administration and troubleshooting, mostly
focused on Microsoft Outlook maintenance.

This repository consolidates four previously separate repositories. Each tool keeps its
own folder, its original README, and its full commit history.

## Tools

| Tool | What it does | Admin required |
|---|---|---|
| [Disable-New-Outlook](Disable-New-Outlook/) | Sets registry values that hide the "New Outlook" toggle and block auto-migration from Outlook Classic. | Yes — the script exits if not elevated |
| [Reset-New-Outlook](Reset-New-Outlook/) | Deletes the New Outlook (Olk) `EBWebView` cache folder and `UserSettings.json` to force a clean reload. | No — touches only `%LOCALAPPDATA%` |
| [Reset-Outlook-Classic-Cache](Reset-Outlook-Classic-Cache/) | Closes Outlook, optionally deletes `.ost` offline cache files (scheduling locked ones for deletion on reboot), and clears the Outlook temp file cache. | No |
| [WindowsSystemInfo_Report](WindowsSystemInfo_Report/) | Writes `SystemInfo_Report.txt` to the Desktop listing recently installed KB updates, mapped network drives, and installed printers. | No |

## Usage

Download or clone the repository, then run the `.bat` file for the tool you need.
Where the table above says admin is required, right-click the file and choose
**Run as administrator**.

```bash
git clone https://github.com/jaylintech/Windows-Scripts-Tools.git
```

## Notes

- **Disable-New-Outlook** targets Office `16.0` registry paths (Microsoft 365 / Office 2016–2024).
- **Reset-Outlook-Classic-Cache** prompts before deleting `.ost` files. Deleting them is safe
  for accounts that sync from a server — Outlook rebuilds the cache on next launch — but any
  data that exists *only* in a local `.ost` would be lost.
- These scripts modify user profile data and registry settings. Review a script before
  running it in a production environment.

## Source repositories

Merged from:

- [Reset-New-Outlook](https://github.com/jaylintech/Reset-New-Outlook)
- [Disable-New-Outlook](https://github.com/jaylintech/Disable-New-Outlook)
- [Reset-Outlook-Classic-Cache](https://github.com/jaylintech/Reset-Outlook-Classic-Cache)
- [WindowsSystemInfo_Report](https://github.com/jaylintech/WindowsSystemInfo_Report)
