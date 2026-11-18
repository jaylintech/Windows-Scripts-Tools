# Fix-QuickBooks (`Fix-QuickBooks.cmd`)

Portable remediation script for the **QuickBooks Online Desktop** (Electron) Windows client when the app hangs on launch, renders a blank white/black screen, or gets stuck in an authentication/cache loop.

## What It Does

1. **Terminates Hung Processes:** Force-closes stuck `QuickBooks*` and `QBO*` process trees (`taskkill /F /T`).
2. **Clears Corrupted Electron State & Caches:** Iterates through both `%APPDATA%\QuickBooks Advanced` and `%APPDATA%\QuickBooks Online`, removing `config.json` and wiping corrupted Chromium/Electron storage directories:
   - `Cache`, `Code Cache`, `GPUCache`, `DawnCache`
   - `Service Worker`, `blob_storage`, `Session Storage`, `Local Storage`, `Partitions`
3. **Relaunches Latest Binary with GPU Cache Bypass:** Locates the newest installed QuickBooks Online executable under `%LOCALAPPDATA%` (excluding Squirrel/installer `\packages\` staging paths) and launches it with `--disable-gpu-shader-disk-cache`.

## Usage

- **Admin Required:** No (operates strictly within the current user's `%APPDATA%` and `%LOCALAPPDATA%` profile directories).
- Save `Fix-QuickBooks.cmd` directly to the user's Desktop (or run from this folder) and double-click to execute.

## Verification

Double-clicking `Fix-QuickBooks.cmd` terminates stuck QuickBooks tasks, removes the `%APPDATA%` Electron cache directories, and automatically launches the latest installed binary from `%LOCALAPPDATA%`.
