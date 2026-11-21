# Reset-New-Outlook

Closes New Outlook (`olk.exe`) and deletes the local `EBWebView` cache folder and `UserSettings.json` under `%LOCALAPPDATA%\Microsoft\Olk` to force a clean reload.

- **Run as the affected user (do NOT run as a different Administrator account)** so `%LOCALAPPDATA%` resolves to the target user's profile.
