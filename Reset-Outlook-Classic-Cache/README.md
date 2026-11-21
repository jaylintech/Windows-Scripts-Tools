# Reset-Outlook-Classic-Cache

Closes Outlook Classic (`outlook.exe`, `ucmapi.exe`, `lync.exe`), optionally deletes `.ost` offline cache files under `%LOCALAPPDATA%\Microsoft\Outlook`, and clears the `Content.Outlook` temporary attachment folder.

- **Admin required:** No for standard deletion (run as the affected user so `%LOCALAPPDATA%` resolves to their profile). Note that scheduling a locked `.ost` for deletion on next reboot via `MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT)` requires elevation.
