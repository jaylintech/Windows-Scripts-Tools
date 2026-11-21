# Disable-New-Outlook

Sets Outlook `16.0` registry values to hide the **Try the new Outlook** toggle and block automatic migration from Outlook Classic.

- **Standard user (recommended for per-user fix):** Applies all `HKCU` settings directly to the signed-in user's profile.
- **Administrator (optional for machine-wide enforcement):** Also writes `HKLM\Software\Policies\Microsoft\Office\16.0\Outlook\Options\General` for all users on the endpoint.
