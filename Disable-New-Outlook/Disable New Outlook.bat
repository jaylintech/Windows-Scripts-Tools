@echo off
setlocal enableextensions

set "IS_ADMIN=0"
net session >nul 2>&1 && set "IS_ADMIN=1"

echo Applying Outlook registry settings for current user (%USERNAME%)...

set "BASE=HKCU\Software\Microsoft\Office\16.0\Outlook"
set "REG=REG ADD"
set "DWORD=/t REG_DWORD /f"
set "ERR=0"

%REG% "%BASE%\Options\General" /v HideNewOutlookToggle                  %DWORD% /d 1 || set "ERR=1"
%REG% "%BASE%\Options\General" /v DoNewOutlookAutoMigration             %DWORD% /d 0 || set "ERR=1"
%REG% "%BASE%\Options\General" /v NewOutlookAutoMigrationRetryIntervals %DWORD% /d 0 || set "ERR=1"
%REG% "%BASE%\Preferences"     /v UseNewOutlook                         %DWORD% /d 0 || set "ERR=1"

set "POL=HKCU\Software\Policies\Microsoft\Office\16.0\Outlook"
%REG% "%POL%\Options\General"  /v HideNewOutlookToggle                  %DWORD% /d 1 || set "ERR=1"

if "%IS_ADMIN%"=="1" (
    echo Running elevated: also applying machine-wide policy under HKLM...
    set "HKLM_POL=HKLM\Software\Policies\Microsoft\Office\16.0\Outlook"
    %REG% "%HKLM_POL%\Options\General" /v HideNewOutlookToggle          %DWORD% /d 1 || set "ERR=1"
    %REG% "%HKLM_POL%\Options\General" /v DoNewOutlookAutoMigration     %DWORD% /d 0 || set "ERR=1"
    echo NOTE: HKCU keys were written to the elevated account ^(%USERNAME%^); HKLM policy applies to all users.
) else (
    echo Tip: Run as Administrator if you also want machine-wide HKLM policy enforcement.
)

if "%ERR%"=="0" (
    echo All settings applied successfully.
) else (
    echo WARNING: One or more registry writes failed. Review the output above.
)
pause
endlocal
