@echo off
setlocal enableextensions
title Reset New Outlook Cache

echo Closing New Outlook if running...
taskkill /f /im olk.exe >nul 2>&1
timeout /t 2 /nobreak >nul

set "OLK_DIR=%LOCALAPPDATA%\Microsoft\Olk"

if exist "%OLK_DIR%\EBWebView" (
    rmdir /s /q "%OLK_DIR%\EBWebView"
    if exist "%OLK_DIR%\EBWebView" (
        echo ERROR: EBWebView folder could not be deleted ^(files may still be locked^).
    ) else (
        echo EBWebView folder deleted successfully.
    )
) else (
    echo EBWebView folder not found ^(already clean^).
)

if exist "%OLK_DIR%\UserSettings.json" (
    del /f /q "%OLK_DIR%\UserSettings.json"
    if exist "%OLK_DIR%\UserSettings.json" (
        echo ERROR: UserSettings.json could not be deleted.
    ) else (
        echo UserSettings.json deleted successfully.
    )
) else (
    echo UserSettings.json not found ^(already clean^).
)

echo.
echo Done. Reopen New Outlook and sign back into your account^(s^).
pause
endlocal
