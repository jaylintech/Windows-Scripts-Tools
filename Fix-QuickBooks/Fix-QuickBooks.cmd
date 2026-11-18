@echo off
title Fixing QuickBooks Online Desktop...
echo Closing hung QuickBooks processes...
taskkill /F /IM "QuickBooks*" /T >nul 2>&1
taskkill /F /IM "QBO*" /T >nul 2>&1
timeout /t 2 /nobreak >nul

echo Clearing corrupted Electron state and caches...
for %%B in ("%APPDATA%\QuickBooks Advanced" "%APPDATA%\QuickBooks Online") do (
    if exist "%%~B" (
        del /F /Q "%%~B\config.json" >nul 2>&1
        for %%D in ("Cache" "Code Cache" "GPUCache" "DawnCache" "Service Worker" "blob_storage" "Session Storage" "Local Storage" "Partitions") do (
            if exist "%%~B\%%~D" rmdir /S /Q "%%~B\%%~D" >nul 2>&1
        )
    )
)

echo Relaunching QuickBooks Online...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$exe = Get-ChildItem -Path $env:LOCALAPPDATA -Include 'QuickBooks Advanced.exe','QuickBooks Online.exe','QBO.exe' -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike '*\packages\*' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName; if ($exe) { Start-Process -FilePath $exe -ArgumentList '--disable-gpu-shader-disk-cache' }"
exit
