@echo off
setlocal enableextensions
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
powershell -NoProfile -ExecutionPolicy Bypass -Command "$names = @('QuickBooks Advanced.exe','QuickBooks Online.exe','QBO.exe'); $roots = @((Join-Path $env:LOCALAPPDATA 'Programs'), (Join-Path $env:LOCALAPPDATA 'Intuit'), (Join-Path $env:LOCALAPPDATA 'QuickBooks*'), (Join-Path $env:ProgramFiles 'Intuit'), (Join-Path ${env:ProgramFiles(x86)} 'Intuit')) | Where-Object { $_ -and (Test-Path $_) }; $exe = Get-ChildItem -Path $roots -Include $names -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike '*\packages\*' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName; if (-not $exe) { $exe = Get-ChildItem -Path $env:LOCALAPPDATA -Include $names -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike '*\packages\*' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName }; if ($exe) { Start-Process -FilePath $exe -ArgumentList '--disable-gpu-shader-disk-cache' } else { Write-Host 'WARNING: QuickBooks Online executable was not found under LocalAppData or Program Files.' -ForegroundColor Yellow; exit 1 }"
if errorlevel 1 pause
endlocal
exit /b 0
