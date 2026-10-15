@echo off
REM Server Security Monitor v2.0
REM Created by FacuSecX
REM https://github.com/FacuSecX/
setlocal
title Server Monitor - Server Security 2.0
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows-launcher.ps1" -Action panel
set "PANEL_EXIT=%ERRORLEVEL%"
if not "%PANEL_EXIT%"=="0" pause
endlocal & exit /b %PANEL_EXIT%
