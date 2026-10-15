@echo off
REM Server Security Monitor v2.0
REM Created by FacuSecX
REM https://github.com/FacuSecX/
setlocal
title Verificar conexion SSH
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows-launcher.ps1" -Action check
set "PANEL_EXIT=%ERRORLEVEL%"
pause
endlocal & exit /b %PANEL_EXIT%
