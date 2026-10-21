@echo off
if exist "%~dp0Server Monitor.exe" (
  start "" "%~dp0Server Monitor.exe"
  exit /b 0
)
echo Falta Server Monitor.exe. Restaura el paquete completo del panel.
pause
exit /b 1
