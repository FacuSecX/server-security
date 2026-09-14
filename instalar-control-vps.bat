@echo off
setlocal EnableExtensions
title Instalar control de Server Security

set "PANEL_DIR=%~dp0"
set "ENV_FILE=%PANEL_DIR%.env"

if not exist "%ENV_FILE%" goto :missing_env
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ENV_FILE%") do (
  if not "%%A"=="" set "%%A=%%B"
)

if not defined SERVER_SECURITY_PAGEANT_PATH set "SERVER_SECURITY_PAGEANT_PATH=C:\Program Files\PuTTY\pageant.exe"
if not defined SERVER_SECURITY_PLINK_PATH set "SERVER_SECURITY_PLINK_PATH=C:\Program Files\PuTTY\plink.exe"
if not defined SERVER_SECURITY_SSH_PORT set "SERVER_SECURITY_SSH_PORT=22"

if not defined SERVER_SECURITY_SSH_HOST goto :missing_config
if not defined SERVER_SECURITY_SSH_USER goto :missing_config
if not defined SERVER_SECURITY_SSH_HOST_KEY goto :missing_config
if not exist "%SERVER_SECURITY_PAGEANT_PATH%" goto :missing_files
if not exist "%SERVER_SECURITY_PLINK_PATH%" goto :missing_files
if not exist "%PANEL_DIR%vps\server-securityctl.py" goto :missing_files
if not exist "%PANEL_DIR%vps\server-security-settings.example.json" goto :missing_files
if not exist "%PANEL_DIR%vps\instalar-control-bloqueos.sh" goto :missing_files
if not exist "%PANEL_DIR%collector.py" goto :missing_files

if defined SERVER_SECURITY_SSH_KEY_PATH (
  if not exist "%SERVER_SECURITY_SSH_KEY_PATH%" goto :missing_files
  start "" "%SERVER_SECURITY_PAGEANT_PATH%" "%SERVER_SECURITY_SSH_KEY_PATH%"
  echo Desbloquea la llave en Pageant si aparece la solicitud.
  timeout /t 3 /nobreak >nul
)

echo.
echo Instalando el controlador limitado en el VPS...
tar.exe -cf - -C "%PANEL_DIR%" collector.py -C "%PANEL_DIR%vps" server-securityctl.py server-security-settings.example.json instalar-control-bloqueos.sh | "%SERVER_SECURITY_PLINK_PATH%" -batch -agent -ssh -P %SERVER_SECURITY_SSH_PORT% -hostkey "%SERVER_SECURITY_SSH_HOST_KEY%" "%SERVER_SECURITY_SSH_USER%@%SERVER_SECURITY_SSH_HOST%" "umask 077; d=$(mktemp -d /tmp/server-security.XXXXXX); tar -xf - -C $d; sudo -n sh $d/instalar-control-bloqueos.sh $d/server-securityctl.py $d/server-security-settings.example.json $d/collector.py"
if errorlevel 1 (
  echo.
  echo ERROR: no se pudo instalar. Verifica Tailscale, Pageant, la llave y el acceso sudo.
  pause
  exit /b 1
)

echo.
echo Instalacion terminada. Reinicia iniciar-panel.bat.
pause
exit /b 0

:missing_env
echo ERROR: falta .env. Copia .env.example como .env y completalo.
pause
exit /b 1

:missing_config
echo ERROR: faltan SERVER_SECURITY_SSH_HOST, SERVER_SECURITY_SSH_USER o SERVER_SECURITY_SSH_HOST_KEY en .env.
pause
exit /b 1

:missing_files
echo ERROR: falta PuTTY, la llave configurada o un archivo del instalador.
pause
exit /b 1
