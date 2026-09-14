@echo off
setlocal EnableExtensions
title Verificar conexion de Server Security

set "PANEL_DIR=%~dp0"
set "ENV_FILE=%PANEL_DIR%.env"
if not exist "%ENV_FILE%" (
  echo ERROR: falta .env. Copia .env.example como .env y completalo.
  pause
  exit /b 1
)
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ENV_FILE%") do (
  if not "%%A"=="" set "%%A=%%B"
)

if not defined SERVER_SECURITY_PLINK_PATH set "SERVER_SECURITY_PLINK_PATH=C:\Program Files\PuTTY\plink.exe"
if not defined SERVER_SECURITY_SSH_PORT set "SERVER_SECURITY_SSH_PORT=22"
if not exist "%SERVER_SECURITY_PLINK_PATH%" (
  echo ERROR: no se encontro Plink.
  pause
  exit /b 1
)
if not defined SERVER_SECURITY_SSH_HOST goto :missing_config
if not defined SERVER_SECURITY_SSH_USER goto :missing_config
if not defined SERVER_SECURITY_SSH_HOST_KEY goto :missing_config

"%SERVER_SECURITY_PLINK_PATH%" -batch -agent -ssh -P %SERVER_SECURITY_SSH_PORT% -hostkey "%SERVER_SECURITY_SSH_HOST_KEY%" "%SERVER_SECURITY_SSH_USER%@%SERVER_SECURITY_SSH_HOST%" "printf 'Conexion privada correcta\n'; hostname; id"
set "CONNECT_ERROR=%ERRORLEVEL%"
if errorlevel 1 (
  echo.
  echo No se pudo conectar. Verifica Tailscale y carga la llave en Pageant.
)
pause
exit /b %CONNECT_ERROR%

:missing_config
echo ERROR: faltan datos SSH obligatorios en .env.
pause
exit /b 1
