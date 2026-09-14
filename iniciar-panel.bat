@echo off
setlocal EnableExtensions
title Server Security

set "PANEL_DIR=%~dp0"
set "ENV_FILE=%PANEL_DIR%.env"

if not exist "%ENV_FILE%" (
  echo ERROR: falta el archivo .env.
  echo Copia .env.example como .env y completa los datos de tu VPS.
  pause
  exit /b 1
)

for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ENV_FILE%") do (
  if not "%%A"=="" set "%%A=%%B"
)

if not defined SERVER_SECURITY_LISTEN_PORT set "SERVER_SECURITY_LISTEN_PORT=8765"
if not defined SERVER_SECURITY_PAGEANT_PATH set "SERVER_SECURITY_PAGEANT_PATH=C:\Program Files\PuTTY\pageant.exe"
if not defined SERVER_SECURITY_NODE_PATH set "SERVER_SECURITY_NODE_PATH=node.exe"

if defined SERVER_SECURITY_SSH_KEY_PATH (
  if not exist "%SERVER_SECURITY_PAGEANT_PATH%" (
    echo ERROR: no se encontro Pageant en "%SERVER_SECURITY_PAGEANT_PATH%".
    pause
    exit /b 1
  )
  if not exist "%SERVER_SECURITY_SSH_KEY_PATH%" (
    echo ERROR: no se encontro la llave configurada en SERVER_SECURITY_SSH_KEY_PATH.
    pause
    exit /b 1
  )
  start "" "%SERVER_SECURITY_PAGEANT_PATH%" "%SERVER_SECURITY_SSH_KEY_PATH%"
  echo Pageant esta cargando la llave del VPS.
  echo Si solicita la frase secreta, ingresala una sola vez en Pageant.
  timeout /t 3 /nobreak >nul
)

if /i "%SERVER_SECURITY_NODE_PATH%"=="node.exe" (
  where node.exe >nul 2>&1
  if errorlevel 1 (
    echo ERROR: no se encontro Node.js 22.13 o posterior.
    pause
    exit /b 1
  )
) else if not exist "%SERVER_SECURITY_NODE_PATH%" (
  echo ERROR: no se encontro Node.js en "%SERVER_SECURITY_NODE_PATH%".
  pause
  exit /b 1
)

powershell.exe -NoProfile -Command "try { $u='http://127.0.0.1:'+$env:SERVER_SECURITY_LISTEN_PORT+'/api/health'; $r=Invoke-RestMethod $u -TimeoutSec 2; if ($r.app -eq 'server-security' -and [int]$r.version -ge 13) { exit 0 }; if ($r.app -eq 'server-security') { exit 2 } } catch {}; exit 1" >nul 2>&1
set "PANEL_CHECK=%ERRORLEVEL%"
if "%PANEL_CHECK%"=="0" (
  echo Server Security ya estaba funcionando.
  start "" "http://127.0.0.1:%SERVER_SECURITY_LISTEN_PORT%"
  exit /b 0
)

if "%PANEL_CHECK%"=="2" (
  echo Actualizando la instancia anterior del panel...
  powershell.exe -NoProfile -Command "$p=[int]$env:SERVER_SECURITY_LISTEN_PORT; Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force }" >nul 2>&1
  timeout /t 2 /nobreak >nul
)

start "" "http://127.0.0.1:%SERVER_SECURITY_LISTEN_PORT%"
"%SERVER_SECURITY_NODE_PATH%" "%PANEL_DIR%server.mjs"

if errorlevel 1 (
  echo.
  echo El panel termino con un error.
  pause
)

endlocal
