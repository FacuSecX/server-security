param([string]$OutputRoot)
$ErrorActionPreference='Stop'
if(-not $OutputRoot){$OutputRoot=Join-Path (Split-Path -Parent $PSScriptRoot) 'build'}
$native=Join-Path $OutputRoot 'native'
& dotnet publish (Join-Path $PSScriptRoot 'MonitorHost\MonitorHost.csproj') -c Release -r win-x64 --self-contained true -o $native --nologo -warnaserror
if($LASTEXITCODE -ne 0){throw 'No se pudo compilar Server Monitor.'}
Copy-Item -LiteralPath (Join-Path $native 'FacuSecX.MonitorHost.exe') -Destination (Join-Path $native 'FacuSecX.SshBridge.exe') -Force
Copy-Item -LiteralPath (Join-Path $native 'FacuSecX.MonitorHost.exe') -Destination (Join-Path $native 'Server Monitor.exe') -Force
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:winexe /optimize+ /reference:System.Windows.Forms.dll ('/win32icon:'+(Join-Path $PSScriptRoot 'MonitorHost\server-monitor.ico')) ('/out:'+(Join-Path $OutputRoot 'Server Monitor.exe')) (Join-Path $PSScriptRoot 'PanelStarter.cs')
if($LASTEXITCODE -ne 0){throw 'No se pudo compilar el iniciador de Server Monitor.'}
