param([string]$SourceRoot)
$ErrorActionPreference='Stop'
if(-not $SourceRoot){$SourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))}
$SourceRoot=[IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')

function Open-ReadyPanel([bool]$SelectServer=$true) {
 $registry='HKLM:\SOFTWARE\FacuSecX\ServerSecurityMonitor\ProtectedV2'
 $record=Get-ItemProperty -LiteralPath $registry
 if($record.Activated -ne 1){throw 'La instalacion todavia no se completo. Volve a iniciar el asistente.'}
 $installed=Join-Path $env:ProgramFiles 'FacuSecX\ServerSecurityMonitor'
 $hostExe=Join-Path $installed 'native\Server Monitor.exe'
 if(-not (Test-Path -LiteralPath $hostExe -PathType Leaf)){throw 'Falta el ejecutable protegido de Server Monitor. Restaura el paquete actualizado.'}
 if((Get-Item -LiteralPath (Split-Path -Parent $hostExe)).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)){throw 'La ubicacion protegida de Server Monitor no es valida.'}
 if($SelectServer){Start-Process -FilePath $hostExe -ArgumentList 'launch' -WindowStyle Normal -ErrorAction Stop;return}
 $config=Get-Content -LiteralPath (Join-Path $installed 'panel\config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
 $port=8766
 if($null -ne $config.listenPort -and -not [int]::TryParse([string]$config.listenPort,[ref]$port)){throw 'El puerto local del panel no es valido.'}
 if($port -lt 1 -or $port -gt 65535){throw 'El puerto local del panel no es valido.'}
 $origin='http://127.0.0.1:'+$port
 $ready=$false
 for($attempt=0;$attempt -lt 12;$attempt++){
  try{$health=Invoke-RestMethod -Uri ($origin+'/api/health') -TimeoutSec 2 -ErrorAction Stop;if($health.app -eq 'storypulse-security' -and $health.protected_runtime -eq $true){$ready=$true;break}}catch{}
  Start-Sleep -Milliseconds 500
 }
 if(-not $ready){throw 'El panel todavia no responde. Volve a abrirlo desde su acceso directo.'}
 Start-Process -FilePath $hostExe -ArgumentList 'agent' -WindowStyle Normal -ErrorAction Stop
 # Open from the user's launcher, with a normal window, after the final restart.
 # The browser is not a child of the hidden native authentication process.
 try{Start-Process -FilePath ($origin+'/login') -Verb Open -WindowStyle Normal -ErrorAction Stop}
 catch{throw ('No se pudo abrir el navegador. Abri '+$origin+'/login')}
}

try{
 $registry='HKLM:\SOFTWARE\FacuSecX\ServerSecurityMonitor\ProtectedV2'
 if(Test-Path -LiteralPath $registry){
  if((Get-ItemProperty -LiteralPath $registry).Activated -eq 1){Open-ReadyPanel;exit 0}
  & (Join-Path $PSScriptRoot 'Install-protected.ps1') -SourceRoot $SourceRoot
  if($LASTEXITCODE -ne 0){exit 1}
  Open-ReadyPanel $false
  exit 0
 }
 $sha=[Security.Cryptography.SHA256]::Create()
 try{$id=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($SourceRoot.ToLowerInvariant())))).Replace('-','').ToLowerInvariant().Substring(0,20)}finally{$sha.Dispose()}
 $accounts=Join-Path $env:LOCALAPPDATA ('FacuSecX\ServerSecurityMonitor\'+$id+'\accounts.dpapi')
 if((Test-Path -LiteralPath $accounts) -or (Test-Path -LiteralPath (Join-Path $SourceRoot 'data\.panel-auth-initialized'))){
  & (Join-Path $SourceRoot 'windows-launcher.ps1') -Action panel
  exit $LASTEXITCODE
 }
 & (Join-Path $PSScriptRoot 'Install-protected.ps1') -SourceRoot $SourceRoot
 if($LASTEXITCODE -ne 0){exit 1}
 Open-ReadyPanel $false
 exit 0
}catch{
 Add-Type -AssemblyName System.Windows.Forms
 [Windows.Forms.MessageBox]::Show($_.Exception.Message,'Server Monitor',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error) | Out-Null
 exit 1
}
