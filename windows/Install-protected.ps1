param([string]$SourceRoot,[string]$OwnerSid,[switch]$Elevated)
$ErrorActionPreference='Stop'
trap {
 Add-Type -AssemblyName System.Windows.Forms
 [Windows.Forms.MessageBox]::Show($_.Exception.Message,'Protección local de Server Monitor',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error) | Out-Null
 exit 1
}
if(-not $SourceRoot){$SourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))}
$SourceRoot=[IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
$currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if(-not $OwnerSid){$OwnerSid=$currentSid}
$isAdministrator=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $isAdministrator){
 if($Elevated){throw 'La elevación administrativa no se completó.'}
 $quotedScript='"'+$PSCommandPath+'"';$quotedSource='"'+$SourceRoot+'"'
 $process=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$quotedScript,'-SourceRoot',$quotedSource,'-OwnerSid',$OwnerSid,'-Elevated') -Verb RunAs -WindowStyle Hidden -PassThru
 $process.WaitForExit();exit $process.ExitCode
}
if($currentSid -ne $OwnerSid){throw 'Usá elevación del mismo usuario de Windows propietario de las cuentas.'}
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class FacuSecXInstallPrivilege {
 [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct Privilege { public uint Count; public Luid Id; public uint Attributes; }
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid id);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref Privilege value,uint length,IntPtr previous,IntPtr result);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 public static void Enable() {
  IntPtr token;if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception();
  try { Luid id;if(!LookupPrivilegeValue(null,"SeRestorePrivilege",out id))throw new Win32Exception();var value=new Privilege{Count=1,Id=id,Attributes=2};if(!AdjustTokenPrivileges(token,false,ref value,0,IntPtr.Zero,IntPtr.Zero)||Marshal.GetLastWin32Error()!=0)throw new Win32Exception(); }
  finally {CloseHandle(token);}
 }
}
'@
[FacuSecXInstallPrivilege]::Enable()
$install=Join-Path $env:ProgramFiles 'FacuSecX\ServerSecurityMonitor'
$state=Join-Path $env:ProgramData 'FacuSecX\ServerSecurityMonitor\ProtectedV2'
$registry='HKLM:\SOFTWARE\FacuSecX\ServerSecurityMonitor\ProtectedV2'
$serviceName='FacuSecXMonitor'
$createdMutex=$false
$installMutex=[Threading.Mutex]::new($true,'Global\FacuSecXMonitorProtectedInstall',[ref]$createdMutex)
if(-not $createdMutex){throw 'Ya hay una instalación de protección en curso.'}
$resume=$false
if(Test-Path -LiteralPath $registry){
 $existing=Get-ItemProperty -LiteralPath $registry
 if($existing.Activated -eq 1){throw 'La instalación ya está activa. Abrí iniciar-panel.bat; no se reemplazará la conexión existente.'}
 if($existing.SetupPending -ne 1 -or $existing.OwnerSid -ne $OwnerSid -or -not [string]::Equals($existing.SourceRoot,$SourceRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'No se puede reanudar esta instalación desde otra identidad o carpeta. No se reinicializarán sus cuentas.'}
 if(-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)){throw 'Falta el servicio de una instalación registrada. Se requiere recuperar la instalación; no se crearán cuentas nuevas.'}
 $resume=$true
}elseif(Get-Service -Name $serviceName -ErrorAction SilentlyContinue){throw 'Existe un servicio sin su registro. Recuperá la instalación; no se creará otro propietario.'}
$package=Join-Path $PSScriptRoot '..\protected-package'
$manifest=Get-Content -LiteralPath (Join-Path $package 'manifest.json') -Raw | ConvertFrom-Json
foreach($entry in $manifest){
 $file=[IO.Path]::GetFullPath((Join-Path $package $entry.path));$base=[IO.Path]::GetFullPath($package).TrimEnd('\')+'\'
 if(-not $file.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or (Get-Item -LiteralPath $file).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $entry.sha256){throw 'El paquete está incompleto o fue modificado.'}
}
if(-not $resume -and (Test-Path -LiteralPath $install)){throw 'La carpeta protegida ya existe. No se reemplazará automáticamente.'}
function Protect-Directory([string]$Path,[string]$ServiceSid,[bool]$ServiceWrite){
 $item=Get-Item -LiteralPath $Path -Force
 if($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)){throw 'La instalación no admite enlaces ni puntos de unión.'}
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'));$acl.SetAccessRuleProtection($true,$false)
 foreach($identity in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($identity),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 if($ServiceSid){$rights=if($ServiceWrite){'FullControl'}else{'ReadAndExecute'};$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($ServiceSid),$rights,'ContainerInherit,ObjectInherit','None','Allow'))}
 if(-not $ServiceWrite){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($OwnerSid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))}
 Set-Acl -LiteralPath $Path -AclObject $acl
}
$oldStopped=@();$serviceCreated=$false;$activated=$false;$createdDirectories=[Collections.Generic.List[string]]::new()
try{
 if(-not $resume){
 New-Item -ItemType Directory -Path $install -Force | Out-Null
 $createdDirectories.Add($install)
 Protect-Directory $install '' $false
 foreach($part in @((Join-Path $env:ProgramData 'FacuSecX'),(Join-Path $env:ProgramData 'FacuSecX\ServerSecurityMonitor'),$state)){
  if(Test-Path -LiteralPath $part){throw 'Hay datos previos en ProgramData. No se modificará una instalación anterior sin revisar su respaldo.'}
  New-Item -ItemType Directory -Path $part | Out-Null;$createdDirectories.Add($part);Protect-Directory $part '' $true
 }
 foreach($entry in $manifest){
  $destination=[IO.Path]::GetFullPath((Join-Path $install $entry.path));$base=$install.TrimEnd('\')+'\'
  if(-not $destination.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)){throw 'Ruta del paquete no válida.'}
  New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $package $entry.path) -Destination $destination
  if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $entry.sha256){throw 'El archivo copiado no coincide con el paquete validado.'}
 }
 $initialConfig=Join-Path $SourceRoot 'config.json'
 if(Test-Path -LiteralPath $initialConfig){Copy-Item -LiteralPath $initialConfig -Destination (Join-Path $install 'panel\config.json')}
 else{
  $initial=Get-Content -LiteralPath (Join-Path $SourceRoot 'config.example.json') -Raw -Encoding UTF8 | ConvertFrom-Json
  $initial.ssh.authMode='password';$initial.ssh.host='';$initial.ssh.user='';$initial.ssh.keyPath='';$initial.ssh.hostKeyFingerprint='';$initial.trustedSshIps=@()
  [IO.File]::WriteAllText((Join-Path $install 'panel\config.json'),($initial | ConvertTo-Json -Depth 50),[Text.UTF8Encoding]::new($false))
 }
 $approvals=Join-Path $SourceRoot 'provider-approvals.json';if(Test-Path -LiteralPath $approvals){Copy-Item -LiteralPath $approvals -Destination (Join-Path $install 'panel\provider-approvals.json')}
 $hostExe=Join-Path $install 'native\FacuSecX.MonitorHost.exe'
 $sc=Join-Path $env:SystemRoot 'System32\sc.exe'
 $serviceBinary='"'+$hostExe+'" service'
 if($PSVersionTable.PSVersion.Major -lt 7){$serviceBinary=$serviceBinary.Replace('"','\"')}
 $registration=@(& $sc create $serviceName binPath= $serviceBinary start= demand obj= ('NT SERVICE\'+$serviceName) 2>&1)
 $registrationExit=$LASTEXITCODE
 if($registrationExit -ne 0){throw ('Windows no pudo registrar el servicio (código '+$registrationExit+'): '+($registration -join ' '))};$serviceCreated=$true
 Set-Service -Name $serviceName -DisplayName 'Server Monitor'
 & $sc sidtype $serviceName unrestricted | Out-Null
 $serviceSid=([Security.Principal.NTAccount]::new('NT SERVICE',$serviceName)).Translate([Security.Principal.SecurityIdentifier]).Value
 Protect-Directory $install $serviceSid $false
 Protect-Directory $state $serviceSid $true
 foreach($parent in @((Join-Path $env:ProgramData 'FacuSecX'),(Join-Path $env:ProgramData 'FacuSecX\ServerSecurityMonitor'))){
  $acl=Get-Acl -LiteralPath $parent;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($serviceSid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $parent -AclObject $acl
 }
 }else{
  $hostExe=Join-Path $install 'native\FacuSecX.MonitorHost.exe';$sc=Join-Path $env:SystemRoot 'System32\sc.exe';$serviceCreated=$true
  Stop-Service -Name $serviceName -ErrorAction Stop
  $serviceSid=([Security.Principal.NTAccount]::new('NT SERVICE',$serviceName)).Translate([Security.Principal.SecurityIdentifier]).Value
 }
 . (Join-Path $PSScriptRoot 'Service-control.ps1')
 Grant-ServerMonitorStart $OwnerSid
 $info=[Diagnostics.ProcessStartInfo]::new($hostExe);$info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $prepareAction=if($resume){'prepare-resume'}else{'prepare'}
 $info.Arguments=$prepareAction+' "'+$SourceRoot+'" '+$OwnerSid
 $prepare=[Diagnostics.Process]::Start($info);$prepare.WaitForExit()
 if($prepare.ExitCode -ne 0){throw 'La verificación local no se completó. El panel anterior conserva sus cuentas.'}
 $anchorAcl=[Security.AccessControl.RegistrySecurity]::new();$anchorAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'));$anchorAcl.SetAccessRuleProtection($true,$false)
 foreach($id in @('S-1-5-18','S-1-5-32-544')){$anchorAcl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($id),'FullControl','ContainerInherit','None','Allow'))}
 $anchorAcl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($serviceSid),'ReadKey,SetValue','ContainerInherit','None','Allow'))
 $anchorAcl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($OwnerSid),'ReadKey','ContainerInherit','None','Allow'))
 Set-Acl -LiteralPath $registry -AclObject $anchorAcl
 $config=Get-Content -LiteralPath (Join-Path $install 'panel\config.json') -Raw | ConvertFrom-Json
 $port=if($config.listenPort){[int]$config.listenPort}else{8766}
 try{$health=Invoke-RestMethod -Uri ('http://127.0.0.1:'+$port+'/api/health') -TimeoutSec 3;if(-not $health.restart_safe){throw 'Hay una operación activa. Esperá a que finalice antes de instalar.'}}catch [System.Net.WebException]{}
 $runtime=Join-Path $install 'node\node.exe'
 & $runtime (Join-Path $install 'panel\backup-local-data.mjs') (Join-Path $SourceRoot 'data') (Join-Path $state 'data')
 if($LASTEXITCODE -ne 0){throw 'No se pudo copiar el historial y los perfiles de forma consistente.'}
 $newConfigPath=Join-Path $install 'panel\config.json'
 $newConfig=Get-Content -LiteralPath $newConfigPath -Raw | ConvertFrom-Json
 $probeListener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$probeListener.Start();$probePort=$probeListener.LocalEndpoint.Port;$probeListener.Stop()
 $newConfig | Add-Member -NotePropertyName listenPort -NotePropertyValue $probePort -Force
 [IO.File]::WriteAllText($newConfigPath,($newConfig | ConvertTo-Json -Depth 50),[Text.UTF8Encoding]::new($false))
 Start-Service -Name $serviceName
 $ready=$false
 for($attempt=0;$attempt -lt 40;$attempt++){
  Start-Sleep -Milliseconds 500
  try{$test=Invoke-RestMethod -Uri ('http://127.0.0.1:'+$probePort+'/api/health') -TimeoutSec 2;if($test.protected_runtime -eq $true){$ready=$true;break}}catch{}
 }
 if(-not $ready){throw 'El nuevo panel no respondió. La configuración no se activó. Abrí iniciar-panel.bat para corregir y reanudar.'}
 $probeCheck=Start-Process -FilePath $hostExe -ArgumentList @('verify-setup',[string]$probePort) -WindowStyle Hidden -PassThru -Wait
 if($probeCheck.ExitCode -ne 0){throw 'La conexión SSH o la pantalla de acceso no superaron la prueba. Abrí iniciar-panel.bat para corregir y reanudar; se conserva el acceso anterior.'}
 $matching=@(Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object {$_.CommandLine -and $_.CommandLine.IndexOf((Join-Path $SourceRoot 'server.mjs'),[StringComparison]::OrdinalIgnoreCase) -ge 0})
 foreach($running in $matching){Stop-Process -Id $running.ProcessId -ErrorAction Stop;$oldStopped+=$running.ProcessId}
 Stop-Service -Name $serviceName
 $migrationRecord=Get-ItemProperty -LiteralPath $registry
 if($migrationRecord.LegacyPath -and (Get-FileHash -LiteralPath $migrationRecord.LegacyPath -Algorithm SHA256).Hash -ne $migrationRecord.LegacyDigest){throw 'Las cuentas cambiaron durante la migración; se conserva el acceso anterior.'}
 & $runtime (Join-Path $install 'panel\backup-local-data.mjs') (Join-Path $SourceRoot 'data') (Join-Path $state 'data')
 if($LASTEXITCODE -ne 0){throw 'No se pudo completar la copia final del historial.'}
 $newConfig.listenPort=$port
 [IO.File]::WriteAllText($newConfigPath,($newConfig | ConvertTo-Json -Depth 50),[Text.UTF8Encoding]::new($false))
 Start-Service -Name $serviceName
 $finalReady=$false
 for($attempt=0;$attempt -lt 40;$attempt++){Start-Sleep -Milliseconds 500;try{$test=Invoke-RestMethod -Uri ('http://127.0.0.1:'+$port+'/api/health') -TimeoutSec 2;if($test.protected_runtime -eq $true){$finalReady=$true;break}}catch{}}
 if(-not $finalReady){throw 'No se pudo activar el nuevo puerto. Las cuentas originales se conservan.'}
 $commit=Start-Process -FilePath $hostExe -ArgumentList @('commit-setup',[string]$port) -WindowStyle Hidden -PassThru -Wait
 if($commit.ExitCode -ne 0){throw 'No se pudo verificar el acceso final. La configuración sigue pendiente; abrí iniciar-panel.bat para reanudar.'}
 Stop-Service -Name $serviceName
 Start-Service -Name $serviceName
 Set-Service -Name $serviceName -StartupType Automatic
 $run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';New-Item -Path $run -Force | Out-Null;Set-ItemProperty -LiteralPath $run -Name 'FacuSecXMonitorHello' -Value ('"'+(Join-Path $install 'native\Server Monitor.exe')+'" agent')
 $activated=$true
 Write-Output 'Protección instalada. Abrí el panel desde su acceso habitual para iniciar Windows Hello.'
}finally{
 if(-not $activated){
  $committed=$false
  if(Test-Path -LiteralPath $registry){$committed=(Get-ItemProperty -LiteralPath $registry).Activated -eq 1}
  if($serviceCreated -and -not $committed){Stop-Service -Name $serviceName -ErrorAction SilentlyContinue;Set-Service -Name $serviceName -StartupType Manual -ErrorAction SilentlyContinue}
  if($oldStopped.Count -gt 0 -and -not $committed){Write-Output 'La activación no se completó. Abrí iniciar-panel.bat para reanudar el asistente; las cuentas anteriores se conservaron.'}
  if(-not (Test-Path -LiteralPath $registry)){
   if($serviceCreated){& $sc delete $serviceName | Out-Null}
   # Only directories created by this attempt, checked against the fixed installation paths.
   $expectedInstall=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'FacuSecX\ServerSecurityMonitor'))
   $expectedState=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'FacuSecX\ServerSecurityMonitor\ProtectedV2'))
   if([IO.Path]::GetFullPath($install) -ne $expectedInstall -or [IO.Path]::GetFullPath($state) -ne $expectedState){throw 'No se pudo comprobar la ruta del intento cancelado.'}
   if($createdDirectories.Contains($install) -and (Test-Path -LiteralPath $install)){Remove-Item -LiteralPath $install -Recurse -Force}
   if($createdDirectories.Contains($state) -and (Test-Path -LiteralPath $state)){Remove-Item -LiteralPath $state -Recurse -Force}
   foreach($parent in @((Join-Path $env:ProgramData 'FacuSecX\ServerSecurityMonitor'),(Join-Path $env:ProgramData 'FacuSecX'))){if($createdDirectories.Contains($parent) -and (Test-Path -LiteralPath $parent) -and @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0){Remove-Item -LiteralPath $parent -Force}}
  }
 }
 $installMutex.Dispose()
}
