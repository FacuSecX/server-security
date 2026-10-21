function Grant-ServerMonitorStart([string]$OwnerSid) {
 $sc=Join-Path $env:SystemRoot 'System32\sc.exe'
 $output=@(& $sc sdshow 'FacuSecXMonitor' 2>&1)
 if($LASTEXITCODE -ne 0){throw 'No se pudieron consultar los permisos del servicio.'}
 $sddl=($output | Where-Object {[string]$_ -match '^[OGDS]:'}) -join ''
 if(-not $sddl){throw 'El descriptor del servicio no es valido.'}
 $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($sddl)
 $sid=[Security.Principal.SecurityIdentifier]::new($OwnerSid)
 # Query status and start this fixed service only. No stop, configuration,
 # binary-path, ownership or permission-editing rights are granted.
 $present=$false
 foreach($entry in $descriptor.DiscretionaryAcl){
  if($entry -is [Security.AccessControl.CommonAce] -and $entry.AceQualifier -eq 'AccessAllowed' -and $entry.SecurityIdentifier -eq $sid -and ($entry.AccessMask -band 0x14) -eq 0x14){$present=$true}
 }
 if(-not $present){
  $ace=[Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,0x14,$sid,$false,$null)
  $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count,$ace)
  $updated=$descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
  & $sc sdset 'FacuSecXMonitor' $updated | Out-Null
  if($LASTEXITCODE -ne 0){throw 'No se pudo habilitar la reapertura de Server Monitor.'}
 }
}
