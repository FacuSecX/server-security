param([ValidateSet('protect','unprotect','prepare')][string]$Action,[string]$Directory)
$ErrorActionPreference='Stop'
try {
  Add-Type -AssemblyName System.Security
  if ($Action -eq 'prepare') {
    $item=Get-Item -LiteralPath $Directory -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Directorio no permitido.' }
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true,$false)
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
    [IO.Directory]::SetAccessControl($item.FullName,$acl)
    $check=[IO.Directory]::GetAccessControl($item.FullName)
    if (-not $check.AreAccessRulesProtected) { throw 'Permisos no protegidos.' }
    foreach ($entry in $check.Access) {
      if ($entry.AccessControlType -eq 'Allow' -and $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Permisos demasiado amplios.' }
    }
    exit 0
  }
  $inputText=[Console]::In.ReadToEnd()
  if ($inputText.Length -gt 1048576) { throw 'Entrada demasiado grande.' }
  $bytes=[Convert]::FromBase64String($inputText)
  $entropy=[Text.Encoding]::UTF8.GetBytes('FacuSecX.ServerSecurityMonitor.Accounts.v1')
  if ($Action -eq 'protect') { $output=[Security.Cryptography.ProtectedData]::Protect($bytes,$entropy,'CurrentUser') }
  else { $output=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$entropy,'CurrentUser') }
  [Console]::Out.Write([Convert]::ToBase64String($output))
} catch {
  [Console]::Error.Write('No se pudo proteger o abrir el almacén local de cuentas de Windows.')
  exit 1
}
