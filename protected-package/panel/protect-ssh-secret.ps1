param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference = 'Stop'
try {
    $item = Get-Item -LiteralPath $Directory
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Ruta temporal no valida.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', $inheritance, 'None', 'Allow')
    $acl.AddAccessRule($rule)
    [IO.Directory]::SetAccessControl($Directory, $acl)
    $verified = [IO.Directory]::GetAccessControl($Directory)
    if (-not $verified.AreAccessRulesProtected) { throw 'Permisos heredados activos.' }
    foreach ($entry in $verified.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($entry.AccessControlType -eq 'Allow' -and $entry.IdentityReference.Value -ne $identity.Value) {
            throw 'Permisos de acceso demasiado amplios.'
        }
    }
    exit 0
} catch {
    [Console]::Error.WriteLine('No se pudieron establecer permisos privados para la autenticacion SSH.')
    exit 1
}
