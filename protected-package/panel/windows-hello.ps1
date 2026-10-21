param([ValidateSet('check','verify')][string]$Action='check',[ValidateSet('terminal','users')][string]$Purpose='terminal')
$ErrorActionPreference='Stop'
try {
    $nonce=[Console]::In.ReadToEnd().Trim()
    if($nonce -notmatch '^[a-f0-9]{64}$'){throw 'Solicitud no valida.'}
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-hello.cs') -ReferencedAssemblies 'System.Windows.Forms.dll','System.Drawing.dll'
    $result=[ServerMonitorHello]::Run(($Action -eq 'verify'),($Purpose -eq 'users'))
    [Console]::Out.Write((@{nonce=$nonce;result=$result;available=($Action -eq 'check' -and $result -eq 0);verified=($Action -eq 'verify' -and $result -eq 0)} | ConvertTo-Json -Compress))
} catch {
    [Console]::Out.Write((@{nonce=$nonce;result=-1;available=$false;verified=$false} | ConvertTo-Json -Compress))
    exit 1
}
